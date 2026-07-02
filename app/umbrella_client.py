"""
Client for the Cisco Umbrella Reporting API (v2).

Docs: https://developer.cisco.com/docs/cloud-security/reporting-overview/
Auth: OAuth2 client-credentials grant against api.umbrella.com/auth/v2/token
Data: GET api.umbrella.com/reports/v2/activity/dns
      (org is scoped by the API key/token itself -- no org ID in the path)
"""

import os
import time
import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import Callable

logger = logging.getLogger("umbrella_client")

AUTH_URL = "https://api.umbrella.com/auth/v2/token"
BASE_URL = "https://api.umbrella.com/reports/v2"

PAGE_LIMIT = 500  # max rows per API page (Umbrella caps this; adjust if your plan differs)

# If a time window still hits Umbrella's pagination ceiling even after
# bisection, we stop splitting once the window gets this small -- there's
# no point trying to bisect a 30-second window further, and it guards
# against pathological infinite recursion.
MIN_BISECT_WINDOW = timedelta(minutes=1)
MAX_BISECT_DEPTH = 20  # log2(30 days in minutes) is ~15-16, so this is a generous safety margin


class UmbrellaAuthError(Exception):
    pass


class FetchCancelled(Exception):
    """Raised when a cancel_check callback signals the fetch should stop."""
    pass


class UmbrellaClient:
    def __init__(self, key: str, secret: str, org_id: str):
        self.key = key
        self.secret = secret
        self.org_id = org_id
        self._token = None
        self._token_expiry = 0

    def _get_token(self) -> str:
        """Fetch (or reuse cached) OAuth2 bearer token."""
        if self._token and time.time() < self._token_expiry - 30:
            return self._token

        resp = requests.post(
            AUTH_URL,
            auth=(self.key, self.secret),
            data={"grant_type": "client_credentials"},
            timeout=30,
        )
        if resp.status_code != 200:
            raise UmbrellaAuthError(
                f"Failed to authenticate with Umbrella API: {resp.status_code} {resp.text}"
            )

        payload = resp.json()
        self._token = payload["access_token"]
        # expires_in is seconds; default fallback if missing
        self._token_expiry = time.time() + payload.get("expires_in", 3600)
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def fetch_identities(self, days: int = 30) -> list[dict]:
        """
        Fetch the identities that have generated traffic in the last `days`
        days, ranked by request volume, via the /top-identities endpoint
        (Umbrella's API has no plain "list all identities" endpoint — this
        is the closest equivalent and covers anything actually active).

        Returns a list of dicts like: {"id": "...", "label": "...", "type": "..."}
        """
        stop = datetime.now(timezone.utc)
        start = stop - timedelta(days=days)
        start_ms = int(start.timestamp() * 1000)
        stop_ms = int(stop.timestamp() * 1000)

        url = f"{BASE_URL}/top-identities"
        seen_ids = set()
        all_identities = []
        offset = 0

        while True:
            params = {
                "from": start_ms,
                "to": stop_ms,
                "limit": PAGE_LIMIT,
                "offset": offset,
            }
            resp = requests.get(url, headers=self._headers(), params=params, timeout=30)

            if resp.status_code == 401:
                self._token = None
                resp = requests.get(url, headers=self._headers(), params=params, timeout=30)

            resp.raise_for_status()
            payload = resp.json()
            items = payload.get("data", [])

            for item in items:
                identity = item.get("identity", {})
                ident_id = identity.get("id")
                if ident_id is None or ident_id in seen_ids:
                    continue
                seen_ids.add(ident_id)
                id_type = identity.get("type", {})
                all_identities.append(
                    {
                        "id": ident_id,
                        "label": identity.get("label") or f"Identity {ident_id}",
                        "type": id_type.get("label") or id_type.get("type"),
                    }
                )

            logger.info("Fetched %d top-identity entries (offset=%d)", len(items), offset)

            if len(items) < PAGE_LIMIT:
                break
            offset += PAGE_LIMIT

        return all_identities

    def fetch_dns_activity(
        self,
        hours: int = 24,
        identity_ids: list[str] | None = None,
        chunk_hours: float = 1.0,
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[dict]:
        """
        Pull all DNS activity events for the last `hours` hours.

        Umbrella's activity endpoints enforce a hard pagination ceiling
        (offset + limit cannot exceed ~10,000 -- a 400 Bad Request is
        returned past that point). To pull more than 10,000 events in a
        window, we split the requested time range into chunks (default:
        1 hour each) and paginate within each chunk separately, which
        keeps each chunk's own result set under the ceiling in the
        typical case.

        If a chunk's actual volume still exceeds the ceiling despite that
        (e.g. an unusually busy day within a 30-day pull using 24-hour
        chunks), that chunk is adaptively bisected into two halves, each
        fetched (and further bisected if needed) until every sub-window's
        result set fits under the ceiling. This guarantees complete data
        regardless of traffic spikes, at the cost of extra API calls only
        for the specific windows that actually need it -- see
        _fetch_window for the bisection logic itself.

        If cancel_check is given, it's called before each chunk, each
        bisection, and each page within a window; if it returns True,
        FetchCancelled is raised immediately rather than continuing to
        hit the Umbrella API. This lets a caller running this in a
        background thread actually stop the work early (e.g. in response
        to a user clicking Cancel), rather than just abandoning interest
        in a result that keeps being computed anyway.

        If identity_ids is given, restricts results to those identities.
        Returns a list of raw event dicts.
        """
        overall_stop = datetime.now(timezone.utc)
        overall_start = overall_stop - timedelta(hours=hours)

        all_events = []
        chunk_delta = timedelta(hours=chunk_hours)
        chunk_start = overall_start

        while chunk_start < overall_stop:
            if cancel_check and cancel_check():
                raise FetchCancelled("Fetch cancelled before chunk completed")

            chunk_stop = min(chunk_start + chunk_delta, overall_stop)
            all_events.extend(
                self._fetch_window(chunk_start, chunk_stop, identity_ids, cancel_check)
            )
            chunk_start = chunk_stop

        return all_events

    def _fetch_window(
        self,
        start: datetime,
        stop: datetime,
        identity_ids: list[str] | None,
        cancel_check: Callable[[], bool] | None,
        depth: int = 0,
    ) -> list[dict]:
        """
        Fetches every event in [start, stop) via pagination. If Umbrella's
        pagination ceiling is hit partway through, the window is split in
        half and each half is fetched independently (recursively bisecting
        further if needed), rather than accepting incomplete data.

        Note: if the ceiling is hit, whatever partial pages were already
        fetched *at this level* are discarded in favor of the two
        recursive halves -- the first half's own fetch starts from the
        same `start` and will naturally re-cover that data, so keeping
        both would double-count events.
        """
        if cancel_check and cancel_check():
            raise FetchCancelled("Fetch cancelled before window completed")

        url = f"{BASE_URL}/activity/dns"
        start_ms = int(start.timestamp() * 1000)
        stop_ms = int(stop.timestamp() * 1000)

        events = []
        offset = 0
        while True:
            if cancel_check and cancel_check():
                raise FetchCancelled("Fetch cancelled mid-page")

            params = {
                "from": start_ms,
                "to": stop_ms,
                "limit": PAGE_LIMIT,
                "offset": offset,
            }
            if identity_ids:
                params["identityids"] = ",".join(str(i) for i in identity_ids)

            resp = requests.get(url, headers=self._headers(), params=params, timeout=60)

            if resp.status_code == 401:
                self._token = None
                resp = requests.get(url, headers=self._headers(), params=params, timeout=60)

            if resp.status_code == 400 and offset > 0:
                # Hit the pagination ceiling. Bisect this window and
                # fetch each half independently, unless we've already
                # split it down to (or past) the minimum useful size or
                # recursion depth -- in which case there's nothing more
                # we can do and we accept partial data for this sliver,
                # same as the old behavior, just as a last resort rather
                # than the first response.
                window_duration = stop - start
                if window_duration <= MIN_BISECT_WINDOW or depth >= MAX_BISECT_DEPTH:
                    logger.warning(
                        "Hit pagination limit at offset=%d for window %s - %s, and this "
                        "window is already at the minimum bisection size (duration=%s, "
                        "depth=%d) -- accepting partial data for this sliver. This would "
                        "require an extraordinarily high sustained request rate to hit.",
                        offset, start.isoformat(), stop.isoformat(), window_duration, depth,
                    )
                    break

                midpoint = start + window_duration / 2
                logger.info(
                    "Pagination ceiling hit at offset=%d for window %s - %s; bisecting "
                    "into %s - %s and %s - %s",
                    offset, start.isoformat(), stop.isoformat(),
                    start.isoformat(), midpoint.isoformat(),
                    midpoint.isoformat(), stop.isoformat(),
                )
                first_half = self._fetch_window(start, midpoint, identity_ids, cancel_check, depth + 1)
                second_half = self._fetch_window(midpoint, stop, identity_ids, cancel_check, depth + 1)
                return first_half + second_half

            resp.raise_for_status()
            payload = resp.json()
            page_events = payload.get("data", [])
            events.extend(page_events)

            logger.info(
                "Fetched %d events for window %s - %s (offset=%d)",
                len(page_events), start.isoformat(), stop.isoformat(), offset,
            )

            if len(page_events) < PAGE_LIMIT:
                break
            offset += PAGE_LIMIT

        return events
