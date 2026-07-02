"""
Client for the Cisco Secure Cloud Analytics (formerly Stealthwatch Cloud) REST API.

Docs: https://developer.cisco.com/docs/stealthwatch/cloud/
Auth: "Authorization: ApiKey <api_user>:<api_key>" header, where api_user/api_key
      are generated per-user under the portal's user management settings.
Base: tenant-specific, e.g. https://<tenant>.obsrvbl.com -- there is no shared
      base URL the way there is for Umbrella/Meraki.

This integration is optional: a home network may not have Secure Cloud Analytics
deployed, so callers should treat missing credentials as "feature not configured"
rather than an error (see get_sca_client() in main.py).
"""

import logging
import requests

logger = logging.getLogger("secure_cloud_client")

ALERTS_PATH = "/api/v3/alerts/alert/"


class SCAAPIError(Exception):
    pass


class SecureCloudClient:
    def __init__(self, portal_url: str, api_user: str, api_key: str):
        # Tolerate a trailing slash on the configured portal URL.
        self.portal_url = portal_url.rstrip("/")
        self.api_user = api_user
        self.api_key = api_key

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"ApiKey {self.api_user}:{self.api_key}",
        }

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        url = f"{self.portal_url}{path}"
        resp = requests.get(url, headers=self._headers(), params=params or {}, timeout=30)
        if resp.status_code == 401:
            raise SCAAPIError(
                "Secure Cloud Analytics API returned 401 -- check SCA_API_USER/SCA_API_KEY."
            )
        if resp.status_code == 429:
            raise SCAAPIError("Secure Cloud Analytics API rate limit exceeded, try again shortly.")
        if not resp.ok:
            raise SCAAPIError(f"Secure Cloud Analytics API error {resp.status_code} for {path}: {resp.text}")
        return resp.json()

    def fetch_alerts(self, status: str = "open") -> list[dict]:
        """
        Returns alert records from Secure Cloud Analytics. `status` follows the
        API's own vocabulary ("open", "closed", "all"); "open" is the useful
        default for a NOC view since it's what an operator needs to act on.
        """
        params = {}
        if status and status != "all":
            params["status"] = status

        data = self._get(ALERTS_PATH, params=params)

        # Confirmed live: the alerts endpoint wraps results in {"objects": [...]}
        # (paginated via "meta"), not "results" or "alerts" as originally guessed.
        if isinstance(data, dict):
            return data.get("objects", data.get("results", data.get("alerts", [])))
        return data
