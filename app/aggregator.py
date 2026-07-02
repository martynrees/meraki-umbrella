"""
Turns raw Umbrella DNS activity events into the shapes the dashboard needs:
a summary strip, a time-series for the chart, a unique-destinations table,
and a categories rollup. All filtering (verdict, category) happens here too,
over an already-fetched batch of events -- no extra Umbrella API calls.
"""

from collections import defaultdict
from datetime import datetime, timezone


def _category_labels(cats) -> set[str]:
    """
    Umbrella's DNS activity 'categories' field is a list of objects like
    {"id": 71, "type": "customer", "label": "Block List"}. Pull out labels,
    but tolerate a list of plain strings too, just in case.
    """
    labels = set()
    if not cats:
        return labels
    for c in cats:
        if isinstance(c, dict):
            label = c.get("label")
            if label:
                labels.add(label)
        elif isinstance(c, str):
            labels.add(c)
    return labels


def _is_blocked(event: dict) -> bool:
    verdict = (event.get("verdict") or "").lower()
    return verdict == "blocked"


def all_categories(events: list[dict]) -> list[str]:
    """Distinct category labels seen across the batch, sorted, for filter dropdowns."""
    labels = set()
    for ev in events:
        labels.update(_category_labels(ev.get("categories")))
    return sorted(labels)


def filter_events(
    events: list[dict],
    verdict: str | None = None,
    categories: list[str] | None = None,
    identity_ids: list[str] | None = None,
) -> list[dict]:
    """
    Filter an already-fetched batch of events in memory.
    verdict: "allowed" | "blocked" | None (None = no filter)
    categories: list of category labels to require at least one match on
    identity_ids: restrict to events involving any of these identity IDs
      (defensive filter -- normally already applied at fetch time, but kept
      here too in case a cached batch covers a broader identity set)
    """
    cat_set = set(categories) if categories else None
    id_set = {str(i) for i in identity_ids} if identity_ids else None

    result = []
    for ev in events:
        if verdict:
            ev_verdict = (ev.get("verdict") or "").lower()
            if ev_verdict != verdict.lower():
                continue
        if cat_set:
            ev_cats = _category_labels(ev.get("categories"))
            if not (ev_cats & cat_set):
                continue
        if id_set:
            ev_identity_ids = {str(i.get("id")) for i in (ev.get("identities") or [])}
            if not (ev_identity_ids & id_set):
                continue
        result.append(ev)
    return result


def distinct_internal_ips(events: list[dict]) -> list[str]:
    """Distinct internal client IPs seen across the batch, sorted, for the IP search dropdown."""
    ips = {ev.get("internalip") for ev in events if ev.get("internalip")}
    return sorted(ips)


def distinct_identities(events: list[dict]) -> list[dict]:
    """
    Distinct identities seen across the batch, deduped by ID, for the By
    Identity tab's search dropdown. Each event's 'identities' field is a
    list (an event can involve more than one identity, e.g. a network and
    a roaming client), so this covers every identity actually present in
    the current fetch -- which can be more than one even if the fetch was
    scoped to a single identity filter, or many if it wasn't scoped at all.
    """
    seen = {}
    for ev in events:
        for identity in ev.get("identities") or []:
            ident_id = identity.get("id")
            if ident_id is None or ident_id in seen:
                continue
            id_type = identity.get("type")
            if isinstance(id_type, dict):
                id_type = id_type.get("label") or id_type.get("type")
            seen[ident_id] = {
                "id": ident_id,
                "label": identity.get("label") or f"Identity {ident_id}",
                "type": id_type,
            }
    return sorted(seen.values(), key=lambda i: i["label"].lower())


def build_identity_requests(events: list[dict], identity_id) -> list[dict]:
    """
    Every individual request involving a given identity, newest first --
    same shape as build_ip_requests, plus the internal IP that made each
    request (useful since a single identity, e.g. a network, can cover
    many different internal IPs), for the By Identity tab.
    """
    identity_id = str(identity_id)
    rows = []
    for ev in events:
        ev_identity_ids = {str(i.get("id")) for i in (ev.get("identities") or [])}
        if identity_id not in ev_identity_ids:
            continue
        ts = ev.get("timestamp")
        rows.append(
            {
                "timestamp": (
                    datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc).isoformat()
                    if ts is not None else None
                ),
                "internal_ip": ev.get("internalip") or "Unknown",
                "destination": ev.get("domain"),
                "category": "; ".join(sorted(_category_labels(ev.get("categories")))) or "Uncategorized",
                "verdict": (ev.get("verdict") or "").capitalize() or "Unknown",
            }
        )
    rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return rows


def build_domain_requests(events: list[dict], domain: str) -> list[dict]:
    """
    Every individual request made TO a given destination domain, newest
    first -- the mirror of build_ip_requests, used to answer "which
    internal IPs have been talking to this domain".
    """
    domain = (domain or "").strip().lower()
    rows = []
    for ev in events:
        if (ev.get("domain") or "").lower() != domain:
            continue
        ts = ev.get("timestamp")
        rows.append(
            {
                "timestamp": (
                    datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc).isoformat()
                    if ts is not None else None
                ),
                "internal_ip": ev.get("internalip") or "Unknown",
                "category": "; ".join(sorted(_category_labels(ev.get("categories")))) or "Uncategorized",
                "verdict": (ev.get("verdict") or "").capitalize() or "Unknown",
            }
        )
    rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return rows


def build_ip_requests(events: list[dict], ip: str) -> list[dict]:
    """
    Every individual request made by a given internal IP, newest first.
    Unlike the destinations/categories views, this is intentionally NOT
    rolled up -- the point of an IP-level search is to see the actual
    request-by-request history for that device.
    """
    ip = (ip or "").strip()
    rows = []
    for ev in events:
        if ev.get("internalip") != ip:
            continue
        ts = ev.get("timestamp")
        rows.append(
            {
                "timestamp": (
                    datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc).isoformat()
                    if ts is not None else None
                ),
                "destination": ev.get("domain"),
                "category": "; ".join(sorted(_category_labels(ev.get("categories")))) or "Uncategorized",
                "verdict": (ev.get("verdict") or "").capitalize() or "Unknown",
            }
        )
    rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return rows


def build_summary(events: list[dict]) -> dict:
    """High-level counts for the overview strip."""
    total = len(events)
    blocked = sum(1 for ev in events if _is_blocked(ev))
    allowed = total - blocked
    destinations = {ev.get("domain") for ev in events if ev.get("domain")}

    category_counts = defaultdict(int)
    for ev in events:
        for label in _category_labels(ev.get("categories")):
            category_counts[label] += 1
    top_category = max(category_counts.items(), key=lambda kv: kv[1])[0] if category_counts else None

    return {
        "total_requests": total,
        "unique_destinations": len(destinations),
        "allowed_requests": allowed,
        "blocked_requests": blocked,
        "allowed_pct": round((allowed / total) * 100, 1) if total else 0,
        "blocked_pct": round((blocked / total) * 100, 1) if total else 0,
        "top_category": top_category,
    }


def build_timeseries(events: list[dict], bucket_minutes: int = 60) -> list[dict]:
    """
    Bucket events into time slices for the chart. bucket_minutes controls
    granularity -- callers should pick something sensible for the range
    (e.g. 15-60 min buckets for short ranges, daily buckets for 7d/30d).

    Buckets are aligned to Australia/Perth local time (UTC+8, no DST) rather
    than UTC -- this matters for the daily/6-hour buckets used on longer
    ranges, where a UTC-aligned bucket would otherwise span 8am-to-8am
    Perth time instead of an actual Perth calendar day.

    Returns a time-sorted list of {bucket_start_iso, allowed, blocked}.
    """
    PERTH_OFFSET_SECONDS = 8 * 3600  # Australia/Perth is fixed UTC+8, no DST

    bucket_seconds = bucket_minutes * 60
    buckets = defaultdict(lambda: {"allowed": 0, "blocked": 0})

    for ev in events:
        ts = ev.get("timestamp")
        if ts is None:
            continue
        # timestamp is epoch ms; shift into Perth local time before bucketing
        # so bucket boundaries land on Perth-local hours/days, then shift back
        # to a true UTC epoch for storage.
        utc_epoch = int(ts) // 1000
        perth_epoch = utc_epoch + PERTH_OFFSET_SECONDS
        bucket_perth_epoch = (perth_epoch // bucket_seconds) * bucket_seconds
        bucket_epoch = bucket_perth_epoch - PERTH_OFFSET_SECONDS
        key = bucket_epoch
        if _is_blocked(ev):
            buckets[key]["blocked"] += 1
        else:
            buckets[key]["allowed"] += 1

    rows = []
    for bucket_epoch in sorted(buckets.keys()):
        dt = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
        rows.append(
            {
                "bucket_start": dt.isoformat(),
                "allowed": buckets[bucket_epoch]["allowed"],
                "blocked": buckets[bucket_epoch]["blocked"],
            }
        )
    return rows


def build_destinations(events: list[dict]) -> list[dict]:
    """One row per unique destination domain, with category and verdict counts."""
    agg = defaultdict(lambda: {"total": 0, "allowed": 0, "blocked": 0, "categories": set()})

    for ev in events:
        domain = ev.get("domain")
        if not domain:
            continue
        entry = agg[domain]
        entry["total"] += 1
        if _is_blocked(ev):
            entry["blocked"] += 1
        else:
            entry["allowed"] += 1
        entry["categories"].update(_category_labels(ev.get("categories")))

    rows = []
    for domain, data in agg.items():
        rows.append(
            {
                "destination": domain,
                "category": "; ".join(sorted(data["categories"])) or "Uncategorized",
                "total": data["total"],
                "allowed": data["allowed"],
                "blocked": data["blocked"],
            }
        )
    rows.sort(key=lambda r: r["total"], reverse=True)
    return rows


def build_categories(events: list[dict]) -> list[dict]:
    """One row per category, with verdict counts and share of total traffic."""
    agg = defaultdict(lambda: {"total": 0, "allowed": 0, "blocked": 0})
    total_events = len(events)

    for ev in events:
        labels = _category_labels(ev.get("categories")) or {"Uncategorized"}
        blocked = _is_blocked(ev)
        for label in labels:
            entry = agg[label]
            entry["total"] += 1
            if blocked:
                entry["blocked"] += 1
            else:
                entry["allowed"] += 1

    rows = []
    for label, data in agg.items():
        rows.append(
            {
                "category": label,
                "total": data["total"],
                "allowed": data["allowed"],
                "blocked": data["blocked"],
                "pct_of_total": round((data["total"] / total_events) * 100, 1) if total_events else 0,
            }
        )
    rows.sort(key=lambda r: r["total"], reverse=True)
    return rows
