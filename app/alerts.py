"""
Pure normalization for the combined NOC alerts view -- takes raw alert
records from meraki_client.get_assurance_alerts() and
secure_cloud_client.fetch_alerts(), and produces a single common shape so
the frontend doesn't need to know which source an alert came from. No I/O
here, same spirit as aggregator.py but for the alerts domain rather than
Umbrella DNS events.

Severity mapping is best-effort. Confirmed against a live tenant: SCA's
"priority" field came back as a flat 20 across every alert type present
(New External Connection, Country Set Deviation, Internal Port Scanner,
etc.) -- this tenant has no per-type priority customized (its
/api/v3/alerts/priorities/ list is empty), so the field currently carries
no severity signal at all. Thresholds below are widened from the original
0-10-scale guess so that an unconfigured-default 20 doesn't render every
SCA alert as "critical"; revisit once this tenant (or one with customized
priorities) shows real variance.
"""

_MERAKI_SEVERITY_MAP = {
    "critical": "critical",
    "severe": "critical",
    "warning": "warning",
    "warn": "warning",
    "info": "info",
    "informational": "info",
}


def _normalize_meraki_severity(raw) -> str:
    return _MERAKI_SEVERITY_MAP.get((raw or "").lower(), "info")


def _normalize_sca_priority(raw) -> str:
    try:
        priority = int(raw)
    except (TypeError, ValueError):
        return "info"
    if priority >= 70:
        return "critical"
    if priority >= 40:
        return "warning"
    return "info"


def normalize_meraki_alert(alert: dict) -> dict:
    network = alert.get("network") or {}
    return {
        "id": f"meraki:{alert.get('id')}",
        "source": "meraki",
        "severity": _normalize_meraki_severity(alert.get("severity")),
        "title": alert.get("title") or alert.get("type") or "Meraki alert",
        "description": alert.get("description"),
        "context": network.get("name"),
        "started_at": alert.get("startedAt"),
        "status": "resolved" if (alert.get("resolvedAt") or alert.get("dismissedAt")) else "open",
        "link": network.get("url"),
    }


def normalize_sca_alert(alert: dict, portal_url: str | None = None) -> dict:
    source_info = alert.get("source_info") or {}
    ips = source_info.get("ips") or []
    hostnames = source_info.get("hostnames") or []
    context = ", ".join(hostnames or ips) or None

    link = None
    alert_id = alert.get("id")
    if portal_url and alert_id is not None:
        link = f"{portal_url.rstrip('/')}/v2/#/alert/{alert_id}"

    return {
        "id": f"sca:{alert_id}",
        "source": "secure_cloud_analytics",
        "severity": _normalize_sca_priority(alert.get("priority")),
        "title": alert.get("type") or "Secure Cloud Analytics alert",
        "description": alert.get("description"),
        "context": context,
        "started_at": alert.get("created") or alert.get("obj_created"),
        "status": "resolved" if alert.get("resolved") else "open",
        "link": link,
    }


_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def merge_and_sort_alerts(meraki_alerts: list[dict], sca_alerts: list[dict]) -> list[dict]:
    """
    Combines already-normalized alert lists (see normalize_meraki_alert /
    normalize_sca_alert) and sorts by severity first, then most recent
    started_at within each severity -- the order an operator actually wants
    to scan a wallboard-style alert list in. Relies on Python's stable sort:
    sorting by recency first, then by severity, yields severity-major/
    recency-minor ordering without needing to negate ISO8601 strings.
    """
    combined = [*meraki_alerts, *sca_alerts]
    combined.sort(key=lambda a: a.get("started_at") or "", reverse=True)
    combined.sort(key=lambda a: _SEVERITY_ORDER.get(a["severity"], 3))
    return combined
