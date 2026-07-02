import os
import json
import time
import uuid
import logging
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, jsonify, request

from umbrella_client import UmbrellaClient, UmbrellaAuthError, FetchCancelled
from meraki_client import MerakiClient, MerakiAPIError, MerakiClientNotFound
from secure_cloud_client import SecureCloudClient, SCAAPIError
import aggregator
import alerts

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("app")

# --- Config from environment ---
UMBRELLA_KEY = os.environ.get("UMBRELLA_API_KEY", "")
UMBRELLA_SECRET = os.environ.get("UMBRELLA_API_SECRET", "")
UMBRELLA_ORG_ID = os.environ.get("UMBRELLA_ORG_ID", "")
MERAKI_API_KEY = os.environ.get("MERAKI_API_KEY", "")
MERAKI_ORG_ID = os.environ.get("MERAKI_ORG_ID", "")
MERAKI_CACHE_TTL_SECONDS = int(os.environ.get("MERAKI_CACHE_TTL_SECONDS", "3600"))
SCA_PORTAL_URL = os.environ.get("SCA_PORTAL_URL", "")
SCA_API_USER = os.environ.get("SCA_API_USER", "")
SCA_API_KEY = os.environ.get("SCA_API_KEY", "")
NOC_CACHE_TTL_SECONDS = int(os.environ.get("NOC_CACHE_TTL_SECONDS", "60"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/data/reports")

app = Flask(__name__)

# --- Time range definitions: name -> (hours, chunk_hours for pagination) ---
# chunk_hours is tuned per range so we stay under Umbrella's ~10,000 row
# pagination ceiling per chunk without making an excessive number of calls.
RANGES = {
    "1h": {"hours": 1, "chunk_hours": 0.5, "bucket_minutes": 5},
    "6h": {"hours": 6, "chunk_hours": 1, "bucket_minutes": 15},
    "12h": {"hours": 12, "chunk_hours": 1, "bucket_minutes": 30},
    "24h": {"hours": 24, "chunk_hours": 1, "bucket_minutes": 60},
    "7d": {"hours": 24 * 7, "chunk_hours": 6, "bucket_minutes": 60 * 6},
    "30d": {"hours": 24 * 30, "chunk_hours": 24, "bucket_minutes": 60 * 24},
}
DEFAULT_RANGE = "24h"

# --- In-memory cache of raw events per (range, identity_ids) combo ---
# Keeps us from re-hitting Umbrella every time a verdict/category filter
# changes -- those are recomputed from the cached raw batch instead.
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))
_cache = {}
_cache_lock = threading.Lock()

# --- Identity selection persistence (same as before) ---
SELECTED_IDENTITIES_FILE = Path(OUTPUT_DIR) / ".selected_identities.json"


def _load_selected_identities() -> list[str]:
    if SELECTED_IDENTITIES_FILE.exists():
        try:
            return json.loads(SELECTED_IDENTITIES_FILE.read_text())
        except Exception:
            logger.warning("Could not parse saved identity selection, ignoring")
    env_default = os.environ.get("DEFAULT_IDENTITY_IDS", "")
    return [i.strip() for i in env_default.split(",") if i.strip()]


def _save_selected_identities(ids: list[str]):
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    SELECTED_IDENTITIES_FILE.write_text(json.dumps(ids))


_selected_identity_ids = _load_selected_identities()

# --- Default network selection (scopes Overview/Network Health/Security
# Alerts/Firmware/Network Map to one Meraki network instead of the whole
# org) -- same persistence pattern as identity selection above, but
# deliberately a separate file/global: Umbrella identities and Meraki
# networks are different concepts and the DNS Activity section keeps using
# its own identity filter independent of this. None means "all networks",
# i.e. today's org-wide behavior.
SELECTED_NETWORK_FILE = Path(OUTPUT_DIR) / ".selected_network.json"


def _load_selected_network() -> str | None:
    if SELECTED_NETWORK_FILE.exists():
        try:
            return json.loads(SELECTED_NETWORK_FILE.read_text()) or None
        except Exception:
            logger.warning("Could not parse saved network selection, ignoring")
    return os.environ.get("DEFAULT_NETWORK_ID") or None


def _save_selected_network(network_id: str | None):
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    SELECTED_NETWORK_FILE.write_text(json.dumps(network_id))


_selected_network_id = _load_selected_network()

# --- Saved presets: named (range, identity_ids, verdict, categories) combos ---
PRESETS_FILE = Path(OUTPUT_DIR) / "presets.json"
_presets_lock = threading.Lock()


def _load_presets() -> list[dict]:
    if PRESETS_FILE.exists():
        try:
            return json.loads(PRESETS_FILE.read_text())
        except Exception:
            logger.warning("Could not parse saved presets file, starting empty")
    return []


def _save_presets(presets: list[dict]):
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    PRESETS_FILE.write_text(json.dumps(presets, indent=2))


_presets = _load_presets()


def get_client() -> UmbrellaClient:
    if not (UMBRELLA_KEY and UMBRELLA_SECRET):
        raise RuntimeError(
            "Missing Umbrella credentials. Set UMBRELLA_API_KEY and UMBRELLA_API_SECRET "
            "environment variables."
        )
    return UmbrellaClient(UMBRELLA_KEY, UMBRELLA_SECRET, UMBRELLA_ORG_ID)


def get_meraki_client() -> MerakiClient:
    if not (MERAKI_API_KEY and MERAKI_ORG_ID):
        raise RuntimeError(
            "Missing Meraki credentials. Set MERAKI_API_KEY and MERAKI_ORG_ID "
            "environment variables."
        )
    return MerakiClient(MERAKI_API_KEY, MERAKI_ORG_ID)


def get_sca_client() -> SecureCloudClient | None:
    """
    Secure Cloud Analytics is an optional NOC data source -- unlike Umbrella
    and Meraki, a home network may not have it deployed at all. Returns None
    (rather than raising) when unconfigured, so the NOC endpoints can simply
    omit that source instead of failing the whole request.
    """
    if not (SCA_PORTAL_URL and SCA_API_USER and SCA_API_KEY):
        return None
    return SecureCloudClient(SCA_PORTAL_URL, SCA_API_USER, SCA_API_KEY)


# --- In-memory cache of Meraki client-info lookups, keyed by internal IP ---
# Clicking the same IP repeatedly within the TTL window is served from here
# instead of re-querying Meraki (which involves several API calls per lookup:
# list networks, search clients, get client detail, get policy, resolve
# group policy name).
_meraki_cache = {}
_meraki_cache_lock = threading.Lock()


def get_meraki_client_info(ip: str) -> dict:
    with _meraki_cache_lock:
        cached = _meraki_cache.get(ip)
        if cached:
            fetched_at, info = cached
            if time.time() - fetched_at < MERAKI_CACHE_TTL_SECONDS:
                return {**info, "cached": True, "fetched_at": fetched_at}

    client = get_meraki_client()
    info = client.get_client_info(ip)
    fetched_at = time.time()

    with _meraki_cache_lock:
        _meraki_cache[ip] = (fetched_at, info)

    return {**info, "cached": False, "fetched_at": fetched_at}


# --- NOC data cache: combined Meraki health + Secure Cloud Analytics alerts ---
# Keyed by network_id (or "__all__" for org-wide), so switching the default
# network selection doesn't serve a stale batch scoped to a different
# network out of cache. Kept short (default 60s) since this powers the
# always-visible status strip and is meant to feel close to live, not a
# 10-minute Umbrella-style batch.
_noc_cache = {}
_noc_cache_lock = threading.Lock()


def _uplink_summary(uplinks: list[dict]) -> dict:
    """
    Rollup of getOrganizationApplianceUplinkStatuses -- "active"/"ready"/
    "online" are treated as healthy. Anything else counts as down *unless*
    the interface has never been provisioned at all (status "not connected"
    with no ip/gateway/ipAssignedBy ever recorded -- confirmed against a
    live org: this is what an unused failover WAN port on a single-WAN
    deployment looks like, not a failed link) -- those are excluded from
    both counts entirely so a device that only has one WAN plugged in
    doesn't permanently show "1 down". Meraki's docs don't enumerate the
    full status enum, so any other unfamiliar value is still conservatively
    treated as down rather than silently ignored.
    """
    healthy, down = 0, 0
    for device in uplinks:
        for uplink in device.get("uplinks", []):
            status = (uplink.get("status") or "").lower()
            if status in ("active", "ready", "online"):
                healthy += 1
            elif status == "not connected" and not (
                uplink.get("ip") or uplink.get("gateway") or uplink.get("ipAssignedBy")
            ):
                continue
            elif status:
                down += 1
    return {"healthy": healthy, "down": down}


# Priority order for reconciling the same third-party VPN peer reported by
# multiple Meraki hubs with different reachability -- "unreachable" from any
# single vantage point is a real signal and wins; "unknown" (a hub with no
# visibility into that tunnel) only wins over "reachable" if nothing better
# is seen.
_REACHABILITY_PRIORITY = {"unreachable": 2, "unknown": 1, "reachable": 0}


def _vpn_summary(vpn_statuses: list[dict]) -> dict:
    """
    Rollup of getOrganizationApplianceVpnStatuses -- confirmed against a
    live org that each entry has both merakiVpnPeers and
    thirdPartyVpnPeers, each with a "reachability" field ("reachable"/
    "unreachable"/"unknown").

    merakiVpnPeers are summed directly. thirdPartyVpnPeers are deduped by
    name first: the same physical tunnel is reported once per Meraki hub
    network, each from that hub's own vantage point, so summing raw entries
    would misrepresent one physical link as several (confirmed live: a
    single third-party peer showed "unreachable" from the hub it actually
    terminates on and "unknown" from two hubs with no visibility into it).
    Each unique peer counts once, using the worst reachability seen across
    hubs, so a real outage isn't hidden by other hubs' "unknown". The full
    per-hub detail (including all raw third-party entries) is still
    returned as-is by /api/noc/network-health for the Network Health table.
    """
    total_peers, down_peers = 0, 0
    for network in vpn_statuses:
        for peer in network.get("merakiVpnPeers") or []:
            total_peers += 1
            reachability = (peer.get("reachability") or "").lower()
            if reachability and reachability != "reachable":
                down_peers += 1

    third_party_reachability = {}
    for network in vpn_statuses:
        for peer in network.get("thirdPartyVpnPeers") or []:
            name = peer.get("name")
            reachability = (peer.get("reachability") or "").lower()
            best = third_party_reachability.get(name)
            if best is None or _REACHABILITY_PRIORITY.get(reachability, 0) > _REACHABILITY_PRIORITY.get(best, 0):
                third_party_reachability[name] = reachability
    for reachability in third_party_reachability.values():
        total_peers += 1
        if reachability == "unreachable":
            down_peers += 1

    return {"total_peers": total_peers, "down_peers": down_peers}


def _get_noc_data(network_id: str | None, force_refresh: bool = False) -> tuple[dict, float]:
    """
    Returns (data, fetched_at) with the raw (not-yet-normalized) payload
    backing the /api/noc/* endpoints: Meraki assurance alerts, uplink
    statuses, VPN statuses, device online/offline summary, and Secure Cloud
    Analytics alerts (if configured). Each source is fetched independently
    and failures are collected into data["errors"] rather than raising, so
    one broken source (e.g. SCA misconfigured) doesn't blank out the rest
    of the NOC view.

    network_id (None = org-wide) is part of the cache key -- switching the
    default network selection shouldn't serve a stale org-wide (or
    other-network) batch out of cache. Secure Cloud Analytics alerts are
    always org-wide regardless of network_id: SCA has no concept of a
    Meraki network id to filter by.
    """
    cache_key = network_id or "__all__"
    with _noc_cache_lock:
        cached = _noc_cache.get(cache_key)
        if cached and not force_refresh:
            fetched_at, data = cached
            if time.time() - fetched_at < NOC_CACHE_TTL_SECONDS:
                return data, fetched_at

    data = {
        "meraki_alerts": [],
        "uplinks": [],
        "vpn_statuses": [],
        "device_summary": None,
        "sca_alerts": [],
        "sca_configured": get_sca_client() is not None,
        "errors": [],
    }

    if MERAKI_API_KEY and MERAKI_ORG_ID:
        client = get_meraki_client()
        for label, key, fetcher in [
            ("Meraki alerts", "meraki_alerts", client.get_assurance_alerts),
            ("Meraki uplinks", "uplinks", client.get_uplink_statuses),
            ("Meraki VPN status", "vpn_statuses", client.get_vpn_statuses),
            ("Meraki device summary", "device_summary", client.get_device_status_summary),
        ]:
            try:
                data[key] = fetcher(network_id=network_id)
            except MerakiAPIError as e:
                logger.exception("NOC fetch failed: %s", label)
                data["errors"].append(f"{label}: {e}")

        # getOrganizationApplianceUplinkStatuses returns networkId but no
        # networkName (confirmed against a live org) -- unlike
        # getOrganizationApplianceVpnStatuses, which already includes
        # networkName on each entry. Enrich uplinks the same way so the
        # Network Health table doesn't show raw network IDs.
        if data["uplinks"]:
            try:
                network_names = {n.get("id"): n.get("name") for n in client.list_networks()}
                for device in data["uplinks"]:
                    device["networkName"] = network_names.get(device.get("networkId"))
            except MerakiAPIError as e:
                logger.exception("NOC fetch failed: network name lookup for uplinks")
                data["errors"].append(f"Meraki network names: {e}")
    else:
        data["errors"].append("Meraki credentials not configured")

    sca_client = get_sca_client()
    if sca_client:
        try:
            data["sca_alerts"] = sca_client.fetch_alerts(status="open")
        except SCAAPIError as e:
            logger.exception("NOC fetch failed: Secure Cloud Analytics alerts")
            data["errors"].append(f"Secure Cloud Analytics: {e}")

    fetched_at = time.time()
    with _noc_cache_lock:
        _noc_cache[cache_key] = (fetched_at, data)

    return data, fetched_at


def _normalized_noc_alerts(data: dict) -> list[dict]:
    meraki_alerts = [alerts.normalize_meraki_alert(a) for a in data["meraki_alerts"]]
    sca_alerts = [alerts.normalize_sca_alert(a, portal_url=SCA_PORTAL_URL) for a in data["sca_alerts"]]
    return alerts.merge_and_sort_alerts(meraki_alerts, sca_alerts)


# --- Firmware and topology caches, both keyed by network_id ---
# Firmware versions and physical topology change far less often than
# alerts/uplink status, so these reuse MERAKI_CACHE_TTL_SECONDS (the same
# TTL as the client-info lookup cache, default 1hr) rather than the NOC
# cache's short 60s TTL. Both are per-network (there's no org-wide "current
# state" for either), so network_id is a required, non-optional key here,
# unlike _get_noc_data's network_id which can be None for org-wide.
_firmware_cache = {}
_firmware_cache_lock = threading.Lock()
_topology_cache = {}
_topology_cache_lock = threading.Lock()


def get_firmware_upgrades(network_id: str, force_refresh: bool = False) -> dict:
    with _firmware_cache_lock:
        cached = _firmware_cache.get(network_id)
        if cached and not force_refresh:
            fetched_at, data = cached
            if time.time() - fetched_at < MERAKI_CACHE_TTL_SECONDS:
                return data

    client = get_meraki_client()
    data = client.get_firmware_upgrades(network_id)
    with _firmware_cache_lock:
        _firmware_cache[network_id] = (time.time(), data)
    return data


def _invalidate_firmware_cache(network_id: str):
    """Called after a schedule/cancel write so the next GET reflects it immediately instead of waiting out the TTL."""
    with _firmware_cache_lock:
        _firmware_cache.pop(network_id, None)


def get_topology(network_id: str, force_refresh: bool = False) -> dict:
    with _topology_cache_lock:
        cached = _topology_cache.get(network_id)
        if cached and not force_refresh:
            fetched_at, data = cached
            if time.time() - fetched_at < MERAKI_CACHE_TTL_SECONDS:
                return data

    client = get_meraki_client()
    data = client.get_topology(network_id)
    with _topology_cache_lock:
        _topology_cache[network_id] = (time.time(), data)
    return data


def _cache_key(range_name: str, identity_ids: list[str]) -> tuple:
    return (range_name, tuple(sorted(identity_ids)))


def get_events(
    range_name: str,
    identity_ids: list[str],
    force_refresh: bool = False,
    cancel_event: threading.Event | None = None,
) -> tuple[list[dict], float]:
    """
    Returns (events, fetched_at) for the given range + identity selection,
    using the in-memory cache when fresh. Triggers a real Umbrella fetch on
    a cache miss or expiry. fetched_at is a unix timestamp (seconds) of
    when that batch was actually pulled from Umbrella -- exposed to the
    frontend so it can show a "data is X minutes old" indicator.

    If cancel_event is given and gets set (typically by a user clicking
    Cancel while this is running in a background job thread), the
    underlying Umbrella fetch stops early and raises FetchCancelled rather
    than continuing to completion. Nothing partial is written to the
    cache in that case -- a cancelled fetch simply hasn't happened yet as
    far as the cache is concerned.
    """
    key = _cache_key(range_name, identity_ids)

    with _cache_lock:
        cached = _cache.get(key)
        if cached and not force_refresh:
            fetched_at, events = cached
            if time.time() - fetched_at < CACHE_TTL_SECONDS:
                return events, fetched_at

    if cancel_event and cancel_event.is_set():
        raise FetchCancelled("Fetch cancelled before it started")

    range_cfg = RANGES[range_name]
    client = get_client()
    events = client.fetch_dns_activity(
        hours=range_cfg["hours"],
        identity_ids=identity_ids or None,
        chunk_hours=range_cfg["chunk_hours"],
        cancel_check=(cancel_event.is_set if cancel_event else None),
    )

    fetched_at = time.time()
    with _cache_lock:
        _cache[key] = (fetched_at, events)

    return events, fetched_at


# --- Background jobs for cancellable activity fetches ---
# The main "Fetch" flow runs as a background job rather than directly in
# the request thread, specifically so a user clicking Cancel can actually
# stop the in-progress Umbrella pull (via the job's cancel_event) instead
# of merely having the browser stop waiting for a response that keeps
# being computed anyway.
_jobs = {}
_jobs_lock = threading.Lock()
JOB_RETENTION_SECONDS = 300  # finished/cancelled/errored jobs are pruned after this


def _prune_old_jobs():
    cutoff = time.time() - JOB_RETENTION_SECONDS
    stale = [jid for jid, j in _jobs.items() if j.get("finished_at") and j["finished_at"] < cutoff]
    for jid in stale:
        del _jobs[jid]


def _run_activity_job(job_id, range_name, identity_ids, verdict, categories, refresh, cancel_event):
    try:
        events, fetched_at = get_events(
            range_name, identity_ids, force_refresh=refresh, cancel_event=cancel_event
        )
        available_categories = aggregator.all_categories(events)
        available_internal_ips = aggregator.distinct_internal_ips(events)
        available_identities_in_data = aggregator.distinct_identities(events)
        filtered = aggregator.filter_events(events, verdict=verdict, categories=categories or None)
        bucket_minutes = RANGES[range_name]["bucket_minutes"]

        payload = {
            "range": range_name,
            "identity_ids": identity_ids,
            "verdict": verdict,
            "categories": categories,
            "raw_event_count": len(events),
            "filtered_event_count": len(filtered),
            "available_categories": available_categories,
            "available_internal_ips": available_internal_ips,
            "available_identities_in_data": available_identities_in_data,
            "fetched_at": fetched_at,
            "cache_ttl_seconds": CACHE_TTL_SECONDS,
            "summary": aggregator.build_summary(filtered),
            "timeseries": aggregator.build_timeseries(filtered, bucket_minutes=bucket_minutes),
            "destinations": aggregator.build_destinations(filtered),
            "category_breakdown": aggregator.build_categories(filtered),
        }
        with _jobs_lock:
            _jobs[job_id] = {"status": "done", "payload": payload, "finished_at": time.time()}
        logger.info("Job %s completed: %d raw events", job_id, len(events))

    except FetchCancelled:
        with _jobs_lock:
            _jobs[job_id] = {"status": "cancelled", "finished_at": time.time()}
        logger.info("Job %s was cancelled", job_id)

    except (UmbrellaAuthError, RuntimeError) as e:
        with _jobs_lock:
            _jobs[job_id] = {"status": "error", "error": str(e), "finished_at": time.time()}
        logger.exception("Job %s failed", job_id)

    except Exception as e:
        with _jobs_lock:
            _jobs[job_id] = {"status": "error", "error": str(e), "finished_at": time.time()}
        logger.exception("Job %s failed unexpectedly", job_id)


@app.route("/")
def index():
    return render_template("index.html", ranges=list(RANGES.keys()), default_range=DEFAULT_RANGE)


@app.route("/api/activity/start", methods=["POST"])
def api_activity_start():
    """
    Starts a background job that fetches (or reuses cached) raw events for
    the requested range + identity selection, applies verdict/category
    filters, and computes the full dashboard payload. Returns a job_id to
    poll via /api/activity/poll/<job_id>, and cancel via
    /api/activity/cancel/<job_id>.
    """
    range_name = request.args.get("range", DEFAULT_RANGE)
    if range_name not in RANGES:
        return jsonify({"error": f"Unknown range '{range_name}'. Valid: {list(RANGES.keys())}"}), 400

    identity_ids_param = request.args.get("identity_ids", "")
    identity_ids = [i.strip() for i in identity_ids_param.split(",") if i.strip()]

    verdict = request.args.get("verdict") or None
    if verdict and verdict.lower() not in ("allowed", "blocked"):
        return jsonify({"error": "verdict must be 'allowed' or 'blocked'"}), 400

    categories_param = request.args.get("categories", "")
    categories = [c.strip() for c in categories_param.split(",") if c.strip()]

    refresh = request.args.get("refresh") == "1"

    job_id = uuid.uuid4().hex
    cancel_event = threading.Event()

    with _jobs_lock:
        _prune_old_jobs()
        _jobs[job_id] = {"status": "running", "cancel_event": cancel_event}

    thread = threading.Thread(
        target=_run_activity_job,
        args=(job_id, range_name, identity_ids, verdict, categories, refresh, cancel_event),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/api/activity/poll/<job_id>")
def api_activity_poll(job_id):
    """Returns the current status of a job started via /api/activity/start."""
    with _jobs_lock:
        job = _jobs.get(job_id)

    if job is None:
        return jsonify({"error": "Unknown or expired job_id"}), 404

    if job["status"] == "running":
        return jsonify({"status": "running"})
    if job["status"] == "cancelled":
        return jsonify({"status": "cancelled"})
    if job["status"] == "error":
        return jsonify({"status": "error", "error": job.get("error", "Unknown error")})

    # status == "done"
    return jsonify({"status": "done", **job["payload"]})


@app.route("/api/activity/cancel/<job_id>", methods=["POST"])
def api_activity_cancel(job_id):
    """
    Signals a running job to stop. The job's own thread notices this on
    its next chunk/page boundary inside fetch_dns_activity and raises
    FetchCancelled, at which point its status flips to 'cancelled' --
    this endpoint itself doesn't set the final status, it just requests it.
    """
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Unknown or expired job_id"}), 404
        if job["status"] == "running":
            job["cancel_event"].set()

    return jsonify({"status": "cancelling"})


@app.route("/api/domain-activity")
def api_domain_activity():
    """
    Every request made TO a given destination domain within the currently
    selected range + identity scope -- mirror of /api/ip-activity, used to
    answer "which internal IPs have been talking to this domain". Reuses
    the same in-memory cache, no extra Umbrella API call.
    """
    range_name = request.args.get("range", DEFAULT_RANGE)
    if range_name not in RANGES:
        return jsonify({"error": f"Unknown range '{range_name}'. Valid: {list(RANGES.keys())}"}), 400

    identity_ids_param = request.args.get("identity_ids", "")
    identity_ids = [i.strip() for i in identity_ids_param.split(",") if i.strip()]

    domain = (request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain query parameter is required"}), 400

    try:
        events, _ = get_events(range_name, identity_ids)
    except (UmbrellaAuthError, RuntimeError) as e:
        logger.exception("Failed to fetch activity for domain search")
        return jsonify({"error": str(e)}), 500

    rows = aggregator.build_domain_requests(events, domain)

    return jsonify(
        {
            "range": range_name,
            "domain": domain,
            "request_count": len(rows),
            "requests": rows,
        }
    )


@app.route("/api/identity-activity")
def api_identity_activity():
    """
    Every request involving a given identity within the currently
    selected range + identity scope. Reuses the same in-memory cache as
    /api/activity -- no extra Umbrella API call.
    """
    range_name = request.args.get("range", DEFAULT_RANGE)
    if range_name not in RANGES:
        return jsonify({"error": f"Unknown range '{range_name}'. Valid: {list(RANGES.keys())}"}), 400

    identity_ids_param = request.args.get("identity_ids", "")
    identity_ids = [i.strip() for i in identity_ids_param.split(",") if i.strip()]

    target_identity = (request.args.get("identity") or "").strip()
    if not target_identity:
        return jsonify({"error": "identity query parameter is required"}), 400

    try:
        events, _ = get_events(range_name, identity_ids)
    except (UmbrellaAuthError, RuntimeError) as e:
        logger.exception("Failed to fetch activity for identity search")
        return jsonify({"error": str(e)}), 500

    rows = aggregator.build_identity_requests(events, target_identity)

    return jsonify(
        {
            "range": range_name,
            "identity": target_identity,
            "request_count": len(rows),
            "requests": rows,
        }
    )


@app.route("/api/ip-activity")
def api_ip_activity():
    """
    Every request made by a given internal IP within the currently
    selected range + identity scope. Reuses the same in-memory cache as
    /api/activity -- no extra Umbrella API call, just a different way of
    slicing the same already-fetched batch.
    """
    range_name = request.args.get("range", DEFAULT_RANGE)
    if range_name not in RANGES:
        return jsonify({"error": f"Unknown range '{range_name}'. Valid: {list(RANGES.keys())}"}), 400

    identity_ids_param = request.args.get("identity_ids", "")
    identity_ids = [i.strip() for i in identity_ids_param.split(",") if i.strip()]

    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip query parameter is required"}), 400

    try:
        events, _ = get_events(range_name, identity_ids)
    except (UmbrellaAuthError, RuntimeError) as e:
        logger.exception("Failed to fetch activity for IP search")
        return jsonify({"error": str(e)}), 500

    rows = aggregator.build_ip_requests(events, ip)

    return jsonify(
        {
            "range": range_name,
            "ip": ip,
            "request_count": len(rows),
            "requests": rows,
        }
    )


@app.route("/api/client-info")
def api_client_info():
    """
    Looks up Meraki client details (description, MAC, policy, status,
    device type/OS, plus whatever else is available) for a given internal
    IP. Results are cached in memory for MERAKI_CACHE_TTL_SECONDS (default
    1 hour) since a single lookup involves several Meraki API calls.
    """
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip query parameter is required"}), 400

    try:
        info = get_meraki_client_info(ip)
        return jsonify(info)
    except MerakiClientNotFound as e:
        return jsonify({"error": str(e)}), 404
    except (MerakiAPIError, RuntimeError) as e:
        logger.exception("Meraki client-info lookup failed for ip %s", ip)
        return jsonify({"error": str(e)}), 500


@app.route("/api/identities")
def api_identities():
    """Returns the org's list of identities so the UI can populate a filter."""
    try:
        client = get_client()
        identities = client.fetch_identities()
        return jsonify({"identities": identities, "selected": _selected_identity_ids})
    except Exception as e:
        logger.exception("Failed to fetch identities")
        return jsonify({"error": str(e)}), 500


@app.route("/api/identities/select", methods=["POST"])
def api_select_identities():
    """Persist which identities the UI should default to on load."""
    global _selected_identity_ids
    body = request.get_json(force=True) or {}
    ids = body.get("identity_ids", [])
    if not isinstance(ids, list):
        return jsonify({"error": "identity_ids must be a list"}), 400
    _selected_identity_ids = [str(i) for i in ids]
    _save_selected_identities(_selected_identity_ids)
    return jsonify({"selected": _selected_identity_ids})


@app.route("/api/networks")
def api_networks():
    """
    Returns the org's Meraki networks, for the network-scoping selector
    (Overview/Network Health/Security Alerts/Firmware/Network Map). Separate
    from /api/identities -- Umbrella identities and Meraki networks are
    different concepts, and DNS Activity keeps its own identity filter.
    """
    try:
        client = get_meraki_client()
        networks = client.list_networks()
        return jsonify({"networks": networks, "selected": _selected_network_id})
    except (MerakiAPIError, RuntimeError) as e:
        logger.exception("Failed to fetch networks")
        return jsonify({"error": str(e)}), 500


@app.route("/api/network/select", methods=["POST"])
def api_select_network():
    """
    Persists the default network for future page loads (null = "all
    networks"). Each /api/noc/*, /api/firmware, /api/topology request still
    takes its own explicit network_id query param -- this endpoint only
    controls what the UI pre-selects on next load, the same relationship
    /api/identities/select has to /api/activity/start.
    """
    global _selected_network_id
    body = request.get_json(force=True) or {}
    network_id = body.get("network_id") or None
    _selected_network_id = str(network_id) if network_id else None
    _save_selected_network(_selected_network_id)
    return jsonify({"selected": _selected_network_id})


@app.route("/api/presets", methods=["GET"])
def api_list_presets():
    """Returns all saved presets for the dropdown next to Fetch."""
    with _presets_lock:
        return jsonify({"presets": _presets})


@app.route("/api/presets", methods=["POST"])
def api_create_preset():
    """
    Saves the current filter selection (range, identity_ids, verdict,
    categories) as a named preset. Selecting a preset later only
    populates these filters -- it never triggers a fetch by itself.
    """
    global _presets
    body = request.get_json(force=True) or {}

    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    range_name = body.get("range")
    if range_name not in RANGES:
        return jsonify({"error": f"Unknown range '{range_name}'. Valid: {list(RANGES.keys())}"}), 400

    identity_ids = body.get("identity_ids", [])
    if not isinstance(identity_ids, list):
        return jsonify({"error": "identity_ids must be a list"}), 400

    verdict = body.get("verdict") or None
    if verdict and verdict.lower() not in ("allowed", "blocked"):
        return jsonify({"error": "verdict must be 'allowed', 'blocked', or null"}), 400

    categories = body.get("categories", [])
    if not isinstance(categories, list):
        return jsonify({"error": "categories must be a list"}), 400

    preset = {
        "id": uuid.uuid4().hex,
        "name": name,
        "range": range_name,
        "identity_ids": [str(i) for i in identity_ids],
        "verdict": verdict,
        "categories": [str(c) for c in categories],
        "created_at": time.time(),
    }

    with _presets_lock:
        _presets.append(preset)
        _save_presets(_presets)

    return jsonify({"preset": preset})


@app.route("/api/presets/<preset_id>", methods=["PUT"])
def api_rename_preset(preset_id):
    """Renames an existing preset in place (used by the inline rename control)."""
    global _presets
    body = request.get_json(force=True) or {}
    new_name = (body.get("name") or "").strip()
    if not new_name:
        return jsonify({"error": "name is required"}), 400

    with _presets_lock:
        for preset in _presets:
            if preset["id"] == preset_id:
                preset["name"] = new_name
                _save_presets(_presets)
                return jsonify({"preset": preset})

    return jsonify({"error": "Unknown preset id"}), 404


@app.route("/api/presets/<preset_id>", methods=["DELETE"])
def api_delete_preset(preset_id):
    """Deletes a preset (used by the inline delete control)."""
    global _presets
    with _presets_lock:
        before = len(_presets)
        _presets = [p for p in _presets if p["id"] != preset_id]
        if len(_presets) == before:
            return jsonify({"error": "Unknown preset id"}), 404
        _save_presets(_presets)

    return jsonify({"deleted": preset_id})


@app.route("/api/noc/overview")
def api_noc_overview():
    """
    Powers the always-visible status strip: uplink/VPN health rollups,
    device online/offline counts, and open-alert counts across both Meraki
    and Secure Cloud Analytics. Cached per network_id for
    NOC_CACHE_TTL_SECONDS (default 60s) -- pass ?refresh=1 to force a live
    pull. network_id (optional) scopes everything except Secure Cloud
    Analytics alerts (which aren't Meraki-network-scoped) to one network --
    omit it for org-wide, same as today.
    """
    force_refresh = request.args.get("refresh") == "1"
    network_id = request.args.get("network_id") or None
    data, fetched_at = _get_noc_data(network_id, force_refresh=force_refresh)
    combined_alerts = _normalized_noc_alerts(data)
    open_alerts = [a for a in combined_alerts if a["status"] == "open"]

    return jsonify(
        {
            "fetched_at": fetched_at,
            "cache_ttl_seconds": NOC_CACHE_TTL_SECONDS,
            "device_summary": data["device_summary"],
            "uplinks": _uplink_summary(data["uplinks"]),
            "vpn": _vpn_summary(data["vpn_statuses"]),
            "open_alert_count": len(open_alerts),
            "critical_alert_count": sum(1 for a in open_alerts if a["severity"] == "critical"),
            "sca_configured": data["sca_configured"],
            "errors": data["errors"],
        }
    )


@app.route("/api/noc/alerts")
def api_noc_alerts():
    """
    Full combined, normalized alert list (Meraki assurance alerts + Secure
    Cloud Analytics), sorted by severity then recency. Backs the Overview
    and Security Alerts sections. Read-only -- no acknowledge/close/mute;
    each alert links out to its source dashboard for that. network_id
    (optional) scopes the Meraki alerts to one network; SCA alerts stay
    org-wide regardless.
    """
    force_refresh = request.args.get("refresh") == "1"
    network_id = request.args.get("network_id") or None
    data, fetched_at = _get_noc_data(network_id, force_refresh=force_refresh)

    return jsonify(
        {
            "fetched_at": fetched_at,
            "alerts": _normalized_noc_alerts(data),
            "sca_configured": data["sca_configured"],
            "errors": data["errors"],
        }
    )


@app.route("/api/noc/network-health")
def api_noc_network_health():
    """Raw (unrolled-up) uplink/VPN/device data for the Network Health section's detail tables. network_id (optional) scopes to one network."""
    force_refresh = request.args.get("refresh") == "1"
    network_id = request.args.get("network_id") or None
    data, fetched_at = _get_noc_data(network_id, force_refresh=force_refresh)

    return jsonify(
        {
            "fetched_at": fetched_at,
            "uplinks": data["uplinks"],
            "vpn_statuses": data["vpn_statuses"],
            "device_summary": data["device_summary"],
            "errors": data["errors"],
        }
    )


@app.route("/api/firmware")
def api_firmware():
    """
    Current/available firmware per product type for one network. Firmware
    is inherently per-network (no org-wide "current state" endpoint), so
    network_id is required here, unlike the /api/noc/* endpoints.
    """
    network_id = (request.args.get("network_id") or "").strip()
    if not network_id:
        return jsonify({"error": "network_id query parameter is required"}), 400

    force_refresh = request.args.get("refresh") == "1"
    try:
        data = get_firmware_upgrades(network_id, force_refresh=force_refresh)
        return jsonify(data)
    except (MerakiAPIError, RuntimeError) as e:
        logger.exception("Failed to fetch firmware upgrades for network %s", network_id)
        return jsonify({"error": str(e)}), 500


def _validate_iso_time(time_iso: str) -> bool:
    try:
        datetime.fromisoformat(time_iso.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


@app.route("/api/firmware/schedule", methods=["POST"])
def api_firmware_schedule():
    """
    Schedules a firmware upgrade for one product type on one network. This
    is a real write against live hardware -- the scheduled upgrade will
    reboot devices of that type during the upgrade window. version_id is
    validated against that product's actual availableVersions (from a
    fresh, uncached read) before anything is written, so a stale or
    fabricated id can't reach Meraki's API.
    """
    body = request.get_json(force=True) or {}
    network_id = (body.get("network_id") or "").strip()
    product_type = (body.get("product_type") or "").strip()
    version_id = str(body.get("version_id") or "").strip()
    time_iso = (body.get("time") or "").strip()

    if not (network_id and product_type and version_id and time_iso):
        return jsonify({"error": "network_id, product_type, version_id, and time are all required"}), 400
    if not _validate_iso_time(time_iso):
        return jsonify({"error": "time must be a valid ISO8601 timestamp"}), 400

    try:
        current = get_firmware_upgrades(network_id, force_refresh=True)
        product = (current.get("products") or {}).get(product_type)
        if product is None:
            return jsonify({"error": f"Unknown product_type '{product_type}' for this network"}), 400

        available_ids = {str(v.get("id")) for v in (product.get("availableVersions") or [])}
        if version_id not in available_ids:
            return jsonify({"error": f"version_id '{version_id}' is not an available version for {product_type}"}), 400

        client = get_meraki_client()
        result = client.schedule_firmware_upgrade(network_id, product_type, version_id, time_iso)
        _invalidate_firmware_cache(network_id)
        logger.info(
            "Scheduled firmware upgrade: network=%s product=%s version=%s time=%s",
            network_id, product_type, version_id, time_iso,
        )
        return jsonify(result)
    except (MerakiAPIError, RuntimeError) as e:
        logger.exception("Failed to schedule firmware upgrade for network %s product %s", network_id, product_type)
        return jsonify({"error": str(e)}), 500


@app.route("/api/firmware/cancel", methods=["POST"])
def api_firmware_cancel():
    """Clears a previously-scheduled firmware upgrade for one product type on one network."""
    body = request.get_json(force=True) or {}
    network_id = (body.get("network_id") or "").strip()
    product_type = (body.get("product_type") or "").strip()

    if not (network_id and product_type):
        return jsonify({"error": "network_id and product_type are required"}), 400

    try:
        client = get_meraki_client()
        result = client.cancel_firmware_upgrade(network_id, product_type)
        _invalidate_firmware_cache(network_id)
        logger.info("Cancelled scheduled firmware upgrade: network=%s product=%s", network_id, product_type)
        return jsonify(result)
    except (MerakiAPIError, RuntimeError) as e:
        logger.exception("Failed to cancel firmware upgrade for network %s product %s", network_id, product_type)
        return jsonify({"error": str(e)}), 500


@app.route("/api/topology")
def api_topology():
    """Device/link topology (LLDP/CDP-discovered) for one network, backing the Network Map section."""
    network_id = (request.args.get("network_id") or "").strip()
    if not network_id:
        return jsonify({"error": "network_id query parameter is required"}), 400

    force_refresh = request.args.get("refresh") == "1"
    try:
        data = get_topology(network_id, force_refresh=force_refresh)
        return jsonify(data)
    except (MerakiAPIError, RuntimeError) as e:
        logger.exception("Failed to fetch topology for network %s", network_id)
        return jsonify({"error": str(e)}), 500


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6961)
