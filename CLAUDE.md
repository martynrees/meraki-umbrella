# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the app

**Primary (Docker):**
```bash
cp .env.example .env   # fill in credentials first
docker compose up -d --build
```
Dashboard: `http://localhost:6961`

**Local dev (no Docker):**
```bash
cd app
python main.py   # or: flask run --port 6961
```
The `app/` directory must be the working directory — `main.py` imports sibling modules (`umbrella_client`, `meraki_client`, `secure_cloud_client`, `aggregator`, `alerts`) directly.

There are no tests and no linting configuration.

## Architecture

```
umbrella_client.py     ──┐
meraki_client.py       ──┤──▶  main.py (Flask)  ──▶  templates/index.html
secure_cloud_client.py ──┤
aggregator.py           ─┤   (pure: Umbrella events)
alerts.py               ─┘   (pure: Meraki + SCA alerts)
```

**`umbrella_client.py`** — OAuth2 client-credentials auth against `api.umbrella.com`, plus `fetch_dns_activity()` which pulls DNS events in time chunks. Handles Umbrella's ~10,000-row pagination ceiling via adaptive bisection: if a chunk hits the limit mid-pagination, `_fetch_window` splits it in half and recurses (up to `MAX_BISECT_DEPTH=20`). Cancellation is done via a `cancel_check` callback polled between every page and every chunk.

**`meraki_client.py`** — Three responsibilities. (1) `get_client_info()` searches every network in the org sequentially for a client matching an IP, falling back to `/organizations/{orgId}/devices/statuses` if no client matches (infrastructure IPs: APs, switches, etc. — that endpoint is deprecated by Meraki but still functional). (2) NOC/health methods used by `/api/noc/*`: `get_assurance_alerts()`, `get_uplink_statuses()`, `get_vpn_statuses()`, `get_device_status_summary()` — each takes an optional `network_id` to scope from org-wide down to one network (see "Default network scoping" below). (3) Firmware/topology methods used by `/api/firmware*` and `/api/topology`: `get_firmware_upgrades()`, `schedule_firmware_upgrade()`, `cancel_firmware_upgrade()` (the latter two are the app's only writes — see "Firmware scheduling is a real write" below), `get_topology()`.

**`secure_cloud_client.py`** — Client for Cisco Secure Cloud Analytics (Stealthwatch Cloud), `fetch_alerts()` against `/api/v3/alerts/alert/` on a tenant-specific portal URL, auth via `Authorization: ApiKey <user>:<key>`. Optional integration — `main.get_sca_client()` returns `None` when `SCA_PORTAL_URL`/`SCA_API_USER`/`SCA_API_KEY` aren't all set, and NOC endpoints simply omit that source rather than failing.

**`aggregator.py`** — Pure in-memory transformation of a raw Umbrella event batch: `filter_events`, `build_summary`, `build_timeseries`, `build_destinations`, `build_categories`, `build_ip_requests`, `build_domain_requests`, `build_identity_requests`. No I/O.

**`alerts.py`** — Pure normalization for the combined NOC alerts view: `normalize_meraki_alert`/`normalize_sca_alert` map each source's alert shape onto a common one (`id`, `source`, `severity`, `title`, `description`, `context`, `started_at`, `status`, `link`); `merge_and_sort_alerts` combines and sorts by severity then recency. Severity thresholds (Meraki's severity enum, SCA's numeric priority) are best-effort and may need tuning once real data is visible — see the module docstring.

**`main.py`** — Flask app. Five in-memory caches:
- `_cache`: raw Umbrella event batches keyed by `(range_name, tuple(sorted(identity_ids)))`, TTL `CACHE_TTL_SECONDS` (default 10 min). Verdict/category filter changes reuse the cached batch without re-fetching.
- `_meraki_cache`: Meraki client-info results keyed by IP, TTL `MERAKI_CACHE_TTL_SECONDS` (default 1 hr).
- `_noc_cache`: keyed by `network_id` (or `"__all__"` for org-wide) — Meraki assurance alerts/uplinks/VPN/device summary + SCA alerts, TTL `NOC_CACHE_TTL_SECONDS` (default 60s) — short, since it backs the always-visible status strip. Failures per source are collected into an `errors` list rather than raised, so e.g. a misconfigured SCA integration doesn't blank out Meraki data. SCA alerts are always fetched org-wide regardless of `network_id` (SCA has no Meraki-network concept).
- `_firmware_cache` / `_topology_cache`: both keyed by `network_id` (required, not optional — there's no org-wide "current state" for either), TTL `MERAKI_CACHE_TTL_SECONDS` since firmware/topology change far less often than alerts. `_firmware_cache` is invalidated immediately after a schedule/cancel write so the next read reflects it without waiting out the TTL.

Background job pattern for cancellable fetches: `POST /api/activity/start` spawns a daemon thread and returns a `job_id`; the browser polls `GET /api/activity/poll/<job_id>`; `POST /api/activity/cancel/<job_id>` sets a `threading.Event` that the fetch thread checks between pages. This pattern is Umbrella-specific (paginated, potentially slow); the `/api/noc/*`, `/api/firmware*`, and `/api/topology` endpoints are plain synchronous GETs/POSTs since each is a single fast call. Gunicorn runs one worker with 4 threads, so all in-memory state (`_cache`, `_meraki_cache`, `_noc_cache`, `_firmware_cache`, `_topology_cache`, `_jobs`, `_presets`) is shared across concurrent requests.

**`templates/index.html`** — Single-page app, vanilla JS, no build step, organized into six top-level sections (Overview / DNS Activity / Network Health / Security Alerts / Firmware / Network Map) via `.section-tab`/`.section-panel` — deliberately separate from the pre-existing `.tab`/`.tab-content` pattern used for the DNS Activity section's own Destinations/Categories/By IP/By Identity sub-tabs, since a single shared `switchToTab()` would clobber whichever nav wasn't being clicked. A persistent status strip above the section nav auto-refreshes every `NOC_REFRESH_MS` (60s, matching the backend cache TTL) regardless of active section. A network selector next to the section nav (`#network-select`) scopes Overview/Network Health/Security Alerts/Firmware/Network Map to one Meraki network — DNS Activity keeps its own independent identity filter. Talks to `/api/activity/start`, `/api/activity/poll/<job_id>`, `/api/identities`, `/api/ip-activity`, `/api/domain-activity`, `/api/identity-activity`, `/api/client-info`, `/api/presets`, `/api/noc/overview`, `/api/noc/alerts`, `/api/noc/network-health`, `/api/networks`, `/api/network/select`, `/api/firmware`, `/api/firmware/schedule`, `/api/firmware/cancel`, `/api/topology`.

The Network Map section renders `/api/topology`'s nodes/links as inline SVG via a plain BFS hop-distance layering from the root node (`renderTopology` in the script) — no graph library vendored, since Meraki's topology is inherently a tree (one `root: true` node) rather than an arbitrary graph.

**`static/vendor/`** — Chart.js, fonts (Space Grotesk, IBM Plex Mono, Inter) vendored locally — nothing loaded from CDNs.

## Persistence

Files written to `OUTPUT_DIR` (`/data/reports` in Docker, mapped to `./data/reports`):
- `presets.json` — saved filter presets (name, range, identity_ids, verdict, categories)
- `.selected_identities.json` — last-selected identity IDs, restored on next page load
- `.selected_network.json` — default Meraki network for the NOC sections (`null` = all networks), restored on next page load. Separate from identity selection on purpose — see `templates/index.html`'s entry above.

## Non-obvious constraints

**Timezone**: The container runs at `TZ=Australia/Perth` (UTC+8, no DST). `aggregator.build_timeseries` uses a hardcoded `PERTH_OFFSET_SECONDS = 8 * 3600` to align time buckets to Perth local days — not system timezone, not UTC.

**Identity list**: Umbrella has no "list all identities" endpoint. `/api/identities` uses `/top-identities` (last 30 days of traffic volume). Identities with zero DNS requests in that window won't appear in the picker.

**Umbrella pagination ceiling**: Umbrella's activity endpoint returns HTTP 400 once `offset + limit` exceeds ~10,000. The bisection in `_fetch_window` handles this; `MIN_BISECT_WINDOW = 1 minute` and `MAX_BISECT_DEPTH = 20` are the safety bounds.

**Meraki infrastructure fallback**: The deprecated `GET /organizations/{orgId}/devices/statuses` endpoint is used as a last resort after all networks' client lists are searched without a match. Worth revisiting if Meraki removes it.

**Secure Cloud Analytics field shapes** (confirmed live against a real tenant, 2026-07-02): the alerts endpoint (`/api/v3/alerts/alert/`) wraps results in `{"objects": [...], "meta": {...}}`, not `{"results": [...]}` or `{"alerts": [...]}` as originally guessed — `secure_cloud_client.fetch_alerts` was fixed to check `"objects"` first. Field names (`priority`, `source_info`, `created`/`obj_created`, `resolved`) were all correct as guessed. However `priority` came back as a flat `20` across every alert type this tenant had (New External Connection, Country Set Deviation, Internal Port Scanner, etc.) — the tenant's `/api/v3/alerts/priorities/` (per-type priority customization) is empty, so the field currently carries no severity signal at all for this org. `alerts._normalize_sca_priority`'s thresholds were widened (from an assumed 0–10 scale to 0–100: `>=70` critical, `>=40` warning) so an unconfigured default of 20 doesn't render every SCA alert as critical — revisit if a tenant with customized priorities shows real variance.

**Meraki uplink/VPN field shapes** (confirmed live against a real org): uplink entries have no loss%/latency fields despite that being a reasonable-looking guess — real fields are `interface`/`status`/`ip`/`publicIp`/`gateway`. Uplink devices carry `networkId` but no `networkName`; `_get_noc_data` in `main.py` enriches it server-side via `list_networks()` before the frontend ever sees it. `_uplink_summary` (`main.py`) excludes a `"not connected"` uplink from both the healthy and down counts when it has no `ip`/`gateway`/`ipAssignedBy` — confirmed live this is what an unused failover WAN port looks like on a single-WAN deployment, not a real failure; without this a single-WAN device would permanently show "1 down". VPN entries have both `merakiVpnPeers` and `thirdPartyVpnPeers`, each with `reachability` (`reachable`/`unreachable`/`unknown`). `_vpn_summary` sums `merakiVpnPeers` directly, and separately dedupes `thirdPartyVpnPeers` by name before counting each once (confirmed live: the same third-party tunnel is reported by every Meraki hub network, "unreachable" from the hub it actually terminates on and "unknown" from hubs with no visibility into it — summing raw entries would misrepresent one physical link as several, but dropping third-party peers from the rollup entirely, as an earlier version of this function did, hid a real outage from the status-strip header). A deduped peer counts as down only if any hub reports it "unreachable" — "unknown" alone doesn't. `thirdPartyVpnPeers` is still shown as-is (undeduped, one row per hub) in the Network Health table.

**Alert severity mapping**: `alerts._normalize_meraki_severity` is still an unverified guess at Meraki's severity enum — tune once real Meraki assurance alerts with varied severities are visible. `_normalize_sca_priority` was tuned against real data; see the Secure Cloud Analytics entry above.

**No MCP runtime dependency**: the user-referenced `meraki-magic-mcp-community` MCP server was deliberately *not* wired into this app — MCP is a protocol for LLM tool-calling clients, not something a synchronous Flask/gunicorn backend embeds. The NOC feature set instead expands `meraki_client.py`'s existing direct Dashboard REST API calls, using that MCP server's tool list only as a reference for "what's worth surfacing."

**Default network scoping — per-source filter params differ** (confirmed live): `getOrganizationAssuranceAlerts` takes `networkId` as a *singular plain string* (`networkId[]` returns a 400); `getOrganizationApplianceUplinkStatuses`, `getOrganizationApplianceVpnStatuses`, and `getOrganizationDevicesStatuses` all take `networkIds[]` (array-bracket form). `meraki_client.py`'s four NOC methods each handle their own correct form internally — don't assume they're interchangeable when adding a new org-wide method. Also: filtering `getOrganizationApplianceVpnStatuses` to a network with Site-to-Site VPN disabled (e.g. this org's "Lab" network) returns a 400, not an empty list — handled the same as any other per-source failure (collected into `errors`, doesn't blank out the rest of the NOC view), but worth knowing so it isn't mistaken for a bug.

**Firmware/topology endpoint paths are easy to get wrong** (confirmed live, both differ from the "obvious" guess): firmware is `/networks/{networkId}/firmwareUpgrades` (run-together camelCase, not `/firmware/upgrades`); topology is `/networks/{networkId}/topology/linkLayer` (not `/topology/link/layer`). Both are per-network only — there's no org-wide "current firmware state" or "org topology" endpoint (`/organizations/{orgId}/firmware/upgrades` exists but returns a *history* of past completed upgrades, not current versions).

**Firmware scheduling is a real write against live hardware**: `schedule_firmware_upgrade`/`cancel_firmware_upgrade` in `meraki_client.py` use read-modify-write (fetch current `products`, re-send every product type unchanged except the one being modified) rather than PUTting just the changed product, because Meraki's docs don't confirm whether an omitted product in the PUT body is left alone or cleared — this sidesteps that ambiguity entirely rather than risking another product's schedule. `main.py`'s `/api/firmware/schedule` route also independently validates `version_id` against a fresh read of that product's `availableVersions` before calling it, so a stale/fabricated ID never reaches the write. The frontend requires an explicit modal confirmation (network/device type/current→target version/scheduled time/reboot warning, `#firmware-modal-overlay` in `templates/index.html`) before calling it — there's no one-click schedule anywhere in the UI.
