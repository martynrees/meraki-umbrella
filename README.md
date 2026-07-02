# Home NOC

A self-hosted network operations dashboard for a home (or small) Meraki
network. It combines three data sources into one page:

- **DNS activity** from Cisco Umbrella -- what your clients are requesting,
  which categories that traffic falls into, and what's allowed vs blocked
  (the original feature this app started as).
- **Network health** from the Meraki Dashboard API -- WAN uplink status,
  VPN peer reachability, device online/offline counts, a firmware
  current-vs-latest view per device type (with the ability to schedule an
  upgrade), and a visual topology map.
- **Security alerts** from Meraki Assurance and (optionally) Cisco Secure
  Cloud Analytics -- a combined, read-only alert feed instead of checking
  two separate dashboards.

A persistent status strip at the top surfaces the state of all three at a
glance, regardless of which section you're looking at. A network selector
next to the section tabs scopes everything except DNS Activity down to one
Meraki network -- useful if, like this app's own dev/test org, you have one
real production network and several test/ancillary ones you don't want
noise from.

## Fully self-contained (mostly)

Chart.js and all fonts (Space Grotesk, IBM Plex Mono, Inter) are vendored
into `static/vendor/` and served by the app -- nothing is loaded from a
CDN. The app talks to three external APIs directly: Umbrella
(`api.umbrella.com`), Meraki (`api.meraki.com`), and, if configured,
Secure Cloud Analytics (your tenant's `*.obsrvbl.com` portal) -- no other
network access is required.

## What it shows

### Status strip

Always visible, regardless of which section is active: WAN uplink status,
VPN peer status, devices online/offline, and open alert count (colored
by worst severity present). Auto-refreshes every 60 seconds
(`NOC_REFRESH_MS` in `templates/index.html`, matching the backend's
`NOC_CACHE_TTL_SECONDS`). Each item jumps to the relevant section on click.

### Network selector

A dropdown next to the section tabs, populated from your org's actual
Meraki networks (`/api/networks`). Selecting one scopes Overview/Network
Health/Security Alerts/Firmware/Network Map down to just that network and
remembers the choice for next time (persisted server-side, same idea as
presets); Secure Cloud Analytics alerts stay org-wide regardless, since SCA
has no concept of a Meraki network. "All networks" (the default) restores
today's org-wide behavior. DNS Activity has its own independent identity
filter and isn't affected by this selector at all.

### Overview section

The landing page: expanded status cards plus the 8 most recent alerts
across both Meraki and Secure Cloud Analytics, each linking out to its
source dashboard for full detail/action (this app is read-only -- no
acknowledge/close/mute here by design).

### Network Health section

Device online/offline/alerting/dormant counts, a WAN uplinks table (per
interface: status, IP, public IP, gateway), and a VPN peers table
(Meraki-to-Meraki and third-party peers, reachability per peer). Backed by
`/api/noc/network-health`.

### Security Alerts section

The full combined alert list (Meraki Assurance alerts + Secure Cloud
Analytics, if configured), filterable by free-text search, source, and
open/resolved status, sortable by any column. If Secure Cloud Analytics
isn't configured, this shows Meraki alerts only with a note explaining
why -- it doesn't error out.

### Firmware section

Current vs. available firmware per device type (appliance, switch,
wireless, camera, sensor, etc.) for the currently-selected network --
prompts you to pick one above if "All networks" is selected, since
firmware is inherently per-network. A badge flags whether Meraki considers
an upgrade available (`isUpgradeAvailable`, not just "is there a newer
version in the list" -- Meraki's own recommendation signal). **Scheduling
an upgrade is a real write against your live hardware** -- devices of that
type reboot during the upgrade window. Clicking Schedule opens a
confirmation modal showing exactly what will change (current -> target
version, scheduled time) with an explicit reboot warning; nothing is
scheduled until you click Confirm. A previously-scheduled upgrade shows
inline with a Cancel link. Backed by `/api/firmware`,
`/api/firmware/schedule`, `/api/firmware/cancel`.

### Network Map section

A visual topology diagram for the currently-selected network (same
"pick a network above" prompt as Firmware if none selected), built from
Meraki's LLDP/CDP-discovered device links (`/api/topology`): your gateway
at the top, switches/APs/cameras laid out by hop distance below it, with
hover tooltips showing device status/client count and per-link port info.
Rendered as plain inline SVG -- no charting/graph library vendored, since
Meraki's topology is inherently a tree (one gateway node) rather than an
arbitrary graph that would need a real force-directed layout.

### DNS Activity section

Everything below this point is the original Umbrella dashboard, unchanged,
now living under its own section rather than being the whole page.

- **Summary cards**: total requests, unique destinations, allowed/blocked
  counts and percentages, and the top content category for the selected
  window.
- **Top blocked destinations callout**: the 5 most-blocked domains for
  the current view, ranked by block count, with their category --
  derived entirely from the already-loaded destinations data (no extra
  fetch). Hidden automatically if there's no blocked traffic to show
  (e.g. when filtered to "Allowed only").
- **Requests-over-time chart**: allowed vs blocked volume, bucketed
  appropriately for the selected range (5-minute buckets for "last hour"
  up to daily buckets for "last 30 days").
- **Destinations table**: every unique domain queried, with its
  category and allowed/blocked counts, sortable and searchable.
- **Categories table**: traffic rolled up by content category (Business,
  Advertising, Malware, etc.), with allowed/blocked counts and share of
  total traffic.
- **By IP tab**: search for a specific internal client IP address and see
  every individual request it made in the selected window -- timestamp,
  destination, category, and verdict, newest first. The IP input
  autocompletes from whatever internal IPs actually appeared in the last
  fetch. This reuses the same cached event batch as the rest of the
  dashboard, so searching a new IP doesn't trigger another Umbrella API
  call unless the underlying cache has expired.
- **By Identity tab**: the same idea as By IP, but scoped to an identity
  (network, roaming client, etc.) instead of an internal IP -- useful
  when a fetch covers more than one identity at once (e.g. when the
  identity filter is left unset). The dropdown autocompletes from every
  identity actually present in the current fetch, and searching shows a
  Time/Internal IP/Destination/Category/Verdict table -- the internal IP
  column is included since a single identity (e.g. a whole network) can
  cover many different devices. Both the destination and the internal IP
  in each row are clickable, same as elsewhere: a destination jumps to
  By IP's domain mode (which IPs talked to it), and an internal IP opens
  the Meraki client info modal. Backed by `/api/identity-activity`,
  reusing the same cache.
- **Click-through from Categories to Destinations**: clicking any category
  in the Categories table switches to the Destinations tab with the
  filter box pre-filled with that category, showing only destinations
  tagged with it. This reuses the same live-filter box, so it works
  exactly like typing the category in yourself -- the Clear button
  appears the same way, and works the same way.
- **Click-through from Destinations to IP**: clicking any destination in
  the Destinations table jumps to the By IP tab and shows every internal
  IP that talked to that domain in the current window (timestamp, internal
  IP, category, verdict) -- the reverse lookup of the IP search. A banner
  shows which domain you're viewing, with a Clear button to return to
  normal IP search mode. Backed by a dedicated `/api/domain-activity`
  endpoint that mirrors `/api/ip-activity`, reusing the same cache.
- **Presets**: a dropdown next to Fetch lets you save the current filter
  combination (range, identity, verdict, categories) under a name, and
  re-apply it later in one click. Applying a preset only populates the
  filters -- it never triggers a fetch by itself, so you can review/adjust
  before clicking Fetch. Presets support inline rename and delete directly
  in the dropdown, and are stored server-side (`presets.json` in
  `OUTPUT_DIR`) so they persist across restarts and are available from any
  browser/device that opens the app.
- **Meraki client info**: clicking an internal IP -- either in the By IP
  view reached from a destination, or via the "View Client Info" button
  shown after a direct IP search -- opens a dialog with that device's
  Meraki client info: description, MAC address, effective policy
  (resolved to its group policy name where applicable), online/offline
  status, device type & OS (prefers Meraki's deviceTypePrediction when
  available, e.g. "iPhone 14, iOS 17"), First Seen/Last Seen (formatted
  in Perth time, not raw timestamps), and connection details specific to
  how it's connected -- switch name and switch port for wired clients,
  or SSID and access point name for wireless ones -- plus anything else
  Meraki has (VLAN, usage, notes, etc.). Results are cached server-side
  for an hour (`MERAKI_CACHE_TTL_SECONDS`) since a single lookup involves
  several Meraki API calls (list networks, search clients by IP, get
  client detail, get policy, resolve group policy name).

## Filters

- **Time range**: last hour, 6 hours, 12 hours, 24 hours, 7 days, or 30
  days (Umbrella's API caps any single query at 30 days, which is why
  the option is "last 30 days" rather than "last calendar month").
- **Identity**: scope everything to one or more identities (e.g. your
  Meraki network) rather than the whole org.
- **Verdict**: All / Allowed only / Blocked only.
- **Category**: multi-select, populated dynamically from whatever
  categories actually appear in the current window.

Changing verdict or category filters does **not** trigger a new Umbrella
API call -- the app fetches the raw events for a given (range, identity)
combination once, caches them in memory briefly, and recomputes every
view from that cached batch. Only a range or identity change (or hitting
Refresh) triggers a real re-fetch.

## Cancelling a fetch

A Cancel button appears next to Fetch while a request is in progress --
handy if a long range (e.g. 30 days) gets selected by accident. This is
genuine backend cancellation, not just the browser giving up on waiting:

- Clicking Fetch starts a background job on the server (`/api/activity/start`)
  and the browser polls `/api/activity/poll/<job_id>` roughly twice a
  second for its status.
- Clicking Cancel calls `/api/activity/cancel/<job_id>`, which sets a
  `threading.Event` that the job thread is checking between every chunk
  and every page of the Umbrella pull (see `cancel_check` in
  `umbrella_client.fetch_dns_activity`). The job thread notices this on
  its very next check and raises `FetchCancelled`, stopping immediately
  rather than continuing to hit the Umbrella API for data nobody's going
  to see.
- The UI itself resets instantly on click -- it doesn't wait for
  confirmation that the backend has actually stopped, since that would
  add a visible delay for no benefit. The cancel signal is fire-and-forget
  from the browser's perspective.
- Nothing partial is cached: a cancelled fetch simply hasn't populated
  the cache, so the next real Fetch starts clean rather than working from
  an incomplete batch.

## Getting your Meraki API credentials

1. Log into your Meraki dashboard, click your username (top right) ->
   **My profile**
2. Under **API access**, click **Generate new API key** and copy it
   immediately -- it's shown only once
3. Find your organization ID: either visit
   `https://api.meraki.com/api/v1/organizations` in a browser while
   logged in, or check the dashboard URL when viewing an organization
4. Set `MERAKI_API_KEY` and `MERAKI_ORG_ID` in your `.env`

**How the lookup works**: given an internal IP, the app searches every
network in your Meraki org (via the `ip` filter on each network's client
list) until it finds a match, then pulls the full client record, its
effective policy, and -- if that policy is a named group policy -- looks
up the group policy's friendly name. A client that's been offline for
more than 30 days won't be found, since Meraki's client list only
returns devices seen within the requested search window.

**Infrastructure devices (APs, switches, etc.)**: these will never show
up in a network's client list, since they're not clients -- but their
management IP still shows up in your traffic logs. If no client matches
the IP, the app falls back to searching your org's device statuses
(`/organizations/{orgId}/devices/statuses`, matched on each device's
`lanIp`) and shows the device's name, MAC, online/offline/alerting
status, model, and product type instead, with "Policy" shown as N/A
since policies don't apply to infrastructure. Note this fallback
endpoint is marked deprecated in Meraki's own docs but is still
functional as of writing -- worth revisiting if Meraki removes it.

## Getting your Secure Cloud Analytics credentials (optional)

Only needed if you have Cisco Secure Cloud Analytics (formerly Stealthwatch
Cloud) deployed. Without it, the Security Alerts section just shows Meraki
alerts.

1. Log into your Secure Cloud Analytics portal (`https://<your-tenant>.obsrvbl.com`)
2. Open your user menu -> user management, and generate an API key for
   your account
3. Set `SCA_PORTAL_URL` (the full `https://<tenant>.obsrvbl.com` URL),
   `SCA_API_USER` (your account email/username), and `SCA_API_KEY` in
   your `.env`

**Note on API field mappings**: `secure_cloud_client.py` and
`alerts.normalize_sca_alert` were built from Cisco's own sample script and
a third-party integration reference rather than a fully-verified live
response, since the primary API docs weren't fully accessible during
development. The first time you set these credentials, check the browser
Network tab on `/api/noc/alerts` against what your tenant actually
returns, and adjust field names in those two files if anything looks off
(e.g. missing titles/context, wrong severity tier).

## Getting your Umbrella API credentials

1. Log into dashboard.umbrella.com
2. Go to **Admin -> API Keys**
3. Create a new key under the **Reporting** scope
4. Note the **Key** and **Secret** -- your token is automatically scoped
   to your org, so no separate org ID is required for a standard
   single-org account. `UMBRELLA_ORG_ID` is kept as an optional env var
   for MSP/multi-org setups.

## Setup

```bash
cd umbrella-report-app
cp .env.example .env
# edit .env and fill in your credentials
docker compose up -d --build
```

Open **http://<your-server-ip>:6961** from any machine on your network.
Pick a time range, optionally narrow by identity/verdict/category, and
the dashboard loads.

## How it works

- `umbrella_client.py` handles OAuth2 auth against
  `api.umbrella.com/auth/v2/token` and pulls DNS activity from
  `api.umbrella.com/reports/v2/activity/dns`. Umbrella's activity
  endpoints enforce a hard pagination ceiling (offset + limit ≈ 10,000),
  so longer ranges are pulled in smaller time chunks internally (1 hour
  for short ranges, up to 24-hour chunks for the 30-day range) to stay
  under that ceiling.
- `aggregator.py` takes a batch of raw events and computes everything
  the UI needs: summary stats, time-series buckets, per-destination
  rollups, and per-category rollups. Verdict/category filtering also
  happens here, in memory, over whatever batch is currently cached.
- `meraki_client.py` also exposes NOC/health methods --
  `get_assurance_alerts()`, `get_uplink_statuses()`, `get_vpn_statuses()`,
  `get_device_status_summary()`, each taking an optional `network_id` to
  scope from org-wide down to one network -- on top of its original
  `get_client_info()`. Plus firmware/topology methods:
  `get_firmware_upgrades()`, `get_topology()` (both read-only), and
  `schedule_firmware_upgrade()`/`cancel_firmware_upgrade()` (the app's only
  writes -- see the Firmware section above and the safety note below).
- `secure_cloud_client.py` is the optional Secure Cloud Analytics
  integration: `fetch_alerts()` against a tenant portal's
  `/api/v3/alerts/alert/`. See the credentials section above for the
  caveat on unverified field mappings.
- `alerts.py` normalizes Meraki assurance alerts and Secure Cloud
  Analytics alerts into one shape (`normalize_meraki_alert`,
  `normalize_sca_alert`) and merges/sorts them by severity then recency
  (`merge_and_sort_alerts`). Pure functions, no I/O -- same spirit as
  `aggregator.py` but for the alerts domain.
- `main.py` is the Flask app. The original `/api/activity` endpoint still
  drives the DNS Activity section, with `range`, `identity_ids`, `verdict`,
  and `categories` query params, cached via `CACHE_TTL_SECONDS` (default
  10 minutes) so filter tweaks don't re-fetch Umbrella. A live "data is X
  minutes old" indicator under that section's heading reflects the actual
  age of the currently displayed batch. `/api/noc/overview`, `/api/noc/alerts`,
  and `/api/noc/network-health` drive the status strip and the
  Overview/Network Health/Security Alerts sections, each taking an optional
  `network_id` query param, backed by a cache keyed by `network_id`
  (`NOC_CACHE_TTL_SECONDS`, default 60s) so switching networks doesn't serve
  a stale batch scoped to the wrong one. Each source's fetch failures are
  collected into an `errors` list rather than raised, so e.g. a Meraki
  hiccup doesn't blank out Secure Cloud Analytics data or vice versa (or,
  live-tested: filtering VPN status to a network with Site-to-Site VPN
  disabled returns a 400 from Meraki -- handled the same way, doesn't break
  the rest of the view). `/api/networks` + `/api/network/select` back the
  network selector, persisting the default the same way identity selection
  already did. `/api/firmware` + `/api/firmware/schedule` +
  `/api/firmware/cancel` + `/api/topology` back the Firmware and Network Map
  sections, each requiring an explicit `network_id` (no org-wide view exists
  for either).
- `templates/index.html` is a single-page app (vanilla JS, no build step)
  organized into six sections (Overview / DNS Activity / Network Health /
  Security Alerts / Firmware / Network Map).

## Identity filtering

Umbrella's API doesn't expose a plain "list all configured identities"
endpoint -- only `/top-identities`, which returns identities ranked by
request volume over a lookback window (30 days here). In practice this
covers anything that's actually been generating traffic; an identity
that's configured but has sent zero DNS requests in the last 30 days
won't appear in the picker.

## Configuration (environment variables)

| Variable | Description | Default |
|---|---|---|
| `UMBRELLA_API_KEY` | Reporting API key | required |
| `UMBRELLA_API_SECRET` | Reporting API secret | required |
| `UMBRELLA_ORG_ID` | Umbrella organization ID (optional; MSP setups only) | optional |
| `MERAKI_API_KEY` | Meraki Dashboard API key, used for the client-info modal | required for that feature |
| `MERAKI_ORG_ID` | Meraki organization ID | required for that feature |
| `MERAKI_CACHE_TTL_SECONDS` | How long a client-info lookup stays cached before a repeat click re-queries Meraki | `3600` |
| `SCA_PORTAL_URL` | Secure Cloud Analytics portal URL, e.g. `https://your-tenant.obsrvbl.com` | optional -- feature disabled if unset |
| `SCA_API_USER` | Secure Cloud Analytics API username (your account email) | optional -- feature disabled if unset |
| `SCA_API_KEY` | Secure Cloud Analytics API key | optional -- feature disabled if unset |
| `NOC_CACHE_TTL_SECONDS` | How long the combined Meraki health + Secure Cloud Analytics data stays cached before the status strip/Overview/Network Health/Security Alerts sections re-fetch | `60` |
| `CACHE_TTL_SECONDS` | How long fetched event batches stay cached in memory before a range/identity change re-fetches | `600` |
| `OUTPUT_DIR` | Where identity-selection state, network-selection state, and presets are persisted inside the container | `/data/reports` |

Firmware and Network Map reuse `MERAKI_CACHE_TTL_SECONDS` for their own
per-network caches (they change far less often than alerts/uplink status).
Neither feature nor the network selector needs new credentials -- both
reuse `MERAKI_API_KEY`/`MERAKI_ORG_ID`.

## Notes / things to adjust for your environment

- **Pagination ceiling**: Umbrella's `/activity/dns` endpoint has a hard
  pagination ceiling (~10,000 rows per query window). The app handles
  this with adaptive bisection: if a chunk's actual volume exceeds the
  ceiling, that chunk is automatically split in half and each half
  fetched independently (recursively, if needed) until every sub-window
  fits under the limit. This guarantees complete data regardless of
  traffic spikes -- the extra API calls are only paid for the specific
  windows that actually need them, not applied everywhere. A log line at
  INFO level records each bisection as it happens; a WARNING only
  appears in the (practically unreachable) case where a window has been
  split down to `MIN_BISECT_WINDOW` (1 minute, in `umbrella_client.py`)
  and still can't fit -- which would require a sustained rate of over
  ~166 requests/second.
- **Memory use for 30-day pulls**: a very busy network could mean a lot
  of raw events held in memory for the cache duration. If this becomes
  an issue, the aggregation step could be moved to happen incrementally
  per-chunk instead of holding every raw event before aggregating --
  let me know if you hit this and want it changed.
- **No more scheduled/exported reports**: earlier versions of this app
  ran a daily scheduled pull and saved timestamped report files. That's
  gone now in favor of the on-demand dashboard. If you want a periodic
  snapshot (e.g. "save yesterday's numbers for trend comparison"), that
  can be added back as a separate feature.
- **Why no MCP**: the Meraki NOC features were built by expanding
  `meraki_client.py`'s direct Dashboard REST API calls, not by embedding
  the `meraki-magic-mcp-community` MCP server. MCP is a protocol for LLM
  tool-calling clients; a synchronous Flask/gunicorn backend doesn't
  benefit from it the way an AI agent would.
- **Unverified API field mappings**: the Meraki uplink/VPN/assurance-alerts/
  firmware/topology fields were all confirmed live against a real org during
  development and are documented as such in `CLAUDE.md`'s "Non-obvious
  constraints". The one integration that's still built from documentation
  and sample scripts rather than a live response is Secure Cloud Analytics
  (`secure_cloud_client.py`, `alerts.py`) -- there was no SCA tenant
  available to test against. Check the browser Network tab on
  `/api/noc/alerts` the first time you set `SCA_PORTAL_URL`/`SCA_API_USER`/
  `SCA_API_KEY`, and adjust field names in those two files if anything
  looks off.
- **Alerts are read-only**: no acknowledge/close/mute actions exist for
  either Meraki or Secure Cloud Analytics alerts -- each alert links out
  to its source dashboard for that. This was a deliberate scope choice,
  not a limitation of the underlying APIs.
- **Firmware scheduling is the one real write in this app**: everything
  else is read-only. `schedule_firmware_upgrade`/`cancel_firmware_upgrade`
  in `meraki_client.py` use read-modify-write rather than a partial PUT,
  since Meraki's docs don't say whether an omitted product type in the
  request body is left alone or cleared -- see `CLAUDE.md` for the full
  reasoning. The frontend requires an explicit modal confirmation (current
  -> target version, scheduled time, a reboot warning) before the request
  is ever sent -- there's no one-click schedule button anywhere.
