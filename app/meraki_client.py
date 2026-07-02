"""
Client for the Cisco Meraki Dashboard API (v1).

Docs: https://developer.cisco.com/meraki/api-v1/
Auth: "Authorization: Bearer <api_key>" header (v1's recommended method;
      the legacy X-Cisco-Meraki-API-Key header still works but Meraki's
      own docs point people away from it now).
Base: https://api.meraki.com/api/v1
"""

import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger("meraki_client")

BASE_URL = "https://api.meraki.com/api/v1"

# How far back to look for a client when searching by IP. Meraki's client
# list only returns devices that have actually been seen within this
# window, so a device that's been off/disconnected longer than this won't
# be found. 30 days comfortably covers "is this thing on my network".
CLIENT_SEARCH_TIMESPAN_SECONDS = 30 * 24 * 3600

# Friendly labels for Meraki's productType values, used when the IP being
# looked up turns out to belong to network infrastructure (an AP, switch,
# etc.) rather than a client device.
PRODUCT_TYPE_LABELS = {
    "wireless": "Wireless Access Point",
    "switch": "Switch",
    "appliance": "Security Appliance",
    "camera": "Camera",
    "sensor": "Sensor",
    "cellularGateway": "Cellular Gateway",
    "wirelessController": "Wireless LAN Controller",
}


class MerakiAPIError(Exception):
    pass


class MerakiClientNotFound(Exception):
    """Raised when no client with the given IP is found in any network in the org."""
    pass


def _epoch_to_iso(epoch_seconds) -> str | None:
    """
    Meraki returns firstSeen/lastSeen as Unix epoch seconds. Convert to an
    ISO8601 UTC string so the frontend can format it in whatever timezone
    the app is configured for, the same way it already does for Umbrella
    activity timestamps.
    """
    if epoch_seconds is None:
        return None
    try:
        return datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc).isoformat()
    except (ValueError, OSError, TypeError):
        return None


class MerakiClient:
    def __init__(self, api_key: str, org_id: str):
        self.api_key = api_key
        self.org_id = org_id

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        url = f"{BASE_URL}{path}"
        resp = requests.get(url, headers=self._headers(), params=params or {}, timeout=30)
        if resp.status_code == 404:
            # Meraki deliberately returns 404 for bad auth as well as
            # genuinely missing resources, to avoid leaking which is which.
            raise MerakiAPIError(
                f"Meraki API returned 404 for {path} -- this can mean either the "
                f"resource doesn't exist or the API key/org ID is wrong."
            )
        if resp.status_code == 429:
            raise MerakiAPIError("Meraki API rate limit exceeded, try again shortly.")
        if not resp.ok:
            raise MerakiAPIError(f"Meraki API error {resp.status_code} for {path}: {resp.text}")
        return resp.json()

    def list_networks(self) -> list[dict]:
        """Returns the networks in the configured organization."""
        return self._get(f"/organizations/{self.org_id}/networks")

    # --- NOC / health methods ---
    # These back the Network Health and Overview sections of the dashboard.
    # Unlike get_client_info (several sequential calls per IP lookup), each
    # of these is a single org-wide GET, so no per-call caching is done here
    # -- main.py caches the combined NOC payload instead.

    def get_assurance_alerts(
        self, active: bool = True, resolved: bool = False, dismissed: bool = False, network_id: str | None = None
    ) -> list[dict]:
        """
        Returns health alerts (device health, connectivity, configuration,
        experience metrics, insights) from Meraki's Assurance alerts feed --
        the modern replacement for eyeballing device statuses to figure out
        what's wrong. Org-wide unless network_id narrows it to one network.

        Confirmed live: this endpoint's network filter param is `networkId`
        (singular, a plain string) -- `networkId[]` (the array-bracket form
        that works on the other three methods below) returns a 400.
        """
        params = {"active": active, "resolved": resolved, "dismissed": dismissed, "perPage": 100}
        if network_id:
            params["networkId"] = network_id
        return self._get(f"/organizations/{self.org_id}/assurance/alerts", params=params)

    def get_uplink_statuses(self, network_id: str | None = None) -> list[dict]:
        """WAN uplink status (up/down, IP/public IP/gateway) for MX/Z appliances -- org-wide unless network_id narrows it."""
        params = {"perPage": 1000}
        if network_id:
            params["networkIds[]"] = network_id
        return self._get(f"/organizations/{self.org_id}/appliance/uplink/statuses", params=params)

    def get_vpn_statuses(self, network_id: str | None = None) -> list[dict]:
        """Site-to-site/client VPN peer status for appliances -- org-wide unless network_id narrows it."""
        params = {"perPage": 300}
        if network_id:
            params["networkIds[]"] = network_id
        return self._get(f"/organizations/{self.org_id}/appliance/vpn/statuses", params=params)

    def get_device_status_summary(self, network_id: str | None = None) -> dict:
        """
        Returns {"online": n, "offline": n, "alerting": n, "dormant": n,
        "total": n, "devices": {"online": [...], "offline": [...],
        "alerting": [...], "dormant": [...]}} across devices, for the status
        strip -- org-wide unless network_id narrows it. Reuses the same
        devices/statuses endpoint as the infrastructure-IP fallback in
        get_client_info. Each "devices" entry is a lean {"name", "model",
        "productType"} dict (confirmed live field names) rather than the
        endpoint's full per-device payload (lanIp, gateway, tags, etc.) --
        just enough for the frontend to list which devices make up a count
        on hover.
        """
        params = {}
        if network_id:
            params["networkIds[]"] = network_id
        statuses = self._get(f"/organizations/{self.org_id}/devices/statuses", params=params)
        counts = {"online": 0, "offline": 0, "alerting": 0, "dormant": 0}
        devices_by_status = {"online": [], "offline": [], "alerting": [], "dormant": []}
        for device in statuses:
            status = (device.get("status") or "").lower()
            if status in counts:
                counts[status] += 1
                devices_by_status[status].append(
                    {
                        "name": device.get("name") or device.get("serial"),
                        "model": device.get("model"),
                        "productType": device.get("productType"),
                    }
                )
        counts["total"] = len(statuses)
        counts["devices"] = devices_by_status
        return counts

    # --- Firmware management ---
    # Unlike the NOC/health methods above, getNetworkFirmwareUpgrades and its
    # PUT counterpart are inherently per-network -- there's no org-wide
    # "current state" endpoint (/organizations/{orgId}/firmware/upgrades
    # returns a *history* of past completed upgrades, not current versions
    # or available candidates).

    def get_firmware_upgrades(self, network_id: str) -> dict:
        """
        Returns the network's firmware state: {"products": {"<type>": {
        currentVersion, lastUpgrade, nextUpgrade, isUpgradeAvailable,
        availableVersions, participateInNextBetaRelease}, ...}, "timezone":
        ..., "upgradeWindow": {...}}. Confirmed live -- path is
        /networks/{networkId}/firmwareUpgrades (run-together camelCase, not
        /firmware/upgrades).
        """
        return self._get(f"/networks/{network_id}/firmwareUpgrades")

    def _put(self, path: str, body: dict) -> dict | list:
        url = f"{BASE_URL}{path}"
        resp = requests.put(url, headers=self._headers(), json=body, timeout=30)
        if resp.status_code == 429:
            raise MerakiAPIError("Meraki API rate limit exceeded, try again shortly.")
        if not resp.ok:
            raise MerakiAPIError(f"Meraki API error {resp.status_code} for {path}: {resp.text}")
        return resp.json()

    def _set_next_upgrade(self, network_id: str, product_type: str, next_upgrade: dict) -> dict:
        """
        Shared read-modify-write for schedule/cancel. Meraki's docs don't
        confirm whether PUTting a `products` object containing only the one
        changed type leaves other product types' schedules alone or clears
        them -- to avoid silently wiping another product's scheduled
        upgrade because of that undocumented behavior, this always re-sends
        every product type currently present, unchanged, except the one
        being modified.
        """
        current = self.get_firmware_upgrades(network_id)
        products = current.get("products", {})
        if product_type not in products:
            raise MerakiAPIError(
                f"Product type '{product_type}' not present in network {network_id}'s firmware state."
            )

        body_products = {}
        for ptype, pdata in products.items():
            body_products[ptype] = {
                "nextUpgrade": next_upgrade if ptype == product_type else (pdata.get("nextUpgrade") or {"time": "", "toVersion": {}}),
                "participateInNextBetaRelease": pdata.get("participateInNextBetaRelease", False),
            }

        return self._put(f"/networks/{network_id}/firmwareUpgrades", {"products": body_products})

    def schedule_firmware_upgrade(self, network_id: str, product_type: str, version_id: str, time_iso: str) -> dict:
        """
        Schedules a firmware upgrade for one product type. Callers (main.py)
        are expected to have already validated version_id against that
        product's actual availableVersions before calling this -- it's a
        real write against live hardware, not something to let a garbage
        client-supplied ID reach Meraki's API untested.
        """
        return self._set_next_upgrade(
            network_id, product_type, {"time": time_iso, "toVersion": {"id": version_id}}
        )

    def cancel_firmware_upgrade(self, network_id: str, product_type: str) -> dict:
        """Clears a scheduled upgrade for one product type -- same read-modify-write as schedule_firmware_upgrade."""
        return self._set_next_upgrade(network_id, product_type, {"time": "", "toVersion": {}})

    # --- Network topology ---

    def get_topology(self, network_id: str) -> dict:
        """
        Returns {"nodes": [...], "links": [...], "errors": [...]} -- LLDP/CDP
        discovered topology for a network. Confirmed live -- path is
        /networks/{networkId}/topology/linkLayer (not /topology/link/layer).
        """
        return self._get(f"/networks/{network_id}/topology/linkLayer")

    def _find_client_summary_by_ip(self, network_id: str, ip: str) -> dict | None:
        """
        Searches one network's client list for an exact IP match. Meraki's
        `ip` filter is a partial/full match, so we still confirm equality
        client-side rather than trusting the first result.
        """
        results = self._get(
            f"/networks/{network_id}/clients",
            params={"ip": ip, "timespan": CLIENT_SEARCH_TIMESPAN_SECONDS, "perPage": 50},
        )
        for client in results:
            if client.get("ip") == ip:
                return client
        return None

    def _get_client_detail(self, network_id: str, client_id: str) -> dict:
        return self._get(f"/networks/{network_id}/clients/{client_id}")

    def _get_client_policy(self, network_id: str, client_id: str) -> dict:
        return self._get(f"/networks/{network_id}/clients/{client_id}/policy")

    def _get_group_policy_name(self, network_id: str, group_policy_id: str) -> str | None:
        policies = self._get(f"/networks/{network_id}/groupPolicies")
        for policy in policies:
            if str(policy.get("groupPolicyId")) == str(group_policy_id):
                return policy.get("name")
        return None

    def _find_device_by_ip(self, ip: str) -> dict | None:
        """
        Searches org-wide device statuses for a device whose management
        (LAN) IP matches. Covers Meraki infrastructure itself -- access
        points, switches, security appliances, etc. -- which show up in
        Umbrella/network traffic but are never going to appear in a
        network's *client* list, since they're not clients.

        Note: /organizations/{orgId}/devices/statuses is marked deprecated
        in Meraki's docs, but remains functional and is currently the
        simplest single call that returns lanIp + status + lastReportedAt
        + model + productType together. Worth revisiting if Meraki
        actually removes it.
        """
        statuses = self._get(f"/organizations/{self.org_id}/devices/statuses")
        for device in statuses:
            if device.get("lanIp") == ip:
                return device
        return None

    def _build_device_info(self, device: dict, network_name: str) -> dict:
        """Builds the same normalized info shape get_client_info returns, for an infrastructure device."""
        product_type = device.get("productType")
        friendly_type = PRODUCT_TYPE_LABELS.get(product_type, product_type or "Infrastructure device")
        model = device.get("model")
        device_type_label = f"{friendly_type} ({model})" if model else friendly_type

        additional = {}
        if device.get("tags"):
            additional["Tags"] = ", ".join(device["tags"])
        if device.get("publicIp"):
            additional["Public IP"] = device["publicIp"]
        if device.get("gateway"):
            additional["Gateway"] = device["gateway"]
        if device.get("serial"):
            additional["Serial"] = device["serial"]
        if device.get("firmware"):
            additional["Firmware"] = device["firmware"]

        return {
            "description": device.get("name") or device.get("serial") or "(unnamed device)",
            "mac": device.get("mac") or "Unknown",
            "policy": "N/A (infrastructure device)",
            "status": (device.get("status") or "unknown").capitalize(),
            "device_type_os": device_type_label,
            "network_name": network_name,
            # lastReportedAt is already an ISO8601 string from Meraki --
            # no epoch conversion needed here, unlike client firstSeen/lastSeen.
            "first_seen": None,
            "last_seen": device.get("lastReportedAt"),
            "connection": {"type": "Infrastructure", "details": {}},
            "additional": additional,
            "is_infrastructure_device": True,
        }

    def get_client_info(self, ip: str) -> dict:
        """
        Searches every network in the org for a client matching this IP,
        and returns a normalized info dict once found:

            {
                "description": ...,
                "mac": ...,
                "policy": ...,
                "status": ...,
                "device_type_os": ...,
                "network_name": ...,
                "first_seen": ...,  # ISO8601 UTC string, or null
                "last_seen": ...,   # ISO8601 UTC string, or null
                "connection": {
                    "type": "Wired" | "Wireless" | None,
                    "details": { ...label: value pairs specific to the
                                  connection type, e.g. Switch/Switch Port
                                  for wired, SSID/Access Point for wireless }
                },
                "additional": { ...whatever else Meraki returned that's
                                 useful context, e.g. VLAN, user, notes,
                                 usage }
            }

        Raises MerakiClientNotFound if no network has a client at that IP
        within the search window.
        """
        networks = self.list_networks()
        if not networks:
            raise MerakiClientNotFound(f"No networks found in organization {self.org_id}")

        for network in networks:
            network_id = network.get("id")
            network_name = network.get("name", network_id)
            try:
                summary = self._find_client_summary_by_ip(network_id, ip)
            except MerakiAPIError:
                logger.exception("Failed to search clients in network %s for ip %s", network_id, ip)
                continue

            if not summary:
                continue

            client_id = summary.get("id")

            # Pull the fuller single-client record -- typically richer
            # than the list entry (e.g. includes ssid/vlan/switchport/
            # usage/notes depending on wired vs wireless).
            try:
                detail = self._get_client_detail(network_id, client_id)
            except MerakiAPIError:
                logger.exception("Failed to get client detail for %s in network %s", client_id, network_id)
                detail = summary

            # Resolve the effective policy name.
            policy_label = "Unknown"
            try:
                policy = self._get_client_policy(network_id, client_id)
                device_policy = policy.get("devicePolicy", "Unknown")
                if device_policy == "Group policy" and policy.get("groupPolicyId"):
                    resolved_name = self._get_group_policy_name(network_id, policy["groupPolicyId"])
                    policy_label = resolved_name or f"Group policy ({policy['groupPolicyId']})"
                else:
                    policy_label = device_policy
            except MerakiAPIError:
                logger.exception("Failed to get policy for client %s in network %s", client_id, network_id)

            # deviceTypePrediction (e.g. "iPhone SE, iOS9.3.5") is a richer
            # single field when Meraki has it; fall back to combining
            # manufacturer + os when it doesn't.
            device_type_prediction = detail.get("deviceTypePrediction")
            manufacturer = detail.get("manufacturer")
            os_name = detail.get("os")
            device_type_os = (
                device_type_prediction
                or " / ".join(part for part in [manufacturer, os_name] if part)
                or "Unknown"
            )

            # Wired vs wireless connection details. recentDeviceConnection
            # tells us which; the relevant fields differ accordingly.
            connection_type = detail.get("recentDeviceConnection")  # "Wired" | "Wireless" | None
            recent_device_name = detail.get("recentDeviceName") or detail.get("recentDeviceSerial")
            connection_details = {}
            if connection_type == "Wired":
                if recent_device_name:
                    connection_details["Switch"] = recent_device_name
                if detail.get("switchport"):
                    connection_details["Switch Port"] = detail["switchport"]
            elif connection_type == "Wireless":
                if detail.get("ssid"):
                    connection_details["SSID"] = detail["ssid"]
                if recent_device_name:
                    connection_details["Access Point"] = recent_device_name

            additional = {}
            for label, key in [
                ("VLAN", "vlan"),
                ("Named VLAN", "namedVlan"),
                ("User", "user"),
                ("Notes", "notes"),
            ]:
                value = detail.get(key)
                if value:
                    additional[label] = value

            usage = detail.get("usage")
            if usage and isinstance(usage, dict):
                sent = usage.get("sent")
                recv = usage.get("recv")
                if sent is not None or recv is not None:
                    additional["Usage (sent/recv KB)"] = f"{sent or 0} / {recv or 0}"

            return {
                "description": detail.get("description") or summary.get("description") or "(no description)",
                "mac": detail.get("mac") or summary.get("mac") or "Unknown",
                "policy": policy_label,
                "status": detail.get("status") or summary.get("status") or "Unknown",
                "device_type_os": device_type_os,
                "network_name": network_name,
                "first_seen": _epoch_to_iso(detail.get("firstSeen")),
                "last_seen": _epoch_to_iso(detail.get("lastSeen")),
                "connection": {"type": connection_type, "details": connection_details},
                "additional": additional,
            }

        # No client matched this IP in any network. Before giving up,
        # check whether it belongs to network infrastructure itself (an
        # AP, switch, security appliance, etc.) -- these show up in
        # traffic logs but are never going to appear in a client list.
        try:
            device = self._find_device_by_ip(ip)
        except MerakiAPIError:
            device = None
            logger.exception("Failed to search organization devices for ip %s", ip)

        if device:
            network_id_to_name = {n.get("id"): n.get("name", n.get("id")) for n in networks}
            network_name = network_id_to_name.get(device.get("networkId"), device.get("networkId"))
            return self._build_device_info(device, network_name)

        raise MerakiClientNotFound(
            f"No client with IP {ip} found in any network in the organization "
            f"within the last {CLIENT_SEARCH_TIMESPAN_SECONDS // 86400} days."
        )
