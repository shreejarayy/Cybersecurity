"""Change detection: compare a new recon result against the previous baseline.

Emits typed change events matching the report:
  new_asset, new_port, closed_port, banner_changed, new_subdomain
The comparison works purely on the two result dicts, so it is easy to test.
"""


def _index(recon_result: dict) -> dict:
    """Build {ip: {port: product}} plus the set of subdomains for comparison."""
    assets = {}
    for a in recon_result.get("assets", []):
        ports = {p["port"]: (p.get("product") or "") for p in a.get("ports", [])}
        assets[a["ip"]] = ports
    subs = {s["subdomain"] for s in recon_result.get("subdomains", {}).get("subdomains", [])}
    return {"assets": assets, "subdomains": subs}


def detect_changes(previous: dict, current: dict) -> list:
    """Return a list of typed change-event dicts. If `previous` is None/empty,
    every asset/port is reported as new (first-ever scan baseline)."""
    events = []
    cur = _index(current)

    if not previous:
        for ip, ports in cur["assets"].items():
            events.append({"asset_ip": ip, "event_type": "new_asset",
                           "detail": f"First observation of {ip} with {len(ports)} open port(s)"})
            for port, product in ports.items():
                events.append({"asset_ip": ip, "event_type": "new_port",
                               "detail": f"Port {port} open ({product or 'no banner'})"})
        for sub in cur["subdomains"]:
            events.append({"asset_ip": "", "event_type": "new_subdomain",
                           "detail": f"Subdomain discovered: {sub}"})
        return events

    prev = _index(previous)

    # New assets.
    for ip, ports in cur["assets"].items():
        if ip not in prev["assets"]:
            events.append({"asset_ip": ip, "event_type": "new_asset",
                           "detail": f"New asset {ip} with {len(ports)} open port(s)"})

    # Per-asset port and banner comparison.
    for ip, cur_ports in cur["assets"].items():
        prev_ports = prev["assets"].get(ip, {})
        for port, product in cur_ports.items():
            if port not in prev_ports:
                events.append({"asset_ip": ip, "event_type": "new_port",
                               "detail": f"Port {port} newly open ({product or 'no banner'})"})
            elif prev_ports[port] != product and product:
                events.append({"asset_ip": ip, "event_type": "banner_changed",
                               "detail": f"Port {port} banner changed: "
                                         f"'{prev_ports[port]}' -> '{product}'"})
        for port in prev_ports:
            if port not in cur_ports:
                events.append({"asset_ip": ip, "event_type": "closed_port",
                               "detail": f"Port {port} closed since last scan"})

    # New subdomains.
    for sub in cur["subdomains"] - prev["subdomains"]:
        events.append({"asset_ip": "", "event_type": "new_subdomain",
                       "detail": f"New subdomain: {sub}"})

    return events
