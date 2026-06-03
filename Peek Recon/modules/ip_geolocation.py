# modules/ip_geolocation.py
# takes an IP address and figures out where it roughly is in the world
# uses ip-api.com — free, no API key needed, up to 45 requests/minute
# NOTE: geolocation is not 100% accurate, it's based on ISP registration data

import socket
import requests
from utils.display import section, success, warning, error, kv


def run(target):
    section("IP Geolocation")

    try:
        # first resolve the domain to an IP if they passed a hostname
        ip = socket.gethostbyname(target)
        success(f"Resolved {target} → {ip}")
    except socket.gaierror:
        error(f"Couldn't resolve hostname: {target}")
        return

    try:
        # ip-api returns JSON with location data
        # 'fields' param lets us pick exactly what we want back
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,timezone,mobile,proxy,hosting"
        resp = requests.get(url, timeout=5)
        data = resp.json()

        if data.get("status") != "success":
            # api returns {"status": "fail", "message": "..."} if something goes wrong
            warning(f"Geolocation failed: {data.get('message')}")
            return

        kv("IP Address",    ip)
        kv("Country",       data.get("country"))
        kv("Region",        data.get("regionName"))
        kv("City",          data.get("city"))
        kv("ISP",           data.get("isp"))
        kv("Org",           data.get("org"))
        kv("AS",            data.get("as"))       # autonomous system number
        kv("Timezone",      data.get("timezone"))
        kv("Coordinates",   f"{data.get('lat')}, {data.get('lon')}")
        kv("Mobile IP",     str(data.get("mobile")))
        kv("Proxy/VPN",     str(data.get("proxy")))
        kv("Hosting/DC",    str(data.get("hosting")))  # is it a datacenter/cloud IP?

        success("Geolocation complete.")

    except requests.exceptions.Timeout:
        error("Request timed out.")
    except Exception as e:
        error(f"Geolocation error: {e}")
