"""
Helpers for the hosted version of EvilTwinGuard.

A website cannot scan Wi-Fi: the server sits in a data centre with no radio,
and browsers give web pages no access to the list of nearby networks. This
module provides what *is* possible:

  * describe_interfaces()  - which network interfaces this server has, and
                             whether any is wireless (logged at start-up)
  * parse_pasted_scan()    - read `netsh` / `nmcli` output that a visitor
                             copied from their own computer
  * client_ip()            - the visitor's public IP address behind Render's
                             proxy (Cloudflare's True-Client-IP first)
  * lookup_ip()            - provider of that IP and whether it is a mobile
                             network, proxy/VPN or data centre (ip-api.com)
  * assess_connection()    - plain-language warnings for the connection check
"""
import ipaddress
import json
import os
import platform
import re
import subprocess
import threading
import time
import urllib.request

# ───────────────────────── server interfaces ─────────────────────────


def describe_interfaces(sys_class_net='/sys/class/net'):
    """Return {'interfaces': [...], 'wireless': [...]} for this machine."""
    system = platform.system().lower()
    interfaces, wireless = [], []
    if system == 'linux' and os.path.isdir(sys_class_net):
        for name in sorted(os.listdir(sys_class_net)):
            interfaces.append(name)
            if os.path.exists(os.path.join(sys_class_net, name, 'wireless')) or \
               os.path.exists(os.path.join(sys_class_net, name, 'phy80211')):
                wireless.append(name)
    elif system == 'windows':
        try:
            out = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True,
                                 text=True, timeout=10).stdout
            wireless = [m.strip() for m in re.findall(r'^\s*Name\s*:\s*(.+)$', out, re.M)]
            interfaces = list(wireless)
        except (OSError, subprocess.SubprocessError):
            pass
    return {'system': system, 'interfaces': interfaces, 'wireless': wireless}


# ───────────────────────── pasted scans ─────────────────────────

MAX_PASTE_CHARS = 200_000
NETSH_MARKER = re.compile(r'^\s*SSID \d+\s*:', re.M)
NMCLI_LINE = re.compile(r'^[^\n]*?(?:[0-9A-Fa-f]{2}\\:){5}[0-9A-Fa-f]{2}:', re.M)


def parse_pasted_scan(text, scanner, timestamp):
    """
    Parse scan output pasted by a visitor. Returns (networks, format) where
    format is 'netsh', 'nmcli' or None if the text was not recognised.
    """
    if NETSH_MARKER.search(text):
        return scanner._parse_netsh(text, timestamp), 'netsh'
    if NMCLI_LINE.search(text):
        return scanner._parse_nmcli(text, timestamp), 'nmcli'
    return [], None


# ───────────────────────── visitor IP ─────────────────────────


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address((value or '').strip()))
    except ValueError:
        return None


def client_ip(headers, remote_addr):
    """
    The visitor's IP address and how it was obtained.

    On Render, Cloudflare sits in front of the service and sets True-Client-IP,
    which the visitor cannot forge. X-Forwarded-For is only a fallback: Render
    keeps whatever value the visitor sent and appends to it, so its first entry
    can be spoofed (only the visitor's own result would be affected).
    """
    for header in ('True-Client-IP', 'CF-Connecting-IP'):
        ip = _valid_ip(headers.get(header))
        if ip:
            return ip, 'proxy'
    forwarded = headers.get('X-Forwarded-For', '')
    if forwarded:
        ip = _valid_ip(forwarded.split(',')[0])
        if ip:
            return ip, 'forwarded (unverified)'
    return _valid_ip(remote_addr), 'direct'


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except (TypeError, ValueError):
        return False


# ───────────────────────── IP lookup (ip-api.com) ─────────────────────────
# Free endpoint: non-commercial use, 45 requests/minute, HTTP only. Results are
# cached for 10 minutes and calls are rate-limited well below the quota.

LOOKUP_URL = 'http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,mobile,proxy,hosting,query'
_cache, _calls, _lock = {}, [], threading.Lock()
CACHE_SECONDS, MAX_CALLS_PER_MINUTE = 600, 30


def _fetch(url, timeout=4):
    with urllib.request.urlopen(url, timeout=timeout) as resp:          # noqa: S310 (fixed host)
        return json.loads(resp.read().decode('utf-8'))


def lookup_ip(ip=None, fetch=_fetch, now=time.time):
    """
    Look up the provider of `ip` (None = this machine's own public address).
    Returns a dict, or {'error': ...} when the lookup is unavailable.
    """
    key = ip or 'self'
    with _lock:
        hit = _cache.get(key)
        if hit and now() - hit[0] < CACHE_SECONDS:
            return hit[1]
        recent = [t for t in _calls if now() - t < 60]
        _calls[:] = recent
        if len(recent) >= MAX_CALLS_PER_MINUTE:
            return {'error': 'Lookup temporarily rate-limited; try again in a minute.'}
        _calls.append(now())
    try:
        data = fetch(LOOKUP_URL.format(ip=ip or ''))
    except Exception as e:                                               # network, timeout, JSON
        return {'error': f'Lookup service unavailable ({type(e).__name__}).'}
    if data.get('status') != 'success':
        return {'error': data.get('message', 'Lookup failed.')}
    result = {k: data.get(k) for k in ('query', 'country', 'city', 'isp', 'org', 'as',
                                       'mobile', 'proxy', 'hosting')}
    with _lock:
        _cache[key] = (now(), result)
    return result


def assess_connection(lookup):
    """Plain-language findings for the connection check."""
    findings = []
    if lookup.get('error'):
        return findings
    if lookup.get('mobile'):
        findings.append({
            'level': 'warning',
            'title': 'Traffic leaves through a mobile network',
            'detail': 'Your internet connection reaches the internet through a mobile (cellular) provider. '
                      'That is normal for a phone hotspot or mobile data, but if you think you are on a '
                      'cafe, hotel or airport Wi-Fi, it can mean the "hotspot" is really a phone or portable '
                      'device - a common way to run an Evil Twin.'})
    if lookup.get('proxy') or lookup.get('hosting'):
        findings.append({
            'level': 'warning',
            'title': 'Traffic leaves through a data centre, VPN or proxy',
            'detail': 'This is expected if you use a VPN. If you do not, the network you are on may be '
                      'sending your traffic through someone else\'s server.'})
    if not findings:
        findings.append({
            'level': 'ok',
            'title': 'No warning signs in how your connection reaches the internet',
            'detail': 'Your traffic leaves through a regular provider. This check cannot see the Wi-Fi '
                      'networks around you, so it cannot rule out an Evil Twin on its own - use "Paste a '
                      'scan" for that.'})
    return findings
