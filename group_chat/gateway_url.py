"""Validate the Agent endpoint before sending a pairing code or bearer token."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def gateway_base_url(value: str) -> str:
    base = str(value or "").strip().rstrip("/")
    parsed = urlsplit(base)
    host = parsed.hostname
    if not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("TLS_AGENT_URL must be an HTTPS URL without credentials or query parameters")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("TLS_AGENT_URL must use HTTPS except for a local loopback test")
    return base
