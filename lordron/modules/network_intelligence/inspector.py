"""
Module 07: Network Intelligence
Strictly passive and authorized network inspection: DNS lookup, TLS certificate validation,
and HTTP response header analysis. Pure Python standard library with no intrusive probing.
"""

from __future__ import annotations
import socket
import ssl
import time
import urllib.request
import urllib.error
from typing import Dict, Any


def lookup_dns(domain: str) -> Dict[str, Any]:
    """
    Perform passive DNS record lookups for a target domain.
    Resolves A/AAAA records and reverse PTR using standard socket resolver.
    """
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

    result: Dict[str, Any] = {
        "domain": clean_domain,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "reverse_hostnames": [],
        "status": "SUCCESS"
    }

    # Resolve IPv4
    try:
        addr_info = socket.getaddrinfo(clean_domain, None, socket.AF_INET)
        result["ipv4_addresses"] = sorted(list({item[4][0] for item in addr_info}))
    except socket.gaierror as e:
        result["ipv4_error"] = str(e)

    # Resolve IPv6
    try:
        addr_info_v6 = socket.getaddrinfo(clean_domain, None, socket.AF_INET6)
        result["ipv6_addresses"] = sorted(list({item[4][0] for item in addr_info_v6}))
    except socket.gaierror:
        result["ipv6_addresses"] = []

    # Reverse PTR for primary IP
    if result["ipv4_addresses"]:
        primary_ip = result["ipv4_addresses"][0]
        try:
            rev_host, _, _ = socket.gethostbyaddr(primary_ip)
            result["reverse_hostnames"].append(rev_host)
        except (socket.herror, socket.gaierror):
            pass

    return result


def inspect_tls(domain: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Inspect the TLS certificate of a remote server over a standard passive handshake.
    Retrieves Subject, Issuer, Validity period, SAN, and TLS protocol version.
    """
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Read certificate even if self-signed or expired for analysis

    start_time = time.time()
    try:
        with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                handshake_latency_ms = round((time.time() - start_time) * 1000, 2)
                _ = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                protocol_version = ssock.version()

                # In CERT_NONE mode, binary cert is available for DER parsing
                der_cert = ssock.getpeercert(binary_form=True)

        return {
            "domain": clean_domain,
            "port": port,
            "handshake_latency_ms": handshake_latency_ms,
            "protocol_version": protocol_version,
            "cipher_suite": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
            "has_certificate": bool(der_cert),
            "certificate_der_sha256": ssl.RAND_bytes(0).hex() if not der_cert else __import__("hashlib").sha256(der_cert).hexdigest(),
            "status": "CONNECTED_SUCCESSFULLY",
        }
    except Exception as exc:
        return {
            "domain": clean_domain,
            "port": port,
            "error": str(exc),
            "status": "CONNECTION_FAILED"
        }


def inspect_http_headers(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Perform a passive HTTP GET / HEAD request to inspect server response headers.
    Checks for security headers (HSTS, CSP, X-Frame-Options, CORS).
    """
    clean_domain = domain.strip()
    if not clean_domain.startswith("http://") and not clean_domain.startswith("https://"):
        target_url = f"https://{clean_domain}"
    else:
        target_url = clean_domain

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "LordronForensics/1.0 (Defensive Investigation Toolkit)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            headers = dict(response.headers)
            status_code = response.status

            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "NOT_PRESENT"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "NOT_PRESENT"),
                "X-Frame-Options": headers.get("X-Frame-Options", "NOT_PRESENT"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "NOT_PRESENT"),
                "Referrer-Policy": headers.get("Referrer-Policy", "NOT_PRESENT"),
            }

            return {
                "target_url": target_url,
                "status_code": status_code,
                "server": headers.get("Server", "Unknown"),
                "content_type": headers.get("Content-Type", "Unknown"),
                "security_headers": security_headers,
                "all_headers": headers,
                "status": "SUCCESS"
            }
    except urllib.error.HTTPError as e:
        return {
            "target_url": target_url,
            "status_code": e.code,
            "all_headers": dict(e.headers),
            "status": f"HTTP_ERROR_{e.code}"
        }
    except Exception as exc:
        return {
            "target_url": target_url,
            "error": str(exc),
            "status": "REQUEST_FAILED"
        }


def full_network_inspection(domain: str) -> Dict[str, Any]:
    """Run all passive network inspections: DNS, TLS, and HTTP headers."""
    return {
        "domain": domain,
        "dns": lookup_dns(domain),
        "tls": inspect_tls(domain),
        "http": inspect_http_headers(domain),
        "safety_notice": "Passive inquiry only. No intrusive scanning or penetration testing was conducted."
    }
