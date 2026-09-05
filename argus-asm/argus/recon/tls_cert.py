"""TLS certificate inspection for HTTPS/TLS ports.

Observational only: it completes a TLS handshake to read the certificate the
server presents (issuer, subject, validity), the same information a browser
padlock shows. It does not verify a chain to a CA (so it can still read
self-signed certs) and never sends application data.
"""
import socket
import ssl
from datetime import datetime, timezone


def _parse_cert_time(value: str):
    # e.g. "Jun  1 12:00:00 2027 GMT"
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def inspect_tls(host: str, port: int, timeout: float = 4.0) -> dict:
    """Return certificate details for a TLS port, or {} if not a TLS service."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # read even self-signed / mismatched certs
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            with ctx.wrap_socket(sock, server_hostname=host if ":" not in host else None) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
                version = ss.version()
    except Exception:
        return {}

    if not cert:
        # Some servers won't expose a parsed cert without verification; still note TLS.
        return {"tls": True, "version": None, "issuer": None, "subject": None,
                "not_after": None, "days_to_expiry": None, "self_signed": None}

    def _name(field):
        try:
            return dict(x[0] for x in field).get("organizationName") \
                or dict(x[0] for x in field).get("commonName")
        except Exception:
            return None

    issuer = _name(cert.get("issuer", []))
    subject = _name(cert.get("subject", []))
    not_after = cert.get("notAfter")
    exp = _parse_cert_time(not_after) if not_after else None
    days = None
    if exp:
        days = (exp - datetime.now(timezone.utc)).days

    return {
        "tls": True,
        "version": version,
        "cipher": cipher[0] if cipher else None,
        "issuer": issuer,
        "subject": subject,
        "not_after": not_after,
        "days_to_expiry": days,
        "self_signed": bool(issuer and subject and issuer == subject),
    }