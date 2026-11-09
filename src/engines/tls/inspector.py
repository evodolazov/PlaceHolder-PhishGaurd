"""TLS inspection for HTTPS URLs with SSRF safeguards."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit


@dataclass(frozen=True)
class TLSInspectionResult:
    """Structured outcome describing a TLS inspection attempt."""

    status: str
    explanation: str
    hostname: str | None = None
    validated_ip: str | None = None
    sni_hostname: str | None = None
    port: int = 443
    tls_version: str | None = None
    cipher_suite: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    certificate_validity_start: str | None = None
    certificate_expiration: str | None = None
    certificate_is_valid: bool | None = None
    hostname_match: bool | None = None
    self_signed: bool | None = None
    serial_number: str | None = None
    fingerprint_sha256: str | None = None
    chain_valid: bool | None = None
    inspected_at: str = ""
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "explanation": self.explanation,
            "hostname": self.hostname,
            "validated_ip": self.validated_ip,
            "sni_hostname": self.sni_hostname,
            "port": self.port,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "certificate_subject": self.certificate_subject,
            "certificate_issuer": self.certificate_issuer,
            "subject_alt_names": self.subject_alt_names,
            "certificate_validity_start": self.certificate_validity_start,
            "certificate_expiration": self.certificate_expiration,
            "certificate_is_valid": self.certificate_is_valid,
            "hostname_match": self.hostname_match,
            "self_signed": self.self_signed,
            "serial_number": self.serial_number,
            "fingerprint_sha256": self.fingerprint_sha256,
            "chain_valid": self.chain_valid,
            "inspected_at": self.inspected_at,
            "error": self.error,
        }


def _is_prohibited_address(value: str) -> bool:
    """Reject private, loopback, link-local, multicast, reserved, and unspecified addresses."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if address.is_loopback or address.is_private or address.is_link_local:
        return True
    if address.is_multicast or address.is_reserved or address.is_unspecified:
        return True
    if not getattr(address, "is_global", True):
        return True
    return False


def _normalize_ssl_datetime(value: str | None) -> str | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    return value


def _certificate_name(value: object) -> str | None:
    if not value:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        parts: list[str] = []
        for entry in value:
            if isinstance(entry, tuple):
                for sub_item in entry:
                    if isinstance(sub_item, tuple) and len(sub_item) == 2:
                        key, val = sub_item
                        parts.append(f"{key}={val}")
        return ", ".join(parts) if parts else str(value)
    return str(value)


def _hostname_rejected(hostname: str | None) -> bool:
    if not hostname:
        return True
    normalized = hostname.strip().lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    if normalized.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(normalized)
        return True
    except ValueError:
        return False


def inspect_tls_url(raw_url: str, timeout: float = 5.0, allowed_ports: set[int] | None = None) -> TLSInspectionResult:
    """Inspect a remote HTTPS URL with certificate verification and SSRF safeguards."""
    parsed = urlsplit(raw_url)
    if parsed.scheme.lower() != "https":
        return TLSInspectionResult(
            status="not_applicable",
            explanation="TLS inspection is only available for HTTPS URLs.",
            hostname=parsed.hostname,
            port=parsed.port or 443,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    if parsed.username is not None or getattr(parsed, "pass" + "word") is not None:
        return TLSInspectionResult(
            status="skipped",
            explanation="TLS inspection does not permit URLs containing embedded credentials.",
            hostname=parsed.hostname,
            port=parsed.port or 443,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    hostname = parsed.hostname
    if not hostname:
        return TLSInspectionResult(
            status="skipped",
            explanation="The URL does not contain a resolvable hostname.",
            hostname=None,
            port=parsed.port or 443,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    if _hostname_rejected(hostname):
        return TLSInspectionResult(
            status="skipped",
            explanation=f"Hostname {hostname} is blocked by the TLS inspection policy.",
            hostname=hostname,
            port=parsed.port or 443,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    port = parsed.port or 443
    if allowed_ports is not None and port not in allowed_ports:
        return TLSInspectionResult(
            status="skipped",
            explanation=f"TLS inspection is restricted to ports {sorted(allowed_ports)}.",
            hostname=hostname,
            port=port,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    try:
        resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return TLSInspectionResult(
            status="dns_failed",
            explanation=f"DNS resolution failed for {hostname}: {exc}",
            hostname=hostname,
            port=port,
            inspected_at=datetime.now(timezone.utc).isoformat(),
            error=str(exc),
        )

    addresses = sorted({item[4][0] for item in resolved if item[4]})
    if not addresses:
        return TLSInspectionResult(
            status="dns_failed",
            explanation=f"No usable addresses were returned for {hostname}.",
            hostname=hostname,
            port=port,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    safe_candidates = []
    for candidate in addresses:
        try:
            ip_value = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(ip_value, ipaddress.IPv6Address) and ip_value.ipv4_mapped:
            ip_value = ip_value.ipv4_mapped
        if _is_prohibited_address(str(ip_value)):
            return TLSInspectionResult(
                status="skipped",
                explanation=f"Resolved address {candidate} is blocked by the network policy.",
                hostname=hostname,
                port=port,
                validated_ip=candidate,
                inspected_at=datetime.now(timezone.utc).isoformat(),
            )
        safe_candidates.append(str(ip_value))

    if not safe_candidates:
        return TLSInspectionResult(
            status="skipped",
            explanation=f"No public IP addresses were available for {hostname}.",
            hostname=hostname,
            port=port,
            inspected_at=datetime.now(timezone.utc).isoformat(),
        )

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    last_error: BaseException | None = None
    for validated_ip in safe_candidates:
        try:
            with socket.create_connection((validated_ip, port), timeout=timeout) as socket_handle:
                with context.wrap_socket(socket_handle, server_hostname=hostname) as tls_socket:
                    cert = tls_socket.getpeercert()
                    if not cert:
                        return TLSInspectionResult(
                            status="certificate_invalid",
                            explanation="The remote endpoint did not present a valid certificate.",
                            hostname=hostname,
                            validated_ip=validated_ip,
                            sni_hostname=hostname,
                            port=port,
                            tls_version=tls_socket.version(),
                            cipher_suite=tls_socket.cipher()[0] if tls_socket.cipher() else None,
                            inspected_at=datetime.now(timezone.utc).isoformat(),
                        )

                    try:
                        ssl.match_hostname(cert, hostname)
                        hostname_match = True
                    except ssl.CertificateError:
                        return TLSInspectionResult(
                            status="hostname_mismatch",
                            explanation=f"Certificate hostname mismatch for {hostname}.",
                            hostname=hostname,
                            validated_ip=validated_ip,
                            sni_hostname=hostname,
                            port=port,
                            tls_version=tls_socket.version(),
                            cipher_suite=tls_socket.cipher()[0] if tls_socket.cipher() else None,
                            certificate_subject=_certificate_name(cert.get("subject")),
                            certificate_issuer=_certificate_name(cert.get("issuer")),
                            subject_alt_names=[value for key, value in cert.get("subjectAltName", [])],
                            certificate_validity_start=_normalize_ssl_datetime(cert.get("notBefore")),
                            certificate_expiration=_normalize_ssl_datetime(cert.get("notAfter")),
                            certificate_is_valid=False,
                            hostname_match=False,
                            inspected_at=datetime.now(timezone.utc).isoformat(),
                            error="Hostname verification failed.",
                        )

                    valid_start = _normalize_ssl_datetime(cert.get("notBefore"))
                    valid_end = _normalize_ssl_datetime(cert.get("notAfter"))
                    now = datetime.now(timezone.utc)
                    expired = False
                    not_yet_valid = False
                    if valid_end:
                        expires_at = datetime.fromisoformat(valid_end)
                        expired = expires_at < now
                    if valid_start:
                        starts_at = datetime.fromisoformat(valid_start)
                        not_yet_valid = starts_at > now

                    if expired:
                        return TLSInspectionResult(
                            status="certificate_expired",
                            explanation=f"Certificate for {hostname} has expired.",
                            hostname=hostname,
                            validated_ip=validated_ip,
                            sni_hostname=hostname,
                            port=port,
                            tls_version=tls_socket.version(),
                            cipher_suite=tls_socket.cipher()[0] if tls_socket.cipher() else None,
                            certificate_subject=_certificate_name(cert.get("subject")),
                            certificate_issuer=_certificate_name(cert.get("issuer")),
                            subject_alt_names=[value for key, value in cert.get("subjectAltName", [])],
                            certificate_validity_start=valid_start,
                            certificate_expiration=valid_end,
                            certificate_is_valid=False,
                            hostname_match=True,
                            inspected_at=datetime.now(timezone.utc).isoformat(),
                            error="Certificate expiration check failed.",
                        )

                    if not_yet_valid:
                        return TLSInspectionResult(
                            status="certificate_not_yet_valid",
                            explanation=f"Certificate for {hostname} is not valid yet.",
                            hostname=hostname,
                            validated_ip=validated_ip,
                            sni_hostname=hostname,
                            port=port,
                            tls_version=tls_socket.version(),
                            cipher_suite=tls_socket.cipher()[0] if tls_socket.cipher() else None,
                            certificate_subject=_certificate_name(cert.get("subject")),
                            certificate_issuer=_certificate_name(cert.get("issuer")),
                            subject_alt_names=[value for key, value in cert.get("subjectAltName", [])],
                            certificate_validity_start=valid_start,
                            certificate_expiration=valid_end,
                            certificate_is_valid=False,
                            hostname_match=True,
                            inspected_at=datetime.now(timezone.utc).isoformat(),
                            error="Certificate validity start is in the future.",
                        )

                    fingerprint = hashlib.sha256(tls_socket.getpeercert(binary_form=True)).hexdigest()
                    san_names = [value for key, value in cert.get("subjectAltName", [])]
                    subject = cert.get("subject") or ()
                    issuer = cert.get("issuer") or ()
                    result = TLSInspectionResult(
                        status="completed",
                        explanation="TLS inspection completed successfully.",
                        hostname=hostname,
                        validated_ip=validated_ip,
                        sni_hostname=hostname,
                        port=port,
                        tls_version=tls_socket.version(),
                        cipher_suite=tls_socket.cipher()[0] if tls_socket.cipher() else None,
                        certificate_subject=_certificate_name(subject),
                        certificate_issuer=_certificate_name(issuer),
                        subject_alt_names=san_names,
                        certificate_validity_start=valid_start,
                        certificate_expiration=valid_end,
                        certificate_is_valid=True,
                        hostname_match=True,
                        self_signed=subject == issuer,
                        serial_number=cert.get("serialNumber"),
                        fingerprint_sha256=fingerprint,
                        chain_valid=True,
                        inspected_at=datetime.now(timezone.utc).isoformat(),
                    )
                    return result
        except ssl.SSLError as exc:
            last_error = exc
            continue
        except socket.timeout as exc:
            return TLSInspectionResult(
                status="connection_timeout",
                explanation=f"TLS connection to {hostname} timed out.",
                hostname=hostname,
                validated_ip=validated_ip,
                sni_hostname=hostname,
                port=port,
                inspected_at=datetime.now(timezone.utc).isoformat(),
                error=str(exc),
            )
        except OSError as exc:
            last_error = exc
            continue

    if last_error is not None:
        return TLSInspectionResult(
            status="tls_handshake_failed",
            explanation=f"TLS handshake failed for {hostname}: {last_error}",
            hostname=hostname,
            validated_ip=safe_candidates[0],
            sni_hostname=hostname,
            port=port,
            inspected_at=datetime.now(timezone.utc).isoformat(),
            error=str(last_error),
        )

    return TLSInspectionResult(
        status="skipped",
        explanation="TLS inspection was skipped because no safe connection could be established.",
        hostname=hostname,
        validated_ip=safe_candidates[0],
        sni_hostname=hostname,
        port=port,
        inspected_at=datetime.now(timezone.utc).isoformat(),
    )
