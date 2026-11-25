import plistlib
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import HTTPException
from .config import Settings


def payload(kind: str, name: str) -> dict:
    identifier = 'local.license-manager.' + name.lower().replace(' ', '-')
    return {
        'PayloadType': kind,
        'PayloadVersion': 1,
        'PayloadIdentifier': identifier,
        'PayloadUUID': str(uuid4()).upper(),
        'PayloadDisplayName': name,
    }


def load_validated_root_ca(settings: Settings) -> x509.Certificate | None:
    if settings.root_ca_path and settings.root_ca_pem:
        raise ValueError('Set only one of ROOT_CA_PATH or ROOT_CA_PEM')
    if not settings.root_ca_path and not settings.root_ca_pem:
        return None
    if settings.root_ca_pem:
        raw = settings.root_ca_pem.replace('\\n', '\n').strip().encode('utf-8')
    else:
        path = Path(settings.root_ca_path).resolve(strict=True)
        if not path.is_file():
            raise ValueError('ROOT_CA_PATH must be a certificate file')
        with path.open('rb') as certificate_file:
            raw = certificate_file.read(65537)
    if not raw or len(raw) > 65536:
        raise ValueError('Root CA must be a certificate no larger than 64 KiB')
    if b'PRIVATE KEY' in raw:
        raise ValueError('Root CA must never contain a private key')
    if b'-----BEGIN CERTIFICATE' in raw and raw.count(b'-----BEGIN CERTIFICATE') != 1:
        raise ValueError('Provide exactly one root CA certificate, not a certificate chain')
    cert = (
        x509.load_pem_x509_certificate(raw)
        if b'-----BEGIN CERTIFICATE' in raw
        else x509.load_der_x509_certificate(raw)
    )
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('Root CA must contain a CA certificate')
    cert.verify_directly_issued_by(cert)
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        raise ValueError('Root CA must allow certificate signing')
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError('The CA certificate is expired or not yet valid')
    return cert


def resolve_doh_server_url(settings: Settings, *, device_label: str | None = None) -> str:
    """
    Resolve the DNS-over-HTTPS ServerURL supporting two modes:
    - Mode B (Custom DoH Lab): Uses `settings.doh_server_url` when configured (validated HTTPS endpoint
      under operator control, e.g. `https://mock.lab.vuthanhluan.bond/dns-query`).
    - Mode A (NextDNS): Uses `https://dns.nextdns.io/<nextdns_id>[/<device_label>]`.
    Never accepts arbitrary URLs from end-user request parameters.
    """
    custom_doh = (getattr(settings, 'doh_server_url', '') or '').strip()
    if custom_doh:
        base_url = custom_doh.rstrip('/')
        if device_label:
            safe_label = ''.join(c for c in device_label if c.isalnum() or c in {'-', '_'})[:32]
            if safe_label and not base_url.endswith('/' + safe_label):
                return f'{base_url}/{safe_label}'
        return base_url

    if not settings.nextdns_id:
        raise HTTPException(503, 'Chưa cấu hình NEXTDNS_ID hoặc DOH_SERVER_URL trên server.')
    server_url = f'https://dns.nextdns.io/{settings.nextdns_id}'
    if device_label:
        safe_label = ''.join(c for c in device_label if c.isalnum() or c in {'-', '_'})[:32]
        if safe_label:
            server_url = f'{server_url}/{safe_label}'
    return server_url


def build_profile(
    settings: Settings,
    *,
    scoped_domains: list[str] | None = None,
    device_label: str | None = None,
    override_ca_cert: x509.Certificate | None = None,
) -> bytes:
    server_url = resolve_doh_server_url(settings, device_label=device_label)
    dns = payload('com.apple.dnsSettings.managed', 'NextDNS' if not getattr(settings, 'doh_server_url', '') else 'Locket Gold DoH Lab')
    dns_settings: dict = {
        'DNSProtocol': 'HTTPS',
        'ServerURL': server_url,
    }
    if scoped_domains:
        dns_settings['SupplementalMatchDomains'] = [d for d in scoped_domains if d]
    dns['DNSSettings'] = dns_settings
    contents = [dns]

    cert = override_ca_cert if override_ca_cert is not None else load_validated_root_ca(settings)
    if cert is not None:
        ca = payload('com.apple.security.root', 'Root CA')
        ca['PayloadCertificateFileName'] = 'root-ca.cer'
        ca['PayloadContent'] = cert.public_bytes(Encoding.DER)
        contents.append(ca)

    profile = payload('Configuration', 'Locket Gold DNS')
    has_ca = any(item.get('PayloadType') == 'com.apple.security.root' for item in contents)
    profile.update(
        PayloadContent=contents,
        PayloadRemovalDisallowed=False,
        PayloadScope='System',
        PayloadDescription=(
            'Cấu hình NextDNS + Research Lab Root CA (chỉ dành cho môi trường Lab thử nghiệm).'
            if has_ca
            else 'Cấu hình NextDNS. Không tự cấp quyền trong ứng dụng Locket.'
        ),
    )
    xml_bytes = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
    # Strict self-validation to ensure valid Apple plist XML before returning
    parsed_back = plistlib.loads(xml_bytes)
    if not isinstance(parsed_back, dict) or not parsed_back.get('PayloadContent'):
        raise ValueError('Generated mobileconfig failed plist validation')
    return xml_bytes
