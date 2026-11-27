from datetime import datetime, timedelta, timezone
import fnmatch
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def cert_not_valid_before_utc(cert: x509.Certificate) -> datetime:
    """Return timezone-aware UTC not_valid_before across cryptography <42 and >=42."""
    dt = getattr(cert, 'not_valid_before_utc', None)
    if dt is None:
        dt = cert.not_valid_before
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def cert_not_valid_after_utc(cert: x509.Certificate) -> datetime:
    """Return timezone-aware UTC not_valid_after across cryptography <42 and >=42."""
    dt = getattr(cert, 'not_valid_after_utc', None)
    if dt is None:
        dt = cert.not_valid_after
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def verify_cert_directly_issued_by(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    """Verify certificate issuer and cryptographic signature across cryptography <40 and >=40."""
    verifier = getattr(cert, 'verify_directly_issued_by', None)
    if callable(verifier):
        verifier(issuer_cert)
        return
    if cert.issuer != issuer_cert.subject:
        raise ValueError('Certificate issuer does not match issuer subject')
    pub = issuer_cert.public_key()
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        raise ValueError(f'Unsupported public key type for signature verification: {type(pub).__name__}')


def generate_lab_root_ca(
    common_name: str = 'LocketGold Research Lab Root CA',
    organization: str = 'LocketGold Research Lab',
    country: str = 'VN',
    validity_days: int = 3650,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Generate a standards-compliant X.509 Root CA for the Research Lab.
    Uses backdated NotBefore (now - 7 days) so devices with minor clock skew never reject it as NotYetValid,
    and includes critical BasicConstraints(ca=True) + KeyUsage(key_cert_sign=True, crl_sign=True).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=7))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert


def generate_lab_leaf_certificate(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    dns_names: list[str],
    validity_days: int = 365,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Generate an Apple HT210176 compliant Server Leaf Certificate (<= 397 days, SAN required, serverAuth EKU)
    strictly for controlled Research Lab domains.
    """
    if validity_days > 397:
        raise ValueError('Apple iOS requires TLS server leaf certificates to have validity <= 398 days')
    if not dns_names:
        raise ValueError('At least one DNS name is required for SubjectAlternativeName')

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'VN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LocketGold Research Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0]),
    ])
    now = datetime.now(timezone.utc)
    san = x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(san, critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return leaf_key, cert


def match_tls_hostname(pattern: str, hostname: str) -> bool:
    """RFC 6125 TLS hostname matching (exact match or single left-most label wildcard)."""
    pat = pattern.strip().lower().rstrip('.')
    host = hostname.strip().lower().rstrip('.')
    if not pat or not host:
        return False
    if '*' not in pat:
        return pat == host
    # Wildcard must only appear in the left-most label (*.example.com) and match a single label
    if not pat.startswith('*.') or '*' in pat[2:]:
        return False
    suffix = pat[1:]  # .example.com
    if not host.endswith(suffix):
        return False
    prefix = host[:-len(suffix)]
    return bool(prefix) and '.' not in prefix


def verify_certificate_chain_and_hostname(
    root_ca: x509.Certificate,
    leaf_cert: x509.Certificate,
    hostname: str,
    now: datetime | None = None,
) -> dict:
    """
    Perform comprehensive X.509 chain, validity window, SHA-256 fingerprint, BasicConstraints,
    ExtendedKeyUsage, and RFC 6125 SAN hostname verification for the Research Lab.
    """
    now = now if now is not None else datetime.now(timezone.utc)
    errors: list[str] = []

    # 1. Verify Root CA self-signature, BasicConstraints, KeyUsage, and validity
    try:
        verify_cert_directly_issued_by(root_ca, root_ca)
    except Exception as exc:
        errors.append(f'Root CA is not a valid self-signed certificate: {type(exc).__name__}')

    root_nvb = cert_not_valid_before_utc(root_ca)
    root_nva = cert_not_valid_after_utc(root_ca)
    if not (root_nvb <= now < root_nva):
        errors.append('Root CA is expired or not yet valid')

    try:
        if not root_ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            errors.append('Root CA BasicConstraints.ca is False')
    except x509.ExtensionNotFound:
        errors.append('Root CA is missing BasicConstraints extension')

    # 2. Verify Leaf Certificate signature by Root CA
    try:
        verify_cert_directly_issued_by(leaf_cert, root_ca)
    except Exception as exc:
        errors.append(f'Leaf certificate signature verification by Root CA failed: {type(exc).__name__}')

    # 3. Verify Leaf validity window and Apple 398-day limit
    leaf_nvb = cert_not_valid_before_utc(leaf_cert)
    leaf_nva = cert_not_valid_after_utc(leaf_cert)
    if not (leaf_nvb <= now < leaf_nva):
        errors.append('Leaf certificate is expired or not yet valid')

    leaf_lifetime_days = (leaf_nva - leaf_nvb).total_seconds() / 86400.0
    if leaf_lifetime_days > 398.0:
        errors.append(f'Leaf certificate validity ({leaf_lifetime_days:.1f} days) exceeds Apple iOS 398-day limit')

    # 4. Verify Leaf BasicConstraints (must be CA=False) and serverAuth EKU
    try:
        if leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            errors.append('Leaf certificate must not have BasicConstraints.ca=True')
    except x509.ExtensionNotFound:
        pass

    try:
        eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            errors.append('Leaf certificate is missing serverAuth ExtendedKeyUsage')
    except x509.ExtensionNotFound:
        errors.append('Leaf certificate is missing ExtendedKeyUsage extension')

    # 5. Verify SAN hostname matching (RFC 6125 / Apple HT210176 require SAN, never CN-only)
    san_names: list[str] = []
    hostname_matched = False
    try:
        san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_names = san.get_values_for_type(x509.DNSName)
        hostname_matched = any(match_tls_hostname(pattern, hostname) for pattern in san_names)
        if not hostname_matched:
            errors.append(f"Hostname '{hostname}' does not match any SAN DNSName {san_names}")
    except x509.ExtensionNotFound:
        errors.append('Leaf certificate is missing SubjectAlternativeName extension')

    root_fp = ':'.join(f'{b:02X}' for b in root_ca.fingerprint(hashes.SHA256()))
    leaf_fp = ':'.join(f'{b:02X}' for b in leaf_cert.fingerprint(hashes.SHA256()))

    return {
        'valid': len(errors) == 0,
        'hostname': hostname,
        'hostname_matched': hostname_matched,
        'san_dns_names': san_names,
        'root_ca_sha256': root_fp,
        'leaf_sha256': leaf_fp,
        'leaf_lifetime_days': round(leaf_lifetime_days, 2),
        'errors': errors,
    }


def inspect_certificate_metadata(cert: x509.Certificate) -> dict:
    """Return structured X.509 metadata and SHA-256 fingerprint for observability and UI verification."""
    fp = ':'.join(f'{b:02X}' for b in cert.fingerprint(hashes.SHA256()))
    now = datetime.now(timezone.utc)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        bc = False
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        can_sign = bool(ku.key_cert_sign)
    except x509.ExtensionNotFound:
        can_sign = False

    nvb = cert_not_valid_before_utc(cert)
    nva = cert_not_valid_after_utc(cert)
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': format(cert.serial_number, 'X'),
        'not_valid_before_utc': nvb.isoformat(),
        'not_valid_after_utc': nva.isoformat(),
        'sha256_fingerprint': fp,
        'is_ca': bc,
        'is_self_signed': cert.subject == cert.issuer,
        'key_cert_sign': can_sign,
        'is_currently_valid': nvb <= now < nva,
        'pem': cert.public_bytes(Encoding.PEM).decode('ascii'),
    }
