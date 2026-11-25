"""
CLI Generator for the LocketGold Research Lab Root CA and Server Leaf Certificates.
Separates public certificates (`--out-public`, default `./certs_public`) from private keys
(`--out-private`, default `./certs_private`) with 0600 permissions.
Also supports `--out-dir` for backward compatibility.
Usage:
  python -m scripts.generate_lab_ca --out-public certs_public --out-private certs_private
"""
import argparse
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.services.pki_service import (
    generate_lab_leaf_certificate,
    generate_lab_root_ca,
    inspect_certificate_metadata,
)

FORBIDDEN_THIRD_PARTY_SAN_DOMAINS = {
    'api.revenuecat.com',
    'revenuecat.com',
    'buy.itunes.apple.com',
    'sandbox.itunes.apple.com',
    'apple.com',
    'icloud.com',
    'api.locketcamera.com',
    'locketcamera.com',
}


def generate_ca_and_leaf_files(
    out_public: Path,
    out_private: Path,
    domains: list[str],
    *,
    rotate: bool = False,
) -> dict:
    for d in domains:
        clean_d = d.strip().lower()
        if clean_d in FORBIDDEN_THIRD_PARTY_SAN_DOMAINS or any(
            clean_d.endswith('.' + fb) for fb in FORBIDDEN_THIRD_PARTY_SAN_DOMAINS
        ):
            raise ValueError(
                f"Domain '{d}' belongs to a third-party service and is prohibited in Research Lab leaf certificates."
            )

    out_public.mkdir(parents=True, exist_ok=True)
    out_private.mkdir(parents=True, exist_ok=True)

    ca_key_path = out_private / 'lab_root_ca.key'
    ca_pem_public_path = out_public / 'lab_root_ca.pem'
    ca_der_public_path = out_public / 'lab_root_ca.cer'
    ca_pem_private_copy = out_private / 'lab_root_ca.pem'

    ca_key = None
    ca_cert = None
    ca_reused = False

    key_exists = ca_key_path.exists()
    cert_exists = ca_pem_public_path.exists()

    if not rotate:
        if key_exists != cert_exists:
            raise RuntimeError(
                'Inconsistent Root CA state: one of lab_root_ca.key or lab_root_ca.pem exists while the other is missing. '
                'Refusing to overwrite existing Root CA state without --rotate.'
            )
        if key_exists and cert_exists:
            if not ca_key_path.is_file() or not ca_pem_public_path.is_file():
                raise RuntimeError(
                    'Existing Root CA key or certificate path is not a regular file. '
                    'Refusing to overwrite without --rotate.'
                )
            try:
                key_raw = ca_key_path.read_bytes()
                cert_raw = ca_pem_public_path.read_bytes()
                loaded_key = serialization.load_pem_private_key(key_raw, password=None)
                loaded_cert = x509.load_pem_x509_certificate(cert_raw)
            except Exception as exc:
                raise RuntimeError(
                    'Existing Root CA key or certificate is unreadable or corrupted. '
                    'Refusing to overwrite without --rotate.'
                ) from exc

            existing_meta = inspect_certificate_metadata(loaded_cert)
            if not (
                existing_meta.get('is_currently_valid')
                and existing_meta.get('is_ca')
                and existing_meta.get('is_self_signed')
            ):
                raise RuntimeError(
                    'Existing Root CA certificate is expired, not a CA, or not self-signed. '
                    'Refusing to overwrite without --rotate.'
                )
            try:
                loaded_cert.verify_directly_issued_by(loaded_cert)
            except Exception as exc:
                raise RuntimeError(
                    'Existing Root CA certificate self-signature verification failed. '
                    'Refusing to overwrite without --rotate.'
                ) from exc

            cert_pub_bytes = loaded_cert.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            key_pub_bytes = loaded_key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            if cert_pub_bytes != key_pub_bytes:
                raise RuntimeError(
                    'Existing Root CA certificate public key does not match lab_root_ca.key. '
                    'Refusing to overwrite without --rotate.'
                )

            ca_key = loaded_key
            ca_cert = loaded_cert
            ca_reused = True
    else:
        # When explicitly rotating (--rotate), back up any existing Root CA files first
        if ca_key_path.is_file():
            bak_key = out_private / 'lab_root_ca.key.bak'
            bak_key.write_bytes(ca_key_path.read_bytes())
            try:
                os.chmod(bak_key, 0o600)
            except OSError:
                pass
        if ca_pem_public_path.is_file():
            bak_pem = out_public / 'lab_root_ca.pem.bak'
            bak_pem.write_bytes(ca_pem_public_path.read_bytes())
            try:
                os.chmod(bak_pem, 0o644)
            except OSError:
                pass

    if ca_key is None or ca_cert is None:
        ca_key, ca_cert = generate_lab_root_ca()
        ca_key_bytes = ca_key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ca_key_path.write_bytes(ca_key_bytes)

    try:
        os.chmod(ca_key_path, 0o600)
    except OSError:
        pass

    ca_pem_bytes = ca_cert.public_bytes(Encoding.PEM)
    ca_der_bytes = ca_cert.public_bytes(Encoding.DER)
    if not ca_reused or not ca_pem_public_path.is_file():
        ca_pem_public_path.write_bytes(ca_pem_bytes)
    if not ca_der_public_path.is_file() or not ca_reused:
        ca_der_public_path.write_bytes(ca_der_bytes)
    if not ca_pem_private_copy.is_file() or not ca_reused:
        ca_pem_private_copy.write_bytes(ca_pem_bytes)
    for pub_file in (ca_pem_public_path, ca_der_public_path, ca_pem_private_copy):
        try:
            os.chmod(pub_file, 0o644)
        except OSError:
            pass

    leaf_key, leaf_cert = generate_lab_leaf_certificate(ca_key, ca_cert, domains)
    leaf_key_path = out_private / 'lab_leaf.key'
    leaf_pem_path = out_private / 'lab_leaf.pem'
    leaf_pub_pem_path = out_public / 'lab_leaf.pem'

    leaf_key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        # 0o640 inside the 0750 certs_private directory restricts leaf key to owner and group (never world-readable)
        # while ca_key_path remains 0o600 (owner-only).
        os.chmod(leaf_key_path, 0o640)
    except OSError:
        pass
    leaf_pem_bytes = leaf_cert.public_bytes(Encoding.PEM)
    leaf_pem_path.write_bytes(leaf_pem_bytes)
    leaf_pub_pem_path.write_bytes(leaf_pem_bytes)
    for lp in (leaf_pem_path, leaf_pub_pem_path):
        try:
            os.chmod(lp, 0o644)
        except OSError:
            pass

    meta = inspect_certificate_metadata(ca_cert)
    return {
        'ca_metadata': meta,
        'ca_reused': ca_reused,
        'ca_key_path': str(ca_key_path),
        'ca_pem_public_path': str(ca_pem_public_path),
        'ca_der_public_path': str(ca_der_public_path),
        'leaf_key_path': str(leaf_key_path),
        'leaf_pem_path': str(leaf_pem_path),
        'domains': domains,
    }


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(description='Generate Research Lab Root CA and Leaf Certificate')
    parser.add_argument(
        '--out-public',
        default=None,
        help='Directory to store public certificates (lab_root_ca.pem, lab_root_ca.cer)',
    )
    parser.add_argument(
        '--out-private',
        default=None,
        help='Directory to store private keys and Caddy TLS bundle (lab_root_ca.key, lab_leaf.key, lab_leaf.pem)',
    )
    parser.add_argument(
        '--out-dir',
        default=None,
        help='Legacy flag: directory to store both public and private files if --out-public/--out-private are omitted',
    )
    parser.add_argument(
        '--domains',
        default='locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond',
        help='Comma-separated SAN domains for the lab leaf certificate (must be controlled lab domains only)',
    )
    parser.add_argument(
        '--rotate',
        action='store_true',
        help='Explicitly rotate and overwrite an existing Root CA key and certificate',
    )
    args = parser.parse_args(argv)

    if args.out_dir and not args.out_public and not args.out_private:
        out_public = Path(args.out_dir).resolve()
        out_private = Path(args.out_dir).resolve()
    else:
        out_public = Path(args.out_public or 'certs_public').resolve()
        out_private = Path(args.out_private or 'certs_private').resolve()

    domains = [d.strip() for d in args.domains.split(',') if d.strip()]
    result = generate_ca_and_leaf_files(out_public, out_private, domains, rotate=bool(args.rotate))
    meta = result['ca_metadata']
    action_label = "Reused Existing Root CA & Signed Leaf" if result.get('ca_reused') else "Generated New Root CA & Leaf"
    print(f"=== Research Lab PKI ({action_label}) ===")
    print("Subject:", meta['subject'])
    print("SHA-256 Fingerprint:", meta['sha256_fingerprint'])
    print("Valid:", meta['not_valid_before_utc'], "->", meta['not_valid_after_utc'])
    print("Public CA PEM:", result['ca_pem_public_path'])
    print("Private CA Key (0600, DO NOT COMMIT):", result['ca_key_path'])
    return result


if __name__ == '__main__':
    main()
