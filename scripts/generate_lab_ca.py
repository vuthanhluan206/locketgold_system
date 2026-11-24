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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
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

    ca_key, ca_cert = generate_lab_root_ca()
    ca_key_path = out_private / 'lab_root_ca.key'
    ca_pem_public_path = out_public / 'lab_root_ca.pem'
    ca_der_public_path = out_public / 'lab_root_ca.cer'
    ca_pem_private_copy = out_private / 'lab_root_ca.pem'

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
    ca_pem_public_path.write_bytes(ca_pem_bytes)
    ca_der_public_path.write_bytes(ca_der_bytes)
    ca_pem_private_copy.write_bytes(ca_pem_bytes)

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
        os.chmod(leaf_key_path, 0o600)
    except OSError:
        pass
    leaf_pem_bytes = leaf_cert.public_bytes(Encoding.PEM)
    leaf_pem_path.write_bytes(leaf_pem_bytes)
    leaf_pub_pem_path.write_bytes(leaf_pem_bytes)

    meta = inspect_certificate_metadata(ca_cert)
    return {
        'ca_metadata': meta,
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
    args = parser.parse_args(argv)

    if args.out_dir and not args.out_public and not args.out_private:
        out_public = Path(args.out_dir).resolve()
        out_private = Path(args.out_dir).resolve()
    else:
        out_public = Path(args.out_public or 'certs_public').resolve()
        out_private = Path(args.out_private or 'certs_private').resolve()

    domains = [d.strip() for d in args.domains.split(',') if d.strip()]
    result = generate_ca_and_leaf_files(out_public, out_private, domains)
    meta = result['ca_metadata']
    print("=== Research Lab Root CA & Leaf Generated ===")
    print("Subject:", meta['subject'])
    print("SHA-256 Fingerprint:", meta['sha256_fingerprint'])
    print("Valid:", meta['not_valid_before_utc'], "->", meta['not_valid_after_utc'])
    print("Public CA PEM:", result['ca_pem_public_path'])
    print("Private CA Key (0600, DO NOT COMMIT):", result['ca_key_path'])
    return result


if __name__ == '__main__':
    main()
