"""
CLI Generator for the LocketGold Research Lab Root CA and Server Leaf Certificates.
Stores private keys outside the web directory with 0600 permissions.
Usage:
  python -m scripts.generate_lab_ca --out-dir ./certs_private
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


def main():
    parser = argparse.ArgumentParser(description='Generate Research Lab Root CA and Leaf Certificate')
    parser.add_argument('--out-dir', default='certs_private', help='Directory to store CA key and certificates')
    parser.add_argument(
        '--domains',
        default='locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond',
        help='Comma-separated SAN domains for the lab leaf certificate',
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = generate_lab_root_ca()
    ca_key_path = out_dir / 'lab_root_ca.key'
    ca_pem_path = out_dir / 'lab_root_ca.pem'
    ca_der_path = out_dir / 'lab_root_ca.cer'

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

    ca_pem_path.write_bytes(ca_cert.public_bytes(Encoding.PEM))
    ca_der_path.write_bytes(ca_cert.public_bytes(Encoding.DER))

    domains = [d.strip() for d in args.domains.split(',') if d.strip()]
    leaf_key, leaf_cert = generate_lab_leaf_certificate(ca_key, ca_cert, domains)
    leaf_key_path = out_dir / 'lab_leaf.key'
    leaf_pem_path = out_dir / 'lab_leaf.pem'

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
    leaf_pem_path.write_bytes(leaf_cert.public_bytes(Encoding.PEM))

    meta = inspect_certificate_metadata(ca_cert)
    print("=== Research Lab Root CA Generated ===")
    print("Subject:", meta['subject'])
    print("SHA-256 Fingerprint:", meta['sha256_fingerprint'])
    print("Valid:", meta['not_valid_before_utc'], "->", meta['not_valid_after_utc'])
    print("Public CA PEM:", ca_pem_path)
    print("Private CA Key (0600, DO NOT COMMIT):", ca_key_path)


if __name__ == '__main__':
    main()
