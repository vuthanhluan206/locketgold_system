"""
StoreKit 2 JWS Transaction Verification & RevenueCat Webhook Synchronization Service (`app/services/payment_service.py`).

Security Invariants (Prompt 28 Payment Security Audit):
1. Strict Separation of Trust Anchors (`payment_trust_level` & `trust_anchor`):
   - `apple_x5c_chain`: JWS signed by an ECDSA P-256 leaf certificate in an X.509 `x5c` chain (`Leaf -> Intermediate -> Root`)
     that cryptographically chains back to an explicitly pinned Root CA certificate (`trusted_root_ca_cert`).
   - `lab_internal_sandbox_key`: JWS signed by the Lab's internal ephemeral ECDSA P-256 test key (`environment in {'Sandbox', 'Xcode'}`).
     Classified honestly as `payment_trust_level = 'lab_simulated_jws'` — NEVER equated with an Apple-authenticated transaction
     and NEVER sets `_server_uid_proof = True` or `uid_assurance = 'independently_verified'` unless the account already
     possesses independent UID proof.
2. X.509 `x5c` Chain Verification:
   - Rejects self-asserted/untrusted root certificates embedded in `x5c[-1]` that do not match the server's pinned `trusted_root_ca_cert`.
   - Verifies validity windows (`not_valid_before_utc <= now < not_valid_after_utc`), `BasicConstraints(ca=True)` on CA certs,
     and cryptographic issuer-to-subject signatures at every link in the chain.
3. Transaction Ownership Binding & Anti-Replay:
   - Enforces `bundleId in ALLOWED_BUNDLE_IDS`.
   - Tracks `transactionId` and `originalTransactionId` bindings to `app_user_id` so a transaction owned by Account A
     can never be replayed to claim Gold for Account B (`HTTP 409 Conflict`).
   - Rejects replayed or stale out-of-order transactions/webhook events (`event_timestamp_ms < last_payment_event_ms`)
     so an old `RENEWAL` or `INITIAL_PURCHASE` cannot resurrect a newer `CANCELLATION` / `revoked` state.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Literal
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from ..models import DEFAULT_ACTIVE_GOLD_FEATURES
from .entitlement_service import FIREBASE_UID_RE, extract_verified_uid_metadata
from .pki_service import cert_not_valid_after_utc, cert_not_valid_before_utc, verify_cert_directly_issued_by

SUPPORTED_GOLD_PRODUCTS = {
    'com.locket.gold.yearly',
    'locket_1600_1y',
    'locket_gold_annual',
    'com.locket.gold.monthly',
}

ALLOWED_BUNDLE_IDS = {
    'com.locket.Locket',
    'bond.vuthanhluan.locketgold.lab',
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(segment: str) -> bytes:
    clean = segment.strip()
    pad = '=' * (-len(clean) % 4)
    return base64.urlsafe_b64decode(clean + pad)


def get_or_create_sandbox_storekit_key(app_state: Any) -> ec.EllipticCurvePrivateKey:
    """Return a per-process ephemeral ECDSA P-256 keypair used for signing Lab StoreKit 2 Sandbox simulation JWS tokens."""
    key = getattr(app_state, '_sandbox_storekit_ec_key', None)
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
        setattr(app_state, '_sandbox_storekit_ec_key', key)
    return key


def generate_storekit2_x5c_test_chain(
    root_ca_name: str = 'LocketGold StoreKit Test Root CA',
) -> dict[str, Any]:
    """
    Build a 3-certificate X.509 ECDSA P-256 chain (`Root CA -> Intermediate CA -> StoreKit Leaf Signer`)
    for testing RFC 7515 `x5c` StoreKit 2 JWS certificate chain validation.
    """
    now = datetime.now(timezone.utc)
    nvb = now - timedelta(days=1)

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'VN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LocketGold Research Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, root_ca_name),
    ])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'VN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LocketGold Research Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'LocketGold StoreKit Intermediate CA'),
    ])
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'VN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LocketGold Research Lab'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'LocketGold StoreKit 2 Transaction Signer'),
    ])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(inter_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(now + timedelta(days=390))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=inter_key, algorithm=hashes.SHA256())
    )

    x5c_list = [
        base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode('ascii')
        for c in (leaf_cert, inter_cert, root_cert)
    ]
    return {
        'root_key': root_key,
        'root_cert': root_cert,
        'inter_key': inter_key,
        'inter_cert': inter_cert,
        'leaf_key': leaf_key,
        'leaf_cert': leaf_cert,
        'x5c': x5c_list,
    }


def sign_storekit2_sandbox_jws(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    app_user_id: str,
    product_id: str = 'com.locket.gold.yearly',
    transaction_id: str | None = None,
    original_transaction_id: str | None = None,
    purchase_date: datetime | None = None,
    expires_date: datetime | None = None,
    revocation_date: datetime | None = None,
    signed_date: datetime | None = None,
    environment: Literal['Sandbox', 'Xcode'] = 'Sandbox',
    bundle_id: str = 'com.locket.Locket',
    x5c_chain: list[str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """
    Create a cryptographically signed RFC 7515 ES256 (ECDSA P-256) StoreKit 2 JWS transaction token
    matching Apple's `JWSTransactionDecodedPayload` structure for Sandbox/StoreKit testing.
    """
    now = datetime.now(timezone.utc)
    p_dt = purchase_date or now
    e_dt = expires_date or (now + timedelta(days=365))
    s_dt = signed_date or now
    tx_id = transaction_id or f'2000000{int(now.timestamp() * 1000) % 1000000000:09d}'
    orig_tx_id = original_transaction_id or tx_id

    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = hashlib.sha256(pub_der).hexdigest()[:16]

    header: dict[str, Any] = {
        'alg': 'ES256',
        'kid': kid,
        'typ': 'JWT',
    }
    if x5c_chain:
        header['x5c'] = list(x5c_chain)
    else:
        header['x5u_spki_b64'] = _b64url_encode(pub_der)

    payload: dict[str, Any] = {
        'transactionId': tx_id,
        'originalTransactionId': orig_tx_id,
        'bundleId': bundle_id,
        'productId': product_id,
        'appAccountToken': app_user_id,
        'app_user_id': app_user_id,
        'purchaseDate': int(p_dt.timestamp() * 1000),
        'originalPurchaseDate': int(p_dt.timestamp() * 1000),
        'expiresDate': int(e_dt.timestamp() * 1000),
        'signedDate': int(s_dt.timestamp() * 1000),
        'type': 'Auto-Renewable Subscription',
        'inAppOwnershipType': 'PURCHASED',
        'environment': environment,
        'storefront': 'VNM',
        'price': 399000000,
        'currency': 'VND',
    }
    if revocation_date is not None:
        payload['revocationDate'] = int(revocation_date.timestamp() * 1000)
        payload['revocationReason'] = 0

    h_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f'{h_b64}.{p_b64}'.encode('ascii')

    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    s_b64 = _b64url_encode(raw_sig)
    return f'{h_b64}.{p_b64}.{s_b64}', payload


def _verify_x5c_certificate_chain(
    x5c_b64_list: list[str],
    trusted_root_ca_cert: x509.Certificate,
) -> ec.EllipticCurvePublicKey:
    """
    Validate an RFC 7515 `x5c` X.509 certificate chain (`[leaf, intermediate, ..., root]`)
    against a pinned `trusted_root_ca_cert`:
    1. Requires at least 2 certificates (`leaf` and `root`, typically 3 with `intermediate`).
    2. Top certificate in chain MUST match the pinned `trusted_root_ca_cert` by SHA-256 fingerprint
       (rejects attacker-supplied self-signed roots!).
    3. Every certificate must be currently within its validity window (`not_valid_before_utc <= now < not_valid_after_utc`).
    4. Every issuer certificate (`certs[i+1]`) must have `BasicConstraints(ca=True)` and cryptographically sign `certs[i]`.
    5. Leaf certificate (`certs[0]`) must have `BasicConstraints(ca=False)` and an ECDSA P-256 public key.
    """
    if not isinstance(x5c_b64_list, list) or len(x5c_b64_list) < 2 or len(x5c_b64_list) > 5:
        raise ValueError('StoreKit 2 x5c header must contain 2 to 5 X.509 DER certificates')

    certs: list[x509.Certificate] = []
    for idx, b64_item in enumerate(x5c_b64_list):
        try:
            der_bytes = base64.b64decode(b64_item)
            certs.append(x509.load_der_x509_certificate(der_bytes))
        except Exception as exc:
            raise ValueError(f'Malformed DER certificate at x5c[{idx}]') from exc

    pinned_fp = trusted_root_ca_cert.fingerprint(hashes.SHA256())
    chain_root_fp = certs[-1].fingerprint(hashes.SHA256())
    if chain_root_fp != pinned_fp:
        raise ValueError('Untrusted x5c Root CA: root certificate does not match pinned trust anchor')

    now = datetime.now(timezone.utc)
    for idx, cert in enumerate(certs):
        nvb = cert_not_valid_before_utc(cert)
        nva = cert_not_valid_after_utc(cert)
        if not (nvb <= now < nva):
            raise ValueError(f'Certificate at x5c[{idx}] is expired or not yet valid')
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if idx == 0 and bc.ca:
            raise ValueError('Leaf certificate at x5c[0] must not be a CA certificate')
        if idx > 0 and not bc.ca:
            raise ValueError(f'Issuer certificate at x5c[{idx}] must have BasicConstraints(ca=True)')

    for idx in range(len(certs) - 1):
        child = certs[idx]
        issuer = certs[idx + 1]
        if child.issuer != issuer.subject:
            raise ValueError(f'Certificate subject/issuer mismatch between x5c[{idx}] and x5c[{idx + 1}]')
        try:
            verify_cert_directly_issued_by(child, issuer)
        except Exception as exc:
            raise ValueError(f'Certificate signature verification failed at x5c[{idx}]') from exc

    verify_cert_directly_issued_by(certs[-1], trusted_root_ca_cert)
    leaf_pub = certs[0].public_key()
    if not isinstance(leaf_pub, ec.EllipticCurvePublicKey):
        raise ValueError('StoreKit 2 x5c[0] leaf certificate must hold an ECDSA public key')
    return leaf_pub


def verify_storekit2_sandbox_jws(
    jws_token: str,
    *,
    trusted_public_key: ec.EllipticCurvePublicKey | None = None,
    trusted_root_ca_cert: x509.Certificate | None = None,
) -> dict[str, Any]:
    """
    Cryptographically verify an ES256 StoreKit 2 JWS transaction token:
    - If the JWS header contains `x5c`, validates the full X.509 certificate chain against `trusted_root_ca_cert`
      and sets `payload['_trust_anchor'] = 'x5c_pinned_root_ca'`.
    - Otherwise, verifies against `trusted_public_key` (Lab internal sandbox key) and sets
      `payload['_trust_anchor'] = 'lab_internal_sandbox_key'` and `payload['_payment_trust_level'] = 'lab_simulated_jws'`.
    Raises `ValueError` on malformed structure, untrusted chain, bundleId/productId mismatch, or signature failure.
    """
    if not isinstance(jws_token, str) or jws_token.count('.') != 2:
        raise ValueError('StoreKit 2 JWS must contain exactly 3 dot-separated segments')

    h_b64, p_b64, s_b64 = jws_token.split('.')
    try:
        header = json.loads(_b64url_decode(h_b64).decode('utf-8'))
        payload = json.loads(_b64url_decode(p_b64).decode('utf-8'))
        raw_sig = _b64url_decode(s_b64)
    except Exception as exc:
        raise ValueError('Malformed base64url or JSON in StoreKit 2 JWS') from exc

    if not isinstance(header, dict) or header.get('alg') != 'ES256':
        raise ValueError('StoreKit 2 JWS must use ES256 algorithm')
    if len(raw_sig) != 64:
        raise ValueError('Invalid ES256 signature length (expected 64 bytes)')

    if 'x5c' in header:
        if trusted_root_ca_cert is None:
            raise ValueError('x5c certificate chain present in JWS, but no trusted_root_ca_cert is configured on server')
        verify_pub_key = _verify_x5c_certificate_chain(header['x5c'], trusted_root_ca_cert)
        trust_anchor = 'x5c_pinned_root_ca'
        payment_trust_level = 'x5c_chain_verified'
    elif trusted_public_key is not None:
        verify_pub_key = trusted_public_key
        trust_anchor = 'lab_internal_sandbox_key'
        payment_trust_level = 'lab_simulated_jws'
    else:
        raise ValueError('No trusted public key or Root CA provided to verify StoreKit 2 JWS')

    r = int.from_bytes(raw_sig[:32], 'big')
    s = int.from_bytes(raw_sig[32:], 'big')
    der_sig = encode_dss_signature(r, s)
    signing_input = f'{h_b64}.{p_b64}'.encode('ascii')

    try:
        verify_pub_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError('StoreKit 2 JWS cryptographic signature verification failed') from exc

    if not isinstance(payload, dict):
        raise ValueError('StoreKit 2 JWS payload must be a JSON object')

    bundle_id = str(payload.get('bundleId') or '')
    if bundle_id not in ALLOWED_BUNDLE_IDS:
        raise ValueError(f"Unauthorized StoreKit bundleId '{bundle_id}'")

    product_id = str(payload.get('productId') or '')
    if product_id not in SUPPORTED_GOLD_PRODUCTS:
        raise ValueError(f"Unsupported StoreKit productId '{product_id}'")

    env = str(payload.get('environment') or '')
    if env not in {'Sandbox', 'Xcode'}:
        raise ValueError(f"Only authorized 'Sandbox' or 'Xcode' StoreKit environments are accepted in Lab (got '{env}')")

    for req_field in ('transactionId', 'originalTransactionId', 'purchaseDate', 'expiresDate'):
        if req_field not in payload:
            raise ValueError(f"Missing required StoreKit 2 field '{req_field}'")

    payload['_trust_anchor'] = trust_anchor
    payload['_payment_trust_level'] = payment_trust_level
    return payload


def _get_tx_registry(app_state: Any) -> dict[str, dict[str, Any]]:
    reg = getattr(app_state, '_payment_tx_registry', None)
    if not isinstance(reg, dict):
        reg = {}
        setattr(app_state, '_payment_tx_registry', reg)
    return reg


def _get_webhook_event_registry(app_state: Any) -> dict[str, dict[str, Any]]:
    reg = getattr(app_state, '_webhook_event_registry', None)
    if not isinstance(reg, dict):
        reg = {}
        setattr(app_state, '_webhook_event_registry', reg)
    return reg


async def apply_verified_payment_state_to_ssot(
    request: Any,
    accounts_col: Any,
    *,
    app_user_id: str,
    product_id: str,
    transaction_id: str,
    original_transaction_id: str | None = None,
    purchase_dt: datetime,
    expires_dt: datetime,
    revoked_dt: datetime | None,
    environment: str,
    event_source: str,
    trust_anchor: str = 'lab_internal_sandbox_key',
    payment_trust_level: str = 'lab_simulated_jws',
    event_timestamp_ms: int | None = None,
) -> dict[str, Any]:
    """
    Synchronize a verified transaction or authenticated RevenueCat Webhook event into MongoDB SSOT:
    - Enforces cross-account transaction ownership binding: if `transaction_id` or `original_transaction_id`
      is already bound to a DIFFERENT `app_user_id`, raises `HTTP 409 Conflict` (prevents receipt replay theft).
    - Enforces monotonic event ordering: rejects stale out-of-order events (`event_timestamp_ms < last_payment_event_ms`).
    - Never marks an account as `verified_uid` / `_server_uid_proof = True` from a Lab-simulated JWS
      (`payment_trust_level == 'lab_simulated_jws'`); preserves honest `uid_assurance` and `grant_basis`.
    """
    if not FIREBASE_UID_RE.fullmatch(app_user_id):
        raise HTTPException(
            422,
            'Verified payment/subscription synchronization requires a canonical 28-character Firebase UID (app_user_id)',
        )

    orig_tx = (original_transaction_id or transaction_id or '').strip()
    tx_reg = _get_tx_registry(request.app.state)
    for tx_key in {k for k in (transaction_id.strip(), orig_tx) if k}:
        existing_binding = tx_reg.get(tx_key)
        if existing_binding and existing_binding.get('app_user_id') != app_user_id:
            raise HTTPException(
                409,
                f"Transaction '{tx_key}' is already bound to another account and cannot be replayed across accounts",
            )

    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    entitlements = getattr(request.app.state, 'entitlements', None)

    existing_v2 = None
    if accounts_v2 is not None and hasattr(accounts_v2, 'find_one'):
        for query_field in ('firebase_uid', 'locket_id'):
            res = accounts_v2.find_one({query_field: app_user_id}, {'_id': 0})
            if hasattr(res, '__await__'):
                res = await res
            if isinstance(res, dict):
                existing_v2 = res
                break

    now = datetime.now(timezone.utc)
    eff_event_ms = event_timestamp_ms if event_timestamp_ms is not None else int(now.timestamp() * 1000)
    prev_event_ms = int(existing_v2.get('last_payment_event_ms') or 0) if isinstance(existing_v2, dict) else 0
    if prev_event_ms and eff_event_ms < prev_event_ms:
        raise HTTPException(
            409,
            f'Stale out-of-order payment/webhook event ({eff_event_ms} < {prev_event_ms}) rejected',
        )

    for tx_key in {k for k in (transaction_id.strip(), orig_tx) if k}:
        tx_reg[tx_key] = {'app_user_id': app_user_id, 'updated_at_ms': eff_event_ms}

    if revoked_dt is not None:
        computed_status = 'revoked'
    elif expires_dt <= now:
        computed_status = 'expired'
    else:
        computed_status = 'active'

    target_locket_id = (
        existing_v2.get('locket_id')
        if isinstance(existing_v2, dict) and existing_v2.get('locket_id')
        else app_user_id
    )
    prev_rev = int(existing_v2.get('grant_revision') or 0) if isinstance(existing_v2, dict) else 0
    new_rev = prev_rev + 1

    # Honest UID Assurance & Grant Basis Policy:
    # A Lab self-signed JWS (`lab_simulated_jws`) NEVER forges `_server_uid_proof = True` or `verified_uid`.
    # Only preserve `_server_uid_proof = True` if the account already had independent server UID proof.
    already_verified = bool(existing_v2 and extract_verified_uid_metadata(existing_v2)[1])
    if already_verified:
        ver_status = 'verified_uid'
        ver_method = 'trusted_proof'
        ver_source = str(existing_v2.get('verification_source') or 'verified_subscriber_traffic')
        server_proof = True
        uid_assurance = 'independently_verified'
        grant_basis = 'independently_verified'
    else:
        ver_status = 'unverified_uid'
        ver_method = str(existing_v2.get('verification_method') or 'authenticated_lookup') if isinstance(existing_v2, dict) else 'direct_uid'
        ver_source = str(existing_v2.get('verification_source') or 'locket_public_share_link') if isinstance(existing_v2, dict) else 'locket_public_share_link'
        server_proof = False
        uid_assurance = 'public_derived'
        grant_basis = 'admin_authorized_public_uid'

    v2_updates: dict[str, Any] = {
        'schema_version': 2,
        'account_id': app_user_id,
        'locket_id': target_locket_id,
        'firebase_uid': app_user_id,
        'uid_verified': server_proof,
        'verification_status': ver_status,
        'verification_method': ver_method,
        'verification_source': ver_source,
        '_server_uid_proof': server_proof,
        'uid_resolution_status': 'found',
        'uid_source': 'verified_provider' if server_proof else 'public_share_link',
        'uid_assurance': uid_assurance,
        'grant_basis': grant_basis,
        'grant_revision': new_rev,
        'status': computed_status,
        'product_identifier': product_id if product_id in SUPPORTED_GOLD_PRODUCTS else 'com.locket.gold.yearly',
        'store_transaction_id': transaction_id,
        'original_transaction_id': orig_tx,
        'payment_environment': environment,
        'payment_trust_anchor': trust_anchor,
        'payment_trust_level': payment_trust_level,
        'last_payment_event': event_source,
        'last_payment_event_ms': eff_event_ms,
        'purchase_date': purchase_dt,
        'expires_date': expires_dt,
        'revoked_at': revoked_dt if computed_status == 'revoked' else None,
        'revoke_reason': f'Revoked via {event_source}' if computed_status == 'revoked' else None,
        'updated_at': now,
    }
    if not existing_v2 or not existing_v2.get('lab_features'):
        v2_updates['lab_features'] = dict(DEFAULT_ACTIVE_GOLD_FEATURES)

    if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
        res = accounts_v2.update_one({'locket_id': target_locket_id}, {'$set': v2_updates}, upsert=True)
        if hasattr(res, '__await__'):
            await res

    if accounts_col is not None and hasattr(accounts_col, 'update_one'):
        v1_updates = {
            'locket_id': target_locket_id,
            'firebase_uid': app_user_id,
            'verification_status': ver_status,
            'verification_method': ver_method,
            'verification_source': ver_source,
            '_server_uid_proof': server_proof,
            'grant_basis': grant_basis,
            'grant_revision': new_rev,
            'status': computed_status,
            'is_active': computed_status != 'revoked',
            'expires_date': expires_dt,
            'revoked_at': revoked_dt if computed_status == 'revoked' else None,
            'updated_at': now,
        }
        res_v1 = accounts_col.update_one({'locket_id': target_locket_id}, {'$set': v1_updates}, upsert=True)
        if hasattr(res_v1, '__await__'):
            await res_v1

    if entitlements is not None and hasattr(entitlements, 'update_one'):
        ent_doc = {
            'account_id': app_user_id,
            'locket_id': target_locket_id,
            'entitlement_key': 'Gold',
            'product_identifier': v2_updates['product_identifier'],
            'store_transaction_id': transaction_id,
            'original_transaction_id': orig_tx,
            'payment_environment': environment,
            'payment_trust_anchor': trust_anchor,
            'payment_trust_level': payment_trust_level,
            'status': computed_status,
            'grant_basis': grant_basis,
            'grant_revision': new_rev,
            'purchase_date': purchase_dt,
            'expires_date': expires_dt,
            'revoked_at': revoked_dt if computed_status == 'revoked' else None,
            'updated_at': now,
        }
        res_ent = entitlements.update_one(
            {'account_id': app_user_id, 'entitlement_key': 'Gold'},
            {'$set': ent_doc},
            upsert=True,
        )
        if hasattr(res_ent, '__await__'):
            await res_ent

    return {
        'locket_id': target_locket_id,
        'firebase_uid': app_user_id,
        'status': computed_status,
        'product_identifier': v2_updates['product_identifier'],
        'store_transaction_id': transaction_id,
        'original_transaction_id': orig_tx,
        'payment_environment': environment,
        'payment_trust_anchor': trust_anchor,
        'payment_trust_level': payment_trust_level,
        'uid_assurance': uid_assurance,
        'grant_basis': grant_basis,
        'grant_revision': new_rev,
        'purchase_date': purchase_dt.isoformat().replace('+00:00', 'Z'),
        'expires_date': expires_dt.isoformat().replace('+00:00', 'Z'),
        'revoked_at': revoked_dt.isoformat().replace('+00:00', 'Z') if revoked_dt else None,
    }
