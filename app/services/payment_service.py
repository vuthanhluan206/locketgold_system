"""
StoreKit 2 JWS Transaction Verification & RevenueCat Webhook Synchronization Service (`app/services/payment_service.py`).

Implements cryptographic verification of StoreKit 2 signed transactions (RFC 7515 JWS with ES256 / ECDSA P-256)
for authorized Sandbox / Xcode StoreKit Testing environments, and synchronizes verified subscription states
(`INITIAL_PURCHASE`, `RENEWAL`, `RESTORE`, `EXPIRATION`, `CANCELLATION` / `REVOKE`) with the MongoDB Single Source of Truth.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Literal
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from fastapi import HTTPException

from ..models import DEFAULT_ACTIVE_GOLD_FEATURES, normalize_expiry
from .entitlement_service import FIREBASE_UID_RE

SUPPORTED_GOLD_PRODUCTS = {
    'com.locket.gold.yearly',
    'locket_1600_1y',
    'locket_gold_annual',
    'com.locket.gold.monthly',
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(segment: str) -> bytes:
    clean = segment.strip()
    pad = '=' * (-len(clean) % 4)
    return base64.urlsafe_b64decode(clean + pad)


def get_or_create_sandbox_storekit_key(app_state: Any) -> ec.EllipticCurvePrivateKey:
    """Return a per-process ephemeral ECDSA P-256 keypair used for signing authorized Lab StoreKit 2 Sandbox JWS tokens."""
    key = getattr(app_state, '_sandbox_storekit_ec_key', None)
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
        setattr(app_state, '_sandbox_storekit_ec_key', key)
    return key


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
    environment: Literal['Sandbox', 'Xcode'] = 'Sandbox',
    bundle_id: str = 'com.locket.Locket',
) -> tuple[str, dict[str, Any]]:
    """
    Create a cryptographically signed RFC 7515 ES256 (ECDSA P-256) StoreKit 2 JWS transaction token
    matching Apple's `JWSTransactionDecodedPayload` structure for Sandbox/StoreKit testing.
    """
    now = datetime.now(timezone.utc)
    p_dt = purchase_date or now
    e_dt = expires_date or (now + timedelta(days=365))
    tx_id = transaction_id or f'2000000{int(now.timestamp() * 1000) % 1000000000:09d}'
    orig_tx_id = original_transaction_id or tx_id

    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = hashlib.sha256(pub_der).hexdigest()[:16]

    header = {
        'alg': 'ES256',
        'kid': kid,
        'typ': 'JWT',
        'x5u_spki_b64': _b64url_encode(pub_der),
    }
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
        'signedDate': int(now.timestamp() * 1000),
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


def verify_storekit2_sandbox_jws(
    jws_token: str,
    *,
    trusted_public_key: ec.EllipticCurvePublicKey,
) -> dict[str, Any]:
    """
    Cryptographically verify an ES256 StoreKit 2 JWS transaction token against `trusted_public_key`.
    Raises `ValueError` on malformed structure, algorithm mismatch, or signature verification failure.
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

    r = int.from_bytes(raw_sig[:32], 'big')
    s = int.from_bytes(raw_sig[32:], 'big')
    der_sig = encode_dss_signature(r, s)
    signing_input = f'{h_b64}.{p_b64}'.encode('ascii')

    try:
        trusted_public_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError('StoreKit 2 JWS cryptographic signature verification failed') from exc

    if not isinstance(payload, dict):
        raise ValueError('StoreKit 2 JWS payload must be a JSON object')

    product_id = str(payload.get('productId') or '')
    if product_id not in SUPPORTED_GOLD_PRODUCTS:
        raise ValueError(f"Unsupported StoreKit productId '{product_id}'")

    env = str(payload.get('environment') or '')
    if env not in {'Sandbox', 'Xcode'}:
        raise ValueError(f"Only authorized 'Sandbox' or 'Xcode' StoreKit environments are accepted in Lab (got '{env}')")

    for req_field in ('transactionId', 'originalTransactionId', 'purchaseDate', 'expiresDate'):
        if req_field not in payload:
            raise ValueError(f"Missing required StoreKit 2 field '{req_field}'")

    return payload


async def apply_verified_payment_state_to_ssot(
    request: Any,
    accounts_col: Any,
    *,
    app_user_id: str,
    product_id: str,
    transaction_id: str,
    purchase_dt: datetime,
    expires_dt: datetime,
    revoked_dt: datetime | None,
    environment: str,
    event_source: str,
) -> dict[str, Any]:
    """
    Synchronize a cryptographically verified StoreKit 2 transaction or authenticated RevenueCat Webhook event
    into the MongoDB Single Source of Truth (`accounts_v2`, `accounts`, `entitlements`).
    Requires a valid 28-character Firebase UID (`app_user_id`) so entitlements are strictly UID-bound.
    """
    if not FIREBASE_UID_RE.fullmatch(app_user_id):
        raise HTTPException(
            422,
            'Verified payment/subscription synchronization requires a canonical 28-character Firebase UID (app_user_id)',
        )

    now = datetime.now(timezone.utc)
    if revoked_dt is not None:
        computed_status = 'revoked'
    elif expires_dt <= now:
        computed_status = 'expired'
    else:
        computed_status = 'active'

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

    target_locket_id = existing_v2.get('locket_id') if isinstance(existing_v2, dict) and existing_v2.get('locket_id') else app_user_id
    prev_rev = int(existing_v2.get('grant_revision') or 0) if isinstance(existing_v2, dict) else 0
    new_rev = prev_rev + 1

    v2_updates: dict[str, Any] = {
        'schema_version': 2,
        'account_id': app_user_id,
        'locket_id': target_locket_id,
        'firebase_uid': app_user_id,
        'uid_verified': True,
        'verification_status': 'verified_uid',
        'verification_method': 'trusted_proof',
        'verification_source': 'verified_subscriber_traffic',
        '_server_uid_proof': True,
        'uid_resolution_status': 'found',
        'uid_source': 'verified_provider',
        'uid_assurance': 'independently_verified',
        'grant_basis': 'independently_verified',
        'grant_revision': new_rev,
        'status': computed_status,
        'product_identifier': product_id if product_id in SUPPORTED_GOLD_PRODUCTS else 'com.locket.gold.yearly',
        'store_transaction_id': transaction_id,
        'payment_environment': environment,
        'last_payment_event': event_source,
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
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'verified_subscriber_traffic',
            '_server_uid_proof': True,
            'grant_basis': 'independently_verified',
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
            'payment_environment': environment,
            'status': computed_status,
            'grant_basis': 'independently_verified',
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
        'payment_environment': environment,
        'grant_basis': 'independently_verified',
        'grant_revision': new_rev,
        'purchase_date': purchase_dt.isoformat().replace('+00:00', 'Z'),
        'expires_date': expires_dt.isoformat().replace('+00:00', 'Z'),
        'revoked_at': revoked_dt.isoformat().replace('+00:00', 'Z') if revoked_dt else None,
    }
