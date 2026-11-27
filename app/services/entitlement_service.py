from datetime import datetime, timezone
import re
from fastapi import HTTPException
from ..models import (
    compute_entitlement_status,
    normalize_expiry,
)

FIREBASE_UID_RE = re.compile(r'^[A-Za-z0-9]{28}$')

# Trusted server-side verification sources that cannot be forged by raw Admin form input
SERVER_TRUSTED_UID_SOURCES = {
    'verified_subscriber_traffic',
    'firebase_admin_sdk',
    'cryptographic_id_token',
    'authorized_identity_provider',
    'owner_localid_match',
}


def merge_canonical_and_legacy_account(doc_v2: dict | None, doc_v1: dict | None) -> dict | None:
    """
    Canonical Account Merger (Single Source of Truth = `accounts_v2`, with legacy `accounts` fallback).
    Strict Precedence Rules:
    1. If only one document exists (`doc_v2` or `doc_v1`), return a copy of that document.
    2. Status Precedence:
       - If EITHER `doc_v2` or `doc_v1` is explicitly `'revoked'` (or `revoked_at` is set or `is_active is False`),
         the merged status is `'revoked'` (fail-closed revocation).
       - Else if `doc_v2` has `status == 'pending'`, the merged status is `'pending'`.
    3. Expiry Date Precedence (`accounts_v2` Canonical Authority):
       - When `doc_v2` exists and has a valid `expires_date`, `doc_v2['expires_date']` is ALWAYS authoritative.
         An older or different `expires_date` in legacy `doc_v1` MUST NEVER overwrite `doc_v2['expires_date']`.
       - Legacy `doc_v1['expires_date']` is used ONLY as a fallback when `doc_v2` has no valid `expires_date`.
    """
    if doc_v2 is None and doc_v1 is None:
        return None
    if doc_v2 is not None and doc_v1 is None:
        return doc_v2.copy()
    if doc_v1 is not None and doc_v2 is None:
        legacy_copy = doc_v1.copy()
        # Prevent legacy username-only fallback records from granting active Gold without verified UID proof
        if 'verification_status' not in legacy_copy and '_server_uid_proof' not in legacy_copy:
            lid_val = str(legacy_copy.get('locket_id') or legacy_copy.get('account_id') or '')
            if not FIREBASE_UID_RE.fullmatch(lid_val):
                legacy_copy['verification_status'] = 'unverified_handle'
                legacy_copy['_server_uid_proof'] = False
        return legacy_copy

    assert isinstance(doc_v2, dict) and isinstance(doc_v1, dict)
    # Start with legacy fields, then overlay canonical accounts_v2 fields so v2 always wins
    merged = {**doc_v1, **doc_v2}

    v2_status = str(doc_v2.get('status') or '').lower()
    v1_status = str(doc_v1.get('status') or '').lower()
    if v2_status == 'revoked' or doc_v2.get('revoked_at') is not None or doc_v2.get('is_active') is False:
        merged['status'] = 'revoked'
        merged['revoked_at'] = doc_v2.get('revoked_at')
        merged['revoke_reason'] = doc_v2.get('revoke_reason')
    elif v1_status == 'revoked' or doc_v1.get('revoked_at') is not None or doc_v1.get('is_active') is False:
        merged['status'] = 'revoked'
        merged['revoked_at'] = doc_v1.get('revoked_at')
        merged['revoke_reason'] = doc_v1.get('revoke_reason')
    elif v2_status == 'pending':
        merged['status'] = 'pending'

    # Canonical Expiry Precedence: doc_v2['expires_date'] is authoritative whenever valid
    v2_raw_exp = doc_v2.get('expires_date') if 'expires_date' in doc_v2 else (
        doc_v2.get('expires_at') or doc_v2.get('gold_expires_at')
    )
    v2_expiry = None
    if v2_raw_exp is not None:
        try:
            v2_expiry = normalize_expiry(v2_raw_exp)
        except (ValueError, TypeError):
            v2_expiry = None

    if v2_expiry is not None:
        merged['expires_date'] = v2_expiry
    elif 'expires_date' in doc_v1 and doc_v1['expires_date'] is not None:
        merged['expires_date'] = doc_v1['expires_date']

    return merged


def extract_verified_uid_metadata(record: dict) -> tuple[str | None, bool, str, str, str]:
    """
    Inspect a database account record and determine its honest UID & verification state:
    Returns `(firebase_uid, uid_verified, verification_status, verification_method, verification_source)`.
    Security Invariant:
    - Never marks a 28-char string as `verified_uid` based on regex length or admin-submitted metadata.
    - Requires `_server_uid_proof == True` AND `verification_source in SERVER_TRUSTED_UID_SOURCES`
      alongside `verification_status == 'verified_uid'` and `verification_method == 'trusted_proof'`.
    - Otherwise, any 28-char UID string is classified honestly as `unverified_uid` (`uid_verified=False`).
    """
    lid = str(record.get('locket_id') or record.get('account_id') or '')
    explicit_uid = record.get('firebase_uid') or record.get('verified_uid')
    candidate_uid = None
    if isinstance(explicit_uid, str) and explicit_uid.strip():
        candidate_uid = explicit_uid.strip()
    elif FIREBASE_UID_RE.fullmatch(lid):
        candidate_uid = lid

    rec_status = record.get('verification_status')
    rec_method = record.get('verification_method')
    rec_source = record.get('verification_source')
    has_server_proof = record.get('_server_uid_proof') is True

    if (
        candidate_uid is not None and FIREBASE_UID_RE.fullmatch(candidate_uid)
        and has_server_proof
        and rec_status == 'verified_uid'
        and rec_method == 'trusted_proof'
        and rec_source in SERVER_TRUSTED_UID_SOURCES
    ):
        return (
            candidate_uid,
            True,
            'verified_uid',
            'trusted_proof',
            str(rec_source),
        )

    if candidate_uid is not None:
        eff_method = (
            str(rec_method)
            if rec_method in {'authenticated_lookup', 'format_only_uid', 'direct_uid'}
            else 'format_only_uid'
        )
        eff_source = (
            str(rec_source)
            if isinstance(rec_source, str) and rec_source.strip() and rec_source != 'admin_direct_input'
            else ('admin_manual_input' if not has_server_proof else str(rec_source or 'db_stored_unverified_uid'))
        )
        return (
            candidate_uid,
            False,
            'unverified_uid',
            eff_method,
            eff_source,
        )

    if record.get('username') or rec_status == 'unverified_handle':
        return (
            None,
            False,
            'unverified_handle',
            'link_handle_only',
            str(rec_source or 'db_username_only'),
        )

    return (
        None,
        False,
        rec_status if rec_status in {'unverified_uid', 'unverified_handle', 'manual_lab_id'} else 'manual_lab_id',
        rec_method if rec_method in {'format_only_uid', 'link_handle_only', 'admin_manual_override'} else 'admin_manual_override',
        str(rec_source or 'admin_direct_input'),
    )


def format_account_record(record: dict, now: datetime | None = None) -> dict:
    """Normalize a raw MongoDB account document (from accounts or accounts_v2) into AccountOutput dict."""
    now = now if now is not None else datetime.now(timezone.utc)
    status, expiry = compute_entitlement_status(record, now)
    if expiry is None:
        raw_exp = record.get('expires_date') or record.get('expires_at') or record.get('gold_expires_at')
        try:
            expiry = normalize_expiry(raw_exp) if raw_exp else datetime.fromtimestamp(0, tz=timezone.utc)
        except (ValueError, TypeError):
            expiry = datetime.fromtimestamp(0, tz=timezone.utc)

    fb_uid, _, ver_status, ver_method, ver_source = extract_verified_uid_metadata(record)
    return {
        'locket_id': str(record.get('locket_id') or record.get('account_id') or ''),
        'expires_date': expiry,
        'status': status,
        'username': record.get('username'),
        'invite_token': record.get('invite_token'),
        'firebase_uid': fb_uid,
        'source_link': record.get('source_link'),
        'verification_status': ver_status,
        'verification_method': ver_method,
        'verification_source': ver_source,
        'identity_lookup_source': record.get('identity_lookup_source') or record.get('uid_resolution_source'),
        'identity_lookup_at': record.get('identity_lookup_at') or record.get('uid_resolved_at'),
        'uid_resolved_at': record.get('uid_resolved_at'),
        'uid_resolution_source': record.get('uid_resolution_source'),
        'resolution_status': record.get('resolution_status'),
        'max_devices': int(record.get('max_devices') or 2),
        'activated_at': record.get('activated_at'),
        'revoked_at': record.get('revoked_at'),
        'revoke_reason': record.get('revoke_reason'),
        'notes': record.get('notes'),
        'updated_at': record.get('updated_at'),
    }


async def find_canonical_account(request, account_id: str, accounts_col=None) -> dict | None:
    """
    Look up an account across canonical `accounts_v2` and legacy `accounts` collection
    by `locket_id`, `username`, or `firebase_uid`.
    Never swallows PyMongoError — database failures propagate and fail closed with HTTP 503.
    """
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    accounts = accounts_col if accounts_col is not None else getattr(request.app.state, 'accounts', None)

    doc_v2 = None
    if accounts_v2 is not None and hasattr(accounts_v2, 'find_one'):
        res = accounts_v2.find_one({'locket_id': account_id}, {'_id': 0})
        if hasattr(res, '__await__'):
            res = await res
        if isinstance(res, dict):
            doc_v2 = res
        else:
            for field in ('username', 'firebase_uid', 'invite_token'):
                try:
                    res_alt = accounts_v2.find_one({field: account_id}, {'_id': 0})
                    if hasattr(res_alt, '__await__'):
                        res_alt = await res_alt
                    if isinstance(res_alt, dict):
                        doc_v2 = res_alt
                        break
                except KeyError:
                    continue

    doc_v1 = None
    if accounts is not None and hasattr(accounts, 'find_one'):
        target_v1_id = doc_v2.get('locket_id', account_id) if isinstance(doc_v2, dict) else account_id
        res = accounts.find_one({'locket_id': target_v1_id}, {'_id': 0})
        if hasattr(res, '__await__'):
            res = await res
        if isinstance(res, dict):
            doc_v1 = res

    return merge_canonical_and_legacy_account(doc_v2, doc_v1)


async def effective_gold_account(request, account, account_id: str, now: datetime):
    """Resolve the Gold grant shared by the admin dashboard and lab APIs."""
    if not account:
        return None
    uid, verified, *_ = extract_verified_uid_metadata(account)
    grant = None
    if verified:
        collection = getattr(request.app.state, 'entitlements', None)
        if collection is None:
            raise HTTPException(503, 'Entitlement lookup unavailable')
        try:
            grant = await collection.find_one({'account_id': uid, 'entitlement_key': 'Gold'}, {'_id': 0})
        except Exception as exc:
            raise HTTPException(503, 'Entitlement lookup unavailable') from exc
    return evaluate_gold_record(account, account_id, grant, now)


def evaluate_gold_record(account, requested_id, grant, now):
    """Intersect account and grant states and return a record usable by the lab response formatter."""
    record = {**account, 'grace_period_expires_date': None}
    uid, verified, *_ = extract_verified_uid_metadata(record)
    if verified and requested_id != uid:
        return None
    account_status, account_expiry = compute_entitlement_status(record, now)
    if account_status == 'revoked':
        return record
    if record.get('status') == 'expired' or account_status == 'expired':
        return {**record, 'expires_date': min(account_expiry or now, now)}
    if not verified or record.get('status') != 'active':
        return {**record, 'status': 'pending'}
    if (not isinstance(grant, dict) or grant.get('account_id') != uid or grant.get('entitlement_key') != 'Gold'
            or grant.get('locket_id', record.get('locket_id')) != record.get('locket_id')
            or grant.get('grant_revision') != record.get('grant_revision')):
        return {**record, 'status': 'pending'}
    grant_status, expiry = compute_entitlement_status({**grant, 'grace_period_expires_date': None}, now)
    if grant_status == 'revoked':
        return {**record, 'status': 'revoked', 'revoked_at': grant.get('revoked_at') or now}
    if grant.get('status') == 'expired' or grant_status == 'expired':
        return {**record, 'expires_date': min(expiry or now, now)}
    if grant.get('status') != 'active' or grant_status != 'active' or account_status != 'active':
        return {**record, 'status': 'pending'}
    return {**record, 'expires_date': min(account_expiry, expiry)}
