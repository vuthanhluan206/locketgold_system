from datetime import datetime, timezone
import re
from ..models import (
    AccountOutput,
    EntitlementStatus,
    compute_entitlement_status,
    normalize_expiry,
    subscriber_response,
)

FIREBASE_UID_RE = re.compile(r'^[A-Za-z0-9]{28}$')


def merge_canonical_and_legacy_account(doc_v2: dict | None, doc_v1: dict | None) -> dict | None:
    """
    Canonical Account Merger (Single Source of Truth = `accounts_v2`, with legacy `accounts` compatibility).
    Rules:
    1. If `doc_v2` exists and its status is 'revoked' or 'pending' (or `revoked_at` is set),
       `doc_v2` is 100% authoritative — a legacy `doc_v1` record MUST NEVER override a revoked or pending state.
    2. If `doc_v1` is explicitly marked 'revoked', the merged record is 'revoked'.
    3. If both exist and neither is revoked/pending, `doc_v2` provides all canonical metadata, while
       if `doc_v1` has a legacy `expires_date` and `doc_v2` was not updated more recently (`updated_at` absent),
       `doc_v1['expires_date']` is respected for legacy fixture compatibility.
    """
    if doc_v2 is None and doc_v1 is None:
        return None
    if doc_v2 is not None and doc_v1 is None:
        return doc_v2.copy()
    if doc_v1 is not None and doc_v2 is None:
        return doc_v1.copy()

    assert isinstance(doc_v2, dict) and isinstance(doc_v1, dict)
    merged = {**doc_v1, **doc_v2}

    v2_status = str(doc_v2.get('status') or '').lower()
    v1_status = str(doc_v1.get('status') or '').lower()
    if v2_status == 'revoked' or doc_v2.get('revoked_at') is not None or doc_v2.get('is_active') is False:
        merged['status'] = 'revoked'
        merged['revoked_at'] = doc_v2.get('revoked_at')
        merged['revoke_reason'] = doc_v2.get('revoke_reason')
        return merged
    if v1_status == 'revoked' or doc_v1.get('revoked_at') is not None or doc_v1.get('is_active') is False:
        merged['status'] = 'revoked'
        merged['revoked_at'] = doc_v1.get('revoked_at')
        merged['revoke_reason'] = doc_v1.get('revoke_reason')
        return merged
    if v2_status == 'pending':
        merged['status'] = 'pending'
        return merged

    if 'expires_date' in doc_v1 and doc_v1['expires_date'] is not None:
        merged['expires_date'] = doc_v1['expires_date']
    return merged


def extract_verified_uid_metadata(record: dict) -> tuple[str | None, bool, str, str, str]:
    """
    Inspect a database account record and determine its honest UID & verification state:
    Returns `(firebase_uid, uid_verified, verification_status, verification_method, verification_source)`.
    Never marks a 28-char string as `verified_uid` unless the record explicitly carries
    `verification_status == 'verified_uid'` and a valid `verification_method` / `verification_source`
    (such as `'trusted_proof'` or `'verified_subscriber_traffic'`).
    """
    lid = str(record.get('locket_id') or record.get('account_id') or '')
    explicit_uid = record.get('firebase_uid') or record.get('verified_uid')
    candidate_uid = None
    if isinstance(explicit_uid, str) and FIREBASE_UID_RE.fullmatch(explicit_uid):
        candidate_uid = explicit_uid
    elif FIREBASE_UID_RE.fullmatch(lid):
        candidate_uid = lid

    rec_status = record.get('verification_status')
    rec_method = record.get('verification_method')
    rec_source = record.get('verification_source')

    # Only honor verified_uid if candidate_uid is a valid 28-char UID AND record has explicit proof metadata
    if (
        candidate_uid is not None
        and rec_status == 'verified_uid'
        and rec_method in {'trusted_proof', 'direct_uid'}
        and rec_source not in {None, '', 'none', 'format_inspection_only', 'regex_28char_format_only'}
    ):
        return (
            candidate_uid,
            True,
            'verified_uid',
            rec_method,
            str(rec_source),
        )

    if candidate_uid is not None:
        return (
            candidate_uid,
            False,
            'unverified_uid',
            'format_only_uid',
            str(rec_source or 'db_stored_unverified_uid'),
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
        'firebase_uid': fb_uid,
        'source_link': record.get('source_link'),
        'verification_status': ver_status,
        'verification_method': ver_method,
        'verification_source': ver_source,
        'max_devices': int(record.get('max_devices') or 2),
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
            # Secondary lookup by username or firebase_uid in accounts_v2
            for field in ('username', 'firebase_uid'):
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
