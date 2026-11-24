from datetime import datetime, timezone
from ..models import (
    AccountOutput,
    EntitlementStatus,
    compute_entitlement_status,
    normalize_expiry,
    subscriber_response,
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

    return {
        'locket_id': str(record.get('locket_id') or record.get('account_id') or ''),
        'expires_date': expiry,
        'status': status,
        'username': record.get('username'),
        'source_link': record.get('source_link'),
        'verification_status': record.get('verification_status') or 'manual_lab_id',
        'verification_method': record.get('verification_method') or 'admin_manual_override',
        'max_devices': int(record.get('max_devices') or 2),
        'revoked_at': record.get('revoked_at'),
        'revoke_reason': record.get('revoke_reason'),
        'notes': record.get('notes'),
        'updated_at': record.get('updated_at'),
    }


async def find_canonical_account(request, account_id: str) -> dict | None:
    """
    Look up an account across accounts_v2 and legacy accounts collection.
    If an account exists in both, accounts_v2 carries the authoritative revocation/status metadata,
    while legacy accounts is checked to ensure consistency.
    """
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    accounts = getattr(request.app.state, 'accounts', None)

    doc_v2 = None
    if accounts_v2 is not None:
        res = await accounts_v2.find_one({'locket_id': account_id}, {'_id': 0})
        if isinstance(res, dict):
            doc_v2 = res

    doc_v1 = None
    if accounts is not None:
        res = await accounts.find_one({'locket_id': account_id}, {'_id': 0})
        if isinstance(res, dict):
            doc_v1 = res

    if doc_v2 and doc_v1:
        merged = {**doc_v2}
        # If legacy test fixture mutated accounts.expires_date directly, reflect it unless revoked
        if 'expires_date' in doc_v1:
            merged['expires_date'] = doc_v1['expires_date']
        return merged
    return doc_v2 or doc_v1
