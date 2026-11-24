import hashlib
import secrets
from datetime import datetime, timezone
from fastapi import HTTPException
from ..models import DeviceCreateInput


def hash_device_token(token: str) -> str:
    return hashlib.sha256(token.encode('ascii')).hexdigest()


async def enroll_device(request, data: DeviceCreateInput) -> dict:
    """Link an iOS test device to an account in the Lab and issue a device enrollment token."""
    devices = getattr(request.app.state, 'devices', None)
    accounts = getattr(request.app.state, 'accounts', None)
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if devices is None:
        raise HTTPException(503, 'Device service unavailable')

    account = None
    if accounts_v2 is not None:
        res = await accounts_v2.find_one({'locket_id': data.locket_id}, {'_id': 0})
        if isinstance(res, dict):
            account = res
    if account is None and accounts is not None:
        res = await accounts.find_one({'locket_id': data.locket_id}, {'_id': 0})
        if isinstance(res, dict):
            account = res
    if account is None:
        raise HTTPException(404, 'Account not found')

    max_devices = int(account.get('max_devices') or 2)
    cursor = devices.find({'locket_id': data.locket_id, 'status': 'active'}, {'_id': 0})
    active_devices = await cursor.to_list(length=max_devices + 1)
    if len(active_devices) >= max_devices:
        raise HTTPException(409, f'Account reached maximum active devices limit ({max_devices})')

    now = datetime.now(timezone.utc)
    device_id = 'dev_' + secrets.token_hex(6)
    raw_token = 'lkg_dev_' + secrets.token_urlsafe(32)
    token_prefix = raw_token[:16]

    doc = {
        'device_id': device_id,
        'locket_id': data.locket_id,
        'device_name': data.device_name,
        'ios_version': data.ios_version,
        'token_hash': hash_device_token(raw_token),
        'token_prefix': token_prefix,
        'status': 'active',
        'created_at': now,
        'last_seen_at': None,
        'revoked_at': None,
    }
    await devices.insert_one(doc.copy())
    return {**doc, 'device_token': raw_token}


async def verify_device_token(request, raw_token: str) -> dict | None:
    """Verify a device token (lkg_dev_*) against active devices in MongoDB."""
    if not raw_token.startswith('lkg_dev_') or not raw_token.isascii():
        return None
    devices = getattr(request.app.state, 'devices', None)
    if devices is None:
        return None
    digest = hash_device_token(raw_token)
    doc = await devices.find_one({'token_hash': digest}, {'_id': 0})
    if not isinstance(doc, dict) or doc.get('status') != 'active' or doc.get('revoked_at') is not None:
        return None
    now = datetime.now(timezone.utc)
    try:
        await devices.update_one({'device_id': doc['device_id']}, {'$set': {'last_seen_at': now}})
    except Exception:
        pass
    return doc
