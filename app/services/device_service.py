import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError
from ..models import DeviceCreateInput

_ENROLL_LOCKS: dict[str, asyncio.Lock] = {}
PROFILE_TICKET_TTL_SECONDS = 300


def hash_device_token(token: str) -> str:
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def _get_account_lock(locket_id: str) -> asyncio.Lock:
    lock = _ENROLL_LOCKS.get(locket_id)
    if lock is None:
        lock = asyncio.Lock()
        _ENROLL_LOCKS[locket_id] = lock
    return lock


async def enroll_device(request, data: DeviceCreateInput) -> dict:
    """
    Link an iOS test device to an account in the Lab and issue a device enrollment token.
    Enforces atomic concurrency protection against exceeding `max_devices`:
    1. Per-account `asyncio.Lock` serializes concurrent requests within the worker.
    2. Assigns a bounded `slot_index` in `0 .. max_devices - 1` backed by the MongoDB unique index
       `[('locket_id', 1), ('slot_index', 1)]`, plus post-insert count verification so concurrent
       calls across processes can never exceed `max_devices`.
    """
    devices = getattr(request.app.state, 'devices', None)
    accounts = getattr(request.app.state, 'accounts', None)
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if devices is None:
        raise HTTPException(503, 'Device service unavailable')

    async with _get_account_lock(data.locket_id):
        account = None
        if accounts_v2 is not None:
            res = await accounts_v2.find_one({'locket_id': data.locket_id}, {'_id': 0})
            if isinstance(res, dict):
                account = res
            else:
                for alt_field in ('firebase_uid', 'username', 'account_id'):
                    try:
                        res_alt = accounts_v2.find_one({alt_field: data.locket_id}, {'_id': 0})
                        if hasattr(res_alt, '__await__'):
                            res_alt = await res_alt
                        if isinstance(res_alt, dict):
                            account = res_alt
                            break
                    except KeyError:
                        continue
        if account is None and accounts is not None:
            res = await accounts.find_one({'locket_id': data.locket_id}, {'_id': 0})
            if isinstance(res, dict):
                account = res
        if account is None:
            raise HTTPException(404, 'Account not found')

        max_devices = int(account.get('max_devices') or 2)
        cursor = devices.find({'locket_id': data.locket_id, 'status': 'active'}, {'_id': 0})
        active_devices = await cursor.to_list(length=max_devices + 5)
        active_list = [d for d in (active_devices if isinstance(active_devices, list) else []) if isinstance(d, dict)]
        if len(active_list) >= max_devices:
            raise HTTPException(409, f'Account reached maximum active devices limit ({max_devices})')

        used_slots: set[int] = {
            d['slot_index']
            for d in active_list
            if isinstance(d.get('slot_index'), int) and not isinstance(d.get('slot_index'), bool)
        }
        # Backfill deterministic slot_index for any active legacy device missing slot_index
        for legacy_dev in active_list:
            if not isinstance(legacy_dev.get('slot_index'), int) or isinstance(legacy_dev.get('slot_index'), bool):
                for candidate_slot in range(max_devices):
                    if candidate_slot not in used_slots:
                        used_slots.add(candidate_slot)
                        if hasattr(devices, 'update_one') and legacy_dev.get('device_id'):
                            upd = devices.update_one(
                                {'device_id': legacy_dev['device_id'], 'status': 'active'},
                                {'$set': {'slot_index': candidate_slot}},
                            )
                            if hasattr(upd, '__await__'):
                                await upd
                        break

        chosen_slot = None
        for slot in range(max_devices):
            if slot not in used_slots:
                chosen_slot = slot
                break
        if chosen_slot is None:
            raise HTTPException(409, f'Account reached maximum active devices limit ({max_devices})')

        now = datetime.now(timezone.utc)
        device_id = 'dev_' + secrets.token_hex(6)
        raw_token = 'lkg_dev_' + secrets.token_urlsafe(32)
        token_hash = hash_device_token(raw_token)
        token_prefix = raw_token[:16]

        doc = {
            'device_id': device_id,
            'locket_id': data.locket_id,
            'canonical_locket_id': account.get('locket_id') or data.locket_id,
            'firebase_uid': account.get('firebase_uid'),
            'slot_index': chosen_slot,
            'device_name': data.device_name,
            'ios_version': data.ios_version,
            'token_hash': token_hash,
            'token_prefix': token_prefix,
            'status': 'active',
            'created_at': now,
            'last_seen_at': None,
            'revoked_at': None,
        }
        try:
            await devices.insert_one(doc.copy())
        except DuplicateKeyError as exc:
            raise HTTPException(409, f'Account reached maximum active devices limit ({max_devices})') from exc

        # Post-insert verification in case an external process inserted concurrently without slot_index.
        # Rollback strictly targets only the newly created (device_id, token_hash) from this request.
        verify_cur = devices.find({'locket_id': data.locket_id, 'status': 'active'}, {'_id': 0})
        after_list = await verify_cur.to_list(length=max_devices + 5)
        if isinstance(after_list, list) and len(after_list) > max_devices:
            if hasattr(devices, 'delete_one'):
                del_res = devices.delete_one({'device_id': device_id, 'token_hash': token_hash})
                if hasattr(del_res, '__await__'):
                    await del_res
            raise HTTPException(409, f'Account reached maximum active devices limit ({max_devices})')

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


async def issue_profile_download_ticket(
    request,
    *,
    device_doc: dict,
    mode: str = 'scoped_lab',
    ttl_seconds: int = PROFILE_TICKET_TTL_SECONDS,
) -> dict:
    """
    Issue a short-lived, single-use download ticket (`lkg_dl_*`) for Safari `.mobileconfig` downloads
    so long-lived Bearer/device tokens never appear in URLs, browser history, or access logs.
    Requires MongoDB `download_tickets` collection (fail-closed; no multi-worker inconsistent in-memory fallback).
    """
    if not isinstance(device_doc, dict) or device_doc.get('status') != 'active':
        raise HTTPException(401, 'Device is not active')
    tickets_col = getattr(request.app.state, 'download_tickets', None)
    if tickets_col is None or not hasattr(tickets_col, 'insert_one'):
        raise HTTPException(503, 'Download ticket storage unavailable')

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max(30, min(ttl_seconds, 900)))
    raw_ticket = 'lkg_dl_' + secrets.token_urlsafe(24)
    ticket_hash = hash_device_token(raw_ticket)

    ticket_doc = {
        'ticket_hash': ticket_hash,
        'device_id': device_doc['device_id'],
        'locket_id': device_doc['locket_id'],
        'mode': mode,
        'created_at': now,
        'expires_at': expires_at,
    }
    res = tickets_col.insert_one(ticket_doc.copy())
    if hasattr(res, '__await__'):
        await res

    return {
        'download_ticket': raw_ticket,
        'device_id': device_doc['device_id'],
        'locket_id': device_doc['locket_id'],
        'mode': mode,
        'expires_at': expires_at,
        'download_url': f'/profile.mobileconfig?mode={mode}&ticket={raw_ticket}',
    }


async def consume_profile_download_ticket(
    request,
    raw_ticket: str,
    *,
    requested_mode: str | None = None,
) -> dict:
    """
    Atomically consume a single-use profile download ticket (`lkg_dl_*`).
    Rejects malformed, expired, already-used (replay), or revoked-device tickets with HTTP 401.
    Enforces strict ticket mode binding: if the client passes a `requested_mode` different from the
    ticket's authorized `mode`, rejects with HTTP 403 (prevents URL mode tampering / privilege escalation).
    """
    if not isinstance(raw_ticket, str) or not raw_ticket.startswith('lkg_dl_') or not raw_ticket.isascii():
        raise HTTPException(401, 'Mã tải cấu hình (download ticket) không hợp lệ.')
    tickets_col = getattr(request.app.state, 'download_tickets', None)
    if tickets_col is None:
        raise HTTPException(503, 'Download ticket storage unavailable')

    now = datetime.now(timezone.utc)
    ticket_hash = hash_device_token(raw_ticket)

    ticket_doc = None
    if hasattr(tickets_col, 'find_one_and_delete'):
        res = tickets_col.find_one_and_delete({'ticket_hash': ticket_hash})
        ticket_doc = await res if hasattr(res, '__await__') else res
    elif hasattr(tickets_col, 'find_one'):
        res = tickets_col.find_one({'ticket_hash': ticket_hash})
        doc = await res if hasattr(res, '__await__') else res
        if isinstance(doc, dict):
            del_res = tickets_col.delete_one({'ticket_hash': ticket_hash})
            if hasattr(del_res, '__await__'):
                await del_res
            ticket_doc = doc

    if not isinstance(ticket_doc, dict):
        raise HTTPException(401, 'Mã tải cấu hình không tồn tại hoặc đã được sử dụng (one-time ticket).')

    exp = ticket_doc.get('expires_at')
    if not isinstance(exp, datetime) or exp <= now:
        raise HTTPException(401, 'Mã tải cấu hình đã hết hạn.')

    # Enforce strict mode binding so a ticket issued for dns_only cannot be escalated to lab_ca/scoped_lab
    authorized_mode = ticket_doc.get('mode') or 'scoped_lab'
    if requested_mode is not None and requested_mode not in ('default', authorized_mode):
        raise HTTPException(
            403,
            f"Mã tải cấu hình này chỉ được cấp quyền cho chế độ '{authorized_mode}', "
            f"không được phép đổi sang chế độ '{requested_mode}'.",
        )

    # Verify the associated device is still active and not revoked
    devices = getattr(request.app.state, 'devices', None)
    if devices is not None and hasattr(devices, 'find_one'):
        dev_res = devices.find_one({'device_id': ticket_doc['device_id']}, {'_id': 0})
        dev_doc = await dev_res if hasattr(dev_res, '__await__') else dev_res
        if not isinstance(dev_doc, dict) or dev_doc.get('status') != 'active' or dev_doc.get('revoked_at') is not None:
            raise HTTPException(401, 'Thiết bị liên kết với mã tải này đã bị thu hồi.')

    ticket_doc['mode'] = authorized_mode
    return ticket_doc
