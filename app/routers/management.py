from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pymongo.errors import DuplicateKeyError
from ..database import get_accounts
from ..middleware import client_ip
from ..models import (
    AccountId,
    AccountInput,
    AccountOutput,
    ActivateAccountInput,
    DeviceCreateInput,
    DeviceOutput,
    LinkVerifyInput,
    LinkVerifyOutput,
    RevokeAccountInput,
    TestResultInput,
    compute_entitlement_status,
)
from ..profile import build_profile, load_validated_root_ca
from ..security import require_admin
from ..config import get_settings
from ..services.device_service import enroll_device, verify_device_token
from ..services.entitlement_service import format_account_record
from ..services.identity_service import verify_account_link_or_identifier
from ..services.pki_service import (
    generate_lab_leaf_certificate,
    generate_lab_root_ca,
    inspect_certificate_metadata,
    verify_certificate_chain_and_hostname,
)

router = APIRouter()
WEB = Path(__file__).resolve().parent.parent.parent / 'web'
Accounts = Annotated[object, Depends(get_accounts)]


async def record_audit(request: Request, admin: dict, action: str, target_id: str, details: dict | None = None):
    audit_col = getattr(request.app.state, 'audit', None)
    if audit_col is None or not hasattr(audit_col, 'insert_one'):
        return
    ip_hash = hashlib.sha256(client_ip(request.scope).encode('utf-8')).hexdigest()[:16]
    try:
        res = audit_col.insert_one({
            'timestamp': datetime.now(timezone.utc),
            'actor': admin.get('email', 'superadmin'),
            'action': action,
            'target_id': target_id,
            'ip_hash': ip_hash,
            'details': details or {},
        })
        if hasattr(res, '__await__'):
            await res
    except Exception:
        pass


@router.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return FileResponse(WEB / 'favicon.ico', media_type='image/vnd.microsoft.icon')


@router.get('/apple-touch-icon.png', include_in_schema=False)
@router.get('/apple-touch-icon-precomposed.png', include_in_schema=False)
async def apple_touch_icon():
    return FileResponse(WEB / 'apple-touch-icon.png', media_type='image/png')


@router.get('/', response_class=HTMLResponse, include_in_schema=False)
async def home(request: Request):
    if 'admin' in request.query_params:
        raise HTTPException(400, 'URL tokens are disabled. Open /admin to sign in.')
    return render_page(False, request)


@router.get('/robots.txt', include_in_schema=False)
async def robots_txt():
    return PlainTextResponse("User-agent: *\nDisallow: /")


@router.get('/api/health')
async def health_check(request: Request):
    settings = get_settings()
    profile_ready = bool(getattr(request.app.state, 'profile', None))
    ca_loaded = False
    ca_fp = None
    try:
        cert = load_validated_root_ca(settings)
        if cert is not None:
            ca_loaded = True
            ca_fp = inspect_certificate_metadata(cert)['sha256_fingerprint']
    except Exception:
        ca_loaded = False
    return {
        'status': 'ok',
        'database': settings.mongodb_database,
        'nextdns_configured': bool(settings.nextdns_id),
        'nextdns_id': settings.nextdns_id or None,
        'profile_ready': profile_ready,
        'root_ca_loaded': ca_loaded,
        'root_ca_sha256': ca_fp,
    }


def render_page(admin: bool, request: Request) -> HTMLResponse:
    page = (WEB / 'index.html').read_text(encoding='utf-8')
    start, end = ('<!-- PUBLIC_START -->', '<!-- PUBLIC_END -->') if admin else ('<!-- ADMIN_START -->', '<!-- ADMIN_END -->')
    before, rest = page.split(start)
    _, after = rest.split(end)
    page = before + after
    page = page.replace('__TURNSTILE_SITE_KEY__', get_settings().turnstile_site_key)
    return HTMLResponse(page.replace('__NONCE__', request.state.csp_nonce).replace('__VIEW__', 'admin' if admin else 'public'))


@router.get('/admin', response_class=HTMLResponse, include_in_schema=False)
async def admin_login_default(request: Request):
    settings = get_settings()
    if getattr(settings, 'admin_path', '/admin') != '/admin':
        raise HTTPException(404, 'Not Found')
    return render_page(True, request)


@router.get('/profile.mobileconfig')
async def download_profile(
    request: Request,
    mode: Literal['default', 'dns_only', 'lab_ca', 'scoped_lab'] = Query('default'),
    device_token: str | None = Query(None, max_length=128),
):
    profile_bytes = getattr(request.app.state, 'profile', None)
    if not profile_bytes:
        raise HTTPException(503, 'Cấu hình DNS hoặc chứng chỉ chưa sẵn sàng.')

    settings = get_settings()
    eff_mode = mode if isinstance(mode, str) else 'default'
    eff_token = device_token if isinstance(device_token, str) else None

    device_label = None
    if eff_token:
        device_doc = await verify_device_token(request, eff_token)
        if device_doc is None:
            raise HTTPException(401, 'Device token không hợp lệ hoặc đã bị thu hồi.')
        device_label = device_doc.get('device_id')

    if eff_mode != 'default' or device_label:
        try:
            scoped = settings.lab_scoped_domains if eff_mode in {'scoped_lab', 'lab_ca'} else None
            if eff_mode == 'dns_only':
                s_copy = settings.model_copy(update={'root_ca_path': '', 'root_ca_pem': ''})
                profile_bytes = build_profile(s_copy, scoped_domains=None, device_label=device_label)
            elif eff_mode in {'lab_ca', 'scoped_lab'}:
                cert = load_validated_root_ca(settings)
                if eff_mode == 'lab_ca' and cert is None:
                    raise ValueError('Lab Root CA is not configured on this server')
                profile_bytes = build_profile(
                    settings,
                    scoped_domains=scoped,
                    device_label=device_label,
                    override_ca_cert=cert,
                )
            else:
                profile_bytes = build_profile(settings, scoped_domains=scoped, device_label=device_label)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, 'Cấu hình DNS hoặc chứng chỉ chưa sẵn sàng.') from exc

    profile_versions = getattr(request.app.state, 'profile_versions', None)
    if profile_versions is not None and hasattr(profile_versions, 'insert_one'):
        try:
            res = profile_versions.insert_one({
                'profile_uuid': str(uuid4()),
                'mode': eff_mode,
                'nextdns_id': settings.nextdns_id,
                'device_label': device_label,
                'created_at': datetime.now(timezone.utc),
            })
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    return Response(
        profile_bytes,
        media_type='application/x-apple-aspen-config',
        headers={'Content-Disposition': 'attachment; filename="locket.mobileconfig"'},
    )


@router.get('/{admin_slug}', response_class=HTMLResponse, include_in_schema=False)
async def admin_login_custom(admin_slug: str, request: Request):
    settings = get_settings()
    configured_path = getattr(settings, 'admin_path', '/admin')
    if f'/{admin_slug}' != configured_path:
        raise HTTPException(404, 'Not Found')
    return render_page(True, request)


admin_router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)])


@admin_router.post('/verify-link', response_model=LinkVerifyOutput)
async def verify_link_endpoint(
    data: LinkVerifyInput,
    request: Request,
    admin: Annotated[dict, Depends(require_admin)],
):
    result = verify_account_link_or_identifier(data.raw_input, trusted_proof=data.trusted_proof)
    await record_audit(
        request,
        admin,
        'IDENTITY_VERIFY',
        result.extracted_identifier or data.raw_input[:32],
        {'input_kind': result.input_kind, 'verification_status': result.verification_status},
    )
    return result


@admin_router.post('/add-account', response_model=AccountOutput)
async def upsert_account(
    data: AccountInput,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    now = datetime.now(timezone.utc)
    # 1. Maintain exact legacy document in `accounts` collection for 100% backward compatibility
    legacy_doc = {'locket_id': data.locket_id, 'expires_date': data.expires_date}
    try:
        await accounts.update_one({'locket_id': data.locket_id}, {'$set': legacy_doc}, upsert=True)
    except DuplicateKeyError:
        await accounts.update_one({'locket_id': data.locket_id}, {'$set': legacy_doc})

    # 2. Write canonical v2 record to `accounts_v2` and `entitlements` if available
    v2_doc = {
        'schema_version': 2,
        'account_id': data.locket_id,
        'locket_id': data.locket_id,
        'username': data.username,
        'source_link': data.source_link,
        'verification_status': data.verification_status,
        'verification_method': data.verification_method,
        'status': data.status,
        'product_identifier': 'com.locket.gold.yearly',
        'expires_date': data.expires_date,
        'revoked_at': now if data.status == 'revoked' else None,
        'revoke_reason': 'Set to revoked on save' if data.status == 'revoked' else None,
        'max_devices': data.max_devices,
        'notes': data.notes,
        'updated_at': now,
        'updated_by': admin.get('email', 'superadmin'),
    }
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
        try:
            res = accounts_v2.update_one(
                {'locket_id': data.locket_id},
                {'$set': v2_doc, '$setOnInsert': {'created_at': now, 'purchase_date': now}},
                upsert=True,
            )
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    entitlements = getattr(request.app.state, 'entitlements', None)
    if entitlements is not None and hasattr(entitlements, 'update_one'):
        try:
            res = entitlements.update_one(
                {'account_id': data.locket_id, 'entitlement_key': 'Gold'},
                {
                    '$set': {
                        'account_id': data.locket_id,
                        'entitlement_key': 'Gold',
                        'product_identifier': 'com.locket.gold.yearly',
                        'status': data.status,
                        'expires_date': data.expires_date,
                        'revoked_at': v2_doc['revoked_at'],
                        'updated_at': now,
                    },
                    '$setOnInsert': {'purchase_date': now},
                },
                upsert=True,
            )
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    await record_audit(
        request,
        admin,
        'ACCOUNT_UPSERT',
        data.locket_id,
        {'expires_date': data.expires_date.isoformat(), 'status': data.status},
    )
    return format_account_record(v2_doc, now)


@admin_router.get('/accounts', response_model=list[AccountOutput])
async def list_accounts(
    request: Request,
    accounts: Accounts,
    skip: int = Query(0, ge=0, le=10000),
    limit: int = Query(50, ge=1, le=100),
):
    now = datetime.now(timezone.utc)
    rows = await accounts.find({}, {'_id': 0}).sort('locket_id', 1).skip(skip).limit(limit).to_list(length=limit)

    # Enrich with v2 metadata if present
    v2_map = {}
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if accounts_v2 is not None and hasattr(accounts_v2, 'find') and rows:
        try:
            ids = [r['locket_id'] for r in rows if isinstance(r, dict) and 'locket_id' in r]
            v2_cursor = accounts_v2.find({'locket_id': {'$in': ids}}, {'_id': 0})
            if hasattr(v2_cursor, 'to_list'):
                v2_list = await v2_cursor.to_list(length=len(ids))
                if isinstance(v2_list, list):
                    v2_map = {item['locket_id']: item for item in v2_list if isinstance(item, dict) and 'locket_id' in item}
        except Exception:
            v2_map = {}

    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        lid = row.get('locket_id')
        merged = {**v2_map.get(lid, {}), **row}
        if lid in v2_map and v2_map[lid].get('status') in {'revoked', 'pending'}:
            merged['status'] = v2_map[lid]['status']
            merged['revoked_at'] = v2_map[lid].get('revoked_at')
            merged['revoke_reason'] = v2_map[lid].get('revoke_reason')
        result.append(format_account_record(merged, now))
    return result


@admin_router.post('/accounts/{account_id}/revoke', response_model=AccountOutput)
async def revoke_account(
    account_id: AccountId,
    data: RevokeAccountInput,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    existing = await accounts.find_one({'locket_id': account_id}, {'_id': 0})
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if existing is None and accounts_v2 is not None:
        existing = await accounts_v2.find_one({'locket_id': account_id}, {'_id': 0})
    if existing is None:
        raise HTTPException(404, 'Account not found')

    now = datetime.now(timezone.utc)
    past_expiry = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    # Also set status='revoked' in legacy accounts and accounts_v2 so both paths fail closed immediately
    await accounts.update_one(
        {'locket_id': account_id},
        {'$set': {'status': 'revoked', 'revoked_at': now, 'revoke_reason': data.reason}},
    )
    if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
        try:
            res = accounts_v2.update_one(
                {'locket_id': account_id},
                {
                    '$set': {
                        'status': 'revoked',
                        'revoked_at': now,
                        'revoke_reason': data.reason,
                        'updated_at': now,
                        'updated_by': admin.get('email', 'superadmin'),
                    }
                },
                upsert=True,
            )
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    await record_audit(request, admin, 'ENTITLEMENT_REVOKE', account_id, {'reason': data.reason})
    updated = {**existing, 'locket_id': account_id, 'status': 'revoked', 'revoked_at': now, 'revoke_reason': data.reason}
    if 'expires_date' not in updated:
        updated['expires_date'] = past_expiry
    return format_account_record(updated, now)


@admin_router.post('/accounts/{account_id}/activate', response_model=AccountOutput)
async def activate_account(
    account_id: AccountId,
    data: ActivateAccountInput,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    existing = await accounts.find_one({'locket_id': account_id}, {'_id': 0})
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if existing is None and accounts_v2 is not None:
        existing = await accounts_v2.find_one({'locket_id': account_id}, {'_id': 0})
    if existing is None:
        raise HTTPException(404, 'Account not found')

    now = datetime.now(timezone.utc)
    new_expiry = data.expires_date or (now + timedelta(days=365))
    if new_expiry <= now:
        raise HTTPException(422, 'expires_date must be in the future')

    await accounts.update_one(
        {'locket_id': account_id},
        {'$set': {'expires_date': new_expiry, 'status': 'active', 'revoked_at': None, 'revoke_reason': None}},
    )
    if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
        try:
            res = accounts_v2.update_one(
                {'locket_id': account_id},
                {
                    '$set': {
                        'status': 'active',
                        'expires_date': new_expiry,
                        'revoked_at': None,
                        'revoke_reason': None,
                        'updated_at': now,
                        'updated_by': admin.get('email', 'superadmin'),
                    }
                },
                upsert=True,
            )
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    await record_audit(request, admin, 'ENTITLEMENT_ACTIVATE', account_id, {'expires_date': new_expiry.isoformat()})
    updated = {**existing, 'locket_id': account_id, 'expires_date': new_expiry, 'status': 'active', 'revoked_at': None}
    return format_account_record(updated, now)


@admin_router.delete('/accounts/{account_id}', status_code=204)
async def delete_account(
    account_id: AccountId,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    result = await accounts.delete_one({'locket_id': account_id})
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if accounts_v2 is not None and hasattr(accounts_v2, 'delete_one'):
        try:
            res = accounts_v2.delete_one({'locket_id': account_id})
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass
    if not result.deleted_count:
        raise HTTPException(404, 'Account not found')
    await record_audit(request, admin, 'ACCOUNT_DELETE', account_id)
    return Response(status_code=204)


@admin_router.post('/devices', response_model=DeviceOutput)
async def create_device_endpoint(
    data: DeviceCreateInput,
    request: Request,
    admin: Annotated[dict, Depends(require_admin)],
):
    device = await enroll_device(request, data)
    await record_audit(
        request,
        admin,
        'DEVICE_ENROLL',
        data.locket_id,
        {'device_id': device['device_id'], 'device_name': data.device_name},
    )
    return device


@admin_router.get('/devices', response_model=list[DeviceOutput])
async def list_devices_endpoint(
    request: Request,
    locket_id: AccountId | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
):
    devices = getattr(request.app.state, 'devices', None)
    if devices is None or not hasattr(devices, 'find'):
        return []
    query = {'locket_id': locket_id} if locket_id else {}
    cursor = devices.find(query, {'_id': 0, 'token_hash': 0}).sort('created_at', -1).limit(limit)
    rows = await cursor.to_list(length=limit)
    return rows if isinstance(rows, list) else []


@admin_router.post('/devices/{device_id}/revoke', response_model=DeviceOutput)
async def revoke_device_endpoint(
    device_id: str,
    request: Request,
    admin: Annotated[dict, Depends(require_admin)],
):
    devices = getattr(request.app.state, 'devices', None)
    if devices is None:
        raise HTTPException(503, 'Device service unavailable')
    doc = await devices.find_one({'device_id': device_id}, {'_id': 0})
    if not isinstance(doc, dict):
        raise HTTPException(404, 'Device not found')
    now = datetime.now(timezone.utc)
    await devices.update_one({'device_id': device_id}, {'$set': {'status': 'revoked', 'revoked_at': now}})
    doc['status'] = 'revoked'
    doc['revoked_at'] = now
    await record_audit(request, admin, 'DEVICE_REVOKE', doc.get('locket_id', device_id), {'device_id': device_id})
    return doc


@admin_router.get('/logs')
async def get_lab_logs(
    request: Request,
    limit: int = Query(30, ge=1, le=100),
):
    audit_col = getattr(request.app.state, 'audit', None)
    lab_req_col = getattr(request.app.state, 'lab_requests', None)
    test_res_col = getattr(request.app.state, 'test_results', None)

    async def fetch_recent(col, sort_field='timestamp'):
        if col is None or not hasattr(col, 'find'):
            return []
        try:
            cur = col.find({}, {'_id': 0}).sort(sort_field, -1).limit(limit)
            if hasattr(cur, 'to_list'):
                items = await cur.to_list(length=limit)
                return items if isinstance(items, list) else []
        except Exception:
            pass
        return []

    return {
        'audit_logs': await fetch_recent(audit_col, 'timestamp'),
        'lab_requests': await fetch_recent(lab_req_col, 'timestamp'),
        'test_results': await fetch_recent(test_res_col, 'timestamp'),
    }


@admin_router.post('/test-results')
async def record_test_result(
    data: TestResultInput,
    request: Request,
    admin: Annotated[dict, Depends(require_admin)],
):
    now = datetime.now(timezone.utc)
    entry = {
        **data.model_dump(),
        'timestamp': now,
        'recorded_by': admin.get('email', 'superadmin'),
    }
    test_res_col = getattr(request.app.state, 'test_results', None)
    if test_res_col is not None and hasattr(test_res_col, 'insert_one'):
        res = test_res_col.insert_one(entry.copy())
        if hasattr(res, '__await__'):
            await res
    await record_audit(request, admin, 'TEST_RESULT_RECORD', data.locket_id or data.scenario, {'verdict': data.verdict})
    return entry


@admin_router.get('/pki/status')
async def get_pki_status(request: Request):
    settings = get_settings()
    try:
        cert = load_validated_root_ca(settings)
    except Exception as exc:
        return {
            'configured': True,
            'valid': False,
            'error': str(exc),
            'nextdns_id': settings.nextdns_id or None,
        }
    if cert is None:
        return {
            'configured': False,
            'valid': False,
            'nextdns_id': settings.nextdns_id or None,
        }
    meta = inspect_certificate_metadata(cert)
    return {
        'configured': True,
        'valid': meta['is_currently_valid'] and meta['is_ca'],
        'nextdns_id': settings.nextdns_id or None,
        'certificate': meta,
    }

