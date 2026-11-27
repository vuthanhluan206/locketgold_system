from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pymongo.errors import DuplicateKeyError
from ..database import account_write_options, get_accounts
from ..middleware import client_ip
from ..models import (
    AccountId,
    AccountInput,
    AccountOutput,
    ActivateAccountInput,
    AdminAccountLookupOutput,
    DeviceCreateInput,
    DeviceOutput,
    LinkVerifyInput,
    LinkVerifyOutput,
    LabGoldFeatures,
    ProfileTicketInput,
    ProfileTicketOutput,
    PublicLookupOutput,
    RevokeAccountInput,
    compute_entitlement_status,
    TestResultInput,
)
from ..profile import build_profile, load_validated_root_ca
from ..security import require_admin
from ..config import get_settings
from ..services.device_service import (
    consume_profile_download_ticket,
    enroll_device,
    issue_profile_download_ticket,
    verify_device_token,
)
from ..services.entitlement_service import (
    effective_gold_account,
    evaluate_gold_record,
    extract_verified_uid_metadata,
    find_canonical_account,
    format_account_record,
    merge_canonical_and_legacy_account,
)
from ..services.identity_service import (
    is_valid_firebase_uid,
    normalize_lookup_query,
    resolve_locket_identity,
    resolve_public_locket_share_link,
    verify_account_link_or_identifier,
)
from ..services.pki_service import inspect_certificate_metadata

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


@router.get('/api/accounts/lookup', response_model=PublicLookupOutput)
async def lookup_account(
    request: Request,
    accounts: Accounts,
    query: str = Query(min_length=1, max_length=512),
):
    """
    Public account lookup endpoint modeled directly on `locketgoldmanager`.
    Accepts a Locket username, @username, or Locket URL (locket.cam / locketcamera.com).
    Returns ONLY `{"exists": true/false}` — never leaks UUID, tokens, expiry, or device details.
    """
    try:
        account_id, _ = normalize_lookup_query(query)
    except ValueError as exc:
        raise HTTPException(422, 'Vui lòng nhập username hoặc link Locket hợp lệ.') from exc

    account = await accounts.find_one({'locket_id': account_id}, {'_id': 1})
    if account is None:
        accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
        if accounts_v2 is not None and hasattr(accounts_v2, 'find_one'):
            for field in ('locket_id', 'username', 'firebase_uid'):
                res = accounts_v2.find_one({field: account_id}, {'_id': 1})
                if hasattr(res, '__await__'):
                    res = await res
                if isinstance(res, dict):
                    account = res
                    break
    return {'exists': account is not None}


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


@router.get('/api/ready')
async def readiness_check(request: Request):
    """Readiness probe that actively verifies MongoDB connectivity before reporting ready."""
    settings = get_settings()
    mongo_client = getattr(request.app.state, 'mongo_client', None)
    accounts = getattr(request.app.state, 'accounts', None)
    try:
        if mongo_client is not None and hasattr(mongo_client, 'admin'):
            res = mongo_client.admin.command('ping')
            if hasattr(res, '__await__'):
                await res
        elif accounts is not None and hasattr(accounts, 'find_one'):
            res = accounts.find_one({'locket_id': '__readiness_probe__'}, {'_id': 0})
            if hasattr(res, '__await__'):
                await res
        else:
            raise HTTPException(503, 'Database connection not initialized')
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, 'Database readiness probe failed') from exc

    return {
        'status': 'ready',
        'database': settings.mongodb_database,
        'mongodb_connected': True,
        'profile_ready': bool(getattr(request.app.state, 'profile', None)),
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


@router.post('/api/profile/download-ticket', response_model=ProfileTicketOutput)
async def create_profile_ticket_from_device_bearer(
    request: Request,
    data: ProfileTicketInput | None = None,
):
    """
    Exchange an authenticated device Bearer token (`Authorization: Bearer lkg_dev_*`)
    for a short-lived, single-use download ticket (`lkg_dl_*`) suitable for Safari `.mobileconfig` download.
    Never logs raw tokens.
    """
    auth_hdr = request.headers.get('authorization', '')
    scheme, _, raw_token = auth_hdr.partition(' ')
    if scheme.lower() != 'bearer' or not raw_token.strip().startswith('lkg_dev_'):
        raise HTTPException(
            401,
            'Yêu cầu Authorization: Bearer <device_token> hợp lệ để cấp mã tải một lần.',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    device_doc = await verify_device_token(request, raw_token.strip())
    if device_doc is None:
        raise HTTPException(401, 'Device token không hợp lệ hoặc đã bị thu hồi.')
    eff_mode = data.mode if data is not None else 'scoped_lab'
    eff_ttl = data.ttl_seconds if data is not None else 300
    return await issue_profile_download_ticket(request, device_doc=device_doc, mode=eff_mode, ttl_seconds=eff_ttl)


@router.get('/profile.mobileconfig')
async def download_profile(
    request: Request,
    mode: Literal['default', 'dns_only', 'lab_ca', 'scoped_lab'] = Query('default'),
    ticket: str | None = Query(None, max_length=128),
):
    # Security Policy (Prompt 11 P1): Long-lived device/Bearer tokens MUST NEVER be passed in URL query parameters!
    if any(k in request.query_params for k in ('device_token', 'token', 'access_token', 'bearer')):
        raise HTTPException(
            400,
            'Không được truyền device_token hoặc Bearer token dài hạn trên URL. '
            'Hãy dùng Authorization: Bearer header hoặc mã tải một lần (?ticket=lkg_dl_...).',
        )

    profile_bytes = getattr(request.app.state, 'profile', None)
    if not profile_bytes:
        raise HTTPException(503, 'Cấu hình DNS hoặc chứng chỉ chưa sẵn sàng.')

    settings = get_settings()
    eff_mode = mode if isinstance(mode, str) else 'default'
    eff_ticket = ticket if isinstance(ticket, str) else None

    device_label = None
    if eff_ticket:
        if eff_ticket.startswith('lkg_dev_'):
            raise HTTPException(
                400,
                'Không được truyền device_token dài hạn vào tham số ticket. Hãy dùng mã tải một lần (lkg_dl_*).',
            )
        ticket_doc = await consume_profile_download_ticket(request, eff_ticket, requested_mode=eff_mode)
        device_label = ticket_doc.get('device_id')
        # Never trust URL mode over the ticket's authorized mode
        eff_mode = ticket_doc.get('mode') or 'scoped_lab'
    else:
        auth_hdr = request.headers.get('authorization', '')
        scheme, _, raw_cred = auth_hdr.partition(' ')
        if scheme.lower() == 'bearer' and raw_cred.strip().startswith('lkg_dev_'):
            device_doc = await verify_device_token(request, raw_cred.strip())
            if device_doc is None:
                raise HTTPException(401, 'Device token không hợp lệ hoặc đã bị thu hồi.')
            device_label = device_doc.get('device_id')

    if settings.app_env == 'production' and eff_mode in {'lab_ca', 'scoped_lab'}:
        raise HTTPException(403, 'Lab CA profiles require a research environment')
    if eff_mode == 'default' and (settings.root_ca_path or settings.root_ca_pem):
        eff_mode = 'dns_only'
    if eff_mode != 'default' or device_label:
        try:
            scoped = settings.lab_scoped_domains if eff_mode in {'scoped_lab', 'lab_ca'} else None
            if eff_mode == 'dns_only':
                s_copy = settings.model_copy(update={'root_ca_path': '', 'root_ca_pem': ''})
                profile_bytes = build_profile(s_copy, scoped_domains=None, device_label=device_label)
            elif eff_mode in {'lab_ca', 'scoped_lab'}:
                cert = load_validated_root_ca(settings)
                if cert is None:
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
        headers={
            'Content-Disposition': 'attachment; filename="locket.mobileconfig"',
            'Cache-Control': 'no-store, no-cache, must-revalidate, private, max-age=0',
            'Pragma': 'no-cache',
            'Expires': '0',
        },
    )


@router.get('/{admin_slug}', response_class=HTMLResponse, include_in_schema=False)
async def admin_login_custom(admin_slug: str, request: Request):
    settings = get_settings()
    configured_path = getattr(settings, 'admin_path', '/admin')
    if f'/{admin_slug}' != configured_path or admin_slug in {'dns-query'}:
        raise HTTPException(404, 'Not Found')
    return render_page(True, request)


admin_router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)])


@admin_router.get('/overview')
async def overview(request: Request):
    state = request.app.state
    counts = dict(accounts=0, active=0, pending=0, revoked=0, expired=0, verified_uid=0)
    # Include legacy-only accounts once. Stream the join so dashboard totals have no page limit.
    pipeline = [
        {'$project': {'locket_id': 1, 'legacy': '$$ROOT'}},
        {'$unionWith': {'coll': 'accounts_v2', 'pipeline': [{'$project': {'locket_id': 1, 'canonical': '$$ROOT'}}]}},
        {'$group': {'_id': '$locket_id', 'canonical': {'$max': '$canonical'}, 'legacy': {'$max': '$legacy'}}},
        {'$set': {'uid': {'$ifNull': ['$canonical.firebase_uid', '$legacy.firebase_uid']}}},
        {'$lookup': {'from': 'entitlements', 'localField': 'uid', 'foreignField': 'account_id',
                     'pipeline': [{'$match': {'entitlement_key': 'Gold'}}], 'as': 'grants'}},
    ]
    now = datetime.now(timezone.utc)
    async for item in await state.accounts.aggregate(pipeline, allowDiskUse=True):
        account = merge_canonical_and_legacy_account(item.get('canonical'), item.get('legacy'))
        uid, verified, *_ = extract_verified_uid_metadata(account)
        grant = next(iter(item['grants']), None)
        effective = evaluate_gold_record(account, uid or item['_id'], grant, now)
        status, _ = compute_entitlement_status(effective, now)
        counts[status] += 1
        counts['verified_uid'] += int(verified)
        counts['accounts'] += 1
    counts['devices'] = await state.devices.count_documents({'status': 'active'})
    counts['entitlements'] = await state.entitlements.count_documents({'entitlement_key': 'Gold'})
    counts['downloads'] = await state.profile_versions.count_documents({})
    counts['uid_errors'] = await state.audit.count_documents({'action': 'ACCOUNT_UID_RESOLUTION_FAILED'})
    counts['gold_errors'] = await state.audit.count_documents({'action': 'GOLD_WRITE_FAILED'})
    return counts


@admin_router.get('/accounts/{account_id}/features', response_model=LabGoldFeatures)
async def admin_features(account_id: AccountId, request: Request):
    doc = await request.app.state.accounts_v2.find_one({'locket_id': account_id}, {'lab_features': 1})
    if doc is None:
        raise HTTPException(404, 'Account not found')
    return doc.get('lab_features', {})


@admin_router.put('/accounts/{account_id}/features', response_model=LabGoldFeatures)
async def save_lab_features(account_id: AccountId, flags: LabGoldFeatures, request: Request,
                            admin: Annotated[dict, Depends(require_admin)]):
    result = await request.app.state.accounts_v2.update_one({'locket_id': account_id},
                                                            {'$set': {'lab_features': flags.model_dump()}})
    if not result.matched_count:
        raise HTTPException(404, 'Account not found')
    await record_audit(request, admin, 'LAB_FEATURES_UPDATED', account_id, flags.model_dump())
    return flags


@admin_router.get('/accounts/lookup', response_model=AdminAccountLookupOutput)
async def admin_lookup_account_endpoint(
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
    query: str = Query(min_length=1, max_length=512),
):
    """
    Authenticated Admin Account & UUID Lookup API.
    Normalizes username / @username / Locket share link, queries MongoDB (`accounts_v2` & `accounts`),
    and returns full diagnostic metadata (username, internal_identifier, firebase_uid if verified/present,
    verification_status, verification_method, verification_source, entitlement_status, updated_at).
    Never depends on external `amlongtruc-source` APIs and never guesses UUIDs.
    """
    try:
        normalized_id, input_kind = normalize_lookup_query(query)
    except ValueError as exc:
        raise HTTPException(422, 'Vui lòng nhập username hoặc link Locket hợp lệ.') from exc

    base_verify = verify_account_link_or_identifier(query)
    record = await find_canonical_account(request, normalized_id, accounts_col=accounts)
    now = datetime.now(timezone.utc)

    if record is None:
        await record_audit(
            request,
            admin,
            'ADMIN_ACCOUNT_LOOKUP',
            normalized_id,
            {'exists': False, 'input_kind': input_kind},
        )
        return AdminAccountLookupOutput(
            exists=False,
            normalized_query=normalized_id,
            input_kind=input_kind,
            username=base_verify.extracted_username,
            internal_identifier=None,
            firebase_uid=base_verify.extracted_identifier if input_kind == 'firebase_uid' else None,
            uid_verified=False,
            verification_status=base_verify.verification_status,
            verification_method=base_verify.verification_method,
            verification_source=base_verify.verification_source,
            entitlement_status=None,
            expires_date=None,
            updated_at=None,
            message=f'Chưa có tài khoản "{normalized_id}" trong MongoDB (locket_manager).',
        )

    formatted = format_account_record(record, now)
    fb_uid, uid_ver, ver_status, ver_method, ver_source = extract_verified_uid_metadata(record)
    effective = await effective_gold_account(request, record, fb_uid or formatted['locket_id'], now)
    formatted['status'], _ = compute_entitlement_status(effective, now)
    internal_id = formatted['locket_id']
    username = formatted.get('username') or (internal_id if not fb_uid else base_verify.extracted_username)

    if uid_ver and fb_uid:
        msg = (
            f'Đã tìm thấy tài khoản trong MongoDB (ID: {internal_id}) kèm Firebase UID đã xác minh '
            f'({fb_uid}, nguồn: {ver_source}, trạng thái thuê bao: {formatted["status"]}).'
        )
    elif fb_uid:
        msg = (
            f'Đã tìm thấy tài khoản trong MongoDB (ID: {internal_id}) có định dạng UID 28 ký tự ({fb_uid}) '
            f'nhưng chưa có bằng chứng xác minh độc lập (trạng thái: {ver_status}, thuê bao: {formatted["status"]}).'
        )
    else:
        msg = (
            f'Đã tìm thấy tài khoản trong MongoDB theo username/handle "{internal_id}" '
            f'(chưa có Firebase UID đã xác minh — trạng thái: unverified_handle, thuê bao: {formatted["status"]}).'
        )

    await record_audit(
        request,
        admin,
        'ADMIN_ACCOUNT_LOOKUP',
        internal_id,
        {'exists': True, 'verification_status': ver_status, 'uid_verified': uid_ver},
    )
    return AdminAccountLookupOutput(
        exists=True,
        normalized_query=normalized_id,
        input_kind=input_kind,
        username=username,
        internal_identifier=internal_id,
        firebase_uid=fb_uid,
        uid_verified=uid_ver,
        verification_status=ver_status,
        verification_method=ver_method,
        verification_source=ver_source,
        entitlement_status=formatted['status'],
        expires_date=formatted['expires_date'],
        updated_at=formatted.get('updated_at'),
        message=msg,
    )


@admin_router.post('/verify-link', response_model=LinkVerifyOutput)
async def verify_link_endpoint(
    data: LinkVerifyInput,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    result = verify_account_link_or_identifier(data.raw_input)
    if result.valid_format and result.extracted_identifier:
        record = await find_canonical_account(request, result.extracted_identifier, accounts_col=accounts)
        if record is not None:
            now = datetime.now(timezone.utc)
            formatted = format_account_record(record, now)
            fb_uid, uid_ver, ver_status, ver_method, ver_source = extract_verified_uid_metadata(record)
            effective = await effective_gold_account(request, record, fb_uid or formatted['locket_id'], now)
            formatted['status'], _ = compute_entitlement_status(effective, now)
            result.exists_in_db = True
            result.resolved_identifier = formatted['locket_id']
            result.resolved_firebase_uid = fb_uid
            result.entitlement_status = formatted['status']
            result.expires_date = formatted['expires_date']
            result.updated_at = formatted.get('updated_at')
            result.uid_verified = uid_ver
            result.verification_status = ver_status
            result.verification_method = ver_method
            result.verification_source = ver_source
            if uid_ver and fb_uid:
                result.message = (
                    f'Đã tìm thấy trong MongoDB: tài khoản "{formatted["locket_id"]}" có Firebase UID đã xác minh '
                    f'({fb_uid}, nguồn: {ver_source}, trạng thái: {formatted["status"]}).'
                )
            else:
                result.message = (
                    f'Đã tìm thấy trong MongoDB: tài khoản "{formatted["locket_id"]}" '
                    f'(trạng thái xác minh: {ver_status}, thuê bao: {formatted["status"]}).'
                )
        else:
            result.message = f'{result.message} (Chưa có bản ghi trong MongoDB locket_manager).'

    await record_audit(
        request,
        admin,
        'IDENTITY_VERIFY',
        result.extracted_identifier or data.raw_input[:32],
        {
            'input_kind': result.input_kind,
            'exists_in_db': result.exists_in_db,
            'verification_status': result.verification_status,
            'verification_source': result.verification_source,
        },
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
    settings = get_settings()
    try:
        canonical_id, input_kind = normalize_lookup_query(data.locket_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    auto_source_link = f'https://locket.cam/{canonical_id}' if input_kind == 'locket_link' else data.source_link
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    provider = getattr(request.app.state, 'identity_provider', None)
    auth_http_client = getattr(request.app.state, 'locket_api_http_client', None)
    public_fetcher = getattr(request.app.state, 'public_link_fetcher', None)
    public_http_client = getattr(request.app.state, 'public_http_client', None)
    has_provider = provider is not None and not data.public_only
    has_public_resolver = public_fetcher is not None or public_http_client is not None
    must_resolve = bool(
        data.resolve_identity
        or data.public_only
        or has_provider
        or has_public_resolver
        or input_kind in {'locket_link', 'handle'}
    )

    existing_v2 = None
    if accounts_v2 is not None and hasattr(accounts_v2, 'find_one'):
        existing_res = accounts_v2.find_one({'locket_id': canonical_id}, {'_id': 0})
        if hasattr(existing_res, '__await__'):
            existing_res = await existing_res
        if isinstance(existing_res, dict):
            existing_v2 = existing_res
        else:
            for alt_field in ('username', 'firebase_uid'):
                try:
                    alt_res = accounts_v2.find_one({alt_field: canonical_id}, {'_id': 0})
                    if hasattr(alt_res, '__await__'):
                        alt_res = await alt_res
                    if isinstance(alt_res, dict):
                        existing_v2 = alt_res
                        if input_kind != 'firebase_uid' and isinstance(existing_v2.get('locket_id'), str):
                            canonical_id = existing_v2['locket_id']
                        break
                except KeyError:
                    continue

    uid_resolved_at = existing_v2.get('uid_resolved_at') if isinstance(existing_v2, dict) else None
    existing_verified = bool(existing_v2 and extract_verified_uid_metadata(existing_v2)[1])
    uid_resolution_source = existing_v2.get('uid_resolution_source') if isinstance(existing_v2, dict) else None
    identity_lookup_at = existing_v2.get('identity_lookup_at') if isinstance(existing_v2, dict) else None
    identity_lookup_source = existing_v2.get('identity_lookup_source') if isinstance(existing_v2, dict) else None
    resolved_invite_token = existing_v2.get('invite_token') if isinstance(existing_v2, dict) else None
    resolution_status_val = existing_v2.get('resolution_status') if isinstance(existing_v2, dict) else None

    if must_resolve:
        if data.public_only:
            resolution = await resolve_public_locket_share_link(
                data.locket_id,
                http_client=public_http_client,
                public_fetcher=public_fetcher,
                check_dns=(public_http_client is None and public_fetcher is None),
            )
        else:
            resolution = await resolve_locket_identity(
                data.locket_id,
                settings=settings,
                accounts_v2=accounts_v2,
                provider=provider,
                http_client=auth_http_client,
                public_http_client=public_http_client,
                public_fetcher=public_fetcher,
                use_public_link=bool(has_public_resolver or (data.resolve_identity and not has_provider)),
            )
        if resolution.status in {'resolved', 'resolved_uid', 'verified_uid'} and resolution.firebase_uid:
            canonical_id = resolution.normalized_id
            resolved_username = resolution.username or data.username or canonical_id
            resolved_fb_uid = resolution.firebase_uid
            if (
                isinstance(existing_v2, dict)
                and existing_v2.get('_server_uid_proof') is True
                and existing_v2.get('verification_status') == 'verified_uid'
                and existing_v2.get('firebase_uid')
                and existing_v2.get('firebase_uid') != resolved_fb_uid
            ):
                raise HTTPException(
                    409,
                    'Không thể ghi đè Firebase UID đã được xác minh bằng một UID khác (conflict).',
                )
            if accounts_v2 is not None and hasattr(accounts_v2, 'find_one'):
                try:
                    owner_res = accounts_v2.find_one({'firebase_uid': resolved_fb_uid}, {'_id': 0})
                    if hasattr(owner_res, '__await__'):
                        owner_res = await owner_res
                except KeyError:
                    owner_res = None
                if isinstance(owner_res, dict) and owner_res.get('locket_id') and owner_res.get('locket_id') != canonical_id:
                    raise HTTPException(
                        409,
                        f'Firebase UID này đã được gắn với tài khoản "{owner_res.get("locket_id")}" trong MongoDB (conflict).',
                    )
            resolved_invite_token = resolution.invite_token or resolved_invite_token
            auto_source_link = resolution.source_link or auto_source_link
            safe_ver_source = resolution.verification_source or 'authorized_identity_provider'
            server_proof = resolution.uid_verified
            if existing_verified and existing_v2['firebase_uid'] == resolved_fb_uid and not server_proof:
                safe_ver_source = existing_v2['verification_source']
                server_proof = True
            safe_ver_status = 'verified_uid' if server_proof else 'unverified_uid'
            safe_ver_method = 'trusted_proof' if server_proof else 'format_only_uid'
            uid_resolved_at = resolution.uid_resolved_at or now
            uid_resolution_source = resolution.uid_resolution_source or safe_ver_source
            identity_lookup_at = resolution.identity_lookup_at or now
            identity_lookup_source = resolution.identity_lookup_source or uid_resolution_source
            resolution_status_val = 'verified_uid' if resolution.status == 'verified_uid' else 'resolved_uid'
        elif resolution.status == 'uid_resolved' and resolution.firebase_uid:
            canonical_id = resolution.normalized_id
            resolved_username = resolution.username or data.username or canonical_id
            resolved_fb_uid = resolution.firebase_uid
            resolved_invite_token = resolution.invite_token or resolved_invite_token
            auto_source_link = resolution.source_link or auto_source_link
            safe_ver_status = 'unverified_uid'
            safe_ver_method = 'authenticated_lookup'
            safe_ver_source = resolution.verification_source or 'locket_invite_lookup'
            server_proof = False
            uid_resolved_at = resolution.uid_resolved_at or now
            uid_resolution_source = resolution.uid_resolution_source or 'locket_invite_lookup'
            identity_lookup_at = resolution.identity_lookup_at or now
            identity_lookup_source = resolution.identity_lookup_source or 'locket_invite_lookup'
            resolution_status_val = 'uid_resolved'
        elif resolution.status == 'invite_token_found' or (
            data.public_only
            and resolution.status == 'verification_required'
            and resolution.verification_source == 'locket_public_share_link'
        ):
            canonical_id = resolution.normalized_id
            resolved_username = resolution.username or data.username or canonical_id
            resolved_invite_token = resolution.invite_token or resolved_invite_token
            auto_source_link = resolution.source_link or auto_source_link
            identity_lookup_at = resolution.identity_lookup_at or now
            identity_lookup_source = resolution.identity_lookup_source or 'public_share_link'
            # Strictly separate invite_token from firebase_uid: NEVER store invite_token as firebase_uid!
            # However, if this account already had a verified firebase_uid in MongoDB, preserve it.
            if (
                isinstance(existing_v2, dict)
                and existing_v2.get('_server_uid_proof') is True
                and existing_v2.get('verification_status') == 'verified_uid'
                and extract_verified_uid_metadata(existing_v2)[1]
            ):
                resolved_fb_uid = existing_v2['firebase_uid']
                safe_ver_status = 'verified_uid'
                safe_ver_method = existing_v2.get('verification_method', 'trusted_proof')
                safe_ver_source = existing_v2.get('verification_source', 'authorized_identity_provider')
                server_proof = True
                resolution_status_val = 'resolved_uid'
            else:
                resolved_fb_uid = (existing_v2 or {}).get('firebase_uid')
                safe_ver_status = 'unverified_uid' if resolved_fb_uid else 'unverified_handle'
                safe_ver_method = 'format_only_uid' if resolved_fb_uid else 'link_handle_only'
                safe_ver_source = 'locket_public_share_link'
                server_proof = False
                resolution_status_val = resolution.status
        else:
            status_map = {
                'not_found': 404,
                'auth_required': 502,
                'session_expired': 502,
                'rate_limited': 429,
                'lookup_unavailable': 503,
                'invalid_link': 422,
                'invalid_response': 422,
                'uid_missing': 422,
                'username_mismatch': 409,
                'uid_conflict': 409,
                'verification_required': 422,
                'conflict': 409,
                'unverified': 422,
            }
            http_code = status_map.get(resolution.status, 503)
            await record_audit(
                request,
                admin,
                'ACCOUNT_UID_RESOLUTION_FAILED',
                canonical_id,
                {'resolution_status': resolution.status, 'input_kind': input_kind},
            )
            raise HTTPException(http_code, resolution.message)
    else:
        is_28char_id = is_valid_firebase_uid(canonical_id)
        has_explicit_fb = bool(data.firebase_uid and data.firebase_uid.strip())
        resolved_username = data.username
        if has_explicit_fb or is_28char_id:
            resolved_fb_uid = data.firebase_uid.strip() if has_explicit_fb else canonical_id
            # Conflict check 1: Never overwrite an existing verified UID with a different UID
            if (
                isinstance(existing_v2, dict)
                and existing_v2.get('_server_uid_proof') is True
                and existing_v2.get('verification_status') == 'verified_uid'
                and existing_v2.get('firebase_uid')
                and existing_v2.get('firebase_uid') != resolved_fb_uid
            ):
                raise HTTPException(
                    409,
                    'Không thể ghi đè Firebase UID đã được xác minh bằng một UID khác (conflict).',
                )
            # Conflict check 2: Never link a Firebase UID that is already attached to another account
            if accounts_v2 is not None and hasattr(accounts_v2, 'find_one'):
                try:
                    owner_res = accounts_v2.find_one({'firebase_uid': resolved_fb_uid}, {'_id': 0})
                    if hasattr(owner_res, '__await__'):
                        owner_res = await owner_res
                except KeyError:
                    owner_res = None
                if isinstance(owner_res, dict) and owner_res.get('locket_id') and owner_res.get('locket_id') != canonical_id:
                    raise HTTPException(
                        409,
                        f'Firebase UID này đã được gắn với tài khoản "{owner_res.get("locket_id")}" trong MongoDB (conflict).',
                    )
            if (
                isinstance(existing_v2, dict)
                and existing_verified
                and existing_v2.get('firebase_uid') == resolved_fb_uid
                and existing_v2.get('verification_status') == 'verified_uid'
            ):
                safe_ver_status = 'verified_uid'
                safe_ver_method = existing_v2.get('verification_method', 'trusted_proof')
                safe_ver_source = existing_v2.get('verification_source', 'authorized_identity_provider')
                server_proof = True
            else:
                safe_ver_status = 'unverified_uid'
                safe_ver_method = 'format_only_uid'
                safe_ver_source = 'admin_manual_input'
                server_proof = False
        elif (
            isinstance(existing_v2, dict)
            and existing_verified
            and existing_v2.get('firebase_uid')
        ):
            # Preserve existing verified UID when renewing expiry date
            resolved_fb_uid = existing_v2['firebase_uid']
            resolved_username = resolved_username or existing_v2.get('username')
            safe_ver_status = 'verified_uid'
            safe_ver_method = existing_v2.get('verification_method', 'trusted_proof')
            safe_ver_source = existing_v2.get('verification_source', 'authorized_identity_provider')
            server_proof = True
        elif resolved_username or data.verification_status == 'unverified_handle':
            safe_ver_status = 'unverified_handle'
            safe_ver_method = 'link_handle_only'
            safe_ver_source = 'admin_manual_input'
            resolved_fb_uid = None
            server_proof = False
        else:
            safe_ver_status = 'manual_lab_id'
            safe_ver_method = 'admin_manual_override'
            safe_ver_source = 'admin_direct_input'
            resolved_fb_uid = None
            server_proof = False

    # Enforce Gold Entitlement SSOT Rule (Prompt 26 Sections 4, 5, 6):
    # Without a verified Firebase UID, the account is saved as 'pending' and does NOT receive active Gold.
    is_verified_uid = bool(
        server_proof
        and safe_ver_status == 'verified_uid'
        and is_valid_firebase_uid(resolved_fb_uid)
    )
    was_revoked = bool(existing_v2 and (existing_v2.get('status') == 'revoked' or existing_v2.get('revoked_at')))
    if data.status == 'revoked' or was_revoked:
        effective_status = 'revoked'
    elif data.status == 'pending' or not is_verified_uid:
        effective_status = 'pending'
    else:
        effective_status = 'active'

    entitlement_account_id = resolved_fb_uid if is_verified_uid else canonical_id

    # 1. Maintain legacy document in `accounts` collection for backward compatibility (including status)
    legacy_doc = {
        'locket_id': canonical_id,
        'expires_date': data.expires_date,
        'status': effective_status,
        'revoked_at': ((existing_v2 or {}).get('revoked_at') or now) if effective_status == 'revoked' else None,
    }
    # 2. Write canonical v2 record to `accounts_v2` and `entitlements` (NEVER swallow write failures!)
    v2_doc = {
        'schema_version': 2,
        'account_id': entitlement_account_id,
        'locket_id': canonical_id,
        'username': resolved_username,
        'invite_token': resolved_invite_token,
        'firebase_uid': resolved_fb_uid,
        'source_link': auto_source_link,
        'verification_status': safe_ver_status,
        'verification_method': safe_ver_method,
        'verification_source': safe_ver_source,
        '_server_uid_proof': server_proof,
        'identity_lookup_source': identity_lookup_source,
        'identity_lookup_at': identity_lookup_at,
        'uid_resolved_at': uid_resolved_at,
        'uid_resolution_source': uid_resolution_source,
        'resolution_status': resolution_status_val,
        'status': effective_status,
        'product_identifier': 'com.locket.gold.yearly',
        'expires_date': data.expires_date,
        'revoked_at': legacy_doc['revoked_at'],
        'revoke_reason': ((existing_v2 or {}).get('revoke_reason') or 'Set to revoked on save') if effective_status == 'revoked' else None,
        'activated_at': ((existing_v2 or {}).get('activated_at') or now) if effective_status == 'active' else (existing_v2 or {}).get('activated_at'),
        'max_devices': data.max_devices if 'max_devices' in data.model_fields_set else (existing_v2 or {}).get('max_devices', data.max_devices),
        'notes': data.notes,
        'updated_at': now,
        'updated_by': admin.get('email', 'superadmin'),
    }
    revision = {}
    if getattr(request.app.state, 'transactions_supported', None) is False or (existing_v2 or {}).get('grant_revision'):
        revision = {'grant_revision': str(uuid4())}
        v2_doc.update(revision)
    if is_verified_uid and getattr(request.app.state, 'entitlements', None) is None:
        raise HTTPException(503, 'Entitlement storage unavailable')
    async with account_write_options(request) as options:
        if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
            try:
                res = accounts_v2.update_one(
                    {
                        'locket_id': canonical_id,
                        'updated_at': (existing_v2 or {}).get('updated_at'),
                        '$or': [
                            {'_server_uid_proof': {'$ne': True}},
                            {'verification_source': 'locket_public_share_link', 'firebase_uid': resolved_fb_uid},
                            {'firebase_uid': resolved_fb_uid, '_server_uid_proof': server_proof,
                             'verification_status': safe_ver_status},
                        ],
                    },
                    {'$set': v2_doc, '$setOnInsert': {'created_at': now, 'purchase_date': now}},
                    upsert=True,
                    **options,
                )
                if hasattr(res, '__await__'):
                    await res
            except DuplicateKeyError:
                raise HTTPException(409, 'UID hoặc tài khoản đã được liên kết đồng thời; vui lòng tra cứu lại (uid_conflict).') from None

        try:
            await accounts.update_one({'locket_id': canonical_id}, {'$set': legacy_doc}, upsert=True, **options)
        except DuplicateKeyError:
            await accounts.update_one({'locket_id': canonical_id}, {'$set': legacy_doc}, **options)

        entitlements = getattr(request.app.state, 'entitlements', None)
        if is_verified_uid and entitlements is not None and hasattr(entitlements, 'update_one'):
            res = entitlements.update_one(
                {'account_id': resolved_fb_uid, 'entitlement_key': 'Gold'},
                {
                    '$set': {
                        'account_id': resolved_fb_uid,
                        **revision,
                        'locket_id': canonical_id,
                        'username': resolved_username or canonical_id,
                        'entitlement_key': 'Gold',
                        'product_identifier': 'com.locket.gold.yearly',
                        'status': effective_status,
                        'expires_date': data.expires_date,
                        'revoked_at': v2_doc['revoked_at'],
                        'updated_at': now,
                    },
                    '$setOnInsert': {'purchase_date': now},
                },
                upsert=True,
                **options,
            )
            if hasattr(res, '__await__'):
                await res
            if canonical_id != resolved_fb_uid and hasattr(entitlements, 'delete_many'):
                del_res = entitlements.delete_many({'account_id': canonical_id}, **options)
                if hasattr(del_res, '__await__'):
                    await del_res

    await record_audit(
        request,
        admin,
        'ACCOUNT_UPSERT',
        entitlement_account_id,
        {
            'locket_id': canonical_id,
            'expires_date': data.expires_date.isoformat(),
            'status': effective_status,
            'firebase_uid': resolved_fb_uid,
            'verification_status': safe_ver_status,
        },
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
    v1_rows = await accounts.find({}, {'_id': 0}).sort('locket_id', 1).skip(0).limit(skip + limit).to_list(length=skip + limit)
    v1_map = {
        r['locket_id']: r
        for r in (v1_rows if isinstance(v1_rows, list) else [])
        if isinstance(r, dict) and isinstance(r.get('locket_id'), str)
    }

    v2_map = {}
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if accounts_v2 is not None and hasattr(accounts_v2, 'find'):
        v2_cursor = accounts_v2.find({}, {'_id': 0})
        if hasattr(v2_cursor, 'sort'):
            v2_cursor = v2_cursor.sort('locket_id', 1)
        if hasattr(v2_cursor, 'skip'):
            v2_cursor = v2_cursor.skip(0)
        if hasattr(v2_cursor, 'limit'):
            v2_cursor = v2_cursor.limit(skip + limit)
        if hasattr(v2_cursor, 'to_list'):
            v2_res = v2_cursor.to_list(length=skip + limit)
            if hasattr(v2_res, '__await__'):
                v2_list = await v2_res
                if isinstance(v2_list, list):
                    v2_map = {
                        item['locket_id']: item
                        for item in v2_list
                        if isinstance(item, dict) and isinstance(item.get('locket_id'), str)
                    }

    all_ids = sorted(set(v1_map.keys()) | set(v2_map.keys()))
    page_ids = all_ids[skip: skip + limit]
    device_counts = {}
    devices = getattr(request.app.state, 'devices', None)
    if devices is not None and hasattr(devices, 'aggregate'):
        cursor = await devices.aggregate([
            {'$match': {'status': 'active', '$or': [{'canonical_locket_id': {'$in': page_ids}},
                                                    {'locket_id': {'$in': page_ids}}]}},
            {'$group': {'_id': {'$ifNull': ['$canonical_locket_id', '$locket_id']}, 'count': {'$sum': 1}}},
        ])
        async for item in cursor:
            device_counts[item['_id']] = item['count']
    result = []
    for lid in page_ids:
        merged = merge_canonical_and_legacy_account(v2_map.get(lid), v1_map.get(lid))
        if merged is not None:
            row = format_account_record(merged, now)
            row['active_devices'] = device_counts.get(lid, 0)
            effective = await effective_gold_account(request, merged, row['firebase_uid'] or lid, now)
            row['status'], _ = compute_entitlement_status(effective, now)
            result.append(row)
    return result


@admin_router.post('/accounts/{account_id}/revoke', response_model=AccountOutput)
async def revoke_account(
    account_id: AccountId,
    data: RevokeAccountInput,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    existing = await find_canonical_account(request, account_id, accounts_col=accounts)
    if existing is None:
        raise HTTPException(404, 'Account not found')

    now = datetime.now(timezone.utc)
    past_expiry = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    eff_expiry = existing.get('expires_date') or past_expiry
    canonical_lid = str(existing.get('locket_id') or account_id)
    fb_uid, uid_verified, *_ = extract_verified_uid_metadata(existing)
    entitlement_uid = fb_uid if (uid_verified and fb_uid) else canonical_lid

    # Update canonical accounts_v2, legacy accounts, and entitlements (never swallow errors!)
    async with account_write_options(request) as options:
        await accounts.update_one(
            {'locket_id': canonical_lid},
            {'$set': {'status': 'revoked', 'revoked_at': now, 'revoke_reason': data.reason}},
            **options,
        )
        accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
        if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
            res = accounts_v2.update_one(
                {'locket_id': canonical_lid},
                {
                    '$set': {
                        'locket_id': canonical_lid,
                        'account_id': entitlement_uid,
                        'status': 'revoked',
                        'expires_date': eff_expiry,
                        'revoked_at': now,
                        'revoke_reason': data.reason,
                        'updated_at': now,
                        'updated_by': admin.get('email', 'superadmin'),
                    }
                },
                upsert=True,
                **options,
            )
            if hasattr(res, '__await__'):
                await res

        entitlements = getattr(request.app.state, 'entitlements', None)
        if entitlements is not None and hasattr(entitlements, 'update_one'):
            res = entitlements.update_one(
                {'account_id': entitlement_uid, 'entitlement_key': 'Gold'},
                {
                    '$set': {
                        'account_id': entitlement_uid,
                        'locket_id': canonical_lid,
                        'entitlement_key': 'Gold',
                        'status': 'revoked',
                        'revoked_at': now,
                        'updated_at': now,
                    }
                },
                upsert=True,
                **options,
            )
            if hasattr(res, '__await__'):
                await res
            if canonical_lid != entitlement_uid and hasattr(entitlements, 'delete_many'):
                del_res = entitlements.delete_many({'account_id': canonical_lid}, **options)
                if hasattr(del_res, '__await__'):
                    await del_res

    await record_audit(
        request,
        admin,
        'ENTITLEMENT_REVOKE',
        entitlement_uid,
        {'locket_id': canonical_lid, 'firebase_uid': fb_uid, 'reason': data.reason},
    )
    updated = {
        **existing,
        'locket_id': canonical_lid,
        'account_id': entitlement_uid,
        'expires_date': eff_expiry,
        'status': 'revoked',
        'revoked_at': now,
        'revoke_reason': data.reason,
    }
    return format_account_record(updated, now)


@admin_router.post('/accounts/{account_id}/activate', response_model=AccountOutput)
async def activate_account(
    account_id: AccountId,
    data: ActivateAccountInput,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    existing = await find_canonical_account(request, account_id, accounts_col=accounts)
    if existing is None:
        raise HTTPException(404, 'Account not found')

    canonical_lid = str(existing.get('locket_id') or account_id)
    fb_uid, uid_verified, *_ = extract_verified_uid_metadata(existing)
    if not uid_verified or not fb_uid:
        raise HTTPException(
            409,
            'Không thể kích hoạt Gold cho tài khoản chưa có Firebase UID đã xác minh (status: pending).',
        )

    now = datetime.now(timezone.utc)
    new_expiry = data.expires_date or existing.get('expires_date')
    if new_expiry is None or new_expiry <= now:
        raise HTTPException(422, 'expires_date must be in the future')
    if getattr(request.app.state, 'entitlements', None) is None:
        raise HTTPException(503, 'Entitlement storage unavailable')
    revision = {}
    if getattr(request.app.state, 'transactions_supported', None) is False or existing.get('grant_revision'):
        revision = {'grant_revision': str(uuid4())}

    async with account_write_options(request) as options:
        await accounts.update_one(
            {'locket_id': canonical_lid},
            {'$set': {'expires_date': new_expiry, 'status': 'active', 'revoked_at': None, 'revoke_reason': None}},
            **options,
        )
        accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
        if accounts_v2 is not None and hasattr(accounts_v2, 'update_one'):
            res = accounts_v2.update_one(
                {'locket_id': canonical_lid},
                {
                    '$set': {
                        'locket_id': canonical_lid,
                        'account_id': fb_uid,
                        **revision,
                        'status': 'active',
                        'activated_at': now,
                        'expires_date': new_expiry,
                        'revoked_at': None,
                        'revoke_reason': None,
                        'updated_at': now,
                        'updated_by': admin.get('email', 'superadmin'),
                    }
                },
                upsert=True,
                **options,
            )
            if hasattr(res, '__await__'):
                await res

        entitlements = getattr(request.app.state, 'entitlements', None)
        if entitlements is not None and hasattr(entitlements, 'update_one'):
            res = entitlements.update_one(
                {'account_id': fb_uid, 'entitlement_key': 'Gold'},
                {
                    '$set': {
                        'account_id': fb_uid,
                        **revision,
                        'locket_id': canonical_lid,
                        'entitlement_key': 'Gold',
                        'status': 'active',
                        'expires_date': new_expiry,
                        'revoked_at': None,
                        'updated_at': now,
                    }
                },
                upsert=True,
                **options,
            )
            if hasattr(res, '__await__'):
                await res
            if canonical_lid != fb_uid and hasattr(entitlements, 'delete_many'):
                del_res = entitlements.delete_many({'account_id': canonical_lid}, **options)
                if hasattr(del_res, '__await__'):
                    await del_res

    await record_audit(
        request,
        admin,
        'ENTITLEMENT_ACTIVATE',
        fb_uid,
        {'locket_id': canonical_lid, 'firebase_uid': fb_uid, 'expires_date': new_expiry.isoformat()},
    )
    updated = {
        **existing,
        'locket_id': canonical_lid,
        'account_id': fb_uid,
        'expires_date': new_expiry,
        'status': 'active',
        'revoked_at': None,
    }
    return format_account_record(updated, now)


@admin_router.delete('/accounts/{account_id}', status_code=204)
async def delete_account(
    account_id: AccountId,
    request: Request,
    accounts: Accounts,
    admin: Annotated[dict, Depends(require_admin)],
):
    existing = await find_canonical_account(request, account_id, accounts_col=accounts)
    if existing is None:
        raise HTTPException(404, 'Account not found')
    lid = existing['locket_id']
    uid, verified, *_ = extract_verified_uid_metadata(existing)
    await record_audit(request, admin, 'ACCOUNT_DELETE_REQUESTED', lid)
    async with account_write_options(request) as options:
        devices = getattr(request.app.state, 'devices', None)
        if devices is not None and hasattr(devices, 'update_many'):
            await devices.update_many({'$or': [{'locket_id': lid}, {'canonical_locket_id': lid}]},
                                      {'$set': {'status': 'revoked', 'revoked_at': datetime.now(timezone.utc)},
                                       '$unset': {'slot_index': ''}}, **options)
        grants = getattr(request.app.state, 'entitlements', None)
        if grants is not None:
            for key in {lid, uid if verified else lid}:
                await grants.delete_many({'account_id': key, 'entitlement_key': 'Gold',
                                          '$or': [{'locket_id': lid}, {'locket_id': {'$exists': False}}]}, **options)
            await grants.delete_many({'locket_id': lid, 'entitlement_key': 'Gold'}, **options)
        await accounts.delete_one({'locket_id': lid}, **options)
        canonical = getattr(request.app.state, 'accounts_v2', None)
        if canonical is not None:
            await canonical.delete_one({'locket_id': lid}, **options)

    await record_audit(request, admin, 'ACCOUNT_DELETE', lid, {'firebase_uid': uid})
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
    await devices.update_one(
        {'device_id': device_id},
        {'$set': {'status': 'revoked', 'revoked_at': now}, '$unset': {'slot_index': ''}},
    )
    doc['status'] = 'revoked'
    doc['revoked_at'] = now
    doc.pop('slot_index', None)
    await record_audit(request, admin, 'DEVICE_REVOKE', doc.get('locket_id', device_id), {'device_id': device_id})
    return doc


@admin_router.post('/devices/{device_id}/profile-ticket', response_model=ProfileTicketOutput)
async def create_admin_device_profile_ticket(
    device_id: str,
    request: Request,
    admin: Annotated[dict, Depends(require_admin)],
    mode: Literal['default', 'dns_only', 'lab_ca', 'scoped_lab'] | None = Query(None),
    data: ProfileTicketInput | None = None,
):
    """Admin endpoint to issue a short-lived one-time Safari `.mobileconfig` download ticket for an enrolled device."""
    devices = getattr(request.app.state, 'devices', None)
    if devices is None:
        raise HTTPException(503, 'Device service unavailable')
    doc = await devices.find_one({'device_id': device_id}, {'_id': 0})
    if not isinstance(doc, dict):
        raise HTTPException(404, 'Device not found')
    if doc.get('status') != 'active':
        raise HTTPException(409, 'Cannot issue download ticket for a revoked device')
    eff_mode = (data.mode if data is not None else None) or (mode if isinstance(mode, str) else None) or 'scoped_lab'
    eff_ttl = data.ttl_seconds if data is not None else 300
    ticket_info = await issue_profile_download_ticket(request, device_doc=doc, mode=eff_mode, ttl_seconds=eff_ttl)
    await record_audit(
        request,
        admin,
        'DEVICE_PROFILE_TICKET_ISSUE',
        doc.get('locket_id', device_id),
        {'device_id': device_id, 'mode': eff_mode},
    )
    return ticket_info


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

