from datetime import datetime, timezone
import time
from typing import Annotated
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from ..config import get_settings
from ..database import get_accounts
from ..models import AccountId, LabGoldFeatures, compute_entitlement_status, subscriber_response
from ..security import require_subscriber_access
from ..services.doh_service import decode_base64url_dns_param, resolve_lab_dns_wireformat
from ..services.entitlement_service import effective_gold_account, find_canonical_account
from ..services.lab_inspector_service import redact_headers, redact_payload

router = APIRouter(tags=["Subscribers"])
Accounts = Annotated[object, Depends(get_accounts)]


@router.get('/api/lab/accounts/{account_id}/features', dependencies=[Depends(require_subscriber_access)])
async def lab_features(account_id: AccountId, request: Request, accounts: Accounts):
    account = await find_canonical_account(request, account_id, accounts_col=accounts)
    now = datetime.now(timezone.utc)
    effective = await effective_gold_account(request, account, account_id, now)
    status, _ = compute_entitlement_status(effective, now)
    flags = LabGoldFeatures.model_validate(account.get('lab_features', {})) if status == 'active' else LabGoldFeatures()
    return {'status': status, 'gold': {'enabled': status == 'active', **flags.model_dump()}}


def _map_api_state_label(status: str) -> str:
    """Map internal EntitlementStatus ('unauthorized') to explicit 'none' label alongside active/expired/revoked."""
    if status == 'unauthorized':
        return 'none'
    return status


async def _resolve_account_and_build_response(
    account_id: str,
    request: Request,
    accounts,
    *,
    inspect_source: str = 'v1_subscribers',
) -> JSONResponse:
    started = time.perf_counter()
    account = await find_canonical_account(request, account_id, accounts_col=accounts)

    now = datetime.now(timezone.utc)
    eff_account = await effective_gold_account(request, account, account_id, now)
    status, _ = compute_entitlement_status(eff_account, now)
    state_label = _map_api_state_label(status)
    payload = subscriber_response(account_id, eff_account, now)
    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)

    resp_headers = {
        'X-Lab-Entitlement-Status': status,
        'X-Lab-Entitlement-State': state_label,
    }

    lab_requests = getattr(request.app.state, 'lab_requests', None)
    if lab_requests is not None and hasattr(lab_requests, 'insert_one'):
        device_doc = getattr(request.state, 'device_doc', None)
        try:
            res = lab_requests.insert_one({
                'request_id': str(uuid4()),
                'timestamp': now,
                'source': inspect_source,
                'endpoint': request.url.path,
                'method': request.method,
                'account_id': account_id,
                'device_id': device_doc.get('device_id') if isinstance(device_doc, dict) else None,
                'caller_kind': getattr(request.state, 'caller_kind', 'unknown'),
                'computed_status': status,
                'entitlement_state': state_label,
                'http_status': 200,
                'latency_ms': latency_ms,
                'request_headers': redact_headers(dict(request.headers)),
                'response_headers': redact_headers(resp_headers),
                'response_body': redact_payload(payload),
            })
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    return JSONResponse(content=payload, headers=resp_headers)


@router.get('/v1/subscribers/{account_id}', dependencies=[Depends(require_subscriber_access)])
@router.post('/v1/subscribers/{account_id}', dependencies=[Depends(require_subscriber_access)])
async def subscriber(account_id: AccountId, request: Request, accounts: Accounts):
    return await _resolve_account_and_build_response(
        account_id, request, accounts, inspect_source='v1_subscribers'
    )


@router.get('/api/lab/subscribers/{account_id}', dependencies=[Depends(require_subscriber_access)])
@router.post('/api/lab/subscribers/{account_id}', dependencies=[Depends(require_subscriber_access)])
async def lab_subscriber_inspect(account_id: AccountId, request: Request, accounts: Accounts):
    """Controlled HTTPS Research Lab endpoint for testing subscription entitlement states and logging."""
    return await _resolve_account_and_build_response(
        account_id, request, accounts, inspect_source='https_research_lab'
    )


@router.post('/v1/receipts', dependencies=[Depends(require_subscriber_access)])
@router.post('/api/lab/receipts', dependencies=[Depends(require_subscriber_access)])
async def subscriber_receipts(request: Request, accounts: Accounts):
    """
    RevenueCat-compatible `/v1/receipts` endpoint for Research Lab testing.
    - When a signed StoreKit 2 JWS transaction (`jws_transaction`, `signed_transaction_info`, or 3-part JWS `fetch_token`)
      is supplied, cryptographically verifies its ES256 signature and synchronizes the verified transaction state
      (`active`, `expired`, or `revoked`) into the MongoDB Single Source of Truth.
    - Supports `is_restore: true` (Restore Purchases) and evaluates `app_user_id` against MongoDB SSOT.
    """
    from datetime import timedelta
    import json
    import re
    from ..models import ACCOUNT_ID_REGEX
    from ..services.payment_service import (
        apply_verified_payment_state_to_ssot,
        get_or_create_sandbox_storekit_key,
        verify_storekit2_sandbox_jws,
    )

    raw_body = await request.body()
    parsed_body = {}
    if raw_body:
        try:
            parsed_body = json.loads(raw_body.decode('utf-8'))
        except Exception:
            parsed_body = {}

    jws_candidate = ''
    is_restore = False
    if isinstance(parsed_body, dict):
        is_restore = bool(parsed_body.get('is_restore'))
        raw_jws = (
            parsed_body.get('jws_transaction')
            or parsed_body.get('signed_transaction_info')
            or ''
        )
        if isinstance(raw_jws, str) and raw_jws.strip():
            jws_candidate = raw_jws.strip()
        else:
            ft = parsed_body.get('fetch_token')
            if isinstance(ft, str) and ft.strip().count('.') == 2:
                jws_candidate = ft.strip()

    jws_payload = None
    if jws_candidate:
        sk_key = get_or_create_sandbox_storekit_key(request.app.state)
        trusted_root_ca = getattr(request.app.state, 'storekit_trusted_root_ca', None)
        try:
            jws_payload = verify_storekit2_sandbox_jws(
                jws_candidate,
                trusted_public_key=sk_key.public_key(),
                trusted_root_ca_cert=trusted_root_ca,
            )
        except ValueError as exc:
            raise HTTPException(422, f'Invalid StoreKit 2 JWS transaction: {exc}') from exc

    candidate_id = ''
    if isinstance(parsed_body, dict):
        candidate_id = str(
            parsed_body.get('app_user_id')
            or parsed_body.get('locket_id')
            or parsed_body.get('uid')
            or ''
        ).strip()
    if not candidate_id and isinstance(jws_payload, dict):
        candidate_id = str(jws_payload.get('app_user_id') or jws_payload.get('appAccountToken') or '').strip()
    if not candidate_id:
        candidate_id = (
            request.headers.get('X-RevenueCat-User-Id')
            or request.headers.get('x-revenuecat-user-id')
            or request.query_params.get('app_user_id')
            or ''
        ).strip()

    if not candidate_id or not re.fullmatch(ACCOUNT_ID_REGEX, candidate_id):
        raise HTTPException(422, 'Valid app_user_id is required in receipt payload or X-RevenueCat-User-Id header')

    device_doc = getattr(request.state, 'device_doc', None)
    if getattr(request.state, 'caller_kind', None) == 'device_token' and isinstance(device_doc, dict):
        allowed_ids = {
            device_doc.get('locket_id'),
            device_doc.get('firebase_uid'),
            device_doc.get('canonical_locket_id'),
        } - {None, ''}
        if candidate_id not in allowed_ids:
            raise HTTPException(403, 'Device token is not authorized to query receipts for another account')

    if isinstance(jws_payload, dict):
        jws_uid = str(jws_payload.get('app_user_id') or jws_payload.get('appAccountToken') or candidate_id).strip()
        if jws_uid != candidate_id:
            raise HTTPException(422, 'StoreKit 2 JWS appAccountToken does not match requested app_user_id')
        p_ms = int(jws_payload['purchaseDate'])
        e_ms = int(jws_payload['expiresDate'])
        r_ms = jws_payload.get('revocationDate')
        s_ms = jws_payload.get('signedDate')
        await apply_verified_payment_state_to_ssot(
            request,
            accounts,
            app_user_id=candidate_id,
            product_id=str(jws_payload.get('productId') or 'com.locket.gold.yearly'),
            transaction_id=str(jws_payload.get('transactionId') or ''),
            original_transaction_id=str(jws_payload.get('originalTransactionId') or ''),
            purchase_dt=datetime.fromtimestamp(p_ms / 1000.0, tz=timezone.utc),
            expires_dt=datetime.fromtimestamp(e_ms / 1000.0, tz=timezone.utc),
            revoked_dt=datetime.fromtimestamp(int(r_ms) / 1000.0, tz=timezone.utc) if r_ms is not None else None,
            environment=str(jws_payload.get('environment') or 'Sandbox'),
            event_source='STOREKIT2_JWS_RESTORE' if is_restore else 'STOREKIT2_JWS_RECEIPT',
            trust_anchor=str(jws_payload.get('_trust_anchor') or 'lab_internal_sandbox_key'),
            payment_trust_level=str(jws_payload.get('_payment_trust_level') or 'lab_simulated_jws'),
            event_timestamp_ms=int(s_ms) if s_ms is not None else None,
        )

    resp = await _resolve_account_and_build_response(
        candidate_id,
        request,
        accounts,
        inspect_source='v1_receipts_restore' if is_restore else 'v1_receipts',
    )
    if is_restore:
        resp.headers['X-RevenueCat-Restored'] = 'true'
    if jws_payload is not None:
        resp.headers['X-StoreKit-Verified'] = 'true'
        resp.headers['X-StoreKit-Trust-Level'] = str(jws_payload.get('_payment_trust_level') or 'lab_simulated_jws')
    return resp


@router.post('/api/lab/storekit/sandbox-transaction', dependencies=[Depends(require_subscriber_access)])
async def create_storekit2_sandbox_transaction(request: Request, accounts: Accounts):
    """
    Generate an ES256-signed StoreKit 2 Sandbox/Xcode JWS transaction for authorized payment & subscription lifecycle testing:
    Supports `action`: `'purchase'`, `'renew'`, `'expire'`, `'revoke'`.
    """
    from datetime import timedelta
    import json
    from ..services.payment_service import (
        get_or_create_sandbox_storekit_key,
        sign_storekit2_sandbox_jws,
    )

    if getattr(request.state, 'caller_kind', None) not in {'admin_session', 'service_token'}:
        raise HTTPException(403, 'Sandbox StoreKit transaction minting requires admin session or service token')

    raw_body = await request.body()
    body = json.loads(raw_body.decode('utf-8')) if raw_body else {}
    app_user_id = str(body.get('app_user_id') or body.get('firebase_uid') or '').strip()
    product_id = str(body.get('product_id') or 'com.locket.gold.yearly').strip()
    action = str(body.get('action') or 'purchase').strip().lower()
    environment = 'Xcode' if str(body.get('environment') or '').strip() == 'Xcode' else 'Sandbox'
    duration_days = int(body.get('duration_days') or 365)

    now = datetime.now(timezone.utc)
    if action == 'expire':
        purchase_dt = now - timedelta(days=duration_days + 5)
        expires_dt = now - timedelta(seconds=60)
        revoked_dt = None
    elif action == 'revoke':
        purchase_dt = now - timedelta(days=1)
        expires_dt = now + timedelta(days=duration_days)
        revoked_dt = now
    else:
        purchase_dt = now
        expires_dt = now + timedelta(days=duration_days)
        revoked_dt = None

    sk_key = get_or_create_sandbox_storekit_key(request.app.state)
    jws_token, payload = sign_storekit2_sandbox_jws(
        sk_key,
        app_user_id=app_user_id,
        product_id=product_id,
        purchase_date=purchase_dt,
        expires_date=expires_dt,
        revocation_date=revoked_dt,
        environment=environment,
    )
    return {
        'jws_transaction': jws_token,
        'decoded_payload': payload,
        'action': action,
        'environment': environment,
    }


@router.post('/api/webhooks/revenuecat', dependencies=[Depends(require_subscriber_access)])
async def revenuecat_server_webhook(request: Request, accounts: Accounts):
    """
    Authenticated RevenueCat Server-to-Server Webhook receiver for synchronizing subscription lifecycle events:
    `INITIAL_PURCHASE`, `RENEWAL`, `UNCANCELLATION`, `EXPIRATION`, `CANCELLATION`, `BILLING_ISSUE`.
    """
    from datetime import timedelta
    import json
    from ..services.payment_service import (
        _get_webhook_event_registry,
        apply_verified_payment_state_to_ssot,
    )

    if getattr(request.state, 'caller_kind', None) not in {'admin_session', 'service_token'}:
        raise HTTPException(403, 'RevenueCat server webhook requires service token or admin authorization')

    started = time.perf_counter()
    raw_body = await request.body()
    try:
        body = json.loads(raw_body.decode('utf-8')) if raw_body else {}
    except Exception as exc:
        raise HTTPException(400, 'Malformed webhook JSON payload') from exc

    event = body.get('event') if isinstance(body.get('event'), dict) else body
    if not isinstance(event, dict):
        raise HTTPException(422, 'Missing RevenueCat event object')

    event_type = str(event.get('type') or '').strip().upper()
    valid_types = {'INITIAL_PURCHASE', 'RENEWAL', 'UNCANCELLATION', 'EXPIRATION', 'CANCELLATION', 'BILLING_ISSUE'}
    if event_type not in valid_types:
        raise HTTPException(422, f"Unsupported RevenueCat webhook event type '{event_type}'")

    explicit_event_id = str(event.get('id') or '').strip()
    wh_reg = _get_webhook_event_registry(request.app.state)
    if explicit_event_id and explicit_event_id in wh_reg:
        return {
            'received': True,
            'duplicate': True,
            'event_id': explicit_event_id,
            'event_type': event_type,
            'synced': wh_reg[explicit_event_id],
        }

    app_user_id = str(event.get('app_user_id') or event.get('original_app_user_id') or '').strip()
    product_id = str(event.get('product_id') or 'com.locket.gold.yearly').strip()
    tx_id = str(event.get('transaction_id') or explicit_event_id or f'rc_{uuid4().hex[:12]}').strip()
    orig_tx_id = str(event.get('original_transaction_id') or tx_id).strip()
    env_raw = str(event.get('environment') or 'SANDBOX').strip().upper()
    environment = 'Sandbox' if env_raw == 'SANDBOX' else 'Production'

    now = datetime.now(timezone.utc)
    p_ms = event.get('purchased_at_ms')
    e_ms = event.get('expiration_at_ms')
    evt_ts_ms = event.get('event_timestamp_ms')
    purchase_dt = datetime.fromtimestamp(int(p_ms) / 1000.0, tz=timezone.utc) if p_ms else now
    if e_ms:
        expires_dt = datetime.fromtimestamp(int(e_ms) / 1000.0, tz=timezone.utc)
    elif event_type == 'EXPIRATION':
        expires_dt = now - timedelta(seconds=10)
    else:
        expires_dt = now + timedelta(days=365)

    revoked_dt = now if event_type == 'CANCELLATION' else None

    synced = await apply_verified_payment_state_to_ssot(
        request,
        accounts,
        app_user_id=app_user_id,
        product_id=product_id,
        transaction_id=tx_id,
        original_transaction_id=orig_tx_id,
        purchase_dt=purchase_dt,
        expires_dt=expires_dt,
        revoked_dt=revoked_dt,
        environment=environment,
        event_source=f'REVENUECAT_WEBHOOK_{event_type}',
        trust_anchor='revenuecat_webhook_token',
        payment_trust_level='webhook_authenticated',
        event_timestamp_ms=int(evt_ts_ms) if evt_ts_ms is not None else None,
    )
    if explicit_event_id:
        wh_reg[explicit_event_id] = synced
    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)

    lab_requests = getattr(request.app.state, 'lab_requests', None)
    if lab_requests is not None and hasattr(lab_requests, 'insert_one'):
        try:
            res = lab_requests.insert_one({
                'request_id': str(uuid4()),
                'timestamp': now,
                'source': 'revenuecat_webhook',
                'endpoint': request.url.path,
                'method': 'POST',
                'account_id': app_user_id,
                'event_type': event_type,
                'computed_status': synced['status'],
                'http_status': 200,
                'latency_ms': latency_ms,
            })
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    return {'received': True, 'event_type': event_type, 'synced': synced}


@router.post('/api/lab/inspect', dependencies=[Depends(require_subscriber_access)])
async def lab_echo_inspect(request: Request):
    """
    Controlled HTTPS Research Lab traffic recorder.
    Records request headers, redacted body, TLS scheme, and returns a structured diagnostic payload.
    """
    started = time.perf_counter()
    now = datetime.now(timezone.utc)
    req_id = str(uuid4())
    raw_body = await request.body()
    parsed_body = {}
    if raw_body:
        try:
            import json
            parsed_body = json.loads(raw_body.decode('utf-8'))
        except Exception:
            parsed_body = {'raw_length': len(raw_body)}

    device_doc = getattr(request.state, 'device_doc', None)
    if getattr(request.state, 'caller_kind', None) == 'device_token' and isinstance(device_doc, dict):
        body_account_id = parsed_body.get('locket_id') if isinstance(parsed_body, dict) else None
        allowed_ids = {
            device_doc.get('locket_id'),
            device_doc.get('firebase_uid'),
            device_doc.get('canonical_locket_id'),
        } - {None, ''}
        if body_account_id and body_account_id not in allowed_ids:
            from fastapi import HTTPException
            raise HTTPException(403, 'Device token is not authorized to inspect another account')

    redacted_req_headers = redact_headers(dict(request.headers))
    redacted_req_body = redact_payload(parsed_body)

    resp_payload = {
        'request_id': req_id,
        'timestamp': now.isoformat().replace('+00:00', 'Z'),
        'service': 'LocketGold HTTPS Research Lab Inspector',
        'tls_scheme': request.url.scheme,
        'host': request.headers.get('host', ''),
        'caller_kind': getattr(request.state, 'caller_kind', 'unknown'),
        'device_id': device_doc.get('device_id') if isinstance(device_doc, dict) else None,
        'recorded_request_headers': redacted_req_headers,
        'recorded_request_body': redacted_req_body,
    }
    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)

    lab_requests = getattr(request.app.state, 'lab_requests', None)
    if lab_requests is not None and hasattr(lab_requests, 'insert_one'):
        try:
            res = lab_requests.insert_one({
                'request_id': req_id,
                'timestamp': now,
                'source': 'https_lab_echo',
                'endpoint': request.url.path,
                'method': request.method,
                'account_id': parsed_body.get('locket_id') if isinstance(parsed_body, dict) else None,
                'device_id': device_doc.get('device_id') if isinstance(device_doc, dict) else None,
                'caller_kind': getattr(request.state, 'caller_kind', 'unknown'),
                'computed_status': 'inspected',
                'entitlement_state': 'inspected',
                'http_status': 200,
                'latency_ms': latency_ms,
                'request_headers': redacted_req_headers,
                'request_body': redacted_req_body,
                'response_body': redact_payload(resp_payload),
            })
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass

    return JSONResponse(content=resp_payload)


async def _record_doh_lab_request(
    request: Request,
    *,
    method: str,
    device_label: str | None,
    meta: dict,
    latency_ms: float,
) -> None:
    lab_requests = getattr(request.app.state, 'lab_requests', None)
    if lab_requests is not None and hasattr(lab_requests, 'insert_one'):
        try:
            res = lab_requests.insert_one({
                'request_id': str(uuid4()),
                'timestamp': datetime.now(timezone.utc),
                'source': 'doh_gateway',
                'endpoint': request.url.path,
                'method': method,
                'device_id': device_label,
                'qname': meta.get('qname'),
                'qtype': meta.get('qtype'),
                'rcode': meta.get('rcode'),
                'answer_ip': meta.get('answer_ip'),
                'http_status': 200,
                'latency_ms': latency_ms,
            })
            if hasattr(res, '__await__'):
                await res
        except Exception:
            pass


@router.get('/dns-query')
@router.get('/dns-query/{device_label}')
async def doh_get_query(
    request: Request,
    dns: str | None = Query(None, max_length=1024),
    name: str | None = Query(None, max_length=253),
    type: str = Query('A', max_length=16),
    device_label: str | None = None,
):
    """
    Controlled Research Lab DNS-over-HTTPS (RFC 8484 GET & JSON) Endpoint.
    Only resolves domains explicitly listed in `settings.lab_scoped_domains`.
    Refuses all external/third-party domains (`REFUSED`) so it never acts as an open DNS proxy.
    """
    started = time.perf_counter()
    settings = get_settings()
    ttl = 60
    if dns is not None:
        try:
            packet = decode_base64url_dns_param(dns)
            resp_bytes, meta = resolve_lab_dns_wireformat(
                packet,
                allowed_domains=settings.lab_scoped_domains,
                target_ipv4=settings.lab_dns_target_ip,
                target_ipv6=getattr(settings, 'lab_dns_target_ipv6', ''),
                ttl=ttl,
            )
        except Exception as exc:
            raise HTTPException(400, 'Malformed RFC 8484 DNS query packet') from exc
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        await _record_doh_lab_request(
            request, method='GET', device_label=device_label, meta=meta, latency_ms=latency_ms
        )
        cache_hdr = f'max-age={ttl}' if meta.get('rcode') == 'NOERROR' else 'no-store'
        return Response(
            content=resp_bytes,
            media_type='application/dns-message',
            headers={
                'Cache-Control': cache_hdr,
                'X-DoH-Rcode': str(meta.get('rcode') or 'UNKNOWN'),
                'X-DoH-Latency-Ms': str(latency_ms),
            },
        )

    if name is not None:
        qname = name.strip().lower().rstrip('.')
        if not qname or len(qname) > 253 or any(ch in qname for ch in (' ', '/', '\\', '\x00', '?')):
            raise HTTPException(400, 'Malformed DNS query name')
        qtype_upper = type.strip().upper()
        type_map = {
            'A': 1, '1': 1,
            'AAAA': 28, '28': 28,
            'CNAME': 5, '5': 5,
            'TXT': 16, '16': 16,
            'SVCB': 64, '64': 64,
            'HTTPS': 65, '65': 65,
        }
        if qtype_upper not in type_map:
            raise HTTPException(400, 'Unsupported or malformed DNS query type')
        qtype_num = type_map[qtype_upper]
        allowed_set = {d.strip().lower().rstrip('.') for d in settings.lab_scoped_domains if d.strip()}
        if qname not in allowed_set:
            latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
            await _record_doh_lab_request(
                request,
                method='GET_JSON',
                device_label=device_label,
                meta={'qname': qname, 'qtype': qtype_num, 'rcode': 'REFUSED', 'answer_ip': None},
                latency_ms=latency_ms,
            )
            return JSONResponse(
                status_code=200,
                headers={'Cache-Control': 'no-store', 'X-DoH-Rcode': 'REFUSED', 'X-DoH-Latency-Ms': str(latency_ms)},
                content={'Status': 5, 'Comment': 'REFUSED: Domain outside controlled Research Lab scope', 'Question': [{'name': qname, 'type': qtype_num}], 'Answer': []},
            )
        target_v6 = getattr(settings, 'lab_dns_target_ipv6', '').strip()
        answer_ip = None
        if qtype_num == 1:
            answer_ip = settings.lab_dns_target_ip
            answers = [{'name': qname, 'type': 1, 'TTL': ttl, 'data': settings.lab_dns_target_ip}]
        elif qtype_num == 28 and target_v6:
            answer_ip = target_v6
            answers = [{'name': qname, 'type': 28, 'TTL': ttl, 'data': target_v6}]
        else:
            answers = []
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        rcode_str = 'NOERROR' if answers else 'NOERROR_NODATA'
        await _record_doh_lab_request(
            request,
            method='GET_JSON',
            device_label=device_label,
            meta={'qname': qname, 'qtype': qtype_num, 'rcode': rcode_str, 'answer_ip': answer_ip},
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=200,
            headers={
                'Cache-Control': f'max-age={ttl}' if answers else 'no-store',
                'X-DoH-Rcode': rcode_str,
                'X-DoH-Latency-Ms': str(latency_ms),
            },
            content={
                'Status': 0,
                'TC': False,
                'RD': True,
                'RA': True,
                'AD': False,
                'CD': False,
                'LabMode': getattr(settings, 'lab_mode', 'local'),
                'LatencyMs': latency_ms,
                'Question': [{'name': qname, 'type': qtype_num}],
                'Answer': answers,
            },
        )
    raise HTTPException(400, 'Provide either RFC 8484 ?dns=<base64url> or JSON ?name=<domain>')


@router.post('/dns-query')
@router.post('/dns-query/{device_label}')
async def doh_post_query(request: Request, device_label: str | None = None):
    """Controlled Research Lab DNS-over-HTTPS (RFC 8484 POST `application/dns-message`) Endpoint."""
    started = time.perf_counter()
    settings = get_settings()
    ttl = 60
    body = await request.body()
    try:
        resp_bytes, meta = resolve_lab_dns_wireformat(
            body,
            allowed_domains=settings.lab_scoped_domains,
            target_ipv4=settings.lab_dns_target_ip,
            target_ipv6=getattr(settings, 'lab_dns_target_ipv6', ''),
            ttl=ttl,
        )
    except Exception as exc:
        raise HTTPException(400, 'Malformed RFC 8484 DNS query packet') from exc
    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
    await _record_doh_lab_request(
        request, method='POST', device_label=device_label, meta=meta, latency_ms=latency_ms
    )
    cache_hdr = f'max-age={ttl}' if meta.get('rcode') == 'NOERROR' else 'no-store'
    return Response(
        content=resp_bytes,
        media_type='application/dns-message',
        headers={
            'Cache-Control': cache_hdr,
            'X-DoH-Rcode': str(meta.get('rcode') or 'UNKNOWN'),
            'X-DoH-Latency-Ms': str(latency_ms),
        },
    )
