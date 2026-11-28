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
    Strictly evaluates the requested `app_user_id` against the MongoDB Single Source of Truth
    (never grants Gold to unknown, expired, or revoked accounts).
    """
    import json
    import re
    from ..models import ACCOUNT_ID_REGEX

    raw_body = await request.body()
    parsed_body = {}
    if raw_body:
        try:
            parsed_body = json.loads(raw_body.decode('utf-8'))
        except Exception:
            parsed_body = {}

    candidate_id = ''
    if isinstance(parsed_body, dict):
        candidate_id = str(
            parsed_body.get('app_user_id')
            or parsed_body.get('locket_id')
            or parsed_body.get('uid')
            or ''
        ).strip()
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

    return await _resolve_account_and_build_response(
        candidate_id, request, accounts, inspect_source='v1_receipts'
    )


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
