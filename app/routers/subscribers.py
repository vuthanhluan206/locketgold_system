from datetime import datetime, timezone
import time
from typing import Annotated
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from ..config import get_settings
from ..database import get_accounts
from ..models import AccountId, compute_entitlement_status, subscriber_response
from ..security import require_subscriber_access
from ..services.doh_service import decode_base64url_dns_param, resolve_lab_dns_wireformat
from ..services.entitlement_service import find_canonical_account
from ..services.lab_inspector_service import redact_headers, redact_payload

router = APIRouter(tags=["Subscribers"])
Accounts = Annotated[object, Depends(get_accounts)]


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
    status, _ = compute_entitlement_status(account if isinstance(account, dict) else None, now)
    state_label = _map_api_state_label(status)
    payload = subscriber_response(account_id, account if isinstance(account, dict) else None, now)
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
async def subscriber(account_id: AccountId, request: Request, accounts: Accounts):
    return await _resolve_account_and_build_response(
        account_id, request, accounts, inspect_source='v1_subscribers'
    )


@router.get('/api/lab/subscribers/{account_id}', dependencies=[Depends(require_subscriber_access)])
async def lab_subscriber_inspect(account_id: AccountId, request: Request, accounts: Accounts):
    """Controlled HTTPS Research Lab endpoint for testing subscription entitlement states and logging."""
    return await _resolve_account_and_build_response(
        account_id, request, accounts, inspect_source='https_research_lab'
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
        if body_account_id and body_account_id != device_doc.get('locket_id'):
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
    settings = get_settings()
    if dns is not None:
        try:
            packet = decode_base64url_dns_param(dns)
            resp_bytes, _ = resolve_lab_dns_wireformat(
                packet,
                allowed_domains=settings.lab_scoped_domains,
                target_ipv4=settings.lab_dns_target_ip,
                target_ipv6=getattr(settings, 'lab_dns_target_ipv6', ''),
            )
        except Exception as exc:
            raise HTTPException(400, 'Malformed RFC 8484 DNS query packet') from exc
        return Response(content=resp_bytes, media_type='application/dns-message')

    if name is not None:
        qname = name.strip().lower().rstrip('.')
        allowed_set = {d.strip().lower().rstrip('.') for d in settings.lab_scoped_domains if d.strip()}
        if qname not in allowed_set:
            return JSONResponse(
                status_code=200,
                content={'Status': 5, 'Comment': 'REFUSED: Domain outside controlled Research Lab scope', 'Question': [{'name': qname, 'type': 1}], 'Answer': []},
            )
        qtype_upper = type.strip().upper()
        target_v6 = getattr(settings, 'lab_dns_target_ipv6', '').strip()
        if qtype_upper in {'A', '1'}:
            answers = [{'name': qname, 'type': 1, 'TTL': 60, 'data': settings.lab_dns_target_ip}]
            qtype_num = 1
        elif qtype_upper in {'AAAA', '28'} and target_v6:
            answers = [{'name': qname, 'type': 28, 'TTL': 60, 'data': target_v6}]
            qtype_num = 28
        else:
            answers = []
            qtype_num = 28 if qtype_upper in {'AAAA', '28'} else 65
        return JSONResponse(
            status_code=200,
            content={
                'Status': 0,
                'TC': False,
                'RD': True,
                'RA': True,
                'AD': False,
                'CD': False,
                'LabMode': getattr(settings, 'lab_mode', 'local'),
                'Question': [{'name': qname, 'type': qtype_num}],
                'Answer': answers,
            },
        )
    raise HTTPException(400, 'Provide either RFC 8484 ?dns=<base64url> or JSON ?name=<domain>')


@router.post('/dns-query')
@router.post('/dns-query/{device_label}')
async def doh_post_query(request: Request, device_label: str | None = None):
    """Controlled Research Lab DNS-over-HTTPS (RFC 8484 POST `application/dns-message`) Endpoint."""
    settings = get_settings()
    body = await request.body()
    try:
        resp_bytes, _ = resolve_lab_dns_wireformat(
            body,
            allowed_domains=settings.lab_scoped_domains,
            target_ipv4=settings.lab_dns_target_ip,
            target_ipv6=getattr(settings, 'lab_dns_target_ipv6', ''),
        )
    except Exception as exc:
        raise HTTPException(400, 'Malformed RFC 8484 DNS query packet') from exc
    return Response(content=resp_bytes, media_type='application/dns-message')
