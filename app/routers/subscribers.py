from datetime import datetime, timezone
import time
from typing import Annotated
from uuid import uuid4
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from ..database import get_accounts
from ..models import AccountId, compute_entitlement_status, subscriber_response
from ..security import require_subscriber_access
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
    account = await accounts.find_one({'locket_id': account_id}, {'_id': 0})
    accounts_v2 = getattr(request.app.state, 'accounts_v2', None)
    if accounts_v2 is not None:
        v2_doc = await accounts_v2.find_one({'locket_id': account_id}, {'_id': 0})
        if isinstance(v2_doc, dict):
            if isinstance(account, dict):
                merged = {**v2_doc}
                if 'expires_date' in account:
                    merged['expires_date'] = account['expires_date']
                account = merged
            else:
                account = v2_doc

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

    redacted_req_headers = redact_headers(dict(request.headers))
    redacted_req_body = redact_payload(parsed_body)
    device_doc = getattr(request.state, 'device_doc', None)

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
