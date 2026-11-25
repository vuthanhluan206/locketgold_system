from datetime import datetime, timezone
import re
from typing import Any

SENSITIVE_HEADER_KEYS = {
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-admin-token',
    'cf-turnstile-response',
}

SENSITIVE_BODY_KEYS = {
    'password',
    'password_hash',
    'access_token',
    'refresh_token',
    'id_token',
    'device_token',
    'download_ticket',
    'ticket',
    'turnstile_token',
    'secret',
    'api_token',
    'token',
}

BEARER_TOKEN_REGEX = re.compile(r'(?i)\b(Bearer\s+)([A-Za-z0-9._\-~+/]+=*)')
TICKET_PARAM_REGEX = re.compile(r'(?i)([?&]ticket=)(lkg_dl_[A-Za-z0-9_\-]+)')


def mask_token_string(raw: str) -> str:
    """Mask a secret token while keeping a tiny diagnostic prefix."""
    cleaned = raw.strip()
    if len(cleaned) <= 8:
        return '***REDACTED***'
    return f'{cleaned[:6]}...***REDACTED***'


def redact_headers(headers: dict[str, Any] | Any) -> dict[str, str]:
    """Return a copy of HTTP headers with all credentials and session cookies masked."""
    redacted: dict[str, str] = {}
    if not headers:
        return redacted
    items = headers.items() if hasattr(headers, 'items') else []
    for k, v in items:
        key_str = str(k)
        key_lower = key_str.lower()
        val_str = str(v)
        if key_lower in SENSITIVE_HEADER_KEYS or 'token' in key_lower or 'secret' in key_lower or 'password' in key_lower:
            if val_str.lower().startswith('bearer '):
                token_part = val_str[7:].strip()
                redacted[key_str] = 'Bearer ' + mask_token_string(token_part)
            else:
                redacted[key_str] = '***REDACTED***'
        else:
            redacted[key_str] = BEARER_TOKEN_REGEX.sub(
                lambda m: m.group(1) + mask_token_string(m.group(2)),
                val_str,
            )
    return redacted


def redact_payload(data: Any) -> Any:
    """Recursively mask sensitive fields in request/response JSON payloads before storing in logs."""
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if key_lower in SENSITIVE_BODY_KEYS or 'password' in key_lower or 'secret' in key_lower:
                out[k] = '***REDACTED***' if not isinstance(v, str) else mask_token_string(v)
            else:
                out[k] = redact_payload(v)
        return out
    if isinstance(data, list):
        return [redact_payload(item) for item in data]
    if isinstance(data, str):
        masked = BEARER_TOKEN_REGEX.sub(lambda m: m.group(1) + mask_token_string(m.group(2)), data)
        return TICKET_PARAM_REGEX.sub(lambda m: m.group(1) + mask_token_string(m.group(2)), masked)
    return data
