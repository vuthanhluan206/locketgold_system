import asyncio
import json
import secrets
import urllib.error
import urllib.request
from urllib.parse import quote
from starlette.datastructures import Headers
from fastapi.encoders import jsonable_encoder
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .config import get_settings
from .routers.management import download_profile
from .security import token_digest

router = APIRouter(prefix="/proxy", tags=["Locket Proxy"])

UPSTREAM_TARGET = "http://127.0.0.1:8081"
FORBIDDEN_THIRD_PARTY_HOSTS = {
    "api.revenuecat.com",
    "buy.itunes.apple.com",
    "sandbox.itunes.apple.com",
}

HOP_HEADERS = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade',
}
MAX_RESPONSE = 50 * 1024 * 1024


def _clean_headers(headers):
    named = {key.strip().lower() for key in headers.get('connection', '').split(',')}
    return {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() not in HOP_HEADERS | named | {'content-length'}
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward credentials to another destination.
        return None


def _forward_upstream(url: str, body: bytes | None, headers: dict[str, str], method: str, timeout: float):
    req = urllib.request.Request(url, data=body if body else None, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        content = response.read(MAX_RESPONSE + 1)
        if len(content) > MAX_RESPONSE:
            raise ValueError('Upstream response exceeds limit')
        return response.code, dict(response.headers.items()), content


@router.get("/install", response_class=Response)
async def download_proxy_profile(request: Request):
    return await download_profile(request)


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def dynamic_reverse_proxy(request: Request, path: str):
    settings = get_settings()
    if not getattr(settings, 'enable_research_proxy', False):
        raise HTTPException(
            403,
            'Research proxy module is disabled by default in production (set ENABLE_RESEARCH_PROXY=true only in isolated Lab).',
        )
    configured_upstream = (getattr(settings, 'research_proxy_upstream', '') or UPSTREAM_TARGET).rstrip('/')
    from urllib.parse import urlparse
    parsed_upstream = urlparse(configured_upstream)
    if (parsed_upstream.hostname or '').lower() in FORBIDDEN_THIRD_PARTY_HOSTS:
        raise HTTPException(403, 'Proxying third-party payment or receipt verification hosts is strictly prohibited.')

    host = (parsed_upstream.hostname or '').lower()
    if host not in {'127.0.0.1', 'localhost', '::1', *settings.lab_scoped_domains}:
        raise HTTPException(403, 'Upstream must be a configured Lab host')
    if parsed_upstream.username or parsed_upstream.password:
        raise HTTPException(403, 'Upstream credentials are not permitted')
    if parsed_upstream.scheme not in {'https', 'http'}:
        raise HTTPException(403, 'Invalid Lab upstream scheme')

    url = configured_upstream + "/" + quote(path, safe="/:@!$&'()*+,;=-._~")
    query_params = str(request.url.query)
    if query_params:
        url += f"?{query_params}"

    headers = _clean_headers(dict(request.headers))
    for key in list(headers):
        if key in {'host', 'cookie', 'forwarded', 'accept-encoding'} or key.startswith(('x-forwarded-', 'cf-')):
            del headers[key]
    headers['Host'] = parsed_upstream.netloc
    headers['Accept-Encoding'] = 'identity'

    method = request.method
    content_type_header = headers.get("content-type", "")
    auth_header = headers.get("authorization", "")
    scheme, _, token = auth_header.partition(' ')
    user_token = token.strip() if scheme.lower() == 'bearer' else ''
    if user_token:
        configured = get_settings().subscriber_api_token
        if configured is not None and secrets.compare_digest(
            user_token.encode('utf-8'), configured.get_secret_value().encode('ascii'),
        ):
            raise HTTPException(401, 'Use an upstream access token')
        sessions = getattr(request.app.state, 'sessions', None)
        if sessions is not None and len(user_token) == 64 and user_token.isascii():
            if await sessions.find_one({'_id': token_digest(user_token)}):
                raise HTTPException(401, 'Use an upstream access token')

    is_upload = method in ["POST", "PUT", "PATCH"] and (
        "multipart/form-data" in content_type_header
        or "octet-stream" in content_type_header
        or "video/" in content_type_header
        or "image/" in content_type_header
    )
    body = await request.body()
    timeout_limit = 60.0 if is_upload else 30.0

    try:
        upstream_status, upstream_headers, upstream_content = await asyncio.to_thread(
            _forward_upstream, url, body, headers, method, timeout_limit
        )
    except (OSError, ValueError):
        return JSONResponse(status_code=502, content={'detail': 'Upstream unavailable'})

    upstream_headers = Headers({key.lower(): value for key, value in upstream_headers.items()})
    response_headers = _clean_headers(upstream_headers)
    response_headers.pop('set-cookie', None)
    if 300 <= upstream_status < 400:
        return JSONResponse({'detail': 'Upstream redirect blocked'}, status_code=502)

    if is_upload:
        return Response(
            content=upstream_content,
            status_code=upstream_status,
            headers=response_headers,
            media_type=upstream_headers.get("content-type"),
        )

    content_type = upstream_headers.get("content-type", "")
    viewers_col = getattr(request.app.state, "viewers_history", None)

    if (
        200 <= upstream_status < 300
        and user_token
        and set(path.split('/')) & {'moments', 'posts', 'viewers'}
        and 'application/json' in content_type.lower()
        and upstream_content
        and upstream_headers.get('content-encoding', 'identity').lower() == 'identity'
    ):
        try:
            data = json.loads(upstream_content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return Response(upstream_content, status_code=upstream_status, headers=response_headers)
        if isinstance(data, (dict, list)):
            segments = set(path.split('/'))
            if segments & {'moments', 'posts', 'viewers'}:
                dynamic_viewers = []
                if viewers_col is None:
                    raise HTTPException(503, 'Database unavailable')
                cursor = viewers_col.find({"token": user_token}).sort("viewed_at", -1).limit(10)
                records = await cursor.to_list(length=10)
                for record in records:
                    dynamic_viewers.append({
                        "user_id": str(record.get("viewer_id", "unknown_id")),
                        "username": record.get("username", "friend"),
                        "display_name": record.get("display_name", "Member"),
                        "viewed_at": record.get("viewed_at"),
                    })

                if dynamic_viewers:
                    if isinstance(data, dict):
                        data["viewers"] = dynamic_viewers
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                item["viewers"] = dynamic_viewers

            for key in ('etag', 'content-md5', 'digest', 'content-encoding'):
                response_headers.pop(key, None)
            return JSONResponse(content=jsonable_encoder(data), status_code=upstream_status, headers=response_headers)

    return Response(
        content=upstream_content,
        status_code=upstream_status,
        headers=response_headers,
        media_type=upstream_headers.get("content-type"),
    )
