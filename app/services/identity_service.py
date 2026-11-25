import asyncio
from datetime import datetime, timezone
import logging
import re
from typing import Any, Callable
from urllib.parse import unquote, urlparse, urlsplit
from httpx import AsyncClient, TimeoutException, TransportError
from ..models import IdentityResolutionOutput, LinkVerifyOutput

logger = logging.getLogger(__name__)

FIREBASE_UID_PATTERN = re.compile(r'^[A-Za-z0-9]{28}$')
MONGO_OBJECT_ID_PATTERN = re.compile(r'^[0-9a-fA-F]{24}$')
UUID_V4_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
HANDLE_PATTERN = re.compile(r'^[A-Za-z0-9_.\-]{3,36}$')
ACCOUNT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_$:@.\-]{1,128}$')

FORBIDDEN_PLACEHOLDER_UIDS = {
    'uid_thuc_te_tu_nguon_tra_cuu',
    'firebase_uid_placeholder_1234',
    'placeholder',
    'undefined',
    'null',
    'none',
    'test',
    'mock',
    'dummy',
}

ALLOWED_LOCKET_HOSTS = {
    'locket.cam',
    'www.locket.cam',
    'locket.camera',
    'www.locket.camera',
    'locketcamera.com',
    'www.locketcamera.com',
}


def normalize_lookup_query(raw_query: str) -> tuple[str, str]:
    """
    Normalize a Locket username, @username, or Locket URL according to the proven
    `locketgoldmanager` logic (`lookup_account` in `app/routers/management.py`).
    Returns `(normalized_identifier, input_kind)` or raises `ValueError` on invalid input.
    Never makes external network calls to third-party lookup APIs.
    """
    if not isinstance(raw_query, str):
        raise ValueError('Vui lòng nhập username hoặc link Locket hợp lệ.')
    candidate = raw_query.strip()
    if not candidate:
        raise ValueError('Vui lòng nhập username hoặc link Locket hợp lệ.')

    is_url = False
    if '://' in candidate or '/' in candidate:
        is_url = True
        link = urlsplit(candidate if '://' in candidate else 'https://' + candidate)
        if link.scheme not in ('http', 'https') or link.netloc.lower() not in ALLOWED_LOCKET_HOSTS:
            raise ValueError('Vui lòng nhập username hoặc link Locket hợp lệ.')
        candidate = unquote(link.path.strip('/'))

    had_at = candidate.startswith('@')
    candidate = candidate.removeprefix('@')
    if not ACCOUNT_ID_PATTERN.fullmatch(candidate):
        raise ValueError('Vui lòng nhập username hoặc link Locket hợp lệ.')

    if is_url:
        kind = 'firebase_uid' if FIREBASE_UID_PATTERN.fullmatch(candidate) else 'locket_link'
    elif had_at:
        kind = 'handle'
    elif FIREBASE_UID_PATTERN.fullmatch(candidate):
        kind = 'firebase_uid'
    else:
        kind = 'custom_id'
    return candidate, kind


def verify_account_link_or_identifier(
    raw_input: str,
    *,
    verified_provider_source: str | None = None,
) -> LinkVerifyOutput:
    """
    Validate a Locket share link, @handle, or direct identifier/UID.
    Strictly enforces Zero-Guessing Policy:
    - Never accepts a client-supplied boolean as proof of verification.
    - Never queries external third-party lookup endpoints.
    - Distinguishes username (@handle / share link), custom identifier, 28-char UUID format,
      and externally verified identity (`verified_provider_source` supplied only by a trusted
      server-side identity verifier or verified MongoDB record).
    """
    cleaned = raw_input.strip()
    if not cleaned:
        return LinkVerifyOutput(
            valid_format=False,
            input_kind='invalid',
            verification_source='none',
            message='Đầu vào trống. Vui lòng nhập link locket.cam/... hoặc UID.',
        )

    # 1. Check if input is a URL or contains path slashes
    if '://' in cleaned or '/' in cleaned or cleaned.lower().startswith(
        ('locket.cam/', 'www.locket.cam/', 'locket.camera/', 'locketcamera.com/')
    ):
        url_str = cleaned if '://' in cleaned else f'https://{cleaned}'
        try:
            parsed = urlparse(url_str)
        except ValueError:
            return LinkVerifyOutput(
                valid_format=False,
                input_kind='invalid',
                verification_source='url_parser',
                message='Định dạng URL không hợp lệ.',
            )
        if parsed.scheme not in {'http', 'https'}:
            return LinkVerifyOutput(
                valid_format=False,
                input_kind='invalid',
                verification_source='url_scheme_check',
                message='Chỉ chấp nhận giao thức http hoặc https.',
            )
        host = (parsed.hostname or '').lower()
        if host not in ALLOWED_LOCKET_HOSTS:
            return LinkVerifyOutput(
                valid_format=False,
                input_kind='invalid',
                verification_source='url_host_check',
                message='Chỉ chấp nhận tên miền hợp lệ của Locket (locket.cam, locket.camera hoặc locketcamera.com).',
            )
        raw_path = unquote((parsed.path or '').strip('/'))
        if not raw_path or '/' in raw_path:
            return LinkVerifyOutput(
                valid_format=False,
                input_kind='invalid',
                verification_source='url_path_check',
                message='Link Locket phải có dạng https://locket.cam/<username> (đúng 1 định danh ở đường dẫn).',
            )
        candidate = raw_path.removeprefix('@').strip()
        if FIREBASE_UID_PATTERN.fullmatch(candidate):
            if verified_provider_source:
                return LinkVerifyOutput(
                    valid_format=True,
                    input_kind='firebase_uid',
                    extracted_identifier=candidate,
                    extracted_username=None,
                    normalized_link=f'https://locket.cam/{candidate}',
                    uid_verified=True,
                    verification_status='verified_uid',
                    verification_method='trusted_proof',
                    verification_source=verified_provider_source,
                    message='Đã trích xuất và xác thực UID chuẩn 28 ký tự từ nguồn xác minh độc lập (verified_uid).',
                )
            return LinkVerifyOutput(
                valid_format=True,
                input_kind='firebase_uid',
                extracted_identifier=candidate,
                extracted_username=None,
                normalized_link=f'https://locket.cam/{candidate}',
                uid_verified=False,
                verification_status='unverified_uid',
                verification_method='format_only_uid',
                verification_source='regex_28char_url_segment',
                message=(
                    'Đã trích xuất chuỗi 28 ký tự khớp định dạng Firebase UID từ đường dẫn, '
                    'nhưng độ dài chuỗi không chứng minh quyền sở hữu tài khoản thực tế (trạng thái: unverified_uid).'
                ),
            )
        if HANDLE_PATTERN.fullmatch(candidate) or ACCOUNT_ID_PATTERN.fullmatch(candidate):
            return LinkVerifyOutput(
                valid_format=True,
                input_kind='locket_link',
                extracted_identifier=candidate,
                extracted_username=candidate,
                normalized_link=f'https://locket.cam/{candidate}',
                uid_verified=False,
                verification_status='unverified_handle',
                verification_method='link_handle_only',
                verification_source='public_share_link_path',
                message=(
                    f'Link hợp lệ (username: @{candidate}), nhưng link chia sẻ công khai chỉ chứa '
                    'username chứ KHÔNG cung cấp Firebase UID nội bộ có thể xác minh độc lập. '
                    'Đã đánh dấu là unverified_handle để kiểm tra trong MongoDB.'
                ),
            )
        return LinkVerifyOutput(
            valid_format=False,
            input_kind='invalid',
            verification_source='url_path_check',
            message='Ký tự định danh trong link không hợp lệ.',
        )

    # 2. Check if input starts with @ (explicit username handle)
    if cleaned.startswith('@'):
        handle = cleaned.removeprefix('@').strip()
        if HANDLE_PATTERN.fullmatch(handle) or ACCOUNT_ID_PATTERN.fullmatch(handle):
            return LinkVerifyOutput(
                valid_format=True,
                input_kind='handle',
                extracted_identifier=handle,
                extracted_username=handle,
                normalized_link=f'https://locket.cam/{handle}',
                uid_verified=False,
                verification_status='unverified_handle',
                verification_method='link_handle_only',
                verification_source='explicit_handle_input',
                message=(
                    f'Đã nhận diện handle @{handle}. Lưu ý: Handle không phải là UID nội bộ '
                    '(trạng thái: unverified_handle).'
                ),
            )
        return LinkVerifyOutput(
            valid_format=False,
            input_kind='invalid',
            verification_source='explicit_handle_input',
            message='Handle @username không đúng định dạng.',
        )

    # 3. Check if input is a 28-char alphanumeric Firebase UID format
    if FIREBASE_UID_PATTERN.fullmatch(cleaned):
        if verified_provider_source:
            return LinkVerifyOutput(
                valid_format=True,
                input_kind='firebase_uid',
                extracted_identifier=cleaned,
                extracted_username=None,
                normalized_link=None,
                uid_verified=True,
                verification_status='verified_uid',
                verification_method='trusted_proof',
                verification_source=verified_provider_source,
                message='Định danh khớp chuẩn Firebase Auth UID (28 ký tự) và được xác minh bởi nguồn độc lập (verified_uid).',
            )
        return LinkVerifyOutput(
            valid_format=True,
            input_kind='firebase_uid',
            extracted_identifier=cleaned,
            extracted_username=None,
            normalized_link=None,
            uid_verified=False,
            verification_status='unverified_uid',
            verification_method='format_only_uid',
            verification_source='regex_28char_format_only',
            message=(
                'Định danh khớp định dạng 28 ký tự alphanumeric của Firebase UID, nhưng chưa có '
                'nguồn xác minh độc lập bên ngoài (trạng thái: unverified_uid).'
            ),
        )

    # 4. General Lab Account ID / Username
    if ACCOUNT_ID_PATTERN.fullmatch(cleaned):
        return LinkVerifyOutput(
            valid_format=True,
            input_kind='custom_id',
            extracted_identifier=cleaned,
            extracted_username=cleaned if HANDLE_PATTERN.fullmatch(cleaned) else None,
            normalized_link=None,
            uid_verified=False,
            verification_status='manual_lab_id',
            verification_method='admin_manual_override',
            verification_source='admin_direct_input',
            message='Định danh hợp lệ cho tài khoản thử nghiệm trong Lab (manual_lab_id).',
        )

    return LinkVerifyOutput(
        valid_format=False,
        input_kind='invalid',
        verification_source='format_inspection_only',
        message='Định danh chứa ký tự không được phép hoặc vượt quá 128 ký tự.',
    )


def is_valid_firebase_uid(candidate: Any) -> bool:
    """
    Validate that a candidate string is a genuine 28-character alphanumeric Firebase UID,
    and NOT a MongoDB 24-hex ObjectId, 36-char UUID, placeholder string, or single-character repeat.
    """
    if not isinstance(candidate, str):
        return False
    val = candidate.strip()
    if not val or val.lower() in FORBIDDEN_PLACEHOLDER_UIDS:
        return False
    if MONGO_OBJECT_ID_PATTERN.fullmatch(val) or UUID_V4_PATTERN.fullmatch(val):
        return False
    if not FIREBASE_UID_PATTERN.fullmatch(val):
        return False
    if len(set(val)) <= 2:
        return False
    return True


def _parse_provider_payload(status_code: int, payload: Any) -> tuple[str, dict | None, str]:
    """
    Inspect HTTP status code and JSON body from an identity provider (e.g. Firebase Callable
    `getUserByUsername` / `fetchUserV2` or authorized identity API).
    Returns `(error_or_ok_status, user_dict_or_none, diagnostic_message)`.
    Never includes raw tokens or private PII in error messages.
    """
    if status_code in (401, 403):
        return ('auth_required', None, 'Nguồn tra cứu danh tính Locket yêu cầu xác thực hợp lệ (auth_required).')
    if status_code == 429:
        return ('rate_limited', None, 'Nguồn tra cứu danh tính đang giới hạn lượt truy vấn (rate_limited). Vui lòng thử lại sau.')
    if status_code == 404:
        return ('not_found', None, 'Không tìm thấy tài khoản Locket tương ứng trên nguồn tra cứu (not_found).')
    if status_code >= 500:
        return ('lookup_unavailable', None, 'Nguồn tra cứu danh tính Locket tạm thời không phản hồi (lookup_unavailable).')

    if not isinstance(payload, dict):
        return ('unverified', None, 'Phản hồi từ nguồn tra cứu danh tính không đúng cấu trúc JSON hợp lệ (unverified).')

    err_obj = payload.get('error')
    if isinstance(err_obj, dict):
        err_status = str(err_obj.get('status') or '').upper()
        err_code = err_obj.get('code')
        if err_code in (401, 403) or err_status in {'UNAUTHENTICATED', 'PERMISSION_DENIED'}:
            return ('auth_required', None, 'Nguồn tra cứu danh tính từ chối xác thực (auth_required).')
        if err_code == 429 or err_status == 'RESOURCE_EXHAUSTED':
            return ('rate_limited', None, 'Nguồn tra cứu danh tính bị giới hạn tốc độ (rate_limited).')
        if err_code == 404 or err_status == 'NOT_FOUND':
            return ('not_found', None, 'Không tìm thấy tài khoản Locket trên nguồn tra cứu (not_found).')
        return ('lookup_unavailable', None, 'Nguồn tra cứu danh tính trả về lỗi dịch vụ (lookup_unavailable).')

    # Unwrap Firebase Callable `result.data` or standard `{data: ...}` / `{user: ...}` envelopes
    result_obj = payload.get('result')
    if isinstance(result_obj, dict):
        res_status = result_obj.get('status')
        if res_status in (401, 403):
            return ('auth_required', None, 'Nguồn tra cứu danh tính yêu cầu phiên xác thực (auth_required).')
        if res_status == 429:
            return ('rate_limited', None, 'Nguồn tra cứu danh tính bị giới hạn lượt gọi (rate_limited).')
        if res_status == 404:
            return ('not_found', None, 'Không tìm thấy tài khoản Locket trên nguồn tra cứu (not_found).')
        if 'data' in result_obj:
            inner = result_obj.get('data')
            if inner is None or inner == {}:
                return ('not_found', None, 'Không tìm thấy tài khoản Locket trên nguồn tra cứu (not_found).')
            if isinstance(inner, dict):
                if isinstance(inner.get('user'), dict):
                    return ('ok', inner['user'], 'OK')
                return ('ok', inner, 'OK')
        return ('ok', result_obj, 'OK')

    if 'data' in payload:
        inner = payload.get('data')
        if inner is None or inner == {}:
            return ('not_found', None, 'Không tìm thấy tài khoản Locket trên nguồn tra cứu (not_found).')
        if isinstance(inner, dict):
            if isinstance(inner.get('user'), dict):
                return ('ok', inner['user'], 'OK')
            return ('ok', inner, 'OK')

    if 'user' in payload:
        u = payload.get('user')
        if u is None or u == {}:
            return ('not_found', None, 'Không tìm thấy tài khoản Locket trên nguồn tra cứu (not_found).')
        if isinstance(u, dict):
            return ('ok', u, 'OK')

    if payload.get('exists') is False or payload.get('found') is False:
        return ('not_found', None, 'Không tìm thấy tài khoản Locket trên nguồn tra cứu (not_found).')

    return ('ok', payload, 'OK')


async def _find_in_accounts_v2(accounts_v2: Any, query: dict) -> dict | None:
    if accounts_v2 is None or not hasattr(accounts_v2, 'find_one'):
        return None
    try:
        res = accounts_v2.find_one(query, {'_id': 0})
        if hasattr(res, '__await__'):
            res = await res
        return res if isinstance(res, dict) else None
    except KeyError:
        return None


async def _exchange_firebase_refresh_token(
    api_key: str,
    refresh_token: str,
    timeout: float,
    http_client: AsyncClient | None = None,
) -> str | None:
    """Exchange a configured Firebase refresh_token for a short-lived id_token without logging credentials."""
    url = f'https://securetoken.googleapis.com/v1/token?key={api_key}'
    body = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    try:
        if http_client is not None:
            resp = await http_client.post(url, data=body, timeout=timeout)
        else:
            async with AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, data=body)
        if resp.status_code == 200:
            data = resp.json()
            token = data.get('id_token') or data.get('access_token')
            if isinstance(token, str) and token.strip():
                return token.strip()
    except Exception:
        logger.warning('IDENTITY_TOKEN_REFRESH_FAILED')
    return None


async def _call_remote_identity_provider(
    lookup_query: str,
    input_kind: str,
    *,
    settings: Any,
    provider: Callable | None = None,
    http_client: AsyncClient | None = None,
) -> tuple[str, dict | None, str, str]:
    """
    Call the injected provider callable or configured HTTPS identity lookup endpoint (`getUserByUsername` / `fetchUserV2`)
    with strict timeout and bounded retries.
    Returns `(parse_status, user_dict_or_none, message, provider_source_label)`.
    """
    max_retries = max(1, int(getattr(settings, 'locket_identity_max_retries', 2) or 2))
    timeout = float(getattr(settings, 'locket_identity_timeout_seconds', 5.0) or 5.0)

    if provider is not None:
        last_err = 'Không thể kết nối nguồn tra cứu danh tính Locket (lookup_unavailable).'
        for attempt in range(max_retries):
            try:
                res = provider(lookup_query, input_kind)
                if hasattr(res, '__await__'):
                    res = await asyncio.wait_for(res, timeout=timeout)
                if isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], int):
                    st_code, body = res
                elif hasattr(res, 'status_code'):
                    st_code = int(res.status_code)
                    try:
                        body = res.json()
                    except Exception:
                        body = None
                else:
                    st_code, body = 200, res
                if st_code in (502, 503, 504) and attempt + 1 < max_retries:
                    continue
                p_status, user_obj, msg = _parse_provider_payload(st_code, body)
                return (p_status, user_obj, msg, 'authorized_identity_provider')
            except (TimeoutError, asyncio.TimeoutError, TimeoutException, TransportError, ConnectionError):
                last_err = 'Hết thời gian chờ hoặc lỗi mạng khi gọi nguồn tra cứu danh tính (lookup_unavailable).'
                if attempt + 1 < max_retries:
                    continue
            except Exception:
                last_err = 'Lỗi khi truy vấn nguồn tra cứu danh tính (lookup_unavailable).'
                break
        return ('lookup_unavailable', None, last_err, 'authorized_identity_provider')

    lookup_url = (getattr(settings, 'locket_identity_lookup_url', '') or '').strip()
    uid_verify_url = (getattr(settings, 'locket_identity_uid_verify_url', '') or '').strip() or lookup_url
    target_url = uid_verify_url if input_kind == 'firebase_uid' else lookup_url
    if not target_url:
        return (
            'lookup_unavailable',
            None,
            'Chưa cấu hình nguồn tra cứu danh tính Locket được phép sử dụng (lookup_unavailable).',
            'none',
        )

    def _secret(attr_name: str) -> str:
        val = getattr(settings, attr_name, None)
        if val is None:
            return ''
        return (val.get_secret_value() if hasattr(val, 'get_secret_value') else str(val)).strip()

    bearer = _secret('locket_identity_bearer_token')
    api_key = _secret('locket_firebase_api_key')
    refresh_tok = _secret('locket_firebase_refresh_token')
    app_check = _secret('locket_firebase_app_check_token')

    if not bearer and api_key and refresh_tok:
        bearer = await _exchange_firebase_refresh_token(api_key, refresh_tok, timeout, http_client) or ''

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if bearer:
        headers['Authorization'] = f'Bearer {bearer}'
    if app_check:
        headers['X-Firebase-AppCheck'] = app_check

    req_body = (
        {'data': {'uid': lookup_query, 'user_uid': lookup_query}}
        if input_kind == 'firebase_uid'
        else {'data': {'username': lookup_query}}
    )

    last_err = 'Không thể kết nối nguồn tra cứu danh tính Locket (lookup_unavailable).'
    for attempt in range(max_retries):
        try:
            if http_client is not None:
                resp = await http_client.post(target_url, json=req_body, headers=headers, timeout=timeout)
            else:
                async with AsyncClient(timeout=timeout) as client:
                    resp = await client.post(target_url, json=req_body, headers=headers)
            if resp.status_code in (502, 503, 504) and attempt + 1 < max_retries:
                continue
            try:
                body = resp.json()
            except Exception:
                body = None
            p_status, user_obj, msg = _parse_provider_payload(resp.status_code, body)
            return (p_status, user_obj, msg, 'authorized_identity_provider')
        except (TimeoutError, asyncio.TimeoutError, TimeoutException, TransportError, ConnectionError):
            last_err = 'Hết thời gian chờ hoặc lỗi mạng khi gọi nguồn tra cứu danh tính (lookup_unavailable).'
            if attempt + 1 < max_retries:
                continue
        except Exception:
            last_err = 'Lỗi kết nối nguồn tra cứu danh tính Locket (lookup_unavailable).'
            break

    return ('lookup_unavailable', None, last_err, 'authorized_identity_provider')


async def resolve_locket_identity(
    raw_input: str,
    *,
    settings: Any = None,
    accounts_v2: Any = None,
    provider: Callable | None = None,
    http_client: AsyncClient | None = None,
) -> IdentityResolutionOutput:
    """
    Automatic Locket ID / Username / Share Link -> Firebase UID Resolver.
    Statuses:
      - `resolved`: Found valid 28-char Firebase UID with matching account proof & zero DB conflicts.
      - `not_found`: Account does not exist on the identity provider.
      - `auth_required`: Identity provider requires valid authentication (401/403).
      - `rate_limited`: Identity provider rate limit reached (429).
      - `lookup_unavailable`: No identity provider configured or network/timeout/5xx error.
      - `conflict`: Returned UID/username mismatches input, differs from existing verified UID, or is bound to another account.
      - `unverified`: Response JSON is missing a valid Firebase UID or lacks matching account proof.
    """
    try:
        normalized_id, input_kind = normalize_lookup_query(raw_input)
    except ValueError as exc:
        return IdentityResolutionOutput(
            status='unverified',
            normalized_id=str(raw_input or '').strip()[:128],
            input_kind='invalid',
            message=str(exc),
        )

    source_link = f'https://locket.cam/{normalized_id}' if input_kind == 'locket_link' else None
    now = datetime.now(timezone.utc)

    # 1. Inspect existing canonical accounts_v2 records for this identifier
    existing_doc = await _find_in_accounts_v2(accounts_v2, {'locket_id': normalized_id})
    if existing_doc is None and input_kind != 'firebase_uid':
        existing_doc = await _find_in_accounts_v2(accounts_v2, {'username': normalized_id})

    has_remote_provider = provider is not None or bool(
        settings is not None and (getattr(settings, 'locket_identity_lookup_url', '') or '').strip()
    )

    # If no remote provider is configured, check if MongoDB already holds a server-verified UID for this account
    if not has_remote_provider:
        if (
            isinstance(existing_doc, dict)
            and existing_doc.get('_server_uid_proof') is True
            and existing_doc.get('verification_status') == 'verified_uid'
            and is_valid_firebase_uid(existing_doc.get('firebase_uid'))
        ):
            cached_uid = str(existing_doc['firebase_uid']).strip()
            cached_user = existing_doc.get('username') or (normalized_id if input_kind != 'firebase_uid' else None)
            return IdentityResolutionOutput(
                status='resolved',
                normalized_id=str(existing_doc.get('locket_id') or normalized_id),
                input_kind=input_kind,
                username=cached_user,
                firebase_uid=cached_uid,
                source_link=source_link or existing_doc.get('source_link'),
                uid_verified=True,
                verification_status='verified_uid',
                verification_method='trusted_proof',
                verification_source=str(existing_doc.get('verification_source') or 'authorized_identity_provider'),
                uid_resolved_at=existing_doc.get('uid_resolved_at') or now,
                uid_resolution_source=str(existing_doc.get('uid_resolution_source') or 'mongodb_verified_cache'),
                message=f'Đã xác nhận Firebase UID đã xác minh trong hệ thống: {cached_uid}.',
            )
        return IdentityResolutionOutput(
            status='lookup_unavailable',
            normalized_id=normalized_id,
            input_kind=input_kind,
            username=normalized_id if input_kind != 'firebase_uid' else None,
            source_link=source_link,
            message='Không thể tra cứu Firebase UID: Nguồn tra cứu danh tính Locket chưa sẵn sàng (lookup_unavailable).',
        )

    # 2. Query the authorized identity provider
    p_status, user_obj, msg, provider_source = await _call_remote_identity_provider(
        normalized_id,
        input_kind,
        settings=settings,
        provider=provider,
        http_client=http_client,
    )
    if p_status != 'ok' or not isinstance(user_obj, dict):
        return IdentityResolutionOutput(
            status=p_status if p_status in {'not_found', 'auth_required', 'rate_limited', 'lookup_unavailable', 'unverified'} else 'lookup_unavailable',
            normalized_id=normalized_id,
            input_kind=input_kind,
            username=normalized_id if input_kind != 'firebase_uid' else None,
            source_link=source_link,
            message=msg,
        )

    # 3. Extract and validate the returned Firebase UID
    raw_uid = user_obj.get('uid') or user_obj.get('firebase_uid') or user_obj.get('localId')
    if not is_valid_firebase_uid(raw_uid):
        return IdentityResolutionOutput(
            status='unverified',
            normalized_id=normalized_id,
            input_kind=input_kind,
            username=normalized_id if input_kind != 'firebase_uid' else None,
            source_link=source_link,
            message='Phản hồi từ nguồn tra cứu thiếu trường Firebase UID 28 ký tự hợp lệ (unverified).',
        )
    resolved_uid = str(raw_uid).strip()

    raw_username = user_obj.get('username')
    returned_username = str(raw_username).strip().removeprefix('@') if isinstance(raw_username, str) and raw_username.strip() else None

    # 4. Verify that the returned UID and username belong to the queried account
    if input_kind == 'firebase_uid':
        if resolved_uid != normalized_id:
            return IdentityResolutionOutput(
                status='conflict',
                normalized_id=normalized_id,
                input_kind=input_kind,
                message='Firebase UID trả về từ nguồn tra cứu không khớp với UID yêu cầu xác minh (conflict).',
            )
        canonical_id = returned_username or normalized_id
        resolved_username = returned_username
    else:
        if returned_username is None:
            return IdentityResolutionOutput(
                status='unverified',
                normalized_id=normalized_id,
                input_kind=input_kind,
                username=normalized_id,
                source_link=source_link,
                message='Phản hồi từ nguồn tra cứu không có trường username để đối chiếu chủ sở hữu UID (unverified).',
            )
        if returned_username.lower() != normalized_id.lower():
            return IdentityResolutionOutput(
                status='conflict',
                normalized_id=normalized_id,
                input_kind=input_kind,
                username=normalized_id,
                source_link=source_link,
                message=f'Username trả về từ nguồn tra cứu ("{returned_username}") không khớp với tài khoản "{normalized_id}" (conflict).',
            )
        canonical_id = normalized_id
        resolved_username = returned_username

    # 5. Enforce MongoDB accounts_v2 integrity:
    # Rule A: Existing verified UID on this account must NEVER be overwritten by a different UID
    if existing_doc is None and canonical_id != normalized_id:
        existing_doc = await _find_in_accounts_v2(accounts_v2, {'locket_id': canonical_id})
    if (
        isinstance(existing_doc, dict)
        and existing_doc.get('_server_uid_proof') is True
        and existing_doc.get('verification_status') == 'verified_uid'
        and existing_doc.get('firebase_uid')
        and existing_doc.get('firebase_uid') != resolved_uid
    ):
        return IdentityResolutionOutput(
            status='conflict',
            normalized_id=canonical_id,
            input_kind=input_kind,
            username=resolved_username,
            source_link=source_link,
            message='Firebase UID trả về khác với Firebase UID đã được xác minh trước đó của tài khoản này (conflict).',
        )

    # Rule B: A single Firebase UID must NEVER be linked to two different accounts in MongoDB
    uid_owner = await _find_in_accounts_v2(accounts_v2, {'firebase_uid': resolved_uid})
    if isinstance(uid_owner, dict):
        owner_lid = str(uid_owner.get('locket_id') or '').strip()
        owner_uname = str(uid_owner.get('username') or '').strip()
        target_names = {n.lower() for n in (canonical_id, normalized_id, resolved_username) if isinstance(n, str) and n}
        owner_names = {n.lower() for n in (owner_lid, owner_uname) if n}
        if owner_lid and not (target_names & owner_names):
            return IdentityResolutionOutput(
                status='conflict',
                normalized_id=canonical_id,
                input_kind=input_kind,
                username=resolved_username,
                source_link=source_link,
                message=f'Firebase UID này đã được gắn với một tài khoản khác ("{owner_lid}") trong MongoDB (conflict).',
            )
        if owner_lid:
            canonical_id = owner_lid

    return IdentityResolutionOutput(
        status='resolved',
        normalized_id=canonical_id,
        input_kind=input_kind,
        username=resolved_username,
        firebase_uid=resolved_uid,
        source_link=source_link,
        uid_verified=True,
        verification_status='verified_uid',
        verification_method='trusted_proof',
        verification_source=provider_source,
        uid_resolved_at=now,
        uid_resolution_source='getUserByUsername' if input_kind != 'firebase_uid' else 'fetchUserV2',
        message=f'Đã tra cứu và xác minh thành công Firebase UID: {resolved_uid}.',
    )
