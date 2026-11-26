from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import re
from typing import Any
from urllib.parse import urlsplit
from httpx import AsyncClient, TimeoutException, TransportError

from ..models import IdentityResolutionOutput
from .identity_service import (
    FORBIDDEN_PLACEHOLDER_UIDS,
    INVITE_TOKEN_CLEAN_PATTERN,
    MONGO_OBJECT_ID_PATTERN,
    UUID_V4_PATTERN,
    _find_in_accounts_v2,
    normalize_lookup_query,
    resolve_public_locket_share_link,
)
from .locket_session_provider import (
    LocketAuthRequiredError,
    LocketSessionExpiredError,
    LocketSessionProvider,
)

logger = logging.getLogger(__name__)

LOCKET_FETCH_USER_BY_INVITE_URL = 'https://api.locketcamera.com/fetchUserForInviteToken'
ALLOWED_LOCKET_API_HOSTS = {'api.locketcamera.com'}
AUTHENTICATED_UID_PATTERN = re.compile(r'^[^\s/\x00-\x1f]{1,128}$')
LOCKETLAM_INSTALLATION_ID_HEX_PATTERN = re.compile(r'^[0-9a-f]{22}$')


def is_valid_authenticated_firebase_uid(
    candidate: Any,
    *,
    invite_token: str | None = None,
    device_uuid: str | None = None,
) -> bool:
    """
    Validate a Firebase UID returned by an authenticated Locket identity endpoint.
    - Supports standard 28-char Firebase UIDs as well as verified 20..128 char Firebase UIDs.
    - Strictly rejects:
      * Empty or non-string values
      * Invite token echoed back as a UID (source separation)
      * MongoDB 24-hex ObjectId
      * 36-char hyphenated Device UUID / Installation UUID
      * 22-char lowercase hex LocketLam auto-generated installation_id (`uuid.uuid4().hex[:22]`)
      * Explicitly known Device UUID / Installation ID
      * Placeholder strings or single-character repeats
    """
    if not isinstance(candidate, str):
        return False
    val = candidate.strip()
    if not val or val.lower() in FORBIDDEN_PLACEHOLDER_UIDS:
        return False
    if invite_token and val == invite_token.strip():
        return False
    if device_uuid and val.lower() == device_uuid.strip().lower():
        return False
    if UUID_V4_PATTERN.fullmatch(val):
        return False
    if MONGO_OBJECT_ID_PATTERN.fullmatch(val):
        return False
    if LOCKETLAM_INSTALLATION_ID_HEX_PATTERN.fullmatch(val):
        return False
    if not AUTHENTICATED_UID_PATTERN.fullmatch(val):
        return False
    if len(set(val)) <= 2:
        return False
    return True


def _validate_locket_api_endpoint(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() != 'https':
        raise ValueError('Locket API endpoint must use HTTPS.')
    host = (parsed.hostname or '').strip().lower().rstrip('.')
    if host not in ALLOWED_LOCKET_API_HOSTS:
        raise ValueError(f'Disallowed Locket API host: {host}')
    return url.strip()


async def _obtain_session_token(session_provider: Any) -> tuple[str, str | None]:
    """
    Retrieve a valid Bearer token from `session_provider`.
    Returns `(token, error_status_or_none)`.
    """
    if session_provider is None:
        return ('', 'auth_required')
    try:
        if isinstance(session_provider, LocketSessionProvider) or hasattr(session_provider, 'get_valid_token'):
            res = session_provider.get_valid_token()
            if asyncio.iscoroutine(res) or hasattr(res, '__await__'):
                res = await res
            token = str(res or '').strip()
        elif callable(session_provider):
            res = session_provider()
            if asyncio.iscoroutine(res) or hasattr(res, '__await__'):
                res = await res
            token = str(res or '').strip()
        elif isinstance(session_provider, str):
            token = session_provider.strip()
        else:
            return ('', 'auth_required')
    except LocketSessionExpiredError:
        return ('', 'session_expired')
    except LocketAuthRequiredError:
        return ('', 'auth_required')
    except Exception as exc:
        logger.warning('LOCKET_SESSION_PROVIDER_ERROR: %s', type(exc).__name__)
        return ('', 'auth_required')

    if not token:
        return ('', 'auth_required')
    if token.startswith('lkg_'):
        # Website admin or device tokens must never be sent to Locket API
        return ('', 'auth_required')
    return (token, None)


def _parse_fetch_user_for_invite_response(
    status_code: int,
    payload: Any,
    *,
    invite_token: str,
) -> dict:
    """
    Parse and validate the HTTP status and JSON body from `fetchUserForInviteToken`.
    Never treats HTTP 200 with an `error` object or a LocketLam error dict as a valid user profile.
    """
    if status_code in (401, 403):
        return {
            'status': 'auth_required',
            'user': None,
            'message': f'Máy chủ Locket từ chối xác thực (HTTP {status_code} · auth_required).',
        }
    if status_code == 404:
        return {
            'status': 'not_found',
            'user': None,
            'message': 'Không tìm thấy người dùng tương ứng với invite token này (not_found).',
        }
    if status_code == 429:
        return {
            'status': 'rate_limited',
            'user': None,
            'message': 'Máy chủ Locket đang giới hạn tần suất tra cứu (HTTP 429 · rate_limited).',
        }
    if status_code >= 500:
        return {
            'status': 'lookup_unavailable',
            'user': None,
            'message': f'Máy chủ Locket tạm thời gặp sự cố (HTTP {status_code} · lookup_unavailable).',
        }
    if status_code < 200 or status_code >= 300:
        return {
            'status': 'invalid_response',
            'user': None,
            'message': f'Yêu cầu tra cứu bị từ chối (HTTP {status_code} · invalid_response).',
        }

    if not isinstance(payload, dict):
        return {
            'status': 'invalid_response',
            'user': None,
            'message': 'Phản hồi từ API không phải đối tượng JSON hợp lệ (invalid_response).',
        }

    # Check for top-level or nested `error` object (including LocketLam post_api error dicts)
    err_obj = payload.get('error')
    if err_obj is not None:
        if isinstance(err_obj, dict):
            err_code = err_obj.get('code') or payload.get('status')
            err_status = str(err_obj.get('status') or '').upper()
            if err_code in (401, 403) or err_status in {'UNAUTHENTICATED', 'PERMISSION_DENIED'}:
                return {
                    'status': 'auth_required',
                    'user': None,
                    'message': 'Phiên xác thực Locket bị từ chối trong phản hồi API (auth_required).',
                }
            if err_code == 404 or err_status == 'NOT_FOUND':
                return {
                    'status': 'not_found',
                    'user': None,
                    'message': 'Invite token không tồn tại hoặc đã hết hạn (not_found).',
                }
            if err_code == 429 or err_status == 'RESOURCE_EXHAUSTED':
                return {
                    'status': 'rate_limited',
                    'user': None,
                    'message': 'Bị giới hạn lượt gọi API Locket (rate_limited).',
                }
        return {
            'status': 'invalid_response',
            'user': None,
            'message': 'Phản hồi API chứa đối tượng lỗi (error), không phải hồ sơ người dùng hợp lệ.',
        }

    result_obj = payload.get('result')
    if isinstance(result_obj, dict) and result_obj.get('error') is not None:
        return {
            'status': 'invalid_response',
            'user': None,
            'message': 'Phản hồi result của API chứa đối tượng lỗi (invalid_response).',
        }

    # Unwrap supported envelopes:
    # 1. {"result": {"data": {"user": {...}}}}
    # 2. {"data": {"user": {...}}}
    # 3. {"result": {"user": {...}}} or {"result": {"data": {...}}} or {"data": {...}} or {"user": {...}}
    user_candidate: Any = None
    if isinstance(result_obj, dict):
        res_st = result_obj.get('status')
        if res_st in (401, 403):
            return {'status': 'auth_required', 'user': None, 'message': 'API yêu cầu xác thực hợp lệ (auth_required).'}
        if res_st == 404:
            return {'status': 'not_found', 'user': None, 'message': 'Không tìm thấy tài khoản từ invite token (not_found).'}
        if res_st == 429:
            return {'status': 'rate_limited', 'user': None, 'message': 'Bị giới hạn tần suất tra cứu (rate_limited).'}
        if 'data' in result_obj:
            data_inner = result_obj.get('data')
            if data_inner is None or data_inner == {}:
                return {'status': 'not_found', 'user': None, 'message': 'Không tìm thấy dữ liệu người dùng cho invite token này (not_found).'}
            if isinstance(data_inner, dict):
                user_candidate = data_inner.get('user', data_inner)
            else:
                return {'status': 'invalid_response', 'user': None, 'message': 'Trường result.data không hợp lệ (invalid_response).'}
        elif 'user' in result_obj:
            user_candidate = result_obj.get('user')
        else:
            user_candidate = result_obj
    elif 'data' in payload:
        data_inner = payload.get('data')
        if data_inner is None or data_inner == {}:
            return {'status': 'not_found', 'user': None, 'message': 'Không tìm thấy dữ liệu người dùng cho invite token này (not_found).'}
        if isinstance(data_inner, dict):
            user_candidate = data_inner.get('user', data_inner)
        else:
            return {'status': 'invalid_response', 'user': None, 'message': 'Trường data không hợp lệ (invalid_response).'}
    elif 'user' in payload:
        user_candidate = payload.get('user')
    else:
        user_candidate = payload

    if user_candidate is None or user_candidate == {}:
        return {'status': 'not_found', 'user': None, 'message': 'Không tìm thấy người dùng cho invite token này (not_found).'}
    if not isinstance(user_candidate, dict):
        return {'status': 'invalid_response', 'user': None, 'message': 'Dữ liệu hồ sơ người dùng không đúng định dạng dict (invalid_response).'}

    if user_candidate.get('error') is not None:
        return {'status': 'invalid_response', 'user': None, 'message': 'API trả lỗi thay vì hồ sơ người dùng.'}

    # Reject if user_candidate only contains installation_id / device_id without a real user uid
    raw_uid = user_candidate.get('uid') or user_candidate.get('firebase_uid')
    if raw_uid is None or (isinstance(raw_uid, str) and not raw_uid.strip()):
        return {
            'status': 'uid_missing',
            'user': None,
            'message': 'Phản hồi từ fetchUserForInviteToken không có trường uid (uid_missing).',
        }

    device_uuid = str(user_candidate.get('installation_id') or user_candidate.get('device_id') or '').strip() or None
    if not is_valid_authenticated_firebase_uid(raw_uid, invite_token=invite_token, device_uuid=device_uuid):
        return {
            'status': 'invalid_response',
            'user': None,
            'message': 'Giá trị UID trả về không hợp lệ (trùng invite_token, Device UUID hoặc ObjectId).',
        }

    clean_uid = str(raw_uid).strip()
    raw_uname = user_candidate.get('username')
    clean_uname = str(raw_uname).strip().removeprefix('@') if isinstance(raw_uname, str) and raw_uname.strip() else None

    return {
        'status': 'ok',
        'user': {
            'uid': clean_uid,
            'username': clean_uname,
            'first_name': user_candidate.get('first_name'),
            'last_name': user_candidate.get('last_name'),
        },
        'message': 'Đã tra cứu được thông tin người dùng từ invite token.',
    }


async def fetch_user_by_invite_token(
    invite_token: str,
    *,
    session_provider: Any,
    http_client: AsyncClient | None = None,
    timeout_seconds: float = 8.0,
    max_retries: int = 2,
) -> dict:
    """
    Step 2: Call `POST https://api.locketcamera.com/fetchUserForInviteToken`
    with an authenticated Locket session Bearer token and `{"data": {"invite_token": invite_token}}`.
    Never logs tokens or raw user PII.
    """
    if not isinstance(invite_token, str) or not invite_token.strip():
        return {
            'status': 'not_found',
            'user': None,
            'message': 'Invite token trống hoặc không hợp lệ (not_found).',
        }
    clean_invite = invite_token.strip()
    if not INVITE_TOKEN_CLEAN_PATTERN.fullmatch(clean_invite):
        return {
            'status': 'not_found',
            'user': None,
            'message': 'Định dạng invite token không hợp lệ (not_found).',
        }

    token, token_err = await _obtain_session_token(session_provider)
    if token_err is not None:
        msg = (
            'Phiên Locket đã hết hạn và không thể làm mới (session_expired).'
            if token_err == 'session_expired'
            else 'Chưa có phiên Locket hợp lệ để tra cứu UID (auth_required).'
        )
        return {'status': token_err, 'user': None, 'message': msg}

    endpoint = _validate_locket_api_endpoint(LOCKET_FETCH_USER_BY_INVITE_URL)
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    body = {'data': {'invite_token': clean_invite}}
    attempts = max(1, min(int(max_retries), 4))

    for attempt in range(attempts):
        try:
            if http_client is not None:
                resp = await http_client.post(
                    endpoint,
                    json=body,
                    headers=headers,
                    timeout=timeout_seconds,
                    follow_redirects=False,
                )
            else:
                async with AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
                    resp = await client.post(endpoint, json=body, headers=headers)
        except (TimeoutError, asyncio.TimeoutError, TimeoutException):
            if attempt + 1 < attempts:
                continue
            return {
                'status': 'lookup_unavailable',
                'user': None,
                'message': 'Hết thời gian chờ khi gọi fetchUserForInviteToken (lookup_unavailable).',
            }
        except (TransportError, ConnectionError, OSError):
            if attempt + 1 < attempts:
                continue
            return {
                'status': 'lookup_unavailable',
                'user': None,
                'message': 'Lỗi kết nối mạng khi gọi fetchUserForInviteToken (lookup_unavailable).',
            }

        if resp.status_code in (502, 503, 504) and attempt + 1 < attempts:
            continue

        try:
            json_payload = resp.json()
        except Exception:
            if resp.status_code in (401, 403, 404, 429) or resp.status_code >= 500:
                return _parse_fetch_user_for_invite_response(resp.status_code, None, invite_token=clean_invite)
            return {
                'status': 'invalid_response',
                'user': None,
                'message': 'Phản hồi từ fetchUserForInviteToken không phải JSON hợp lệ (invalid_response).',
            }

        return _parse_fetch_user_for_invite_response(
            resp.status_code,
            json_payload,
            invite_token=clean_invite,
        )

    return {
        'status': 'lookup_unavailable',
        'user': None,
        'message': 'Không thể kết nối tới fetchUserForInviteToken (lookup_unavailable).',
    }


async def verify_target_firebase_uid(
    *,
    username: str,
    candidate_uid: str,
    owner_identity_proof: dict | None = None,
    returned_username: str | None = None,
    invite_token: str | None = None,
    accounts_v2: Any = None,
) -> dict:
    """
    Step 3: Enforce the 3-level Firebase UID Verification Policy (Section 5):
      - Validates candidate_uid format & source separation from invite_token and Device UUID.
      - Verifies returned_username matches target username (`username_mismatch` on mismatch).
      - Checks MongoDB `accounts_v2` against overwriting an existing verified UID or linking one UID to two accounts (`uid_conflict`).
      - Distinguishes:
        * Level B (`uid_resolved` / `unverified_uid`): UID returned by authenticated lookup, without target owner proof.
        * Level C (`verified_uid`): Target account owner's authenticated session `localId` matches `candidate_uid`.
          NEVER accepts another account's `localId` as proof for the target account!
    """
    clean_target_user = username.strip().removeprefix('@')
    if not is_valid_authenticated_firebase_uid(candidate_uid, invite_token=invite_token):
        return {
            'status': 'invalid_response',
            'firebase_uid': None,
            'uid_verified': False,
            'verification_status': 'unverified_handle',
            'verification_method': 'link_handle_only',
            'verification_source': 'locket_invite_lookup',
            '_server_uid_proof': False,
            'message': 'Firebase UID ứng viên không hợp lệ hoặc trùng với invite token / Device UUID.',
        }
    clean_uid = candidate_uid.strip()

    if not isinstance(returned_username, str) or not returned_username.strip().removeprefix('@'):
        return {
            'status': 'invalid_response', 'firebase_uid': None, 'uid_verified': False,
            'message': 'API chưa cung cấp username để đối chiếu tài khoản.',
        }

    if returned_username is not None:
        clean_ret_user = returned_username.strip().removeprefix('@')
        if clean_ret_user and clean_ret_user.lower() != clean_target_user.lower():
            return {
                'status': 'username_mismatch',
                'firebase_uid': None,
                'uid_verified': False,
                'verification_status': 'unverified_handle',
                'verification_method': 'authenticated_lookup',
                'verification_source': 'locket_invite_lookup',
                '_server_uid_proof': False,
                'message': (
                    f'Username trả về từ API ("{clean_ret_user}") không khớp với username yêu cầu '
                    f'("{clean_target_user}") (username_mismatch).'
                ),
            }

    # Check MongoDB accounts_v2 conflicts
    existing_doc = await _find_in_accounts_v2(accounts_v2, {'locket_id': clean_target_user})
    if existing_doc is None:
        existing_doc = await _find_in_accounts_v2(accounts_v2, {'username': clean_target_user})

    if (
        isinstance(existing_doc, dict)
        and existing_doc.get('_server_uid_proof') is True
        and existing_doc.get('verification_status') == 'verified_uid'
        and existing_doc.get('firebase_uid')
        and existing_doc.get('firebase_uid') != clean_uid
    ):
        return {
            'status': 'uid_conflict',
            'firebase_uid': None,
            'uid_verified': False,
            'verification_status': 'unverified_handle',
            'verification_method': 'authenticated_lookup',
            'verification_source': 'locket_invite_lookup',
            '_server_uid_proof': False,
            'message': 'UID trả về mâu thuẫn với Firebase UID đã được xác minh trước đó của tài khoản này (uid_conflict).',
        }

    uid_owner = await _find_in_accounts_v2(accounts_v2, {'firebase_uid': clean_uid})
    if isinstance(uid_owner, dict):
        owner_lid = str(uid_owner.get('locket_id') or '').strip()
        owner_uname = str(uid_owner.get('username') or '').strip()
        known_names = {n.lower() for n in (owner_lid, owner_uname) if n}
        if known_names and clean_target_user.lower() not in known_names:
            return {
                'status': 'uid_conflict',
                'firebase_uid': None,
                'uid_verified': False,
                'verification_status': 'unverified_handle',
                'verification_method': 'authenticated_lookup',
                'verification_source': 'locket_invite_lookup',
                '_server_uid_proof': False,
                'message': f'Firebase UID này đã được liên kết với một tài khoản khác ("{owner_lid}") trong MongoDB (uid_conflict).',
            }

    # Evaluate owner_identity_proof for Level C (`verified_uid`)
    owner_verified = False
    from .locket_session_provider import VerifiedOwnerProof
    if isinstance(owner_identity_proof, VerifiedOwnerProof):
        owner_identity_proof = vars(owner_identity_proof)
        proof_local_id = str(
            owner_identity_proof.get('localId')
            or owner_identity_proof.get('local_id')
            or owner_identity_proof.get('uid')
            or ''
        ).strip()
        proof_username = str(owner_identity_proof.get('username') or '').strip().removeprefix('@')
        is_target_owner = owner_identity_proof.get('is_target_owner') is True
        # Target ownership requires BOTH:
        # 1. The proof's localId equals the resolved candidate_uid
        # 2. The proof belongs to the target account (is_target_owner=True, and if proof_username is set it matches target username)
        if (
            proof_local_id
            and proof_local_id == clean_uid
            and is_target_owner
            and proof_username.lower() == clean_target_user.lower()
        ):
            owner_verified = True

    if owner_verified:
        return {
            'status': 'verified_uid',
            'firebase_uid': clean_uid,
            'uid_verified': True,
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'owner_localid_match',
            '_server_uid_proof': True,
            'message': f'Đã xác minh quyền sở hữu Firebase UID ({clean_uid}) khớp với localId của tài khoản mục tiêu.',
        }

    return {
        'status': 'uid_resolved',
        'firebase_uid': clean_uid,
        'uid_verified': False,
        'verification_status': 'unverified_uid',
        'verification_method': 'authenticated_lookup',
        'verification_source': 'locket_invite_lookup',
        '_server_uid_proof': False,
        'message': 'Đã tìm được UID từ invite token — cần xác minh quyền sở hữu tài khoản (uid_resolved).',
    }


async def resolve_and_verify_locket_uid(
    username_or_link: str,
    *,
    session_provider: Any = None,
    accounts_v2: Any = None,
    http_client: AsyncClient | None = None,
    public_http_client: AsyncClient | None = None,
    public_fetcher: Any = None,
    owner_identity_proof: dict | None = None,
) -> IdentityResolutionOutput:
    """
    End-to-end 2-step Locket Username / Share Link -> Invite Token -> Authenticated Firebase UID Resolver:
      1. Extracts `invite_token` from `https://locket.cam/<username>` using `resolve_public_locket_share_link()`.
      2. If `session_provider` is connected, calls `fetch_user_by_invite_token()` against
         `https://api.locketcamera.com/fetchUserForInviteToken`.
      3. Verifies candidate UID, username consistency, MongoDB uniqueness, and owner proof via `verify_target_firebase_uid()`.
    """
    now = datetime.now(timezone.utc)
    try:
        normalized_id, input_kind = normalize_lookup_query(username_or_link)
    except ValueError as exc:
        return IdentityResolutionOutput(
            status='invalid_link',
            normalized_id=str(username_or_link or '').strip()[:128],
            input_kind='invalid',
            identity_lookup_at=now,
            message=str(exc),
        )

    # Step 1: Resolve invite_token from public share link https://locket.cam/<username>
    pub_res = await resolve_public_locket_share_link(
        username_or_link,
        http_client=public_http_client,
        public_fetcher=public_fetcher,
        check_dns=(public_http_client is None and public_fetcher is None),
    )
    if pub_res.status != 'invite_token_found' or not pub_res.invite_token:
        return pub_res

    invite_token = pub_res.invite_token
    share_url = pub_res.source_link or f'https://locket.cam/{normalized_id}'

    # Step 2: Call authenticated `fetchUserForInviteToken` using `session_provider`
    api_res = await fetch_user_by_invite_token(
        invite_token,
        session_provider=session_provider,
        http_client=http_client,
    )
    api_status = api_res['status']
    if api_status != 'ok' or not isinstance(api_res.get('user'), dict):
        return IdentityResolutionOutput(
            status=api_status,
            normalized_id=normalized_id,
            input_kind=input_kind,
            username=normalized_id,
            invite_token=invite_token,
            firebase_uid=None,
            source_link=share_url,
            uid_verified=False,
            verification_status='unverified_handle',
            verification_method='link_handle_only',
            verification_source='locket_public_share_link',
            identity_lookup_source='locket_invite_lookup',
            identity_lookup_at=now,
            message=api_res.get('message') or 'Không thể tra cứu Firebase UID từ invite token.',
        )

    user_info = api_res['user']
    candidate_uid = user_info['uid']
    returned_username = user_info.get('username')

    # Resolve owner_identity_proof from explicit argument or from session_provider (if target owner session)
    eff_proof = owner_identity_proof
    if eff_proof is None and isinstance(session_provider, LocketSessionProvider):
        eff_proof = await session_provider.verify_owner_identity(http_client=http_client)

    # Step 3: Verify candidate UID, username match, DB conflicts, and owner proof
    ver_res = await verify_target_firebase_uid(
        username=normalized_id,
        candidate_uid=candidate_uid,
        owner_identity_proof=eff_proof,
        returned_username=returned_username,
        invite_token=invite_token,
        accounts_v2=accounts_v2,
    )
    ver_status = ver_res['status']
    if ver_status not in {'uid_resolved', 'verified_uid'}:
        return IdentityResolutionOutput(
            status=ver_status,
            normalized_id=normalized_id,
            input_kind=input_kind,
            username=normalized_id,
            invite_token=invite_token,
            firebase_uid=None,
            source_link=share_url,
            uid_verified=False,
            verification_status='unverified_handle',
            verification_method='authenticated_lookup',
            verification_source='locket_invite_lookup',
            identity_lookup_source='locket_invite_lookup',
            identity_lookup_at=now,
            message=ver_res['message'],
        )

    is_verified = ver_status == 'verified_uid'
    return IdentityResolutionOutput(
        status='verified_uid' if is_verified else 'uid_resolved',
        normalized_id=normalized_id,
        input_kind=input_kind,
        username=returned_username or normalized_id,
        invite_token=invite_token,
        firebase_uid=ver_res['firebase_uid'],
        source_link=share_url,
        uid_verified=is_verified,
        verification_status=ver_res['verification_status'],
        verification_method=ver_res['verification_method'],
        verification_source=ver_res['verification_source'],
        identity_lookup_source='locket_invite_lookup',
        identity_lookup_at=now,
        uid_resolved_at=now,
        uid_resolution_source=ver_res['verification_source'],
        message=ver_res['message'],
    )
