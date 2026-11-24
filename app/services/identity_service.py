import re
from urllib.parse import urlparse
from ..models import LinkVerifyOutput

FIREBASE_UID_PATTERN = re.compile(r'^[A-Za-z0-9]{28}$')
HANDLE_PATTERN = re.compile(r'^[A-Za-z0-9_.\-]{3,36}$')
ACCOUNT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_$:@.\-]{1,128}$')


def verify_account_link_or_identifier(
    raw_input: str,
    *,
    verified_provider_source: str | None = None,
) -> LinkVerifyOutput:
    """
    Validate a Locket share link, @handle, or direct identifier/UID.
    Strictly enforces Zero-Guessing Policy:
    - Never accepts a client-supplied boolean as proof of verification.
    - Distinguishes username (@handle / share link), custom identifier, 28-char UUID format,
      and externally verified identity (`verified_provider_source` supplied only by a trusted
      server-side identity verifier, never from raw user request bodies).
    - When no trusted external verification provider is configured, returns an unverified status
      (`unverified_uid`, `unverified_handle`, or `manual_lab_id`) while recording both
      `verification_method` and `verification_source`.
    """
    cleaned = raw_input.strip()
    if not cleaned:
        return LinkVerifyOutput(
            valid_format=False,
            input_kind='invalid',
            verification_source='none',
            message='Đầu vào trống. Vui lòng nhập link locket.cam/... hoặc UID.',
        )

    # 1. Check if input is a URL (e.g. https://locket.cam/username or locket.camera/links/...)
    if '://' in cleaned or cleaned.lower().startswith(('locket.cam/', 'www.locket.cam/', 'locket.camera/')):
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
        host = (parsed.hostname or '').lower()
        if host not in {'locket.cam', 'www.locket.cam', 'locket.camera', 'www.locket.camera'}:
            return LinkVerifyOutput(
                valid_format=False,
                input_kind='invalid',
                verification_source='url_host_check',
                message='Chỉ chấp nhận tên miền hợp lệ của Locket (locket.cam hoặc locket.camera).',
            )
        segments = [seg for seg in (parsed.path or '').split('/') if seg]
        if not segments:
            return LinkVerifyOutput(
                valid_format=False,
                input_kind='invalid',
                verification_source='url_path_check',
                message='Link Locket không chứa username hoặc mã định danh ở đường dẫn.',
            )
        candidate = segments[-1].lstrip('@').strip()
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
        if HANDLE_PATTERN.fullmatch(candidate):
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
                    'Đã đánh dấu là unverified_handle để kiểm thử trong Lab hoặc bạn có thể nhập trực tiếp UID 28 ký tự.'
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
        handle = cleaned.lstrip('@').strip()
        if HANDLE_PATTERN.fullmatch(handle):
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

    # 4. General Lab Account ID
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
