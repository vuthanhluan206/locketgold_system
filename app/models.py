from datetime import date, datetime, time, timezone
from typing import Annotated, Literal
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

ACCOUNT_ID_REGEX = r'^[A-Za-z0-9_$:@.\-]{1,128}$'
AccountId = Annotated[str, Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_$:@.\-]+$')]
EntitlementStatus = Literal['active', 'expired', 'revoked', 'pending', 'unauthorized']
VerificationStatus = Literal['verified_uid', 'unverified_uid', 'unverified_handle', 'manual_lab_id']
VerificationMethod = Literal['trusted_proof', 'direct_uid', 'format_only_uid', 'link_handle_only', 'admin_manual_override']


def normalize_expiry(value) -> datetime:
    if isinstance(value, str):
        value = date.fromisoformat(value) if len(value) == 10 else datetime.fromisoformat(value.replace('Z', '+00:00'))
    if isinstance(value, date) and not isinstance(value, datetime):
        value = datetime.combine(value, time(23, 59, 59), tzinfo=timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('expires_date must be a date or a datetime with timezone')
    return value.astimezone(timezone.utc)


def compute_entitlement_status(account: dict | None, now: datetime | None = None) -> tuple[EntitlementStatus, datetime | None]:
    """Single Source of Truth for account entitlement status. Fails closed on missing or invalid records."""
    now = now if now is not None else datetime.now(timezone.utc)
    if not account or not isinstance(account, dict):
        return 'unauthorized', None

    explicit_status = str(account.get('status') or '').lower()
    if explicit_status == 'revoked' or account.get('revoked_at') is not None or account.get('is_active') is False:
        try:
            raw_exp = account.get('expires_date') or account.get('expires_at') or account.get('gold_expires_at')
            expiry = normalize_expiry(raw_exp) if raw_exp is not None else None
        except (ValueError, TypeError, KeyError):
            expiry = None
        return 'revoked', expiry

    if explicit_status == 'pending':
        try:
            raw_exp = account.get('expires_date') or account.get('expires_at') or account.get('gold_expires_at')
            expiry = normalize_expiry(raw_exp) if raw_exp is not None else None
        except (ValueError, TypeError, KeyError):
            expiry = None
        return 'pending', expiry

    try:
        raw_exp = account.get('expires_date') if 'expires_date' in account else (
            account.get('expires_at') or account.get('gold_expires_at')
        )
        expiry = normalize_expiry(raw_exp) if raw_exp is not None else None
    except (ValueError, TypeError, KeyError):
        expiry = None

    try:
        raw_grace = account.get('grace_period_expires_date')
        grace_expiry = normalize_expiry(raw_grace) if raw_grace is not None else None
    except (ValueError, TypeError, KeyError):
        grace_expiry = None

    if expiry is None:
        return 'expired', None

    if expiry > now:
        return 'active', expiry
    if grace_expiry is not None and grace_expiry > now:
        return 'active', grace_expiry
    return 'expired', expiry


class AccountInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    locket_id: AccountId
    expires_date: AwareDatetime
    username: str | None = Field(default=None, max_length=64, pattern=r'^[A-Za-z0-9_.\-]*$')
    firebase_uid: str | None = Field(default=None, pattern=r'^[A-Za-z0-9]{28}$')
    source_link: str | None = Field(default=None, max_length=256)
    verification_status: VerificationStatus = 'manual_lab_id'
    verification_method: VerificationMethod = 'admin_manual_override'
    verification_source: str = Field(default='admin_direct_input', max_length=128)
    status: Literal['active', 'pending', 'revoked'] = 'active'
    max_devices: int = Field(default=2, ge=1, le=10)
    notes: str | None = Field(default=None, max_length=256)

    @field_validator('expires_date', mode='before')
    @classmethod
    def parse_expiry(cls, value):
        return normalize_expiry(value)

    @field_validator('expires_date')
    @classmethod
    def future_date(cls, value: datetime) -> datetime:
        if value <= datetime.now(timezone.utc):
            raise ValueError('expires_date must be in the future')
        return value


class AccountOutput(BaseModel):
    locket_id: str
    expires_date: AwareDatetime
    status: EntitlementStatus = 'active'
    username: str | None = None
    firebase_uid: str | None = None
    source_link: str | None = None
    verification_status: VerificationStatus = 'manual_lab_id'
    verification_method: VerificationMethod = 'admin_manual_override'
    verification_source: str = 'admin_direct_input'
    max_devices: int = 2
    revoked_at: AwareDatetime | None = None
    revoke_reason: str | None = None
    notes: str | None = None
    updated_at: AwareDatetime | None = None


class PublicLookupOutput(BaseModel):
    exists: bool


class AdminAccountLookupOutput(BaseModel):
    exists: bool
    normalized_query: str
    input_kind: Literal['firebase_uid', 'locket_link', 'handle', 'custom_id']
    username: str | None = None
    internal_identifier: str | None = None
    firebase_uid: str | None = None
    uid_verified: bool = False
    verification_status: VerificationStatus = 'unverified_handle'
    verification_method: VerificationMethod = 'link_handle_only'
    verification_source: str = 'format_inspection_only'
    entitlement_status: EntitlementStatus | None = None
    expires_date: AwareDatetime | None = None
    updated_at: AwareDatetime | None = None
    message: str


class LinkVerifyInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    raw_input: str = Field(min_length=1, max_length=256)


class LinkVerifyOutput(BaseModel):
    valid_format: bool
    input_kind: Literal['firebase_uid', 'locket_link', 'handle', 'custom_id', 'invalid']
    extracted_identifier: str | None = None
    extracted_username: str | None = None
    normalized_link: str | None = None
    exists_in_db: bool = False
    resolved_identifier: str | None = None
    resolved_firebase_uid: str | None = None
    entitlement_status: EntitlementStatus | None = None
    expires_date: AwareDatetime | None = None
    updated_at: AwareDatetime | None = None
    uid_verified: bool = False
    verification_status: VerificationStatus = 'unverified_handle'
    verification_method: VerificationMethod = 'link_handle_only'
    verification_source: str = 'format_inspection_only'
    message: str


class RevokeAccountInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    reason: str = Field(default='Revoked by administrator', min_length=1, max_length=256)


class ActivateAccountInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expires_date: AwareDatetime | None = None

    @field_validator('expires_date', mode='before')
    @classmethod
    def parse_optional_expiry(cls, value):
        if value is None:
            return None
        return normalize_expiry(value)


class DeviceCreateInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    locket_id: AccountId
    device_name: str = Field(min_length=1, max_length=64, pattern=r'^[A-Za-z0-9 _.\-()]+$')
    ios_version: str = Field(default='18.0', min_length=1, max_length=24, pattern=r'^[0-9A-Za-z._\-]+$')


class DeviceOutput(BaseModel):
    device_id: str
    locket_id: str
    device_name: str
    ios_version: str
    token_prefix: str
    device_token: str | None = None
    status: Literal['active', 'revoked']
    created_at: AwareDatetime
    last_seen_at: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None


class TestResultInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scenario: str = Field(min_length=1, max_length=128)
    locket_id: AccountId | None = None
    device_id: str | None = Field(default=None, max_length=64)
    dns_verified: bool = False
    tls_verified: bool = False
    mock_entitlement_active: bool = False
    observed_client_state: str = Field(min_length=1, max_length=512)
    verdict: Literal['VERIFIED', 'PARTIALLY_VERIFIED', 'NOT_VERIFIED', 'FAILED'] = 'NOT_VERIFIED'


def subscriber_response(account_id: str, account: dict | None, now: datetime | None = None) -> dict:
    """Build RevenueCat-compatible CustomerInfo response strictly from verified database state."""
    now = now if now is not None else datetime.now(timezone.utc)
    status, expiry = compute_entitlement_status(account, now)
    active = (status == 'active' and expiry is not None)
    entitlement_expires = expiry.isoformat().replace('+00:00', 'Z') if active and expiry else None

    product_id = "com.locket.gold.yearly"
    now_str = now.isoformat().replace('+00:00', 'Z')
    purchase_str = "2026-01-01T00:00:00Z"
    if isinstance(account, dict) and isinstance(account.get('purchase_date'), datetime):
        purchase_str = account['purchase_date'].astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

    grace_str = None
    if active and isinstance(account, dict) and account.get('grace_period_expires_date') is not None:
        try:
            grace_dt = normalize_expiry(account['grace_period_expires_date'])
            grace_str = grace_dt.isoformat().replace('+00:00', 'Z')
        except (ValueError, TypeError):
            grace_str = None

    entitlement = {
        'expires_date': entitlement_expires,
        'grace_period_expires_date': grace_str,
        'product_identifier': product_id,
        'purchase_date': purchase_str,
    } if active else None

    subscriptions = {
        product_id: {
            'expires_date': entitlement_expires,
            'grace_period_expires_date': grace_str,
            'is_sandbox': False,
            'original_purchase_date': purchase_str,
            'purchase_date': purchase_str,
            'ownership_type': 'PURCHASED',
            'store': 'app_store',
        }
    } if active else {}

    return {
        'request_date': now_str,
        'request_date_ms': int(now.timestamp() * 1000),
        'subscriber': {
            'original_app_user_id': account_id,
            'non_subscriptions': {},
            'first_seen': now_str,
            'entitlements': {'Gold': entitlement} if active else {},
            'subscriptions': subscriptions,
            'management_url': None,
            'original_purchase_date': purchase_str,
        },
    }
