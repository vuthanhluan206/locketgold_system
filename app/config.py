import json
import os
import re
from functools import lru_cache
from ipaddress import ip_network
from typing import Annotated, Any
from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from .passwords import validate_password_hash


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore', hide_input_in_errors=True)
    superadmin_email: str = Field(
        min_length=3,
        max_length=254,
        pattern=r'^[^\s@]+@[^\s@]+\.[^\s@]+$',
        validation_alias=AliasChoices('superadmin_email', 'SUPERADMIN_EMAIL', 'admin_email', 'ADMIN_EMAIL'),
    )
    superadmin_password_hash: SecretStr = Field(
        validation_alias=AliasChoices(
            'superadmin_password_hash',
            'SUPERADMIN_PASSWORD_HASH',
            'admin_password_hash',
            'ADMIN_PASSWORD_HASH',
        )
    )
    mongodb_uri: SecretStr = Field(
        validation_alias=AliasChoices('mongodb_uri', 'MONGODB_URI', 'mongo_uri', 'MONGO_URI')
    )
    mongodb_database: str = 'locket_manager'
    nextdns_id: str = Field(default='', pattern=r'^([a-fA-F0-9]{6})?$')
    root_ca_path: str = ''
    root_ca_pem: str = Field(default='', max_length=65536, repr=False)
    lab_domain: str = Field(default='locketgold.vuthanhluan.bond', max_length=253)
    lab_scoped_domains: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            'mock.lab.vuthanhluan.bond',
            'sub.lab.vuthanhluan.bond',
            'locketgold.vuthanhluan.bond',
        ]
    )
    admin_path: str = Field(default='/admin', pattern=r'^/[A-Za-z0-9_-]{1,64}$')
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ['localhost', '127.0.0.1', '[::1]']
    )
    vercel: str = ''
    vercel_url: str = ''
    vercel_project_production_url: str = ''
    vercel_branch_url: str = ''
    require_https: bool = False
    enable_research_proxy: bool = False
    research_proxy_upstream: str = 'http://127.0.0.1:8081'
    session_ttl_seconds: int = Field(default=3600, ge=300, le=86400)
    subscriber_api_token: SecretStr | None = None
    turnstile_site_key: str = Field(default='', pattern=r'^[A-Za-z0-9_-]*$', max_length=256)
    turnstile_secret_key: SecretStr = SecretStr('')
    turnstile_hostname: str = ''
    trusted_proxy_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @model_validator(mode='before')
    @classmethod
    def check_legacy_admin_conflicts(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        def _get_ci(keys: tuple[str, ...]):
            for k in keys:
                if k in data and data[k] not in (None, ''):
                    return data[k]
                env_val = os.environ.get(k)
                if env_val not in (None, ''):
                    return env_val
            return None

        sup_email = _get_ci(('superadmin_email', 'SUPERADMIN_EMAIL'))
        leg_email = _get_ci(('admin_email', 'ADMIN_EMAIL'))
        if sup_email and leg_email and str(sup_email).strip().lower() != str(leg_email).strip().lower():
            raise ValueError(
                'Conflicting environment variables: SUPERADMIN_EMAIL and ADMIN_EMAIL differ; unify them in .env'
            )

        def _unwrap(val):
            return val.get_secret_value() if isinstance(val, SecretStr) else str(val)

        sup_hash = _get_ci(('superadmin_password_hash', 'SUPERADMIN_PASSWORD_HASH'))
        leg_hash = _get_ci(('admin_password_hash', 'ADMIN_PASSWORD_HASH'))
        if sup_hash and leg_hash and _unwrap(sup_hash).strip() != _unwrap(leg_hash).strip():
            raise ValueError(
                'Conflicting environment variables: SUPERADMIN_PASSWORD_HASH and ADMIN_PASSWORD_HASH differ'
            )
        return data

    @field_validator('admin_path')
    @classmethod
    def validate_admin_path(cls, value: str) -> str:
        if value in {'/proxy', '/api', '/v1', '/favicon', '/robots'}:
            raise ValueError('ADMIN_PATH conflicts with an application route')
        return value

    @model_validator(mode='after')
    def deployment_hosts(self):
        if self.vercel == '1':
            for host in (self.vercel_url, self.vercel_branch_url):
                if host:
                    if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.vercel\.app', host):
                        raise ValueError('Vercel system URL must be an exact vercel.app hostname')
                    if host.lower() not in self.allowed_hosts:
                        self.allowed_hosts.append(host.lower())
            host = self.vercel_project_production_url.lower()
            if re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.vercel\.app', host) and host not in self.allowed_hosts:
                self.allowed_hosts.append(host)
        return self

    @field_validator('trusted_proxy_cidrs', mode='before')
    @classmethod
    def validate_proxy_cidrs(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                cidrs = []
            elif raw.startswith('['):
                cidrs = json.loads(raw)
            else:
                cidrs = [c.strip() for c in raw.split(',') if c.strip()]
        elif isinstance(value, list):
            cidrs = [str(c).strip() for c in value if str(c).strip()]
        else:
            raise ValueError('TRUSTED_PROXY_CIDRS must be a list of CIDRs')
        for network in cidrs:
            ip_network(network)
        return cidrs

    @field_validator('lab_scoped_domains', mode='before')
    @classmethod
    def validate_scoped_domains(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return []
            if raw.startswith('['):
                items = json.loads(raw)
            else:
                items = [d.strip() for d in raw.split(',') if d.strip()]
        elif isinstance(value, list):
            items = [str(d).strip() for d in value if str(d).strip()]
        else:
            raise ValueError('LAB_SCOPED_DOMAINS must be a list of domain names')
        forbidden = {
            'api.revenuecat.com',
            'revenuecat.com',
            'buy.itunes.apple.com',
            'sandbox.itunes.apple.com',
            'api.locketcamera.com',
        }
        for d in items:
            clean = d.lower()
            if clean in forbidden or any(clean.endswith('.' + fb) for fb in forbidden):
                raise ValueError(f"Third-party domain '{d}' is prohibited in LAB_SCOPED_DOMAINS")
        return items

    @field_validator('subscriber_api_token')
    @classmethod
    def validate_subscriber_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            raw = value.get_secret_value()
            if not 32 <= len(raw) <= 256 or not raw.isascii() or any(c.isspace() for c in raw):
                raise ValueError('SUBSCRIBER_API_TOKEN must be a random ASCII token of 32-256 characters')
        return value

    @field_validator('superadmin_password_hash')
    @classmethod
    def validate_hash(cls, value: SecretStr) -> SecretStr:
        validate_password_hash(value.get_secret_value())
        return value

    @field_validator('superadmin_email')
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower()

    @field_validator('mongodb_uri')
    @classmethod
    def validate_uri(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith(('mongodb://', 'mongodb+srv://')):
            raise ValueError('MONGODB_URI must be a MongoDB connection URI')
        return value

    @field_validator('allowed_hosts', mode='before')
    @classmethod
    def validate_hosts(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            raw = value.strip()
            if raw.startswith('['):
                try:
                    hosts = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError('Invalid JSON array in ALLOWED_HOSTS') from exc
            else:
                hosts = [h.strip() for h in raw.split(',') if h.strip()]
        elif isinstance(value, list):
            hosts = [str(h).strip() for h in value if str(h).strip()]
        else:
            raise ValueError('ALLOWED_HOSTS must be a list of hostnames')
        if not hosts or any('*' in host or '://' in host or '/' in host for host in hosts):
            raise ValueError('ALLOWED_HOSTS must contain explicit hostnames and never wildcard (*)')
        return hosts


@lru_cache
def get_settings() -> Settings:
    return Settings()
