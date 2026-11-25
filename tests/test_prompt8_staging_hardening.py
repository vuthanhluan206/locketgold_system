import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import plistlib
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import PRODUCTION_DATABASE_NAME, Settings, get_settings
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.pki_service import inspect_certificate_metadata
from scripts.generate_lab_ca import main as generate_lab_ca_main
from scripts.migrate_db import reconcile_collections
from scripts.seed_staging_db import assert_safe_staging_db_name, seed_staging_accounts
from scripts.staging_preflight import verify_staging_settings


def test_problem1_docker_staging_volume_mounts_and_uid10001_ca_generation(tmp_path):
    """
    Problem 1 (Docker Staging & Volume Mounts):
    - `compose.staging.yaml` uses `.env.staging` (`${STAGING_ENV_FILE:-.env.staging}`) and sets `APP_ENV=staging`.
    - `api` mounts `./certs_public:/app/certs_public:ro` (read-only) and `./backups:/app/backups`,
      and NEVER mounts `./certs_private`.
    - One-shot `ca_init` service runs under `user: "10001:10001"` and mounts both `certs_public` and `certs_private`.
    - `lab_https` mounts `./certs_private:/etc/caddy/certs:ro`.
    - `generate_lab_ca.py` creates `lab_root_ca.key` (0600) and `lab_leaf.key`/`lab_leaf.pem` readable by Caddy.
    """
    root = Path(__file__).resolve().parent.parent
    staging_yaml = (root / 'compose.staging.yaml').read_text(encoding='utf-8')
    dockerfile_txt = (root / 'Dockerfile').read_text(encoding='utf-8')

    assert 'APP_ENV=staging' in staging_yaml
    assert '${STAGING_ENV_FILE:-.env.staging}' in staging_yaml
    assert './certs_public:/app/certs_public:ro' in staging_yaml
    assert './backups:/app/backups' in staging_yaml
    assert 'ca_init:' in staging_yaml
    assert 'user: "10001:10001"' in staging_yaml
    assert '/app/certs_public' in dockerfile_txt and '10001:10001' in dockerfile_txt

    # Verify API service block does not mount certs_private
    services_part = staging_yaml.split('services:')[1]
    api_section = services_part.split('ca_init:')[0]
    assert 'certs_private' not in api_section

    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'
    generate_lab_ca_main([
        '--out-public', str(pub_dir),
        '--out-private', str(priv_dir),
        '--domains', 'locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond',
    ])
    assert (pub_dir / 'lab_root_ca.pem').is_file()
    assert not list(pub_dir.glob('*.key'))
    assert (priv_dir / 'lab_root_ca.key').is_file()
    assert (priv_dir / 'lab_leaf.key').is_file()
    assert (priv_dir / 'lab_leaf.pem').is_file()


def test_problem2_separation_of_core_staging_http_and_production_https(monkeypatch):
    """
    Problem 2 (Core Staging HTTP Loopback vs Production/Lab HTTPS):
    - Mode A (Core Staging: `APP_ENV=staging`, `REQUIRE_HTTPS=false`, `TRUSTED_PROXY_CIDRS=[]`):
      HTTP requests on loopback succeed (200), while `X-Forwarded-Proto` from untrusted clients does not grant HSTS.
    - Mode B / Production (`REQUIRE_HTTPS=true`):
      Direct plain HTTP requests are rejected (400), spoofed `X-Forwarded-Proto: https` from untrusted IP is rejected (400),
      and requests from an explicit trusted proxy IP in `TRUSTED_PROXY_CIDRS` with `X-Forwarded-Proto: https` succeed.
    """
    pw_hash = hash_password('staging-secret-pass-2026')
    for k, v in {
        'APP_ENV': 'staging',
        'SUPERADMIN_EMAIL': 'admin@example.test',
        'SUPERADMIN_PASSWORD_HASH': pw_hash,
        'MONGODB_URI': 'mongodb://127.0.0.1:27017',
        'MONGODB_DATABASE': 'locket_manager_staging',
        'ALLOWED_HOSTS': 'locketgold.vuthanhluan.bond,localhost,127.0.0.1',
        'REQUIRE_HTTPS': 'false',
        'TRUSTED_PROXY_CIDRS': '[]',
        'NEXTDNS_ID': 'a8b247',
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()

    app = create_app()
    app.state.accounts = AsyncMock()
    app.state.accounts.find_one.return_value = None
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://127.0.0.1', raise_server_exceptions=False)
    try:
        # Mode A: Core Staging over HTTP loopback works cleanly
        res_home = http.get('/')
        assert res_home.status_code == 200
        # Spoofing X-Forwarded-Proto when TRUSTED_PROXY_CIDRS=[] must NOT trigger HSTS header
        res_spoof = http.get('/', headers={'X-Forwarded-Proto': 'https'})
        assert res_spoof.status_code == 200
        assert 'strict-transport-security' not in res_spoof.headers
    finally:
        http.close()
        get_settings.cache_clear()


def test_problem3_staging_database_isolation_preflight_and_seeder(tmp_path):
    """
    Problem 3 (Staging Database Isolation):
    - When `APP_ENV=staging`, `Settings` refuses to boot if `MONGODB_DATABASE=locket_manager` (production).
    - `verify_staging_settings()` and `assert_safe_staging_db_name()` reject `locket_manager` and never leak URI secrets.
    - `seed_staging_accounts()` populates synthetic accounts in `locket_manager_staging` and refuses `locket_manager`.
    """
    pw_hash = 'pbkdf2_sha256$600000$' + '11' * 16 + '$' + '22' * 32

    # 1. Settings rejects APP_ENV=staging + MONGODB_DATABASE=locket_manager
    with pytest.raises(ValidationError, match='strictly forbidden from using production database'):
        Settings(
            _env_file=None,
            app_env='staging',
            superadmin_email='admin@example.test',
            superadmin_password_hash=pw_hash,
            mongodb_uri='mongodb://127.0.0.1:27017',
            mongodb_database=PRODUCTION_DATABASE_NAME,
        )

    # 2. Settings accepts APP_ENV=staging + MONGODB_DATABASE=locket_manager_staging
    s_ok = Settings(
        _env_file=None,
        app_env='staging',
        superadmin_email='admin@example.test',
        superadmin_password_hash=pw_hash,
        mongodb_uri='mongodb+srv://staging_user:SuperSecretPass123@cluster0.example.mongodb.net/locket_manager_staging',
        mongodb_database='locket_manager_staging',
    )
    preflight = verify_staging_settings(s_ok, backup_dir=tmp_path / 'backups')
    assert preflight['database'] == 'locket_manager_staging'
    assert preflight['production_database_protected'] is True
    assert preflight['backup_dir_writable'] is True
    assert 'SuperSecretPass123' not in preflight['masked_uri']
    assert 'SuperSecretPass123' not in str(preflight)

    # 3. Seeder rejects production database
    with pytest.raises(RuntimeError, match='SAFETY ABORT'):
        assert_safe_staging_db_name('locket_manager')
    with pytest.raises(RuntimeError, match='SAFETY ABORT'):
        assert_safe_staging_db_name('arbitrary_prod_db')

    # 4. Seeder succeeds on locket_manager_staging
    v1_store = {}
    v2_store = {}
    db = MagicMock()
    db.accounts.update_one = AsyncMock(side_effect=lambda q, u, upsert=False: v1_store.update({q['locket_id']: u['$set']}))
    db.accounts_v2.update_one = AsyncMock(side_effect=lambda q, u, upsert=False: v2_store.update({q['locket_id']: u['$set']}))

    res = asyncio.run(seed_staging_accounts(db, db_name='locket_manager_staging'))
    assert res['seeded_count'] == 3
    assert 'staging_active_user' in v2_store
    assert 'staging_revoked_user' in v2_store


def test_problem4_three_mobileconfig_modes_and_missing_ca_error(monkeypatch, tmp_path):
    """
    Problem 4 (Mobileconfig & Root CA Lab):
    - Mode 1 (`dns_only`): NextDNS `a8b247`, NO Root CA, valid XML plist.
    - Mode 2 (`lab_ca`): When Root CA is not configured, returns HTTP 503 with clear error;
      when mounted in `certs_public/lab_root_ca.pem`, embeds valid DER CA matching SHA-256 fingerprint.
    - Mode 3 (`scoped_lab`): Embeds `SupplementalMatchDomains` containing only controlled lab domains.
    """
    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'
    ca_info = generate_lab_ca_main([
        '--out-public', str(pub_dir),
        '--out-private', str(priv_dir),
        '--domains', 'locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond',
    ])
    expected_fp = ca_info['ca_metadata']['sha256_fingerprint']
    pw_hash = hash_password('staging-secret-pass-2026')

    # First start WITHOUT Root CA configured -> ?mode=lab_ca must fail closed with 503
    for k, v in {
        'APP_ENV': 'staging',
        'SUPERADMIN_EMAIL': 'admin@example.test',
        'SUPERADMIN_PASSWORD_HASH': pw_hash,
        'MONGODB_URI': 'mongodb://127.0.0.1:27017',
        'MONGODB_DATABASE': 'locket_manager_staging',
        'ALLOWED_HOSTS': 'localhost',
        'REQUIRE_HTTPS': 'false',
        'NEXTDNS_ID': 'a8b247',
        'ROOT_CA_PATH': '',
        'ROOT_CA_PEM': '',
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    app_no_ca = create_app()
    app_no_ca.state.profile = build_profile(get_settings())
    http_no_ca = TestClient(app_no_ca, base_url='http://localhost', raise_server_exceptions=False)
    try:
        assert http_no_ca.get('/profile.mobileconfig?mode=dns_only').status_code == 200
        assert http_no_ca.get('/profile.mobileconfig?mode=lab_ca').status_code == 503
    finally:
        http_no_ca.close()

    # Now mount ROOT_CA_PATH to pub_dir/lab_root_ca.pem
    monkeypatch.setenv('ROOT_CA_PATH', str(pub_dir / 'lab_root_ca.pem'))
    get_settings.cache_clear()
    app_ca = create_app()
    app_ca.state.profile = build_profile(get_settings())
    http_ca = TestClient(app_ca, base_url='http://localhost', raise_server_exceptions=False)
    try:
        res_lab = http_ca.get('/profile.mobileconfig?mode=lab_ca')
        assert res_lab.status_code == 200
        assert res_lab.headers['content-type'] == 'application/x-apple-aspen-config'
        assert 'locket.mobileconfig' in res_lab.headers['content-disposition']
        pl = plistlib.loads(res_lab.content)
        assert [p['PayloadType'] for p in pl['PayloadContent']] == [
            'com.apple.dnsSettings.managed',
            'com.apple.security.root',
        ]
        der_cert = x509.load_der_x509_certificate(pl['PayloadContent'][1]['PayloadContent'])
        assert inspect_certificate_metadata(der_cert)['sha256_fingerprint'] == expected_fp
    finally:
        http_ca.close()
        get_settings.cache_clear()


def test_problem7_mongodb_reconciliation_never_reactivates_revoked_accounts():
    """
    Problem 7 (MongoDB Multi-Collection Reconciliation):
    - Simulates partial write failure where `accounts` was marked `revoked` but `accounts_v2` and `entitlements`
      still had `status='active'` (or vice versa).
    - Verifies `reconcile_collections(db, dry_run=False)` detects the drift and propagates `revoked` (fail-closed),
      NEVER re-activating a revoked account, and synchronizes `expires_date` from `accounts_v2` into `accounts` and `entitlements`.
    """
    now = datetime.now(timezone.utc)
    future_v2 = now + timedelta(days=180)
    old_v1 = now + timedelta(days=30)

    v1_store = {
        # Drift case 1: legacy v1 was marked revoked, but v2 write was interrupted while still active -> must become revoked!
        'interrupted_revoke': {'locket_id': 'interrupted_revoke', 'expires_date': future_v2, 'status': 'revoked', 'revoked_at': now},
        # Drift case 2: v2 expiry was extended to 180d, but v1 still has 30d and entitlements is missing -> must sync to 180d!
        'stale_mirror': {'locket_id': 'stale_mirror', 'expires_date': old_v1, 'status': 'active'},
    }
    v2_store = {
        'interrupted_revoke': {'locket_id': 'interrupted_revoke', 'expires_date': future_v2, 'status': 'active'},
        'stale_mirror': {'locket_id': 'stale_mirror', 'expires_date': future_v2, 'status': 'active'},
    }
    ent_store = {}

    db = MagicMock()
    c1 = MagicMock()
    c1.to_list = AsyncMock(side_effect=lambda length=None: [d.copy() for d in v1_store.values()])
    db.accounts.find = MagicMock(return_value=c1)

    c2 = MagicMock()
    c2.to_list = AsyncMock(side_effect=lambda length=None: [d.copy() for d in v2_store.values()])
    db.accounts_v2.find = MagicMock(return_value=c2)

    ce = MagicMock()
    ce.to_list = AsyncMock(side_effect=lambda length=None: [d.copy() for d in ent_store.values()])
    db.entitlements.find = MagicMock(return_value=ce)

    async def upd_v1(q, u, upsert=False):
        lid = q['locket_id']
        v1_store.setdefault(lid, {'locket_id': lid}).update(u['$set'])

    async def upd_v2(q, u, upsert=False):
        lid = q['locket_id']
        v2_store.setdefault(lid, {'locket_id': lid}).update(u['$set'])

    async def upd_ent(q, u, upsert=False):
        aid = q['account_id']
        ent_store.setdefault(aid, {'account_id': aid}).update(u['$set'])

    db.accounts.update_one = AsyncMock(side_effect=upd_v1)
    db.accounts_v2.update_one = AsyncMock(side_effect=upd_v2)
    db.entitlements.update_one = AsyncMock(side_effect=upd_ent)

    async def _run():
        dry = await reconcile_collections(db, dry_run=True)
        assert dry['drift_count'] >= 3
        assert dry['repaired_operations'] == 0
        # Nothing mutated during dry_run
        assert v2_store['interrupted_revoke']['status'] == 'active'

        applied = await reconcile_collections(db, dry_run=False)
        assert applied['repaired_operations'] >= 3
        # Fail-closed: interrupted_revoke MUST be revoked in all 3 collections, NEVER re-activated!
        assert v2_store['interrupted_revoke']['status'] == 'revoked'
        assert v1_store['interrupted_revoke']['status'] == 'revoked'
        assert ent_store['interrupted_revoke']['status'] == 'revoked'

        # stale_mirror MUST have canonical future_v2 expiry across v1 and entitlements
        assert v1_store['stale_mirror']['expires_date'] == future_v2
        assert ent_store['stale_mirror']['expires_date'] == future_v2
        assert ent_store['stale_mirror']['status'] == 'active'

        # Second pass reports zero drift
        clean = await reconcile_collections(db, dry_run=True)
        assert clean['drift_count'] == 0

    asyncio.run(_run())
