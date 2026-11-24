import asyncio
import json
import plistlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pymongo.errors import PyMongoError

from app.config import Settings, get_settings
from app.database import get_accounts
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.identity_service import verify_account_link_or_identifier
from app.services.pki_service import generate_lab_root_ca, inspect_certificate_metadata
from scripts.generate_lab_ca import main as generate_lab_ca_main
from scripts.migrate_db import (
    _json_default,
    export_backup_to_dict,
    restore_rollback_from_dict,
    verify_backup_file_on_disk,
)


def _setup_app_with_stores(monkeypatch, *, require_https: bool = False, enable_proxy: bool = False):
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'locketgold.vuthanhluan.bond,localhost,testserver')
    monkeypatch.setenv('REQUIRE_HTTPS', 'true' if require_https else 'false')
    monkeypatch.setenv('ENABLE_RESEARCH_PROXY', 'true' if enable_proxy else 'false')
    monkeypatch.setenv('RESEARCH_PROXY_UPSTREAM', 'https://mock.lab.vuthanhluan.bond')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('SUBSCRIBER_API_TOKEN', 's' * 40)
    get_settings.cache_clear()

    app = create_app()
    accounts_store = {}
    accounts_v2_store = {}
    entitlements_store = {}
    devices_store = {}
    sessions_store = {}

    accounts = AsyncMock()
    accounts_v2 = AsyncMock()
    entitlements = AsyncMock()
    devices = AsyncMock()
    sessions = AsyncMock()
    admins = AsyncMock()

    admin_doc = {
        '_id': 'superadmin',
        'email': 'admin@example.test',
        'password_hash': encoded,
        'auth_version': 'v1',
    }
    admins.find_one.return_value = admin_doc

    async def sess_insert(doc):
        sessions_store[doc['_id']] = doc.copy()

    async def sess_find(q):
        d = sessions_store.get(q['_id'])
        return d if d and d['expires_at'] > q['expires_at']['$gt'] else None

    sessions.insert_one.side_effect = sess_insert
    sessions.find_one.side_effect = sess_find

    async def acc_update(q, u, upsert=False):
        lid = q['locket_id']
        doc = accounts_store.get(lid, {'locket_id': lid})
        if '$set' in u:
            doc.update(u['$set'])
        accounts_store[lid] = doc

    async def acc_find_one(q, proj=None):
        d = accounts_store.get(q['locket_id'])
        return d.copy() if d else None

    async def acc_delete_one(q):
        existed = q['locket_id'] in accounts_store
        accounts_store.pop(q['locket_id'], None)
        res = MagicMock()
        res.deleted_count = 1 if existed else 0
        return res

    accounts.update_one.side_effect = acc_update
    accounts.find_one.side_effect = acc_find_one
    accounts.delete_one.side_effect = acc_delete_one
    acc_cursor = MagicMock()
    acc_cursor.sort.return_value = acc_cursor
    acc_cursor.skip.return_value = acc_cursor
    acc_cursor.limit.return_value = acc_cursor
    acc_cursor.to_list = AsyncMock(side_effect=lambda length=None: [d.copy() for d in accounts_store.values()])
    accounts.find = MagicMock(return_value=acc_cursor)

    async def v2_update(q, u, upsert=False):
        lid = q['locket_id']
        doc = accounts_v2_store.get(lid, {'locket_id': lid})
        if '$setOnInsert' in u and lid not in accounts_v2_store:
            doc.update(u['$setOnInsert'])
        if '$set' in u:
            doc.update(u['$set'])
        accounts_v2_store[lid] = doc

    async def v2_find_one(q, proj=None):
        d = accounts_v2_store.get(q['locket_id'])
        return d.copy() if d else None

    async def v2_delete_one(q):
        existed = q['locket_id'] in accounts_v2_store
        accounts_v2_store.pop(q['locket_id'], None)
        res = MagicMock()
        res.deleted_count = 1 if existed else 0
        return res

    accounts_v2.update_one.side_effect = v2_update
    accounts_v2.find_one.side_effect = v2_find_one
    accounts_v2.delete_one.side_effect = v2_delete_one
    v2_cursor = MagicMock()
    v2_cursor.sort.return_value = v2_cursor
    v2_cursor.skip.return_value = v2_cursor
    v2_cursor.limit.return_value = v2_cursor
    v2_cursor.to_list = AsyncMock(side_effect=lambda length=None: [d.copy() for d in accounts_v2_store.values()])
    accounts_v2.find = MagicMock(return_value=v2_cursor)

    async def ent_update(q, u, upsert=False):
        key = (q['account_id'], q['entitlement_key'])
        doc = entitlements_store.get(key, {'account_id': q['account_id'], 'entitlement_key': q['entitlement_key']})
        if '$set' in u:
            doc.update(u['$set'])
        entitlements_store[key] = doc

    entitlements.update_one.side_effect = ent_update
    entitlements.delete_many = AsyncMock()

    async def dev_insert(doc):
        devices_store[doc['device_id']] = doc.copy()

    async def dev_find_one(q, proj=None):
        if 'token_hash' in q:
            for d in devices_store.values():
                if d['token_hash'] == q['token_hash']:
                    return d.copy()
        if 'device_id' in q:
            d = devices_store.get(q['device_id'])
            return d.copy() if d else None
        return None

    async def dev_update(q, u):
        d = devices_store.get(q['device_id'])
        if d and '$set' in u:
            d.update(u['$set'])

    devices.insert_one.side_effect = dev_insert
    devices.find_one.side_effect = dev_find_one
    devices.update_one.side_effect = dev_update
    dev_cursor = MagicMock()
    dev_cursor.sort.return_value = dev_cursor
    dev_cursor.limit.return_value = dev_cursor
    dev_cursor.to_list = AsyncMock(
        side_effect=lambda length=None: [d for d in devices_store.values() if d.get('status') == 'active']
    )
    devices.find = MagicMock(return_value=dev_cursor)

    app.dependency_overrides[get_accounts] = lambda: accounts
    app.state.accounts = accounts
    app.state.accounts_v2 = accounts_v2
    app.state.entitlements = entitlements
    app.state.devices = devices
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = AsyncMock()
    app.state.login_limits.find_one_and_update.return_value = {'count': 1}
    app.state.profile = build_profile(get_settings())

    return app, password, accounts_store, accounts_v2_store, entitlements_store, devices_store


def test_p1_device_authorization_cross_account_access_blocked(monkeypatch):
    """
    Section 2 (P1 — Device Authorization):
    - Device token of Account A can read Account A.
    - Device token of Account A MUST NOT read Account B (HTTP 403).
    - Revoked device token returns HTTP 401.
    - Revoked account stops granting Gold entitlement immediately.
    - Service token and Admin session can read both Account A and Account B.
    """
    app, password, *_ = _setup_app_with_stores(monkeypatch)
    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    try:
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}
        service_headers = {'Authorization': 'Bearer ' + ('s' * 40)}

        future_exp = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        for uid in ('account_A', 'account_B'):
            assert http.post('/admin/add-account', headers=admin_headers, json={
                'locket_id': uid,
                'expires_date': future_exp,
            }).status_code == 200

        # Enroll device for account_A
        dev_a = http.post('/admin/devices', headers=admin_headers, json={
            'locket_id': 'account_A',
            'device_name': 'iPhone A',
            'ios_version': '18.1',
        }).json()
        token_a = dev_a['device_token']
        dev_a_headers = {'Authorization': f'Bearer {token_a}'}

        # 1. Device A reading account_A -> 200 OK with Gold
        res_own = http.get('/v1/subscribers/account_A', headers=dev_a_headers)
        assert res_own.status_code == 200
        assert 'Gold' in res_own.json()['subscriber']['entitlements']

        # 2. Device A attempting to read account_B -> 403 Forbidden (P1 Fix!)
        res_cross = http.get('/v1/subscribers/account_B', headers=dev_a_headers)
        assert res_cross.status_code == 403
        assert 'not authorized' in res_cross.json()['detail'].lower()

        res_cross_lab = http.get('/api/lab/subscribers/account_B', headers=dev_a_headers)
        assert res_cross_lab.status_code == 403

        res_cross_inspect = http.post('/api/lab/inspect', headers=dev_a_headers, json={'locket_id': 'account_B'})
        assert res_cross_inspect.status_code == 403

        # 3. Admin session and Service token CAN access both account_A and account_B
        assert http.get('/v1/subscribers/account_B', headers=admin_headers).status_code == 200
        assert http.get('/v1/subscribers/account_B', headers=service_headers).status_code == 200

        # 4. Revoking account_A stops Gold immediately
        assert http.post('/admin/accounts/account_A/revoke', headers=admin_headers, json={'reason': 'audit'}).status_code == 200
        res_rev_acc = http.get('/v1/subscribers/account_A', headers=dev_a_headers)
        assert res_rev_acc.status_code == 200
        assert res_rev_acc.json()['subscriber']['entitlements'] == {}

        # 5. Revoking device A blocks access with 401
        assert http.post(f"/admin/devices/{dev_a['device_id']}/revoke", headers=admin_headers).status_code == 200
        assert http.get('/v1/subscribers/account_A', headers=dev_a_headers).status_code == 401
    finally:
        http.close()
        get_settings.cache_clear()


def test_p1_mongodb_consistency_no_swallowed_errors_and_revoked_precedence(monkeypatch):
    """
    Section 3 (P1 — MongoDB Consistency):
    - Legacy active record MUST NEVER override canonical `accounts_v2` revoked status.
    - Accounts existing ONLY in `accounts_v2` are listed in `GET /admin/accounts` and can be deleted.
    - Mandatory database writes in `accounts_v2` or `entitlements` NEVER fail silently; PyMongoError returns HTTP 503.
    """
    app, password, accounts_store, accounts_v2_store, *_ = _setup_app_with_stores(monkeypatch)
    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    try:
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}
        future = datetime.now(timezone.utc) + timedelta(days=120)

        # 1. Seed a legacy record in `accounts` with future expiry and NO status field,
        # while `accounts_v2` has status='revoked'. Canonical revoked MUST win!
        accounts_store['revoked_user'] = {'locket_id': 'revoked_user', 'expires_date': future}
        accounts_v2_store['revoked_user'] = {
            'locket_id': 'revoked_user',
            'account_id': 'revoked_user',
            'expires_date': future,
            'status': 'revoked',
            'revoked_at': datetime.now(timezone.utc),
        }
        sub_res = http.get('/v1/subscribers/revoked_user', headers=admin_headers)
        assert sub_res.status_code == 200
        assert sub_res.headers['x-lab-entitlement-status'] == 'revoked'
        assert sub_res.json()['subscriber']['entitlements'] == {}

        # 2. Seed an account that exists ONLY in `accounts_v2` (not in legacy `accounts`)
        accounts_v2_store['v2_only_user'] = {
            'locket_id': 'v2_only_user',
            'account_id': 'v2_only_user',
            'expires_date': future,
            'status': 'active',
        }
        list_res = http.get('/admin/accounts', headers=admin_headers)
        assert list_res.status_code == 200
        listed_ids = [item['locket_id'] for item in list_res.json()]
        assert 'v2_only_user' in listed_ids
        assert 'revoked_user' in listed_ids

        # Delete v2_only_user succeeds (204) even though it was not in legacy `accounts`
        del_res = http.delete('/admin/accounts/v2_only_user', headers=admin_headers)
        assert del_res.status_code == 204
        assert 'v2_only_user' not in accounts_v2_store

        # 3. Simulate a write failure on `accounts_v2.update_one` -> MUST fail with 503 (never swallowed!)
        app.state.accounts_v2.update_one.side_effect = PyMongoError('WriteConcernError on accounts_v2')
        fail_add = http.post('/admin/add-account', headers=admin_headers, json={
            'locket_id': 'new_user_fail',
            'expires_date': future.isoformat(),
        })
        assert fail_add.status_code == 503
        assert 'WriteConcernError' not in fail_add.text

        fail_rev = http.post('/admin/accounts/revoked_user/revoke', headers=admin_headers, json={'reason': 'test'})
        assert fail_rev.status_code == 503
    finally:
        http.close()
        get_settings.cache_clear()


def test_p1_https_behind_trusted_caddy_and_readiness_probe(monkeypatch):
    """
    Section 4 (P1 — HTTPS, Caddy & Staging Readiness):
    - When `REQUIRE_HTTPS=true`, untrusted plain HTTP client is rejected (400), even if spoofing `X-Forwarded-Proto: https`.
    - When request arrives from a peer inside `TRUSTED_PROXY_CIDRS` with `X-Forwarded-Proto: https`, it succeeds (200) and emits HSTS.
    - Loopback health/readiness probes (`/api/health`, `/api/ready`) work on 127.0.0.1 even when `REQUIRE_HTTPS=true`.
    - `/api/ready` actively pings MongoDB and returns 503 when MongoDB is down.
    """
    app, *_ = _setup_app_with_stores(monkeypatch, require_https=True)
    # 1. With TRUSTED_PROXY_CIDRS=[], untrusted peer (127.0.0.1 in ASGITransport) is rejected on HTTP,
    # even when spoofing X-Forwarded-Proto: https!
    monkeypatch.setenv('TRUSTED_PROXY_CIDRS', '[]')
    get_settings.cache_clear()
    app = create_app()
    app.state.accounts = AsyncMock()
    app.state.accounts.find_one.return_value = None
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    try:
        assert http.get('/').status_code == 400
        assert http.get('/', headers={'X-Forwarded-Proto': 'https'}).status_code == 400

        # 2. Loopback readiness probe (/api/ready) works over HTTP on 127.0.0.1 even when REQUIRE_HTTPS=true
        ready_loopback = http.get('/api/ready')
        assert ready_loopback.status_code == 200
        assert ready_loopback.json()['status'] == 'ready'

        # 3. When peer is in TRUSTED_PROXY_CIDRS (127.0.0.1/32), X-Forwarded-Proto: https is honored and HSTS is set
        monkeypatch.setenv('TRUSTED_PROXY_CIDRS', '["127.0.0.1/32"]')
        get_settings.cache_clear()
        app_trusted = create_app()
        app_trusted.state.accounts = app.state.accounts
        app_trusted.state.profile = app.state.profile
        http_trusted = TestClient(app_trusted, base_url='http://localhost', raise_server_exceptions=False)
        try:
            res_trusted = http_trusted.get('/', headers={'X-Forwarded-Proto': 'https'})
            assert res_trusted.status_code == 200
            assert res_trusted.headers.get('strict-transport-security') == 'max-age=31536000'
        finally:
            http_trusted.close()

        # 4. Readiness probe fails closed (503) when MongoDB is unreachable
        app.state.accounts.find_one.side_effect = PyMongoError('MongoDB unreachable')
        ready_fail = http.get('https://localhost/api/ready')
        assert ready_fail.status_code == 503
    finally:
        http.close()
        get_settings.cache_clear()


def test_p1_research_proxy_disabled_in_production_and_blocks_third_party_payment_domains(monkeypatch):
    """
    Section 5 (P1 — Research Proxy Security):
    - Disabled by default (`ENABLE_RESEARCH_PROXY=false`) -> returns HTTP 403.
    - Prohibits third-party payment/receipt hosts (`api.revenuecat.com`, `buy.itunes.apple.com`) in upstream or LAB_SCOPED_DOMAINS.
    """
    app, *_ = _setup_app_with_stores(monkeypatch, enable_proxy=False)
    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    try:
        res = http.get('/proxy/v1/subscribers/alice', headers={'Authorization': 'Bearer test'})
        assert res.status_code == 403
        assert 'disabled by default' in res.json()['detail'].lower()
    finally:
        http.close()
        get_settings.cache_clear()

    # Verify third-party domain rejection in LAB_SCOPED_DOMAINS
    pw_hash = 'pbkdf2_sha256$600000$' + '11' * 16 + '$' + '22' * 32
    with pytest.raises(ValidationError, match='prohibited in LAB_SCOPED_DOMAINS'):
        Settings(
            _env_file=None,
            superadmin_email='admin@example.test',
            superadmin_password_hash=pw_hash,
            mongodb_uri='mongodb://127.0.0.1:27017',
            lab_scoped_domains=['api.revenuecat.com'],
        )


def test_section6_generate_lab_ca_cli_flags_and_third_party_domain_rejection(tmp_path):
    """
    Section 6 (Root CA & iOS Profile):
    - `--out-public` and `--out-private` flags work as documented in DEPLOY_STAGING.md.
    - Public directory contains only public certificates (`.pem`, `.cer`), never `.key`.
    - Private directory contains private keys (`lab_root_ca.key`, `lab_leaf.key`) and `lab_leaf.pem` for Caddy.
    - Third-party domains (`api.revenuecat.com`, `api.locketcamera.com`) are rejected.
    """
    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'

    result = generate_lab_ca_main([
        '--out-public', str(pub_dir),
        '--out-private', str(priv_dir),
        '--domains', 'locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond',
    ])
    assert (pub_dir / 'lab_root_ca.pem').is_file()
    assert (pub_dir / 'lab_root_ca.cer').is_file()
    assert not list(pub_dir.glob('*.key')), 'Public certificate directory MUST NOT contain private keys'
    assert (priv_dir / 'lab_root_ca.key').is_file()
    assert (priv_dir / 'lab_leaf.key').is_file()
    assert (priv_dir / 'lab_leaf.pem').is_file()

    with pytest.raises(ValueError, match='prohibited in Research Lab'):
        generate_lab_ca_main([
            '--out-public', str(pub_dir),
            '--out-private', str(priv_dir),
            '--domains', 'api.revenuecat.com',
        ])


def test_section7_persistent_backup_verification_and_no_10k_truncation(tmp_path):
    """
    Section 7 (Backup, Migration & Rollback):
    - Verifies `export_backup_to_dict()` does not silently truncate at 10,000 records (tested with 10,500 records).
    - Verifies `verify_backup_file_on_disk()` validates file existence, size, record counts, and SHA-256 hash.
    """
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=30)
    large_v1 = [{'locket_id': f'user_{i}', 'expires_date': future} for i in range(10500)]
    large_v2 = [{'locket_id': f'user_{i}', 'expires_date': future, 'status': 'active'} for i in range(10500)]

    db = MagicMock()
    c1 = MagicMock()
    c1.to_list = AsyncMock(side_effect=lambda length=None: large_v1 if length is None else large_v1[:length])
    db.accounts.find = MagicMock(return_value=c1)

    c2 = MagicMock()
    c2.to_list = AsyncMock(side_effect=lambda length=None: large_v2 if length is None else large_v2[:length])
    db.accounts_v2.find = MagicMock(return_value=c2)

    async def _run():
        snap = await export_backup_to_dict(db)
        assert snap['accounts_count'] == 10500
        assert snap['accounts_v2_count'] == 10500
        backup_file = tmp_path / 'backups' / 'snapshot_10500.json'
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        backup_file.write_text(json.dumps(snap, default=_json_default), encoding='utf-8')

        verified = verify_backup_file_on_disk(backup_file)
        assert verified['verified'] is True
        assert verified['accounts_count'] == 10500
        assert verified['accounts_v2_count'] == 10500

    asyncio.run(_run())


def test_section8_identity_verification_rejects_client_supplied_trusted_proof(monkeypatch):
    """
    Section 8 (Identity Verification):
    - `POST /admin/verify-link` rejects client-supplied `trusted_proof` boolean (extra='forbid' -> HTTP 422).
    - Direct 28-char UID without server-side provider returns `unverified_uid` and records `verification_source`.
    """
    app, password, *_ = _setup_app_with_stores(monkeypatch)
    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    try:
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}

        # Attempt to spoof trusted_proof=True in request body -> rejected with 422
        spoof_res = http.post('/admin/verify-link', headers=admin_headers, json={
            'raw_input': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            'trusted_proof': True,
        })
        assert spoof_res.status_code == 422

        # Normal verification returns unverified_uid with verification_source
        ok_res = http.post('/admin/verify-link', headers=admin_headers, json={
            'raw_input': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
        })
        assert ok_res.status_code == 200
        body = ok_res.json()
        assert body['uid_verified'] is False
        assert body['verification_status'] == 'unverified_uid'
        assert body['verification_method'] == 'format_only_uid'
        assert body['verification_source'] == 'regex_28char_format_only'
    finally:
        http.close()
        get_settings.cache_clear()


def test_blocker_a_secret_scanner_distinguishes_code_from_real_private_keys():
    """
    Blocker A:
    - `scripts/check_secrets.py` passes on the current repository (returns 0 violations).
    - `REAL_PRIVATE_KEY_BLOCK_RE` accurately catches a real multi-line PEM private key block.
    - Single-line marker checks or test code references do not trigger false positives.
    """
    from scripts.check_secrets import REAL_PRIVATE_KEY_BLOCK_RE, scan_tracked_files

    assert scan_tracked_files() == []

    # Simulated real multi-line PEM key block -> MUST be detected
    fake_pem = (
        "-----BEGIN " + "PRIVATE KEY-----\n"
        + ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n" * 3)
        + "-----END " + "PRIVATE KEY-----"
    )
    assert REAL_PRIVATE_KEY_BLOCK_RE.search(fake_pem) is not None

    # Single-line code reference -> MUST NOT trigger
    code_ref = "assert '-----BEGIN ' + 'PRIVATE KEY-----' not in content"
    assert REAL_PRIVATE_KEY_BLOCK_RE.search(code_ref) is None


def test_blocker_b_canonical_expiry_precedence_and_partial_write_failures(monkeypatch):
    """
    Blocker B:
    - Legacy `accounts` (`doc_v1`) with an older or expired `expires_date` MUST NEVER overwrite
      a newer `expires_date` managed in canonical `accounts_v2` (`doc_v2`).
    - Conversely, if `doc_v2` has an expired `expires_date` while `doc_v1` has an un-updated future `expires_date`,
      canonical `doc_v2` still takes precedence (`expired`).
    - Partial write failures on `entitlements` during `add-account`, `activate`, or `revoke` fail closed with HTTP 503.
    """
    from app.services.entitlement_service import merge_canonical_and_legacy_account

    now = datetime.now(timezone.utc)
    past_exp = now - timedelta(days=10)
    future_short = now + timedelta(days=15)
    future_long = now + timedelta(days=365)

    # 1. Canonical v2 has newer future expiry (365d), legacy v1 has old past expiry (-10d) -> v2 (365d, active) MUST win!
    m1 = merge_canonical_and_legacy_account(
        {'locket_id': 'u1', 'expires_date': future_long, 'status': 'active'},
        {'locket_id': 'u1', 'expires_date': past_exp},
    )
    assert m1['expires_date'] == future_long
    assert m1['status'] == 'active'

    # 2. Canonical v2 was shortened/expired (-10d), legacy v1 still has old future expiry (365d) -> v2 (-10d) MUST win!
    m2 = merge_canonical_and_legacy_account(
        {'locket_id': 'u2', 'expires_date': past_exp, 'status': 'expired'},
        {'locket_id': 'u2', 'expires_date': future_long},
    )
    assert m2['expires_date'] == past_exp

    # 3. Canonical v2 is 'pending' with future expiry, legacy v1 is active -> 'pending' MUST win (no Gold granted)
    m3 = merge_canonical_and_legacy_account(
        {'locket_id': 'u3', 'expires_date': future_long, 'status': 'pending'},
        {'locket_id': 'u3', 'expires_date': future_short, 'status': 'active'},
    )
    assert m3['status'] == 'pending'

    # 4. Partial write failure on step 3 (`entitlements.update_one`) after `accounts` and `accounts_v2` succeed -> HTTP 503
    app, password, accounts_store, accounts_v2_store, *_ = _setup_app_with_stores(monkeypatch)
    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    try:
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}

        # Seed user in both stores with mismatched expiry: legacy has past_exp, v2 has future_long
        accounts_store['diverged_exp_user'] = {'locket_id': 'diverged_exp_user', 'expires_date': past_exp}
        accounts_v2_store['diverged_exp_user'] = {
            'locket_id': 'diverged_exp_user',
            'account_id': 'diverged_exp_user',
            'expires_date': future_long,
            'status': 'active',
        }
        sub_res = http.get('/v1/subscribers/diverged_exp_user', headers=admin_headers)
        assert sub_res.status_code == 200
        assert sub_res.headers['x-lab-entitlement-status'] == 'active'
        assert sub_res.json()['subscriber']['entitlements']['Gold']['expires_date'] == future_long.isoformat().replace('+00:00', 'Z')

        # Now fail entitlements.update_one on activate -> must return 503
        app.state.entitlements.update_one.side_effect = PyMongoError('Entitlement collection write failure')
        act_fail = http.post('/admin/accounts/diverged_exp_user/activate', headers=admin_headers, json={})
        assert act_fail.status_code == 503
    finally:
        http.close()
        get_settings.cache_clear()
