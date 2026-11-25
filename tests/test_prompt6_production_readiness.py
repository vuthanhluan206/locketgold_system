import asyncio
import plistlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pymongo.errors import OperationFailure

from app.config import Settings, get_settings
from app.database import get_accounts, lifespan, run_controlled_migration
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.pki_service import generate_lab_root_ca, inspect_certificate_metadata
from scripts.migrate_db import (
    export_backup_to_dict,
    preview_rollback,
    restore_rollback_from_dict,
    verify_snapshot_integrity,
)


def test_issue1_legacy_env_vars_compatibility_and_conflict_detection(monkeypatch):
    """Verify legacy ADMIN_EMAIL / ADMIN_PASSWORD_HASH / MONGO_URI compatibility and conflict rejection."""
    pw_hash_1 = 'pbkdf2_sha256$600000$' + '11' * 16 + '$' + '22' * 32
    pw_hash_2 = 'pbkdf2_sha256$600000$' + '33' * 16 + '$' + '44' * 32

    # 1. Legacy ADMIN_EMAIL & ADMIN_PASSWORD_HASH & MONGO_URI work seamlessly when SUPERADMIN_* are absent
    for k in ['SUPERADMIN_EMAIL', 'SUPERADMIN_PASSWORD_HASH', 'MONGODB_URI', 'ADMIN_EMAIL', 'ADMIN_PASSWORD_HASH', 'MONGO_URI']:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv('ADMIN_EMAIL', 'legacy@vuthanhluan.bond')
    monkeypatch.setenv('ADMIN_PASSWORD_HASH', pw_hash_1)
    monkeypatch.setenv('MONGO_URI', 'mongodb+srv://cluster0.example.mongodb.net/locket_manager')
    monkeypatch.setenv('ALLOWED_HOSTS', 'locketgold.vuthanhluan.bond,localhost')

    s_legacy = Settings(_env_file=None)
    assert s_legacy.superadmin_email == 'legacy@vuthanhluan.bond'
    assert s_legacy.superadmin_password_hash.get_secret_value() == pw_hash_1
    assert 'mongodb+srv://' in s_legacy.mongodb_uri.get_secret_value()
    # SecretStr never exposes password hash in repr or str
    assert pw_hash_1 not in repr(s_legacy)
    assert pw_hash_1 not in str(s_legacy)

    # 2. Both SUPERADMIN_* and ADMIN_* set with IDENTICAL values -> accepted
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'legacy@vuthanhluan.bond')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', pw_hash_1)
    s_both_same = Settings(_env_file=None)
    assert s_both_same.superadmin_email == 'legacy@vuthanhluan.bond'

    # 3. Conflicting SUPERADMIN_EMAIL vs ADMIN_EMAIL -> rejected clearly
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'new@vuthanhluan.bond')
    with pytest.raises(ValidationError) as exc_email:
        Settings(_env_file=None)
    assert 'Conflicting environment variables' in str(exc_email.value)

    # 4. Conflicting SUPERADMIN_PASSWORD_HASH vs ADMIN_PASSWORD_HASH -> rejected without leaking hash
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'legacy@vuthanhluan.bond')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', pw_hash_2)
    with pytest.raises(ValidationError) as exc_hash:
        Settings(_env_file=None)
    err_text = str(exc_hash.value)
    assert 'Conflicting environment variables' in err_text
    assert pw_hash_1 not in err_text and pw_hash_2 not in err_text


def test_issue2_staging_compose_zero_port_conflict_with_production_caddy():
    """Verify compose.staging.yaml does not bind ports 80 or 443 and isolates container names."""
    root = Path(__file__).resolve().parent.parent
    staging_yaml = (root / 'compose.staging.yaml').read_text(encoding='utf-8')
    prod_yaml = (root / 'compose.yaml').read_text(encoding='utf-8')

    assert 'locket_staging_api' in staging_yaml
    assert '127.0.0.1:18000:8000' in staging_yaml
    assert '127.0.0.1:18443:8443' in staging_yaml
    assert '"80:80"' not in staging_yaml
    assert '"443:443"' not in staging_yaml
    assert '"80:80"' in prod_yaml and '"443:443"' in prod_yaml


def test_issue3_no_automatic_db_migration_on_fastapi_startup(monkeypatch):
    """Verify FastAPI lifespan startup NEVER automatically mutates or migrates `accounts` -> `accounts_v2`."""
    pw_hash = hash_password('test-secret-password-123')
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', pw_hash)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'localhost')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    get_settings.cache_clear()

    fake_db = MagicMock()
    for col_name in [
        'accounts',
        'accounts_v2',
        'entitlements',
        'devices',
        'admins',
        'sessions',
        'login_limits',
        'audit_logs',
        'lab_requests',
        'test_results',
        'profile_versions',
        'viewers_history',
    ]:
        col = AsyncMock()
        setattr(fake_db, col_name, col)

    fake_client = MagicMock()
    fake_client.admin.command = AsyncMock(return_value={'ok': 1})
    fake_client.__getitem__.return_value = fake_db
    fake_client.close = AsyncMock()

    monkeypatch.setattr('app.database.AsyncMongoClient', lambda *a, **kw: fake_client)

    app = create_app()

    async def _run_lifespan():
        async with lifespan(app):
            # Verify accounts_v2.update_one was NEVER called during startup
            assert fake_db.accounts_v2.update_one.call_count == 0
            assert fake_db.accounts.find.call_count == 0

    asyncio.run(_run_lifespan())
    get_settings.cache_clear()


def test_issue3_and_4_controlled_migration_and_safe_partial_vs_full_rollback():
    """
    Verify controlled migration (dry-run, inserted, skipped, invalid, conflict detection)
    and safe rollback (partial non-destructive vs full collection restore with SHA-256 verification).
    """
    now = datetime.now(timezone.utc)
    future_old = now + timedelta(days=30)
    future_newer = now + timedelta(days=180)

    legacy_store = {
        'valid_new': {'locket_id': 'valid_new', 'expires_date': future_old},
        'already_same': {'locket_id': 'already_same', 'expires_date': future_old},
        'conflict_user': {'locket_id': 'conflict_user', 'expires_date': future_old},
        'bad_id': {'locket_id': 'bad id with spaces!', 'expires_date': future_old},
        'bad_date': {'locket_id': 'bad_date_user', 'expires_date': 'not-a-date'},
    }
    v2_store = {
        'already_same': {
            'locket_id': 'already_same',
            'account_id': 'already_same',
            'expires_date': future_old,
            'status': 'active',
        },
        'conflict_user': {
            'locket_id': 'conflict_user',
            'account_id': 'conflict_user',
            'expires_date': future_newer,
            'status': 'revoked',
        },
    }

    db = MagicMock()
    acc_cursor = MagicMock()
    acc_cursor.to_list = AsyncMock(side_effect=lambda length: [d.copy() for d in legacy_store.values()])
    db.accounts.find = MagicMock(return_value=acc_cursor)

    v2_cursor = MagicMock()
    v2_cursor.to_list = AsyncMock(side_effect=lambda length: [d.copy() for d in v2_store.values()])
    db.accounts_v2.find = MagicMock(return_value=v2_cursor)

    async def v2_find_one(q, proj=None):
        d = v2_store.get(q['locket_id'])
        return d.copy() if d else None

    async def v2_update(q, u, upsert=False):
        lid = q['locket_id']
        doc = v2_store.get(lid, {'locket_id': lid})
        if '$setOnInsert' in u and lid not in v2_store:
            doc.update(u['$setOnInsert'])
        if '$set' in u:
            doc.update(u['$set'])
        v2_store[lid] = doc

    async def v2_delete(q):
        lid = q['locket_id']
        existed = lid in v2_store
        v2_store.pop(lid, None)
        res = MagicMock()
        res.deleted_count = 1 if existed else 0
        return res

    db.accounts_v2.find_one = AsyncMock(side_effect=v2_find_one)
    db.accounts_v2.update_one = AsyncMock(side_effect=v2_update)
    db.accounts_v2.delete_one = AsyncMock(side_effect=v2_delete)

    async def _run():
        # 1. Pre-migration backup with SHA-256 checksum
        snap = await export_backup_to_dict(db)
        assert 'snapshot_sha256' in snap
        assert verify_snapshot_integrity(snap) is True

        # Tampered snapshot fails integrity check
        tampered = {**snap, 'accounts_v2': []}
        with pytest.raises(ValueError, match='SHA-256 integrity check failed'):
            verify_snapshot_integrity(tampered)

        # 2. Dry-run accurately reports counts without mutating v2_store
        dry_report = await run_controlled_migration(db, dry_run=True)
        assert dry_report['total_legacy'] == 5
        assert dry_report['inserted'] == 1       # valid_new
        assert dry_report['skipped'] == 1        # already_same
        assert dry_report['conflict'] == 1       # conflict_user (never overwritten!)
        assert dry_report['invalid'] == 2        # bad_id + bad_date
        assert 'valid_new' not in v2_store       # dry_run performed zero writes

        # 3. Apply controlled migration
        apply_report = await run_controlled_migration(db, dry_run=False)
        assert apply_report['inserted'] == 1
        assert 'valid_new' in v2_store
        # Conflict record in accounts_v2 MUST NOT be overwritten by older legacy data
        assert v2_store['conflict_user']['status'] == 'revoked'
        assert v2_store['conflict_user']['expires_date'] == future_newer

        # 4. Simulate a new account created AFTER snapshot and mutation of an existing record
        v2_store['post_migration_user'] = {
            'locket_id': 'post_migration_user',
            'expires_date': future_newer,
            'status': 'active',
        }
        v2_store['already_same']['status'] = 'revoked'

        # 5. Preview rollback in both modes
        prev_partial = await preview_rollback(db, snap, mode='partial')
        assert prev_partial['to_delete_count'] == 0
        assert set(prev_partial['extra_ids_created_after_snapshot']) == {'post_migration_user', 'valid_new'}

        prev_full = await preview_rollback(db, snap, mode='full')
        assert prev_full['to_delete_count'] == 2

        # 6. Partial rollback restores snapshot records WITHOUT deleting post-snapshot records
        part_res = await restore_rollback_from_dict(db, snap, mode='partial')
        assert part_res['restored_count'] == 2
        assert part_res['deleted_count'] == 0
        assert v2_store['already_same']['status'] == 'active'
        assert 'post_migration_user' in v2_store

        # 7. Full rollback without confirm_destructive=True MUST raise ValueError
        with pytest.raises(ValueError, match='confirm_destructive'):
            await restore_rollback_from_dict(db, snap, mode='full', confirm_destructive=False)

        # 8. Full rollback WITH confirm_destructive=True restores exact collection state at snapshot time
        full_res = await restore_rollback_from_dict(db, snap, mode='full', confirm_destructive=True)
        assert full_res['restored_count'] == 2
        assert full_res['deleted_count'] == 2
        assert set(v2_store.keys()) == {'already_same', 'conflict_user'}

    asyncio.run(_run())


def test_issue5_mobileconfig_dns_only_vs_lab_ca_and_plist_validation(monkeypatch):
    """Verify mobileconfig generation for DNS-only production vs Lab Root CA mode, validated with plistlib."""
    pw_hash = hash_password('test-secret-password-123')
    _, ca_cert = generate_lab_root_ca()
    ca_pem = inspect_certificate_metadata(ca_cert)['pem']

    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', pw_hash)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'localhost')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PEM', ca_pem)
    monkeypatch.setenv('ROOT_CA_PATH', '')
    get_settings.cache_clear()

    app = create_app()
    app.state.profile = build_profile(get_settings())
    http = TestClient(app, base_url='http://localhost')
    try:
        # 1. Production DNS-only profile (?mode=dns_only) contains ONLY NextDNS payload (no Root CA)
        res_dns = http.get('/profile.mobileconfig?mode=dns_only')
        assert res_dns.status_code == 200
        plist_dns = plistlib.loads(res_dns.content)
        payload_types_dns = [p['PayloadType'] for p in plist_dns['PayloadContent']]
        assert payload_types_dns == ['com.apple.dnsSettings.managed']
        assert plist_dns['PayloadContent'][0]['DNSSettings']['ServerURL'] == 'https://dns.nextdns.io/a8b247'

        # 2. Lab CA profile (?mode=lab_ca) contains NextDNS + Scoped Domains + Root CA
        res_lab = http.get('/profile.mobileconfig?mode=lab_ca')
        assert res_lab.status_code == 200
        plist_lab = plistlib.loads(res_lab.content)
        payload_types_lab = [p['PayloadType'] for p in plist_lab['PayloadContent']]
        assert payload_types_lab == ['com.apple.dnsSettings.managed', 'com.apple.security.root']
        der_bytes = plist_lab['PayloadContent'][1]['PayloadContent']
        loaded_der = x509.load_der_x509_certificate(der_bytes)
        assert inspect_certificate_metadata(loaded_der)['sha256_fingerprint'] == inspect_certificate_metadata(ca_cert)['sha256_fingerprint']
    finally:
        http.close()
        get_settings.cache_clear()


def test_issue6_and_7_mongodb_fail_closed_and_srv_auth_error_resilience(monkeypatch):
    """Verify subscriber endpoint fails closed (HTTP 503) on MongoDB errors (Auth, SRV DNS, network failure)."""
    pw_hash = hash_password('test-secret-password-123')
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', pw_hash)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'localhost')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('SUBSCRIBER_API_TOKEN', 's' * 40)
    get_settings.cache_clear()

    app = create_app()
    failing_accounts = AsyncMock()
    failing_accounts.find_one.side_effect = OperationFailure('Authentication failed.')
    app.dependency_overrides[get_accounts] = lambda: failing_accounts
    app.state.accounts = failing_accounts

    http = TestClient(app, base_url='http://localhost')
    try:
        res = http.get('/v1/subscribers/test_user', headers={'Authorization': 'Bearer ' + ('s' * 40)})
        assert res.status_code == 503
        # Must NEVER leak active Gold entitlement on DB failure
        assert 'Gold' not in res.text
    finally:
        http.close()
        get_settings.cache_clear()
