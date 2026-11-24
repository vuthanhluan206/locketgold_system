import asyncio
import json
import py_compile
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.database import get_accounts, sync_legacy_accounts_to_v2
from app.main import create_app
from app.models import compute_entitlement_status, subscriber_response
from app.passwords import hash_password
from app.profile import build_profile
from scripts.migrate_db import export_backup_to_dict, restore_rollback_from_dict


def test_python_compile_and_static_checks():
    """Compile every Python file in app/, scripts/, and tests/ to verify zero syntax errors."""
    root = Path(__file__).resolve().parent.parent
    py_files = (
        list((root / 'app').rglob('*.py'))
        + list((root / 'scripts').rglob('*.py'))
        + list((root / 'tests').rglob('*.py'))
        + [root / 'index.py']
    )
    assert len(py_files) >= 20
    for f in py_files:
        py_compile.compile(str(f), doraise=True)


def test_grace_period_entitlement_support():
    now = datetime.now(timezone.utc)
    past_exp = now - timedelta(days=2)
    future_grace = now + timedelta(days=3)

    account_in_grace = {
        'locket_id': 'grace_user',
        'expires_date': past_exp,
        'grace_period_expires_date': future_grace,
        'status': 'active',
    }
    status, eff_expiry = compute_entitlement_status(account_in_grace, now)
    assert status == 'active'
    assert eff_expiry == future_grace

    resp = subscriber_response('grace_user', account_in_grace, now)
    gold = resp['subscriber']['entitlements']['Gold']
    assert gold['grace_period_expires_date'] == future_grace.isoformat().replace('+00:00', 'Z')


def test_database_migration_backup_and_rollback():
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=30)

    legacy_store = {
        'legacy_1': {'locket_id': 'legacy_1', 'expires_date': future},
        'legacy_2': {'locket_id': 'legacy_2', 'expires_date': now - timedelta(days=10)},
    }
    v2_store = {}

    db = MagicMock()
    acc_cursor = MagicMock()
    acc_cursor.to_list = AsyncMock(side_effect=lambda length: list(legacy_store.values()))
    db.accounts.find = MagicMock(return_value=acc_cursor)

    v2_cursor = MagicMock()
    v2_cursor.to_list = AsyncMock(side_effect=lambda length: list(v2_store.values()))
    db.accounts_v2.find = MagicMock(return_value=v2_cursor)

    async def v2_update(q, u, upsert=False):
        lid = q['locket_id']
        doc = v2_store.get(lid, {'locket_id': lid})
        if '$setOnInsert' in u and lid not in v2_store:
            doc.update(u['$setOnInsert'])
        if '$set' in u:
            doc.update(u['$set'])
        v2_store[lid] = doc

    db.accounts_v2.update_one = AsyncMock(side_effect=v2_update)

    async def _run():
        # 1. Apply migration
        count = await sync_legacy_accounts_to_v2(db)
        assert count == 2
        assert v2_store['legacy_1']['status'] == 'active'
        assert v2_store['legacy_2']['status'] == 'expired'
        assert len(legacy_store) == 2  # Zero data loss in legacy accounts

        # 2. Export backup snapshot
        snap = await export_backup_to_dict(db)
        assert len(snap['accounts']) == 2
        assert len(snap['accounts_v2']) == 2

        # 3. Simulate accidental mutation and rollback from snapshot
        v2_store['legacy_1']['status'] = 'revoked'
        restored = await restore_rollback_from_dict(db, snap)
        assert restored['restored_count'] == 2
        assert v2_store['legacy_1']['status'] == 'active'

    asyncio.run(_run())


def test_admin_frontend_ui_elements_and_docker_configs(monkeypatch):
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'localhost')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    get_settings.cache_clear()

    app = create_app()
    app.state.profile = build_profile(get_settings())
    http = TestClient(app, base_url='http://localhost')
    try:
        admin_html = http.get('/admin').text
        for required_id in [
            'loginForm',
            'verifyLinkForm',
            'rawLinkInput',
            'accountForm',
            'deviceForm',
            'labClientForm',
            'adminDownloadProfile',
            'adminDownloadScopedProfile',
            'auditLogBox',
            'devicesBody',
        ]:
            assert f'id="{required_id}"' in admin_html, f'Missing UI element #{required_id}'

        root = Path(__file__).resolve().parent.parent
        compose_main = (root / 'compose.yaml').read_text(encoding='utf-8')
        compose_lab = (root / 'compose.lab.yaml').read_text(encoding='utf-8')
        caddy_main = (root / 'Caddyfile').read_text(encoding='utf-8')
        caddy_lab = (root / 'Caddyfile.lab').read_text(encoding='utf-8')

        assert 'mem_limit: 384m' in compose_main
        assert 'mem_limit: 128m' in compose_main
        assert '8443:8443' in compose_lab
        assert '80:80' not in compose_lab and '443:443' not in compose_lab
        assert 'locketgold.vuthanhluan.bond' in caddy_main
        assert '8443' in caddy_lab
    finally:
        http.close()
        get_settings.cache_clear()
