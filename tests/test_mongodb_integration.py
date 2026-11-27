"""Opt in with TEST_MONGODB_URI; all writes use a disposable, uniquely named database."""
import asyncio
import httpx
from datetime import datetime, timedelta, timezone
import os
import secrets
from uuid import uuid4

from fastapi.testclient import TestClient
from pymongo import AsyncMongoClient
import pytest

from app.config import get_settings
from app.main import create_app
from app.passwords import hash_password


@pytest.mark.skipif(not os.environ.get('TEST_MONGODB_URI'), reason='Requires disposable MongoDB')
def test_uid_migration_backup_and_rollback(tmp_path):
    from scripts.migrate_db import apply_uid_journal, inspect_and_migrate_uid_entitlements, uid_journal

    async def run():
        async with AsyncMongoClient(os.environ['TEST_MONGODB_URI'], tz_aware=True) as client:
            if not (await client.admin.command('hello')).get('setName'):
                pytest.skip('Transaction rollback requires a replica set')
            db = client['locket_test_' + uuid4().hex]
            try:
                await db.accounts_v2.insert_one({'locket_id': 'vt.l', 'status': 'active'})
                key = {'entitlement_key': 'Gold', 'account_id': 'vt.l'}
                await db.entitlements.insert_one({**key, 'status': 'active'})
                changes = []
                report = await inspect_and_migrate_uid_entitlements(db, changes_out=changes)
                assert report['planned_changes'] == 2
                path = tmp_path / 'uid.json'
                saved = uid_journal(path, db.name, changes)
                await apply_uid_journal(db, saved)
                assert (await db.entitlements.find_one(key))['status'] == 'revoked'
                assert (await db.accounts_v2.find_one({}))['status'] == 'pending'
                assert (await inspect_and_migrate_uid_entitlements(db))['planned_changes'] == 0
                await apply_uid_journal(db, uid_journal(path, db.name), rollback=True)
                assert (await db.entitlements.find_one(key))['status'] == 'active'
                assert (await db.accounts_v2.find_one({}))['status'] == 'active'
            finally:
                await client.drop_database(db.name)
    asyncio.run(run())


@pytest.mark.skipif(not os.environ.get('TEST_MONGODB_URI'), reason='Set TEST_MONGODB_URI for real MongoDB tests')
def test_real_mongodb_accounts_rotation_and_cold_starts(monkeypatch):
    from app.bootstrap import sync_admin
    uri = os.environ['TEST_MONGODB_URI']
    database = 'locket_test_' + uuid4().hex
    password, new_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    encoded = hash_password(password)
    values = {
        'MONGODB_URI': uri, 'MONGODB_DATABASE': database,
        'SUPERADMIN_EMAIL': 'admin@example.test', 'SUPERADMIN_PASSWORD_HASH': encoded,
        'ALLOWED_HOSTS': '["localhost"]', 'REQUIRE_HTTPS': 'false',
        'ROOT_CA_PEM': '', 'ROOT_CA_PATH': '', 'NEXTDNS_ID': 'abc123',
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()

    def login(http, value):
        result = http.post('/api/admin/login', json={'email': values['SUPERADMIN_EMAIL'], 'password': value})
        assert result.status_code == 200, result.text
        return {'Authorization': 'Bearer ' + result.json()['access_token']}

    async def cleanup():
        assert database.startswith('locket_test_') and len(database) == len('locket_test_') + 32
        client = AsyncMongoClient(uri, serverSelectionTimeoutMS=5000)
        try:
            await client.drop_database(database)
        finally:
            await client.close()

    try:
        with TestClient(create_app(), base_url='http://localhost') as http:
            verified_mongo_uid = 'MongoIntegVerifiedUid1234567'
            http.app.state.identity_provider = lambda q, k: (
                200,
                {'result': {'status': 200, 'data': {'uid': verified_mongo_uid, 'username': 'internal_user_123'}}},
            )
            headers = login(http, password)
            expiry = datetime.now(timezone.utc) + timedelta(days=30)
            for value in [expiry, expiry + timedelta(days=1)]:
                result = http.post('/admin/add-account', headers=headers, json={
                    'locket_id': 'internal_user_123', 'expires_date': value.isoformat(),
                    'max_devices': 2,
                })
                assert result.status_code == 200
            rows = http.get('/admin/accounts', headers=headers).json()
            assert len(rows) == 1
            summary = http.get('/admin/overview', headers=headers).json()
            assert summary['accounts'] == summary['active'] == summary['verified_uid'] == 1
            if http.app.state.transactions_supported:
                from app.database import account_write_options
                from starlette.requests import Request

                async def interrupted_write():
                    async with account_write_options(Request({'type': 'http', 'app': http.app})) as options:
                        await http.app.state.accounts_v2.update_one({'locket_id': 'internal_user_123'},
                                                                   {'$set': {'status': 'pending'}}, **options)
                        raise RuntimeError('simulated interruption before grant write')
                with pytest.raises(RuntimeError, match='simulated interruption'):
                    http.portal.call(interrupted_write)
                assert http.get('/admin/accounts', headers=headers).json()[0]['status'] == 'active'
            response = http.get(f'/v1/subscribers/{verified_mongo_uid}', headers=headers)
            assert 'Gold' in response.json()['subscriber']['entitlements']
            feature_path = '/admin/accounts/internal_user_123/features'
            lab_path = f'/api/lab/accounts/{verified_mongo_uid}/features'
            flags = dict(max_video_duration_seconds=60, enable_private_posts=True, unlocked_filters=True,
                         camera_filters_enabled=True, holiday_effects_enabled=True, unlocked_all_filters=True)
            assert http.put(feature_path, headers=headers, json={**flags, 'enabled': True}).status_code == 422
            assert http.put(feature_path, headers=headers, json=flags).json() == flags
            assert http.get(lab_path, headers=headers).json()['gold'] == {'enabled': True, **flags}

            # Verify canonical accounts_v2 precedence: revoking in v2 cannot be overridden by active legacy accounts
            rev_res = http.post('/admin/accounts/internal_user_123/revoke', headers=headers, json={'reason': 'Real Mongo revoke test'})
            assert rev_res.status_code == 200
            renewed = http.post('/admin/add-account', headers=headers, json={
                'locket_id': 'internal_user_123', 'expires_date': expiry.isoformat(),
            })
            assert renewed.json()['status'] == 'revoked'
            assert not any(http.get(lab_path, headers=headers).json()['gold'].values())
            assert http.get(feature_path, headers=headers).json() == flags

            async def force_legacy_active():
                await http.app.state.accounts.update_one(
                    {'locket_id': 'internal_user_123'},
                    {'$set': {'status': 'active', 'is_active': True, 'expires_date': datetime.now(timezone.utc) + timedelta(days=365)}},
                )

            http.portal.call(force_legacy_active)
            sub_after_legacy_tamper = http.get(f'/v1/subscribers/{verified_mongo_uid}', headers=headers)
            assert sub_after_legacy_tamper.headers['x-lab-entitlement-status'] == 'revoked'
            assert sub_after_legacy_tamper.json()['subscriber']['entitlements'] == {}

            # Re-activate and verify 10 concurrent device enrollments strictly respect max_devices=2 on real MongoDB
            act_res = http.post('/admin/accounts/internal_user_123/activate', headers=headers, json={})
            assert act_res.status_code == 200

            async def concurrent_enrollments():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=http.app),
                                             base_url='http://localhost') as client:
                    responses = await asyncio.gather(*(client.post('/admin/devices', headers=headers, json={
                        'locket_id': 'internal_user_123', 'device_name': f'iPhone Concurrent {idx}', 'ios_version': '18.2',
                    }) for idx in range(10)))
                    return [response.status_code for response in responses]
            statuses = http.portal.call(concurrent_enrollments)
            assert statuses.count(200) == 2
            assert statuses.count(409) == 8

            # Verify revoking both devices and re-enrolling works without slot_index DuplicateKeyError
            active_devs = http.get('/admin/devices?locket_id=internal_user_123', headers=headers).json()
            assert len(active_devs) == 2
            for d in active_devs:
                r_rev = http.post(f"/admin/devices/{d['device_id']}/revoke", headers=headers)
                assert r_rev.status_code == 200

            reenroll_res = http.post('/admin/devices', headers=headers, json={
                'locket_id': 'internal_user_123',
                'device_name': 'iPhone Reenrolled After Revoke',
                'ios_version': '18.2',
            })
            assert reenroll_res.status_code == 200
            reenrolled_dev = reenroll_res.json()
            device_headers = {'Authorization': 'Bearer ' + reenrolled_dev['device_token']}
            assert http.put(feature_path, headers=device_headers, json=flags).status_code == 401
            assert http.get('/api/lab/accounts/another_user/features', headers=device_headers).status_code == 403

            # Verify one-time ticket mode binding & atomic replay protection on real MongoDB
            tk_dns = http.post(
                f"/admin/devices/{reenrolled_dev['device_id']}/profile-ticket?mode=dns_only",
                headers=headers,
            )
            assert tk_dns.status_code == 200
            dns_ticket_val = tk_dns.json()['download_ticket']
            # Escalating dns_only ticket to lab_ca MUST return 403
            assert http.get(f'/profile.mobileconfig?mode=lab_ca&ticket={dns_ticket_val}').status_code == 403
            # Ticket was atomically consumed on the attempt, so second use returns 401
            assert http.get(f'/profile.mobileconfig?mode=dns_only&ticket={dns_ticket_val}').status_code == 401

            async def expire():
                await http.app.state.accounts_v2.update_one({'locket_id': 'internal_user_123'}, {
                    '$set': {'expires_date': datetime.now(timezone.utc) - timedelta(seconds=1), 'status': 'expired'},
                })
                await http.app.state.accounts.update_one({'locket_id': 'internal_user_123'}, {
                    '$set': {'expires_date': datetime.now(timezone.utc) - timedelta(seconds=1), 'status': 'expired'},
                })

            http.portal.call(expire)
            assert http.get('/v1/subscribers/internal_user_123', headers=headers).json()['subscriber']['entitlements'] == {}

        # A different deployment must not overwrite the existing account at startup.
        monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', hash_password(new_password))
        get_settings.cache_clear()
        with TestClient(create_app(), base_url='http://localhost') as http:
            headers = login(http, password)
            http.portal.call(sync_admin, get_settings())
            assert http.get('/api/admin/me', headers=headers).status_code == 401
            headers = login(http, new_password)
            assert http.delete('/admin/accounts/internal_user_123', headers=headers).status_code == 204
            assert http.get('/admin/accounts', headers=headers).json() == []

        # Returning to old environment values must not roll back an explicit password update.
        monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
        get_settings.cache_clear()
        with TestClient(create_app(), base_url='http://localhost') as http:
            headers = login(http, new_password)
            assert http.post('/api/admin/logout', headers=headers).status_code == 204
            assert http.get('/api/admin/me', headers=headers).status_code == 401
    finally:
        asyncio.run(cleanup())
        get_settings.cache_clear()
