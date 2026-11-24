import plistlib
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.database import get_accounts, sync_legacy_accounts_to_v2
from app.main import create_app
from app.models import compute_entitlement_status, subscriber_response
from app.passwords import hash_password
from app.profile import build_profile
from app.services.entitlement_service import format_account_record
from app.services.identity_service import verify_account_link_or_identifier
from app.services.pki_service import (
    generate_lab_leaf_certificate,
    generate_lab_root_ca,
    inspect_certificate_metadata,
)


def test_regression_allowed_hosts_accepts_comma_separated_and_json():
    pw_hash = 'pbkdf2_sha256$600000$' + '11' * 16 + '$' + '22' * 32
    s_csv = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=pw_hash,
        mongodb_uri='mongodb+srv://cluster0.example.mongodb.net/locket_manager',
        allowed_hosts='locketgold.vuthanhluan.bond, localhost , 127.0.0.1',
        trusted_proxy_cidrs='192.0.2.0/24, 198.51.100.0/24',
        lab_scoped_domains='mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond',
    )
    assert s_csv.allowed_hosts == ['locketgold.vuthanhluan.bond', 'localhost', '127.0.0.1']
    assert s_csv.trusted_proxy_cidrs == ['192.0.2.0/24', '198.51.100.0/24']
    assert s_csv.lab_scoped_domains == ['mock.lab.vuthanhluan.bond', 'sub.lab.vuthanhluan.bond']


def test_regression_no_default_gold_for_nonexistent_or_revoked_accounts():
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=365)

    # 1. Non-existent account (None) MUST fail closed (unauthorized, empty entitlements)
    status_none, exp_none = compute_entitlement_status(None, now)
    assert status_none == 'unauthorized' and exp_none is None
    resp_none = subscriber_response('unknown_uid', None, now)
    assert resp_none['subscriber']['entitlements'] == {}
    assert resp_none['subscriber']['subscriptions'] == {}

    # 2. Active account gets Gold
    active_doc = {'locket_id': 'user_1', 'expires_date': future, 'status': 'active'}
    status_act, _ = compute_entitlement_status(active_doc, now)
    assert status_act == 'active'
    resp_act = subscriber_response('user_1', active_doc, now)
    assert 'Gold' in resp_act['subscriber']['entitlements']

    # 3. Revoked account MUST fail closed even if expires_date is in the future
    revoked_doc = {'locket_id': 'user_1', 'expires_date': future, 'status': 'revoked'}
    status_rev, _ = compute_entitlement_status(revoked_doc, now)
    assert status_rev == 'revoked'
    resp_rev = subscriber_response('user_1', revoked_doc, now)
    assert resp_rev['subscriber']['entitlements'] == {}
    assert resp_rev['subscriber']['subscriptions'] == {}

    # 4. Pending account MUST fail closed
    pending_doc = {'locket_id': 'user_1', 'expires_date': future, 'status': 'pending'}
    status_pend, _ = compute_entitlement_status(pending_doc, now)
    assert status_pend == 'pending'
    assert subscriber_response('user_1', pending_doc, now)['subscriber']['entitlements'] == {}


def test_regression_legacy_record_without_status_field_never_raises_keyerror():
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=15)
    legacy_doc = {'locket_id': 'legacy_user', 'expires_date': future}
    formatted = format_account_record(legacy_doc, now)
    assert formatted['status'] == 'active'
    assert formatted['locket_id'] == 'legacy_user'

    legacy_alt_field = {'locket_id': 'legacy_alt', 'gold_expires_at': future.isoformat()}
    formatted_alt = format_account_record(legacy_alt_field, now)
    assert formatted_alt['status'] == 'active'


def test_identity_service_zero_guessing_policy():
    # 1. Public share link with username handle -> valid link, but NOT a verified UID
    res_link = verify_account_link_or_identifier('https://locket.cam/luongcamnhung')
    assert res_link.valid_format is True
    assert res_link.input_kind == 'locket_link'
    assert res_link.extracted_identifier == 'luongcamnhung'
    assert res_link.uid_verified is False
    assert res_link.verification_status == 'unverified_handle'

    # 2. Direct 28-character alphanumeric Firebase UID without external proof -> unverified_uid (format_only_uid)
    uid = '4Vee1rBLoJN9TDjql9xPzDEuf5D2'
    res_uid = verify_account_link_or_identifier(uid)
    assert res_uid.valid_format is True
    assert res_uid.input_kind == 'firebase_uid'
    assert res_uid.extracted_identifier == uid
    assert res_uid.uid_verified is False
    assert res_uid.verification_status == 'unverified_uid'
    assert res_uid.verification_method == 'format_only_uid'

    # 2b. Direct 28-character Firebase UID WITH explicit trusted proof -> verified_uid
    res_uid_trusted = verify_account_link_or_identifier(uid, trusted_proof=True)
    assert res_uid_trusted.uid_verified is True
    assert res_uid_trusted.verification_status == 'verified_uid'
    assert res_uid_trusted.verification_method == 'trusted_proof'

    # 3. Link from non-Locket domain -> rejected
    res_bad = verify_account_link_or_identifier('https://evil.example.com/luongcamnhung')
    assert res_bad.valid_format is False
    assert res_bad.input_kind == 'invalid'


def test_pki_lab_root_ca_and_leaf_generation():
    ca_key, ca_cert = generate_lab_root_ca()
    meta = inspect_certificate_metadata(ca_cert)
    assert meta['is_ca'] is True
    assert meta['key_cert_sign'] is True
    assert meta['is_currently_valid'] is True

    leaf_key, leaf_cert = generate_lab_leaf_certificate(
        ca_key, ca_cert, ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond'], validity_days=365
    )
    leaf_cert.verify_directly_issued_by(ca_cert)
    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond']

    with pytest.raises(ValueError):
        generate_lab_leaf_certificate(ca_key, ca_cert, ['locketgold.vuthanhluan.bond'], validity_days=400)


def test_end_to_end_lab_flow_devices_revocation_and_scoped_profile(monkeypatch):
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'locketgold.vuthanhluan.bond,localhost')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    _, ca_cert = generate_lab_root_ca()
    ca_pem = inspect_certificate_metadata(ca_cert)['pem']
    monkeypatch.setenv('ROOT_CA_PEM', ca_pem)
    monkeypatch.setenv('ROOT_CA_PATH', '')
    get_settings.cache_clear()

    app = create_app()
    # In-memory collections
    accounts_store = {}
    accounts_v2_store = {}
    devices_store = {}
    sessions_store = {}
    audit_store = []
    lab_req_store = []

    accounts = AsyncMock()
    accounts_v2 = AsyncMock()
    devices = AsyncMock()
    sessions = AsyncMock()
    admins = AsyncMock()
    audit = AsyncMock()
    lab_requests = AsyncMock()

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

    accounts.update_one.side_effect = acc_update
    accounts.find_one.side_effect = acc_find_one
    acc_cursor = MagicMock()
    acc_cursor.sort.return_value = acc_cursor
    acc_cursor.skip.return_value = acc_cursor
    acc_cursor.limit.return_value = acc_cursor
    acc_cursor.to_list = AsyncMock(side_effect=lambda length: list(accounts_store.values()))
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

    accounts_v2.update_one.side_effect = v2_update
    accounts_v2.find_one.side_effect = v2_find_one
    v2_cursor = MagicMock()
    v2_cursor.to_list = AsyncMock(side_effect=lambda length: list(accounts_v2_store.values()))
    accounts_v2.find = MagicMock(return_value=v2_cursor)

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
        side_effect=lambda length: [d for d in devices_store.values() if d.get('status') == 'active']
    )
    devices.find = MagicMock(return_value=dev_cursor)

    audit.insert_one = AsyncMock(side_effect=lambda doc: audit_store.append(doc))
    lab_requests.insert_one = AsyncMock(side_effect=lambda doc: lab_req_store.append(doc))

    app.dependency_overrides[get_accounts] = lambda: accounts
    app.state.accounts = accounts
    app.state.accounts_v2 = accounts_v2
    app.state.devices = devices
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.audit = audit
    app.state.lab_requests = lab_requests
    app.state.login_limits = AsyncMock()
    app.state.login_limits.find_one_and_update.return_value = {'count': 1}
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://locketgold.vuthanhluan.bond')
    try:
        # 1. Health check
        health = http.get('/api/health').json()
        assert health['status'] == 'ok'
        assert health['nextdns_id'] == 'a8b247'
        assert health['root_ca_loaded'] is True

        # 2. Admin login
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}

        # 3. Verify link
        ver_res = http.post('/admin/verify-link', headers=admin_headers, json={'raw_input': 'https://locket.cam/alice_lab'})
        assert ver_res.status_code == 200
        assert ver_res.json()['verification_status'] == 'unverified_handle'

        # 4. Add account
        future_exp = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
        add_res = http.post('/admin/add-account', headers=admin_headers, json={
            'locket_id': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            'expires_date': future_exp,
            'max_devices': 1,
        })
        assert add_res.status_code == 200
        assert add_res.json()['status'] == 'active'

        # 5. Enroll iPhone device
        dev_res = http.post('/admin/devices', headers=admin_headers, json={
            'locket_id': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            'device_name': 'iPhone 15 Pro Lab',
            'ios_version': '18.1',
        })
        assert dev_res.status_code == 200
        device_token = dev_res.json()['device_token']
        device_id = dev_res.json()['device_id']
        assert device_token.startswith('lkg_dev_')

        # 6. Second device exceeds max_devices=1 -> 409 Conflict
        dev2_res = http.post('/admin/devices', headers=admin_headers, json={
            'locket_id': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            'device_name': 'iPhone 16 Lab',
            'ios_version': '18.2',
        })
        assert dev2_res.status_code == 409

        # 7. Download scoped mobileconfig using device_token
        mc_res = http.get(f'/profile.mobileconfig?mode=scoped_lab&device_token={device_token}')
        assert mc_res.status_code == 200
        parsed_mc = plistlib.loads(mc_res.content)
        dns_payload = parsed_mc['PayloadContent'][0]['DNSSettings']
        assert dns_payload['ServerURL'] == f'https://dns.nextdns.io/a8b247/{device_id}'
        assert 'mock.lab.vuthanhluan.bond' in dns_payload['SupplementalMatchDomains']

        # 8. Query subscriber endpoint using device_token -> Active Gold
        sub_res = http.get(
            '/v1/subscribers/4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            headers={'Authorization': f'Bearer {device_token}'},
        )
        assert sub_res.status_code == 200
        assert sub_res.headers['x-lab-entitlement-status'] == 'active'
        assert 'Gold' in sub_res.json()['subscriber']['entitlements']

        # 9. Revoke account -> Subscriber endpoint immediately returns empty entitlements
        rev_res = http.post(
            '/admin/accounts/4Vee1rBLoJN9TDjql9xPzDEuf5D2/revoke',
            headers=admin_headers,
            json={'reason': 'Testing immediate revocation'},
        )
        assert rev_res.status_code == 200
        assert rev_res.json()['status'] == 'revoked'

        sub_after_rev = http.get(
            '/v1/subscribers/4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            headers={'Authorization': f'Bearer {device_token}'},
        )
        assert sub_after_rev.status_code == 200
        assert sub_after_rev.headers['x-lab-entitlement-status'] == 'revoked'
        assert sub_after_rev.json()['subscriber']['entitlements'] == {}

        # 10. Re-activate account -> Gold restored
        act_res = http.post(
            '/admin/accounts/4Vee1rBLoJN9TDjql9xPzDEuf5D2/activate',
            headers=admin_headers,
            json={},
        )
        assert act_res.status_code == 200
        assert act_res.json()['status'] == 'active'

        sub_after_act = http.get(
            '/v1/subscribers/4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            headers={'Authorization': f'Bearer {device_token}'},
        )
        assert sub_after_act.status_code == 200
        assert sub_after_act.headers['x-lab-entitlement-status'] == 'active'
        assert 'Gold' in sub_after_act.json()['subscriber']['entitlements']

        # 11. Revoke device token -> Device token immediately rejected with 401
        rev_dev_res = http.post(f'/admin/devices/{device_id}/revoke', headers=admin_headers)
        assert rev_dev_res.status_code == 200
        assert rev_dev_res.json()['status'] == 'revoked'

        sub_revoked_dev = http.get(
            '/v1/subscribers/4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            headers={'Authorization': f'Bearer {device_token}'},
        )
        assert sub_revoked_dev.status_code == 401

        assert len(audit_store) >= 5
        assert len(lab_req_store) == 3
    finally:
        http.close()

    get_settings.cache_clear()
