import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from app.config import get_settings
from app.database import get_accounts
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.lab_inspector_service import redact_headers, redact_payload
from app.services.pki_service import (
    generate_lab_leaf_certificate,
    generate_lab_root_ca,
    inspect_certificate_metadata,
    match_tls_hostname,
    verify_certificate_chain_and_hostname,
)
from scripts.lab_test_client import format_entitlement_report


def test_x509_chain_fingerprint_and_tls_hostname_verification():
    ca_key, ca_cert = generate_lab_root_ca()
    leaf_key, leaf_cert = generate_lab_leaf_certificate(
        ca_key,
        ca_cert,
        ['locketgold.vuthanhluan.bond', '*.lab.vuthanhluan.bond'],
        validity_days=365,
    )

    # 1. Exact SAN match
    res_exact = verify_certificate_chain_and_hostname(ca_cert, leaf_cert, 'locketgold.vuthanhluan.bond')
    assert res_exact['valid'] is True
    assert res_exact['hostname_matched'] is True
    assert res_exact['errors'] == []
    assert len(res_exact['root_ca_sha256'].split(':')) == 32
    assert len(res_exact['leaf_sha256'].split(':')) == 32

    # 2. Wildcard SAN match (*.lab.vuthanhluan.bond)
    res_wild = verify_certificate_chain_and_hostname(ca_cert, leaf_cert, 'mock.lab.vuthanhluan.bond')
    assert res_wild['valid'] is True
    assert res_wild['hostname_matched'] is True

    # 3. Multi-level subdomain must NOT match single-level wildcard (RFC 6125)
    assert match_tls_hostname('*.lab.vuthanhluan.bond', 'a.b.lab.vuthanhluan.bond') is False
    res_deep = verify_certificate_chain_and_hostname(ca_cert, leaf_cert, 'a.b.lab.vuthanhluan.bond')
    assert res_deep['valid'] is False
    assert res_deep['hostname_matched'] is False

    # 4. Unrelated hostname must fail verification
    res_wrong_host = verify_certificate_chain_and_hostname(ca_cert, leaf_cert, 'evil.example.com')
    assert res_wrong_host['valid'] is False
    assert any('does not match any SAN' in e for e in res_wrong_host['errors'])

    # 5. Untrusted / different Root CA must fail chain signature verification
    _, other_ca_cert = generate_lab_root_ca(common_name='Untrusted Other CA')
    res_wrong_ca = verify_certificate_chain_and_hostname(other_ca_cert, leaf_cert, 'locketgold.vuthanhluan.bond')
    assert res_wrong_ca['valid'] is False
    assert any('signature verification by Root CA failed' in e for e in res_wrong_ca['errors'])

    # 6. Future timestamp beyond leaf expiration must fail validity check
    future_now = datetime.now(timezone.utc) + timedelta(days=400)
    res_expired = verify_certificate_chain_and_hostname(
        ca_cert, leaf_cert, 'locketgold.vuthanhluan.bond', now=future_now
    )
    assert res_expired['valid'] is False
    assert any('expired' in e for e in res_expired['errors'])


def test_sensitive_data_redaction_in_headers_and_payloads():
    raw_headers = {
        'Host': 'locketgold.vuthanhluan.bond',
        'Authorization': 'Bearer lkg_dev_SuperSecretDeviceTokenValue1234567890',
        'Cookie': 'session=secret_cookie_value',
        'X-Admin-Token': 'secret_admin_token_xyz',
        'User-Agent': 'LocketGoldLabTestClient/3.0',
    }
    redacted_h = redact_headers(raw_headers)
    assert redacted_h['Host'] == 'locketgold.vuthanhluan.bond'
    assert redacted_h['User-Agent'] == 'LocketGoldLabTestClient/3.0'
    assert 'SuperSecretDeviceTokenValue1234567890' not in redacted_h['Authorization']
    assert '***REDACTED***' in redacted_h['Authorization']
    assert redacted_h['Cookie'] == '***REDACTED***'
    assert redacted_h['X-Admin-Token'] == '***REDACTED***'

    raw_body = {
        'locket_id': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
        'password': 'my_super_secret_password',
        'nested': {
            'sessions': [{'refreshToken': 'firebase-refresh-credential',
                          'private_key': 'private-key-material'}],
            'device_token': 'lkg_dev_SuperSecretDeviceTokenValue1234567890',
            'note': 'Using Bearer secret_inline_token_987654321 in text',
        },
    }
    redacted_b = redact_payload(raw_body)
    assert redacted_b['nested']['sessions'] == [
        {'refreshToken': '***REDACTED***', 'private_key': '***REDACTED***'}
    ]
    assert redacted_b['locket_id'] == '4Vee1rBLoJN9TDjql9xPzDEuf5D2'
    assert 'my_super_secret_password' not in redacted_b['password']
    assert 'SuperSecretDeviceTokenValue1234567890' not in redacted_b['nested']['device_token']
    assert 'secret_inline_token_987654321' not in redacted_b['nested']['note']


def test_https_lab_four_states_inspector_and_test_client(monkeypatch):
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    service_token = secrets.token_urlsafe(40)
    _, ca_cert = generate_lab_root_ca()
    ca_meta = inspect_certificate_metadata(ca_cert)

    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond,localhost')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PEM', ca_meta['pem'])
    monkeypatch.setenv('ROOT_CA_PATH', '')
    monkeypatch.setenv('SUBSCRIBER_API_TOKEN', service_token)
    get_settings.cache_clear()

    app = create_app()
    now = datetime.now(timezone.utc)
    active_uid = '4Vee1rBLoJN9TDjql9xPzDEuf5D2'
    accounts_store = {
        active_uid: {
            'locket_id': active_uid,
            'account_id': active_uid,
            'firebase_uid': active_uid,
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'verified_subscriber_traffic',
            '_server_uid_proof': True,
            'expires_date': now + timedelta(days=90),
            'status': 'active',
        },
        'user_expired': {
            'locket_id': 'user_expired',
            'expires_date': now - timedelta(days=5),
            'status': 'expired',
        },
        'user_revoked': {
            'locket_id': 'user_revoked',
            'expires_date': now + timedelta(days=90),
            'status': 'revoked',
            'revoked_at': now - timedelta(minutes=10),
        },
    }
    lab_req_store = []
    sessions_store = {}

    accounts = AsyncMock()
    accounts.find_one = AsyncMock(side_effect=lambda q, proj=None: accounts_store.get(q['locket_id']))
    accounts_v2 = AsyncMock()
    accounts_v2.find_one = AsyncMock(side_effect=lambda q, proj=None: accounts_store.get(q['locket_id']))
    lab_requests = AsyncMock()
    lab_requests.insert_one = AsyncMock(side_effect=lambda doc: lab_req_store.append(doc))
    lab_cursor = MagicMock()
    lab_cursor.sort.return_value = lab_cursor
    lab_cursor.limit.return_value = lab_cursor
    lab_cursor.to_list = AsyncMock(side_effect=lambda length: list(reversed(lab_req_store)))
    lab_requests.find = MagicMock(return_value=lab_cursor)

    admins = AsyncMock()
    admins.find_one.return_value = {
        '_id': 'superadmin',
        'email': 'admin@example.test',
        'password_hash': encoded,
        'auth_version': 'v1',
    }
    sessions = AsyncMock()
    sessions.insert_one = AsyncMock(side_effect=lambda d: sessions_store.setdefault(d['_id'], d))
    sessions.find_one = AsyncMock(side_effect=lambda q: sessions_store.get(q['_id']))

    app.dependency_overrides[get_accounts] = lambda: accounts
    app.state.accounts = accounts
    app.state.accounts_v2 = accounts_v2
    app.state.lab_requests = lab_requests
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = AsyncMock()
    app.state.login_limits.find_one_and_update.return_value = {'count': 1}
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://locketgold.vuthanhluan.bond')
    try:
        auth_headers = {'Authorization': f'Bearer {service_token}'}

        app.state.entitlements = AsyncMock()
        app.state.entitlements.find_one.return_value = {
            'account_id': active_uid, 'entitlement_key': 'Gold', 'status': 'active', 'expires_date': accounts_store[active_uid]['expires_date'],
        }
        # 1. Verify 4 distinct entitlement states: active, expired, revoked, none
        for uid, expected_state, expected_gold in [
            (active_uid, 'active', True),
            ('user_expired', 'expired', False),
            ('user_revoked', 'revoked', False),
            ('user_nonexistent', 'none', False),
        ]:
            resp = http.get(f'/api/lab/subscribers/{uid}', headers=auth_headers)
            assert resp.status_code == 200
            assert resp.headers['x-lab-entitlement-state'] == expected_state
            report = format_entitlement_report(uid, resp.status_code, dict(resp.headers), resp.json())
            assert report['lab_entitlement_state'] == expected_state
            assert report['gold_active'] is expected_gold

        # 2. Verify POST /api/lab/inspect records traffic and masks sensitive data
        echo_res = http.post(
            '/api/lab/inspect',
            headers=auth_headers,
            json={'locket_id': 'user_active', 'password': 'secret_password_123', 'note': 'lab test'},
        )
        assert echo_res.status_code == 200
        echo_data = echo_res.json()
        assert 'secret_password_123' not in str(echo_data)
        assert service_token not in str(echo_data)

        # 3. Verify Admin PKI status and Logs viewer endpoint
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        admin_hdr = {'Authorization': 'Bearer ' + login_res.json()['access_token']}

        pki_res = http.get('/admin/pki/status', headers=admin_hdr)
        assert pki_res.status_code == 200
        assert pki_res.json()['valid'] is True
        assert pki_res.json()['certificate']['sha256_fingerprint'] == ca_meta['sha256_fingerprint']

        logs_res = http.get('/admin/logs', headers=admin_hdr)
        assert logs_res.status_code == 200
        recorded_reqs = logs_res.json()['lab_requests']
        assert len(recorded_reqs) == 5
        assert service_token not in str(recorded_reqs)
        assert 'secret_password_123' not in str(recorded_reqs)
    finally:
        http.close()
        get_settings.cache_clear()
