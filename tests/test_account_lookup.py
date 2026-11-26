"""
Comprehensive Regression Test Suite for Account Lookup & UUID Resolution (`tests/test_account_lookup.py`).
Covers all 12 mandatory scenarios from Prompt 7 Addendum + reference tests from `locketgoldmanager`:
1. Lookup by username (`alice`)
2. Lookup by `@username` (`@alice`)
3. Lookup by Locket share link (`https://locket.cam/alice`, `locket.cam/alice/`, `https://locketcamera.com/alice`)
4. Lookup account existing in MongoDB (`accounts` or `accounts_v2`)
5. Lookup account not existing in MongoDB
6. Record with username only (no Firebase UID) -> `unverified_handle`
7. Record with Firebase UID and valid verification proof -> `verified_uid`
8. Record with unverified/format-only 28-char UID or invalid UID -> `unverified_uid` (never auto-verified by length)
9. Forged/spoofed link hostnames (`https://locket.cam.evil.test/alice`, `https://example.com/alice`) -> HTTP 422 without querying DB
10. MongoDB unavailable (`PyMongoError`) -> fails closed with HTTP 503
11. Zero UUID/token/private data leakage via public `/api/accounts/lookup`
12. Zero dependency on `amlongtruc-source` external lookup APIs
"""
import inspect
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from pymongo.errors import PyMongoError

from app.config import get_settings
from app.database import get_accounts
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services import entitlement_service, identity_service


@pytest.fixture
def lookup_env(monkeypatch):
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', 'locketgold.vuthanhluan.bond,localhost,testserver')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    get_settings.cache_clear()

    app = create_app()
    v1_store: dict[str, dict] = {}
    v2_store: dict[str, dict] = {}
    sessions_store: dict[str, dict] = {}

    accounts = AsyncMock()
    accounts_v2 = AsyncMock()
    sessions = AsyncMock()
    admins = AsyncMock()

    admins.find_one.return_value = {
        '_id': 'superadmin',
        'email': 'admin@example.test',
        'password_hash': encoded,
        'auth_version': 'v1',
    }

    async def sess_insert(doc):
        sessions_store[doc['_id']] = doc.copy()

    async def sess_find(q):
        d = sessions_store.get(q['_id'])
        return d if d and d['expires_at'] > q['expires_at']['$gt'] else None

    sessions.insert_one.side_effect = sess_insert
    sessions.find_one.side_effect = sess_find

    async def v1_find_one(q, proj=None):
        lid = q.get('locket_id')
        doc = v1_store.get(lid)
        if doc is None:
            return None
        if proj == {'_id': 1}:
            return {'_id': 'v1_oid'}
        return doc.copy()

    async def v2_find_one(q, proj=None):
        for doc in v2_store.values():
            for field in ('locket_id', 'username', 'firebase_uid'):
                if field in q and doc.get(field) == q[field]:
                    if proj == {'_id': 1}:
                        return {'_id': 'v2_oid'}
                    return doc.copy()
        return None

    async def v2_update_one(q, u, upsert=False):
        lid = q['locket_id']
        doc = v2_store.get(lid, {'locket_id': lid})
        if '$setOnInsert' in u and lid not in v2_store:
            doc.update(u['$setOnInsert'])
        if '$set' in u:
            doc.update(u['$set'])
        v2_store[lid] = doc

    accounts.find_one.side_effect = v1_find_one
    accounts_v2.find_one.side_effect = v2_find_one
    accounts_v2.update_one.side_effect = v2_update_one

    app.dependency_overrides[get_accounts] = lambda: accounts
    app.state.accounts = accounts
    app.state.accounts_v2 = accounts_v2
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.audit = AsyncMock()
    app.state.login_limits = AsyncMock()
    app.state.login_limits.find_one_and_update.return_value = {'count': 1}
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
    assert login_res.status_code == 200
    admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}

    yield http, app, accounts, accounts_v2, v1_store, v2_store, admin_headers
    http.close()
    get_settings.cache_clear()


# Scenarios 1, 2, 3, 4, 5 & 11: Public lookup by username, @username, Locket link, exists/not-exists, and zero data leak
@pytest.mark.parametrize('query', [
    'alice',
    ' @alice ',
    'https://locket.cam/alice',
    'locket.cam/alice/',
    'https://locket.cam/alice?share=1',
    'https://www.locket.cam/@alice',
    'https://locketcamera.com/alice',
])
@pytest.mark.parametrize('exists', [True, False])
def test_public_lookup_by_username_handle_and_link_with_zero_uuid_leak(lookup_env, query, exists):
    http, _, accounts, _, v1_store, v2_store, _ = lookup_env
    future = datetime.now(timezone.utc) + timedelta(days=60)
    if exists:
        v2_store['alice'] = {
            'locket_id': 'alice',
            'username': 'alice',
            'firebase_uid': '4Vee1rBLoJN9TDjql9xPzDEuf5D2',
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'verified_subscriber_traffic',
            'secret_device_token': 'lkg_dev_super_secret_should_never_leak',
            'expires_date': future,
            'status': 'active',
        }
    else:
        v1_store.clear()
        v2_store.clear()

    response = http.get('/api/accounts/lookup', params={'query': query})
    assert response.status_code == 200
    # Scenario 11: Public lookup MUST return ONLY {'exists': bool} and NEVER leak UUID, tokens, or expiry
    body = response.json()
    assert body == {'exists': exists}
    raw_text = response.text
    assert '4Vee1rBLoJN9TDjql9xPzDEuf5D2' not in raw_text
    assert 'lkg_dev_' not in raw_text
    assert 'expires_date' not in raw_text
    accounts.update_one.assert_not_called()


# Scenario 9: Forged hostname & malformed inputs rejected with 422 before querying MongoDB
@pytest.mark.parametrize('bad_query', [
    '',
    '   ',
    'https://example.com/alice',
    'https://locket.cam.evil.test/alice',
    'https://evil-locket.cam/alice',
    'ftp://locket.cam/alice',
    'https://locket.cam/',
    'https://locket.cam/a/b',
    'a' * 129,
    'https://locket.cam/%24%7Bbad%7D',
])
def test_forged_hostname_and_invalid_queries_do_not_query_mongodb(lookup_env, bad_query):
    http, _, accounts, accounts_v2, _, _, admin_headers = lookup_env
    accounts.find_one.reset_mock()
    accounts_v2.find_one.reset_mock()

    res_pub = http.get('/api/accounts/lookup', params={'query': bad_query})
    assert res_pub.status_code == 422
    accounts.find_one.assert_not_called()
    accounts_v2.find_one.assert_not_called()

    res_adm = http.get('/admin/accounts/lookup', params={'query': bad_query}, headers=admin_headers)
    assert res_adm.status_code == 422
    accounts.find_one.assert_not_called()
    accounts_v2.find_one.assert_not_called()


# Scenarios 5, 6, 7, 8: Admin Account Lookup distinguishes not-found, username-only, verified UID, and unverified UID
def test_admin_lookup_distinguishes_handle_unverified_uid_and_verified_uid(lookup_env):
    http, _, _, _, _, v2_store, admin_headers = lookup_env
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=45)

    # Scenario 5: Account does not exist in MongoDB
    res_missing = http.get(
        '/admin/accounts/lookup',
        params={'query': 'https://locket.cam/nonexistent_user'},
        headers=admin_headers,
    )
    assert res_missing.status_code == 200
    data_missing = res_missing.json()
    assert data_missing['exists'] is False
    assert data_missing['normalized_query'] == 'nonexistent_user'
    assert data_missing['internal_identifier'] is None
    assert data_missing['uid_verified'] is False
    assert data_missing['verification_status'] == 'unverified_handle'

    # Scenario 6: Account in MongoDB has username only, NO Firebase UID -> unverified_handle
    v2_store['handle_only_user'] = {
        'locket_id': 'handle_only_user',
        'username': 'handle_only_user',
        'firebase_uid': None,
        'verification_status': 'unverified_handle',
        'verification_method': 'link_handle_only',
        'verification_source': 'public_share_link_path',
        'expires_date': future,
        'status': 'active',
        'updated_at': now,
    }
    res_handle = http.get(
        '/admin/accounts/lookup',
        params={'query': 'https://locket.cam/handle_only_user'},
        headers=admin_headers,
    )
    assert res_handle.status_code == 200
    data_handle = res_handle.json()
    assert data_handle['exists'] is True
    assert data_handle['username'] == 'handle_only_user'
    assert data_handle['internal_identifier'] == 'handle_only_user'
    assert data_handle['firebase_uid'] is None
    assert data_handle['uid_verified'] is False
    assert data_handle['verification_status'] == 'unverified_handle'
    assert data_handle['entitlement_status'] == 'pending'

    # Scenario 7: Account in MongoDB has 28-char Firebase UID AND valid server-side verification proof -> verified_uid
    verified_uid = '4Vee1rBLoJN9TDjql9xPzDEuf5D2'
    v2_store['verified_member'] = {
        'locket_id': verified_uid,
        'username': 'verified_member',
        'firebase_uid': verified_uid,
        'verification_status': 'verified_uid',
        'verification_method': 'trusted_proof',
        'verification_source': 'verified_subscriber_traffic',
        '_server_uid_proof': True,
        'expires_date': future,
        'status': 'active',
        'updated_at': now,
    }
    res_ver = http.get(
        '/admin/accounts/lookup',
        params={'query': 'https://locket.cam/verified_member'},
        headers=admin_headers,
    )
    assert res_ver.status_code == 200
    data_ver = res_ver.json()
    assert data_ver['exists'] is True
    assert data_ver['username'] == 'verified_member'
    assert data_ver['internal_identifier'] == verified_uid
    assert data_ver['firebase_uid'] == verified_uid
    assert data_ver['uid_verified'] is True
    assert data_ver['verification_status'] == 'verified_uid'
    assert data_ver['verification_method'] == 'trusted_proof'
    assert data_ver['verification_source'] == 'verified_subscriber_traffic'

    # Scenario 8: Account in MongoDB has a 28-char UID string, but NO trusted verification source
    # (or was manually entered by format only) -> MUST be reported as `unverified_uid` (uid_verified=False)!
    unverified_28 = '9Xzz2aBCdEF3GHijk4lMnOPqr5S6'
    v2_store[unverified_28] = {
        'locket_id': unverified_28,
        'username': 'unverified_member',
        'firebase_uid': unverified_28,
        'verification_status': 'verified_uid',  # Even if marked verified_uid, missing valid source downgrades it!
        'verification_method': 'format_only_uid',
        'verification_source': 'regex_28char_format_only',
        'expires_date': future,
        'status': 'pending',
        'updated_at': now,
    }
    res_unver = http.get(
        '/admin/accounts/lookup',
        params={'query': '@unverified_member'},
        headers=admin_headers,
    )
    assert res_unver.status_code == 200
    data_unver = res_unver.json()
    assert data_unver['exists'] is True
    assert data_unver['firebase_uid'] == unverified_28
    assert data_unver['uid_verified'] is False
    assert data_unver['verification_status'] == 'unverified_uid'
    assert data_unver['verification_method'] == 'format_only_uid'
    assert data_unver['entitlement_status'] == 'pending'


# Scenario 10: MongoDB unavailable during public or admin lookup -> fails closed with HTTP 503
def test_lookup_fails_closed_with_503_when_mongodb_unavailable(lookup_env):
    http, _, accounts, _, _, _, admin_headers = lookup_env
    accounts.find_one.side_effect = PyMongoError('MongoDB connection refused')

    res_pub = http.get('/api/accounts/lookup', params={'query': 'alice'})
    assert res_pub.status_code == 503
    assert 'MongoDB connection refused' not in res_pub.text

    res_adm = http.get('/admin/accounts/lookup', params={'query': 'alice'}, headers=admin_headers)
    assert res_adm.status_code == 503
    assert 'MongoDB connection refused' not in res_adm.text


# Scenario 12: Zero dependency on `amlongtruc-source` or external HTTP calls in identity/lookup services
def test_zero_dependency_on_amlongtruc_or_external_network_in_lookup():
    id_src = inspect.getsource(identity_service)
    ent_src = inspect.getsource(entitlement_service)
    combined = (id_src + '\n' + ent_src).lower()

    assert 'amlongtruc' not in combined
    assert 'uplocket' not in combined
    assert 'urllib.request.urlopen' not in combined
    assert 'httpx.' not in combined


# Scenario 13 (Prompt 7 Blocker C): Admin attempting to spoof verification_status='verified_uid',
# verification_method='trusted_proof', verification_source='verified_subscriber_traffic' via POST /admin/add-account
def test_admin_cannot_spoof_verified_uid_metadata_via_add_account(lookup_env):
    http, _, _, _, _, v2_store, admin_headers = lookup_env
    future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    spoofed_uid = '7Abc1dEFgHI2JKlmn3oPqRS4tUvW'

    res_add = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': spoofed_uid,
            'username': 'spoof_attempt_user',
            'firebase_uid': spoofed_uid,
            'expires_date': future,
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'verified_subscriber_traffic',
        },
    )
    assert res_add.status_code == 200
    saved = res_add.json()
    # Even though Admin sent verified_uid/trusted_proof/verified_subscriber_traffic, backend MUST downgrade to unverified_uid!
    assert saved['verification_status'] == 'unverified_uid'
    assert saved['verification_method'] == 'format_only_uid'
    assert saved['verification_source'] == 'admin_manual_input'
    assert v2_store[spoofed_uid]['_server_uid_proof'] is False

    # Confirm via GET /admin/accounts/lookup that uid_verified is False
    res_lookup = http.get(
        '/admin/accounts/lookup',
        params={'query': 'https://locket.cam/spoof_attempt_user'},
        headers=admin_headers,
    )
    assert res_lookup.status_code == 200
    lookup_data = res_lookup.json()
    assert lookup_data['exists'] is True
    assert lookup_data['firebase_uid'] == spoofed_uid
    assert lookup_data['uid_verified'] is False
    assert lookup_data['verification_status'] == 'unverified_uid'
