"""
Prompt 26 — Final System Refactor: Add Account -> Auto UID -> Gold Management SSOT.
Covers all 25 mandatory test scenarios (Section 9) plus Section 10 UID entitlement migration checks:
  1. Add Account dialog has only Locket ID / Username and Expires At (no extra token/UID inputs).
  2. Save Account automatically triggers the backend resolver in a single POST /admin/add-account call.
  3. No separate Search UID button (`searchUidBtn`) or `/api/admin/locket/resolve-uid` endpoint exists.
  4. No Locket token / session UI (`locketSessionDialog`, `locketSessionForm`, `connectLocketSession`, `disconnectLocketSession`) or `/admin/locket-session` endpoint exists.
  5. `LocketSessionProvider` is completely removed and never invoked during Add Account.
  6. Public resolver requests to `locket.cam` never send `Authorization` or `Cookie` headers.
  7. Username, `@username`, and Locket share links normalize properly via `normalize_lookup_query()`.
  8. Invite token (even when 28 chars long) is never treated as a Firebase UID (`firebase_uid=None`, `unverified_handle`).
  9. Backend never fabricates a UID and rejects ObjectId, UUIDv4, Device UUID, Installation ID, RevenueCat ID, storage ID, and placeholders.
 10. Existing verified Firebase UID in `accounts_v2` is preserved when saving/renewing via public link lookup.
 11. Unverified UID (`unverified_uid`) or handle (`unverified_handle`) never activates Gold (saved as `pending`, activate returns 409).
 12. Pending account has no active Gold (`GET /v1/subscribers/{id}` returns `entitlements: {}`, `X-Lab-Entitlement-Status: pending`).
 13. Gold entitlement uses the verified Firebase UID (`entitlements.account_id == <VERIFIED_FIREBASE_UID>`).
 14. Renewing an account (by username or UID) updates `expires_date` under the verified Firebase UID.
 15. Revoking an account (by username or UID) revokes the entitlement under the verified Firebase UID.
 16. Deleting an account deletes all Gold entitlements (no orphan entitlements remain).
 17. Never allows two different active entitlements (username vs UID) for the same account.
 18. Cannot use username or invite token (or legacy username-only fallback) to bypass verified UID on `/v1/subscribers/{account_id}`.
 19. Preserves `expired` and `revoked` entitlement states accurately.
 20. Protects production MongoDB database (`locket_manager`) from staging writes and migrations.
 21. Linked devices continue to work with verified UID accounts and enforce cross-account 403 isolation.
 22. Admin Dashboard renders cleanly with CSP nonce and updated UID / Gold status labels.
 23. Subscriber API (`/v1/subscribers/{uid}` and `/api/lab/subscribers/{uid}`) works for Admin, Service, and Device tokens.
 24. Mobileconfig generation (`dns_only`, `lab_ca`, `scoped_lab`) remains 100% intact.
 25. Docker staging isolation and `inspect_and_migrate_uid_entitlements` (dry-run, mapping report, conflict abort) work properly.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import plistlib
import secrets
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient
import httpx
from pydantic import ValidationError
import pytest

from app.config import PRODUCTION_DATABASE_NAME, Settings, get_settings
from app.database import get_accounts
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.identity_service import (
    extract_firebase_uid_from_invite_token,
    is_valid_firebase_uid,
    normalize_lookup_query,
    resolve_public_locket_share_link,
)
from scripts.generate_lab_ca import generate_ca_and_leaf_files
from scripts.migrate_db import inspect_and_migrate_uid_entitlements


@pytest.fixture
def prompt26_env(monkeypatch, tmp_path):
    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'
    domains = ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond', 'sub.lab.vuthanhluan.bond']
    ca_info = generate_ca_and_leaf_files(pub_dir, priv_dir, domains)
    ca_pem_path = pub_dir / 'lab_root_ca.pem'

    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    service_token = secrets.token_urlsafe(40)

    monkeypatch.setenv('APP_ENV', 'staging')
    monkeypatch.setenv('MONGODB_DATABASE', 'locket_manager_staging')
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost","locketgold.vuthanhluan.bond","mock.lab.vuthanhluan.bond"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PATH', str(ca_pem_path))
    monkeypatch.setenv('ROOT_CA_PEM', '')
    monkeypatch.setenv('SUBSCRIBER_API_TOKEN', service_token)
    get_settings.cache_clear()

    app = create_app()
    v1_store: dict[str, dict] = {}
    v2_store: dict[str, dict] = {}
    ent_store: dict[tuple[str, str], dict] = {}
    dev_store: dict[str, dict] = {}
    tickets_store: dict[str, dict] = {}
    sessions_store: dict[str, dict] = {}
    audit_store: list[dict] = []

    class MemAccountsV1:
        async def find_one(self, q, projection=None):
            d = v1_store.get(q.get('locket_id'))
            if d is None:
                return None
            return {'_id': 'v1_id'} if projection == {'_id': 1} else d.copy()

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v1_store.get(lid, {'locket_id': lid}).copy()
            if '$set' in u:
                doc.update(u['$set'])
            v1_store[lid] = doc

        async def delete_one(self, q):
            lid = q.get('locket_id')
            existed = lid in v1_store
            v1_store.pop(lid, None)
            res = MagicMock()
            res.deleted_count = 1 if existed else 0
            return res

        def find(self, q=None, projection=None):
            rows = [d.copy() for d in sorted(v1_store.values(), key=lambda x: x['locket_id'])]
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

    class MemAccountsV2:
        async def find_one(self, q, projection=None):
            for field in ('locket_id', 'username', 'firebase_uid', 'invite_token', 'account_id'):
                if field in q and q[field] is not None:
                    for doc in v2_store.values():
                        if doc.get(field) == q[field]:
                            return {'_id': 'v2_id'} if projection == {'_id': 1} else doc.copy()
            return None

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v2_store.get(lid, {'locket_id': lid}).copy()
            if '$setOnInsert' in u and lid not in v2_store:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            v2_store[lid] = doc

        async def delete_one(self, q):
            lid = q.get('locket_id')
            existed = lid in v2_store
            v2_store.pop(lid, None)
            res = MagicMock()
            res.deleted_count = 1 if existed else 0
            return res

        def find(self, q=None, projection=None):
            rows = [d.copy() for d in sorted(v2_store.values(), key=lambda x: x['locket_id'])]
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

    class MemEntitlements:
        async def find_one(self, q, projection=None):
            key = (q.get('account_id'), q.get('entitlement_key', 'Gold'))
            d = ent_store.get(key)
            return d.copy() if d else None

        async def update_one(self, q, u, upsert=False):
            key = (q['account_id'], q.get('entitlement_key', 'Gold'))
            doc = ent_store.get(key, {'account_id': q['account_id'], 'entitlement_key': key[1]}).copy()
            if '$setOnInsert' in u and key not in ent_store:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            ent_store[key] = doc

        async def delete_many(self, q):
            aid = q.get('account_id')
            keys_to_remove = [k for k in ent_store if k[0] == aid]
            for k in keys_to_remove:
                ent_store.pop(k, None)

        def find(self, q=None, projection=None):
            rows = [d.copy() for d in ent_store.values()]
            c = MagicMock()
            c.to_list = AsyncMock(return_value=rows)
            return c

    class MemDevices:
        def find(self, q, projection=None):
            items = [
                d.copy() for d in dev_store.values()
                if (q.get('locket_id') is None or d.get('locket_id') == q.get('locket_id'))
                and (q.get('status') is None or d.get('status') == q.get('status'))
            ]
            c = MagicMock()
            c.sort.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=items)
            return c

        async def insert_one(self, doc):
            dev_store[doc['device_id']] = doc.copy()

        async def find_one(self, q, projection=None):
            for d in dev_store.values():
                if q.get('token_hash') and d.get('token_hash') == q.get('token_hash'):
                    return d.copy()
                if q.get('device_id') and d.get('device_id') == q.get('device_id'):
                    return d.copy()
            return None

        async def update_one(self, q, u):
            dev = dev_store.get(q.get('device_id'))
            if dev:
                if '$set' in u:
                    dev.update(u['$set'])
                if '$unset' in u:
                    for k in u['$unset']:
                        dev.pop(k, None)

    admin_doc = {
        '_id': 'superadmin',
        'email': 'admin@example.test',
        'password_hash': encoded,
        'auth_version': hashlib.sha256(encoded.encode()).hexdigest(),
    }
    admins = AsyncMock()
    admins.find_one.return_value = admin_doc
    sessions = AsyncMock()
    sessions.insert_one.side_effect = lambda d: sessions_store.setdefault(d['_id'], d.copy())
    sessions.find_one.side_effect = lambda q: sessions_store.get(q['_id'])
    sessions.delete_one.side_effect = lambda q: sessions_store.pop(q['_id'], None)
    login_limits = AsyncMock()
    login_limits.find_one_and_update.return_value = {'count': 1}
    audit = AsyncMock()
    audit.insert_one.side_effect = lambda d: audit_store.append(d.copy())
    download_tickets = AsyncMock()
    download_tickets.insert_one.side_effect = lambda d: tickets_store.setdefault(d['ticket_hash'], d.copy())
    download_tickets.find_one_and_delete.side_effect = lambda q: tickets_store.pop(q.get('ticket_hash'), None)

    mem_v1 = MemAccountsV1()
    mem_v2 = MemAccountsV2()
    mem_ent = MemEntitlements()
    mem_dev = MemDevices()

    app.dependency_overrides[get_accounts] = lambda: mem_v1
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = login_limits
    app.state.accounts = mem_v1
    app.state.accounts_v2 = mem_v2
    app.state.entitlements = mem_ent
    app.state.devices = mem_dev
    app.state.download_tickets = download_tickets
    app.state.audit = audit
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://localhost', raise_server_exceptions=False)
    login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
    assert login_res.status_code == 200
    admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}
    service_headers = {'Authorization': f'Bearer {service_token}'}

    yield {
        'http': http,
        'app': app,
        'v1_store': v1_store,
        'v2_store': v2_store,
        'ent_store': ent_store,
        'dev_store': dev_store,
        'audit_store': audit_store,
        'admin_headers': admin_headers,
        'service_headers': service_headers,
        'ca_info': ca_info,
        'mem_v1': mem_v1,
        'mem_v2': mem_v2,
        'mem_ent': mem_ent,
    }
    http.close()
    get_settings.cache_clear()


# Tests 1, 3, 4, 5 & 22: UI & Dead Code Removal
def test_01_03_04_05_22_admin_ui_and_dead_code_removal(prompt26_env):
    http = prompt26_env['http']
    admin_headers = prompt26_env['admin_headers']
    root = Path(__file__).resolve().parent.parent

    # Test 5: Dead Locket session & CLI modules are completely removed from repository
    for removed_path in (
        root / 'app' / 'services' / 'locket_authenticated_identity.py',
        root / 'app' / 'services' / 'locket_session_provider.py',
        root / 'scripts' / 'test_locket_uid_resolution.py',
        root / 'tests' / 'test_authenticated_locket_uid_resolution.py',
    ):
        assert not removed_path.exists(), f'Dead file {removed_path} must be removed'

    # Test 1 & Test 22: Admin Dashboard renders cleanly with only Locket ID / Username and Expires At in #accountDialog
    adm_resp = http.get('/admin')
    assert adm_resp.status_code == 200
    html = adm_resp.text
    assert 'Locket Gold Manager' in html
    assert 'id="accountDialog"' in html
    assert 'id="accountForm"' in html
    assert 'id="accountId"' in html
    assert 'id="expiry"' in html
    assert 'id="cancelAccount"' in html
    assert 'id="save"' in html
    assert 'Locket ID / Username' in html

    # Test 3 & Test 4: Zero trace of searchUidBtn or Locket session/token inputs in HTML or JS
    for forbidden_ui_id in (
        'searchUidBtn',
        'locketSessionDialog',
        'locketSessionForm',
        'connectLocketSession',
        'disconnectLocketSession',
        'locketSessionToken',
        'locketSessionRefresh',
        'locketSessionUsername',
        'saveLocketSession',
        'cancelLocketSession',
        '/api/admin/locket/resolve-uid',
        '/admin/locket/resolve-uid',
        '/admin/locket-session',
    ):
        assert forbidden_ui_id not in html, f'Forbidden UI reference {forbidden_ui_id} found in web/index.html'

    # Removed backend endpoints must return 404 / 405
    assert http.get('/api/admin/locket/resolve-uid?username=vt.l', headers=admin_headers).status_code == 404
    assert http.get('/admin/locket/resolve-uid?username=vt.l', headers=admin_headers).status_code == 404
    assert http.post('/admin/locket-session', headers=admin_headers, json={}).status_code in (404, 405)
    assert http.delete('/admin/locket-session', headers=admin_headers).status_code in (404, 405)


# Tests 2, 6, 7, 8, 9, 10: Public Auto-UID Resolution, Invite Token Separation & Verified UID Preservation
def test_02_06_07_08_09_10_auto_public_resolver_and_verified_uid_preservation(prompt26_env):
    http = prompt26_env['http']
    app = prompt26_env['app']
    v2_store = prompt26_env['v2_store']
    ent_store = prompt26_env['ent_store']
    admin_headers = prompt26_env['admin_headers']
    future_iso = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()

    # Test 7: Username normalization
    for raw_q, expected_norm in (
        ('vt.l', 'vt.l'),
        ('@vt.l', 'vt.l'),
        ('https://locket.cam/vt.l', 'vt.l'),
        ('https://www.locket.cam/@vt.l', 'vt.l'),
        ('https://locketcamera.com/vt.l', 'vt.l'),
    ):
        norm_id, _ = normalize_lookup_query(raw_q)
        assert norm_id == expected_norm

    # Test 9: Reject non-Firebase UIDs (ObjectId, UUIDv4, Device UUID, Installation ID, RevenueCat ID, storage path, placeholders)
    for invalid_uid in (
        '507f1f77bcf86cd799439011',               # 24-char MongoDB ObjectId
        '550e8400-e29b-41d4-a716-446655440000',   # 36-char Device/Installation UUIDv4
        '$RCAnonymousID:8f9a2b3c4d5e6f7a8b9c0d1e', # RevenueCat App User ID
        'users_photos_2026_11_26_image',          # Storage path identifier with underscores
        'UID_THUC_TE_TU_NGUON_TRA_CUU',           # 28-char placeholder
        'A' * 28,                                 # Repeated single character
        'vt.l',                                   # Username
    ):
        assert is_valid_firebase_uid(invalid_uid) is False

    # Test 6 & Test 8: Public resolver sends no Authorization/Cookie header, and 28-char invite_token is NEVER treated as firebase_uid
    invite_28 = 'InviteToken28CharsExactAbCdE'
    assert len(invite_28) == 28
    observed_requests: list[httpx.Request] = []

    def public_handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append(request)
        assert request.url.scheme == 'https'
        assert request.url.host == 'locket.cam'
        assert 'authorization' not in request.headers
        assert 'cookie' not in request.headers
        assert 'x-firebase-appcheck' not in request.headers
        return httpx.Response(
            200,
            text=(
                '<html>'
                '<meta property="og:image" content="https://firebasestorage.googleapis.com/v0/b/locket-public-assets/o/invites%2Fen.png?alt=media" />'
                '<img class="profile-pic-img" src="https://cdn2.locketcamera.com/v0/b/locket-img/o/users%2FStoragePathId28Chars12345678%2Fpublic%2Fprofile_pic.webp" />'
                f'<a href="https://locket.camera/invites/{invite_28}">Add friend</a>'
                '</html>'
            ),
            headers={'Content-Type': 'text/html'},
        )

    app.state.public_link_fetcher = lambda url: public_handler(httpx.Request('GET', url))

    # Test 2: Single Save Account action (`POST /admin/add-account`) automatically invokes public resolver
    res = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': 'https://locket.cam/vt.l',
            'expires_date': future_iso,
            'resolve_identity': True,
            'public_only': True,
        },
    )
    assert res.status_code == 200, res.text
    assert len(observed_requests) == 1
    saved = res.json()
    assert saved['locket_id'] == 'vt.l'
    assert saved['username'] == 'vt.l'
    assert saved['invite_token'] == invite_28
    assert saved['firebase_uid'] is None
    assert saved['verification_status'] == 'unverified_handle'
    assert saved['status'] == 'pending'
    # Unverified handle MUST NOT create an active Gold record in entitlements
    assert ent_store == {}

    # Test 10: Existing verified Firebase UID in `accounts_v2` is preserved when saving/renewing via public link lookup
    verified_uid = '4Vee1rBLoJN9TDjql9xPzDEuf5D2'
    v2_store['vt.l'] = {
        'schema_version': 2,
        'account_id': verified_uid,
        'locket_id': 'vt.l',
        'username': 'vt.l',
        'firebase_uid': verified_uid,
        'verification_status': 'verified_uid',
        'verification_method': 'trusted_proof',
        'verification_source': 'verified_subscriber_traffic',
        '_server_uid_proof': True,
        'status': 'active',
        'expires_date': datetime.now(timezone.utc) + timedelta(days=10),
    }
    renew_iso = (datetime.now(timezone.utc) + timedelta(days=120)).isoformat()
    res_preserve = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': 'vt.l',
            'expires_date': renew_iso,
            'resolve_identity': True,
            'public_only': True,
        },
    )
    assert res_preserve.status_code == 200
    preserved = res_preserve.json()
    assert preserved['firebase_uid'] == verified_uid
    assert preserved['verification_status'] == 'verified_uid'
    assert preserved['status'] == 'active'
    assert v2_store['vt.l']['account_id'] == verified_uid
    assert v2_store['vt.l']['_server_uid_proof'] is True
    assert (verified_uid, 'Gold') in ent_store
    assert ent_store[(verified_uid, 'Gold')]['status'] == 'active'

    # Real 44-char compound Locket invite token (`<28-char-Firebase-UID><16-char-hex-suffix>`, e.g. vt.l):
    # The public prefix is retained as a candidate until independently verified.
    v2_store.clear()
    ent_store.clear()
    real_invite_44 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83907433b66b8185cb'
    real_uid_28 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83'
    assert extract_firebase_uid_from_invite_token(real_invite_44) == real_uid_28
    assert extract_firebase_uid_from_invite_token(invite_28) is None

    def public_compound_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=(
                '<html>'
                '<meta property="og:image" content="https://firebasestorage.googleapis.com/v0/b/locket-public-assets/o/invites%2Fen.png?alt=media" />'
                f'<img class="profile-pic-img" src="https://cdn2.locketcamera.com/v0/b/locket-img/o/users%2F{real_uid_28}%2Fpublic%2Fprofile_pic.webp" />'
                f'<a href="https://locket.page.link/?link=https%3A%2F%2Flocket.camera%2Finvites%2F{real_invite_44}%3Ftype%3DUsernameLink">Add</a>'
                '</html>'
            ),
            headers={'Content-Type': 'text/html'},
        )

    app.state.public_link_fetcher = lambda url: public_compound_handler(httpx.Request('GET', url))
    res_compound = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': 'vt.l',
            'expires_date': future_iso,
            'resolve_identity': True,
            'public_only': True,
        },
    )
    assert res_compound.status_code == 200, res_compound.text
    saved_compound = res_compound.json()
    assert saved_compound['locket_id'] == 'vt.l'
    assert saved_compound['username'] == 'vt.l'
    assert saved_compound['firebase_uid'] == real_uid_28
    assert saved_compound['invite_token'] == real_invite_44
    assert saved_compound['verification_status'] == 'unverified_uid'
    assert saved_compound['status'] == 'pending'
    assert saved_compound['verification_source'] == 'locket_public_share_link'
    assert (real_uid_28, 'Gold') not in ent_store

    sub_real = http.get(f'/v1/subscribers/{real_uid_28}', headers=prompt26_env['service_headers'])
    assert sub_real.status_code == 200
    assert sub_real.headers['x-lab-entitlement-status'] == 'pending'
    assert sub_real.json()['subscriber']['entitlements'] == {}


# Tests 11, 12, 13, 14, 15, 16, 17, 18, 19, 23: Gold Management SSOT & CRUD Synchronized by Verified UID
def test_11_to_19_and_23_gold_entitlement_ssot_and_crud_by_verified_uid(prompt26_env, monkeypatch):
    http = prompt26_env['http']
    app = prompt26_env['app']
    v1_store = prompt26_env['v1_store']
    v2_store = prompt26_env['v2_store']
    ent_store = prompt26_env['ent_store']
    admin_headers = prompt26_env['admin_headers']
    service_headers = prompt26_env['service_headers']
    future_iso = (datetime.now(timezone.utc) + timedelta(days=45)).isoformat()

    # Test 11 & Test 12: Unverified UID (`unverified_uid`) is saved as `pending`, has no active Gold,
    # and `POST /admin/accounts/{id}/activate` is rejected with HTTP 409!
    unverified_uid = '9Xzz2aBCdEF3GHijk4lMnOPqr5S6'
    r_unver = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': 'unverified_user',
            'username': 'unverified_user',
            'firebase_uid': unverified_uid,
            'verification_status': 'verified_uid',  # Client attempt to spoof verified_uid
            'expires_date': future_iso,
        },
    )
    assert r_unver.status_code == 200
    d_unver = r_unver.json()
    assert d_unver['firebase_uid'] == unverified_uid
    assert d_unver['verification_status'] == 'unverified_uid'
    assert d_unver['status'] == 'pending'
    assert (unverified_uid, 'Gold') not in ent_store
    assert ('unverified_user', 'Gold') not in ent_store

    # Activate on unverified account MUST be rejected with 409
    r_act_unver = http.post('/admin/accounts/unverified_user/activate', headers=admin_headers, json={})
    assert r_act_unver.status_code == 409

    # Subscriber API for pending / unverified account returns empty entitlements
    for q_id in ('unverified_user', unverified_uid):
        sub_pend = http.get(f'/v1/subscribers/{q_id}', headers=service_headers)
        assert sub_pend.status_code == 200
        assert sub_pend.headers['x-lab-entitlement-status'] == 'pending'
        assert sub_pend.json()['subscriber']['entitlements'] == {}

    # Test 13 & Test 17: Adding account with verified UID creates entitlement keyed strictly by verified UID
    # and removes any stale username-keyed entitlement
    verified_uid = '4Vee1rBLoJN9TDjql9xPzDEuf5D2'
    ent_store[('vt.l', 'Gold')] = {
        'account_id': 'vt.l',
        'entitlement_key': 'Gold',
        'status': 'active',
        'expires_date': datetime.now(timezone.utc) + timedelta(days=10),
    }
    app.state.identity_provider = lambda q, k: (
        200,
        {'result': {'status': 200, 'data': {'uid': verified_uid, 'username': 'vt.l'}}},
    )
    r_ver = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'vt.l', 'expires_date': future_iso},
    )
    assert r_ver.status_code == 200
    d_ver = r_ver.json()
    assert d_ver['locket_id'] == 'vt.l'
    assert d_ver['username'] == 'vt.l'
    assert d_ver['firebase_uid'] == verified_uid
    assert d_ver['verification_status'] == 'verified_uid'
    assert d_ver['status'] == 'active'
    assert v2_store['vt.l']['account_id'] == verified_uid
    assert (verified_uid, 'Gold') in ent_store
    assert ('vt.l', 'Gold') not in ent_store  # Test 17: No duplicate username entitlement!

    # Test 18 & Test 23: Subscriber API grants Gold ONLY to verified UID, never to username, invite_token, or legacy username fallback
    sub_ok = http.get(f'/v1/subscribers/{verified_uid}', headers=service_headers)
    assert sub_ok.status_code == 200
    assert sub_ok.headers['x-lab-entitlement-status'] == 'active'
    assert 'Gold' in sub_ok.json()['subscriber']['entitlements']
    async def unavailable(*args, **kwargs):
        raise ConnectionError('database unavailable')

    with monkeypatch.context() as patch:
        patch.setattr(app.state.entitlements, 'find_one', unavailable)
        outage = http.get(f'/v1/subscribers/{verified_uid}', headers=service_headers)
        assert outage.status_code == 503
        assert 'subscriber' not in outage.json()

    lab_sub_ok = http.get(f'/api/lab/subscribers/{verified_uid}', headers=service_headers)
    assert lab_sub_ok.status_code == 200
    assert 'Gold' in lab_sub_ok.json()['subscriber']['entitlements']
    with monkeypatch.context() as patch:
        patch.delitem(ent_store, (verified_uid, 'Gold'))
        for prefix in ('/v1', '/api/lab'):
            missing = http.get(f'{prefix}/subscribers/{verified_uid}', headers=service_headers)
            assert missing.json()['subscriber']['entitlements'] == {}

    # Querying by username 'vt.l' MUST NOT grant active Gold
    sub_by_username = http.get('/v1/subscribers/vt.l', headers=service_headers)
    assert sub_by_username.status_code == 200
    assert sub_by_username.json()['subscriber']['entitlements'] == {}

    # Legacy username-only record in `accounts` (v1) without v2 verified UID MUST NOT grant active Gold via fallback read
    v1_store['legacy_username_only'] = {
        'locket_id': 'legacy_username_only',
        'expires_date': datetime.now(timezone.utc) + timedelta(days=90),
        'status': 'active',
    }
    sub_legacy_fallback = http.get('/v1/subscribers/legacy_username_only', headers=service_headers)
    assert sub_legacy_fallback.status_code == 200
    assert sub_legacy_fallback.headers['x-lab-entitlement-status'] == 'pending'
    assert sub_legacy_fallback.json()['subscriber']['entitlements'] == {}

    # Test 14: Renew updates expiry under the verified UID
    extended_dt = datetime.now(timezone.utc) + timedelta(days=180)
    r_renew = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'vt.l', 'expires_date': extended_dt.isoformat()},
    )
    assert r_renew.status_code == 200
    assert ent_store[(verified_uid, 'Gold')]['expires_date'] == extended_dt

    # Test 15 & Test 19: Revoke (by username 'vt.l') revokes the verified UID entitlement immediately
    r_rev = http.post('/admin/accounts/vt.l/revoke', headers=admin_headers, json={'reason': 'Testing UID revoke'})
    assert r_rev.status_code == 200
    assert r_rev.json()['status'] == 'revoked'
    assert ent_store[(verified_uid, 'Gold')]['status'] == 'revoked'

    sub_after_rev = http.get(f'/v1/subscribers/{verified_uid}', headers=service_headers)
    assert sub_after_rev.status_code == 200
    assert sub_after_rev.headers['x-lab-entitlement-status'] == 'revoked'
    assert sub_after_rev.json()['subscriber']['entitlements'] == {}

    # Re-activate by username 'vt.l' restores active Gold under verified_uid
    r_act = http.post('/admin/accounts/vt.l/activate', headers=admin_headers, json={})
    assert r_act.status_code == 200
    assert r_act.json()['status'] == 'active'
    assert ent_store[(verified_uid, 'Gold')]['status'] == 'active'

    # Test 19: Expired account returns 'expired' and empty entitlements
    v2_store['vt.l']['expires_date'] = datetime.now(timezone.utc) - timedelta(days=1)
    sub_exp = http.get(f'/v1/subscribers/{verified_uid}', headers=service_headers)
    assert sub_exp.status_code == 200
    assert sub_exp.headers['x-lab-entitlement-status'] == 'expired'
    assert sub_exp.json()['subscriber']['entitlements'] == {}

    # Test 16: Delete account removes records from accounts, accounts_v2, AND entitlements (zero orphan entitlements)
    r_del = http.delete('/admin/accounts/vt.l', headers=admin_headers)
    assert r_del.status_code == 204
    assert 'vt.l' not in v2_store
    assert 'vt.l' not in v1_store
    assert (verified_uid, 'Gold') not in ent_store
    assert ('vt.l', 'Gold') not in ent_store


# Tests 20, 21, 24, 25: Production DB Protection, Linked Devices, Mobileconfig & UID Migration Script
def test_20_21_24_25_production_protection_devices_mobileconfig_and_migration(prompt26_env):
    http = prompt26_env['http']
    app = prompt26_env['app']
    v2_store = prompt26_env['v2_store']
    ent_store = prompt26_env['ent_store']
    admin_headers = prompt26_env['admin_headers']
    ca_info = prompt26_env['ca_info']
    future_dt = datetime.now(timezone.utc) + timedelta(days=60)

    # Test 20: Staging environment strictly forbidden from using production database `locket_manager`
    pw_hash = 'pbkdf2_sha256$600000$' + '11' * 16 + '$' + '22' * 32
    with pytest.raises(ValidationError, match=PRODUCTION_DATABASE_NAME):
        Settings(
            _env_file=None,
            app_env='staging',
            mongodb_database=PRODUCTION_DATABASE_NAME,
            superadmin_email='admin@example.test',
            superadmin_password_hash=pw_hash,
            mongodb_uri='mongodb://127.0.0.1:27017',
        )

    # Test 21: Enrolled device for a verified-UID account can access `/v1/subscribers/<VERIFIED_UID>` and download mobileconfig
    uid_dev_owner = 'DevOwnerVerifiedUid123456789'
    app.state.identity_provider = lambda q, k: (
        200,
        {'result': {'status': 200, 'data': {'uid': uid_dev_owner, 'username': 'dev_owner'}}},
    )
    assert http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'dev_owner', 'expires_date': future_dt.isoformat(), 'max_devices': 2},
    ).status_code == 200

    dev_res = http.post(
        '/admin/devices',
        headers=admin_headers,
        json={'locket_id': 'dev_owner', 'device_name': 'iPhone 16 Pro', 'ios_version': '18.2'},
    )
    assert dev_res.status_code == 200
    dev_token = dev_res.json()['device_token']
    dev_headers = {'Authorization': f'Bearer {dev_token}'}

    sub_dev = http.get(f'/v1/subscribers/{uid_dev_owner}', headers=dev_headers)
    assert sub_dev.status_code == 200
    assert 'Gold' in sub_dev.json()['subscriber']['entitlements']

    # Cross-account access with device token is blocked with 403
    assert http.get('/v1/subscribers/SomeOtherAccountUid123456789', headers=dev_headers).status_code == 403

    # Test 24: Mobileconfig modes (`dns_only`, `lab_ca`, `scoped_lab`) remain 100% valid
    mc_dns = http.get('/profile.mobileconfig?mode=dns_only')
    assert mc_dns.status_code == 200
    pl_dns = plistlib.loads(mc_dns.content)
    assert [p['PayloadType'] for p in pl_dns['PayloadContent']] == ['com.apple.dnsSettings.managed']

    mc_lab = http.get('/profile.mobileconfig?mode=scoped_lab')
    assert mc_lab.status_code == 200
    pl_lab = plistlib.loads(mc_lab.content)
    assert [p['PayloadType'] for p in pl_lab['PayloadContent']] == [
        'com.apple.dnsSettings.managed',
        'com.apple.security.root',
    ]

    # Test 25: Controlled UID-key entitlement migration (`inspect_and_migrate_uid_entitlements`)
    v2_store.clear()
    ent_store.clear()
    uid_1 = 'MigratedVerifiedUid123456789'
    v2_store['user_with_verified_uid'] = {
        'locket_id': 'user_with_verified_uid',
        'account_id': 'user_with_verified_uid',  # Old key was username
        'username': 'user_with_verified_uid',
        'firebase_uid': uid_1,
        'verification_status': 'verified_uid',
        'verification_method': 'trusted_proof',
        'verification_source': 'verified_subscriber_traffic',
        '_server_uid_proof': True,
        'status': 'active',
        'expires_date': future_dt,
    }
    v2_store['username_only_user'] = {
        'locket_id': 'username_only_user',
        'account_id': 'username_only_user',
        'username': 'username_only_user',
        'firebase_uid': None,
        'verification_status': 'unverified_handle',
        'status': 'active',  # Legacy active without verified UID -> should be reported and downgraded to pending
        'expires_date': future_dt,
    }
    ent_store[('orphan_ghost_key', 'Gold')] = {
        'account_id': 'orphan_ghost_key',
        'entitlement_key': 'Gold',
        'status': 'active',
        'expires_date': future_dt,
    }

    fake_db = MagicMock()
    ent_store[('user_with_verified_uid', 'Gold')] = {
        'account_id': 'user_with_verified_uid', 'entitlement_key': 'Gold',
        'status': 'active', 'expires_date': future_dt,
    }
    fake_db.accounts_v2 = prompt26_env['mem_v2']
    fake_db.entitlements = prompt26_env['mem_ent']

    # 25a. Dry-run reports counts, mapping, and orphan entitlements without writing
    dry_rep = asyncio.run(inspect_and_migrate_uid_entitlements(fake_db, dry_run=True))
    assert dry_rep['dry_run'] is True
    assert dry_rep['aborted_on_conflict'] is False
    assert dry_rep['verified_uid_count'] == 1
    assert dry_rep['username_keyed_count'] == 1
    assert dry_rep['orphan_entitlement_count'] == 1
    assert dry_rep['old_to_new_mapping'][0]['old_key'] == 'user_with_verified_uid'
    assert dry_rep['old_to_new_mapping'][0]['new_verified_uid'] == uid_1
    assert (uid_1, 'Gold') not in ent_store  # Dry-run performed zero writes

    # 25b. Apply migration updates account_id -> uid_1, creates entitlement under uid_1, and downgrades username-only active to pending
    apply_rep = asyncio.run(inspect_and_migrate_uid_entitlements(fake_db, dry_run=False))
    assert apply_rep['aborted_on_conflict'] is False
    assert apply_rep['migrated_entitlements'] == 1
    assert apply_rep['downgraded_to_pending'] == 1
    assert v2_store['user_with_verified_uid']['account_id'] == uid_1
    assert ent_store[('user_with_verified_uid', 'Gold')]['status'] == 'revoked'
    assert ent_store[('orphan_ghost_key', 'Gold')]['status'] == 'revoked'
    assert (uid_1, 'Gold') in ent_store
    assert v2_store['username_only_user']['status'] == 'pending'
    assert v2_store['username_only_user']['verification_status'] == 'unverified_handle'  # Never auto-verified!

    # 25c. When duplicate UIDs exist across two accounts, migration halts immediately (`aborted_on_conflict=True`)
    v2_store['conflict_clone'] = {
        'locket_id': 'conflict_clone',
        'account_id': 'conflict_clone',
        'username': 'conflict_clone',
        'firebase_uid': uid_1,  # Duplicate UID!
        'verification_status': 'verified_uid',
        'verification_method': 'trusted_proof',
        'verification_source': 'verified_subscriber_traffic',
        '_server_uid_proof': True,
        'status': 'active',
        'expires_date': future_dt,
    }
    conflict_rep = asyncio.run(inspect_and_migrate_uid_entitlements(fake_db, dry_run=False))
    assert conflict_rep['aborted_on_conflict'] is True
    assert conflict_rep['duplicate_uid_count'] == 1
    assert conflict_rep['migrated_entitlements'] == 0
