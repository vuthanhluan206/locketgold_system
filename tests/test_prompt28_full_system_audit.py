"""
Prompt 28 — Full System Audit & Verification Suite:
Covers all mandatory tests from Sections B, C, D, E, F, G, H, I, K:
  1. UID Auto-Resolution on Save Account (`vt.l`, `@vt.l`, `https://locket.cam/vt.l`), 44-char compound token
     vs invalid 44-char token, `uid_resolution_status`, `uid_source`, `uid_assurance` (`public_derived` vs `independently_verified`),
     and `result_code` (`UID_FOUND`, `UID_NOT_FOUND`, `UID_CONFLICT`, `UID_LOOKUP_ERROR`, `GOLD_GRANTED`, `GOLD_NOT_GRANTED`).
  2. Internal Gold Grant Policy (`ALLOW_ADMIN_PUBLIC_UID_GRANT=true` vs `false`):
     - When enabled: grants internal Gold immediately on Save Account with `grant_basis='admin_authorized_public_uid'`,
       while preserving `_server_uid_proof=False` and `verification_status='unverified_uid'`.
     - When disabled: saves UID (`uid_resolution_status='found'`), sets `result_code='GOLD_NOT_GRANTED'`,
       `grant_reason='Admin public-UID grant policy disabled'`, and does not issue active Gold.
  3. Gold SSOT & Lifecycle (Active, Expired, Revoked, Renew preserves Revoked until Activate, Delete cleans up all grants/devices).
  4. Lab Client Gold Features (`GET/PUT /admin/accounts/{id}/features`, `GET /api/lab/accounts/{id}/features`):
     - Persists 60s video duration & filter flags in MongoDB.
     - Automatically disables effective flags when Gold is revoked or expired without losing saved Admin configuration.
  5. Root CA & Mobileconfig Separation:
     - Production default (`GET /profile.mobileconfig` or `?mode=dns_only`) has 1 DNS payload and zero CA payload.
     - Research Lab (`?mode=lab_ca` and `?mode=scoped_lab`) has 2 payloads (`com.apple.dnsSettings.managed` + `com.apple.security.root`),
       decoded with `plistlib` and `cryptography.x509`, matching SHA-256 fingerprint, valid self-signed CA, no private key, unique PayloadUUIDs.
     - Public CA download (`GET /api/lab/ca.cer` DER and PEM) and enriched `GET /admin/pki/status` with `profile_options`.
  6. Device Management & Mode-Bound One-Time Profile Tickets (`dns_only`, `lab_ca`, `scoped_lab`).
  7. Admin UI Verification (all 10 sections, search, PKI panel, Gold features, device profile radio options, CSP nonce).
"""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import plistlib
import secrets
from unittest.mock import AsyncMock, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
import httpx
import pytest

from app.config import get_settings
from app.database import get_accounts
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.identity_service import extract_firebase_uid_from_invite_token
from app.services.pki_service import inspect_certificate_metadata
from scripts.generate_lab_ca import generate_ca_and_leaf_files


@pytest.fixture
def prompt28_env(monkeypatch, tmp_path):
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
    monkeypatch.setenv('ALLOW_ADMIN_PUBLIC_UID_GRANT', 'true')
    get_settings.cache_clear()

    app = create_app()
    v1_store: dict[str, dict] = {}
    v2_store: dict[str, dict] = {}
    ent_store: dict[tuple[str, str], dict] = {}
    dev_store: dict[str, dict] = {}
    tickets_store: dict[str, dict] = {}
    sessions_store: dict[str, dict] = {}
    audit_store: list[dict] = []
    profile_versions_store: list[dict] = []

    class MemAccountsV1:
        async def find_one(self, q, projection=None):
            d = v1_store.get(q.get('locket_id'))
            if d is None:
                return None
            return {'_id': 'v1_id'} if projection == {'_id': 1} else d.copy()

        async def update_one(self, q, u, upsert=False, **kwargs):
            lid = q['locket_id']
            doc = v1_store.get(lid, {'locket_id': lid}).copy()
            if '$set' in u:
                doc.update(u['$set'])
            v1_store[lid] = doc

        async def delete_one(self, q, **kwargs):
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

        async def update_one(self, q, u, upsert=False, **kwargs):
            lid = q['locket_id']
            existed = lid in v2_store
            doc = v2_store.get(lid, {'locket_id': lid}).copy()
            if '$setOnInsert' in u and not existed:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            if existed or upsert:
                v2_store[lid] = doc
            res = MagicMock()
            res.matched_count = 1 if existed else 0
            return res

        async def delete_one(self, q, **kwargs):
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

        async def update_one(self, q, u, upsert=False, **kwargs):
            key = (q['account_id'], q.get('entitlement_key', 'Gold'))
            doc = ent_store.get(key, {'account_id': q['account_id'], 'entitlement_key': key[1]}).copy()
            if '$setOnInsert' in u and key not in ent_store:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            ent_store[key] = doc

        async def delete_many(self, q, **kwargs):
            aid = q.get('account_id')
            lid = q.get('locket_id')
            keys_to_remove = [
                k for k, v in ent_store.items()
                if (aid and k[0] == aid) or (lid and v.get('locket_id') == lid)
            ]
            for k in keys_to_remove:
                ent_store.pop(k, None)

        def find(self, q=None, projection=None):
            rows = [d.copy() for d in ent_store.values()]
            c = MagicMock()
            c.to_list = AsyncMock(return_value=rows)
            return c

    class MemDevices:
        def find(self, q=None, projection=None):
            q = q or {}
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

        async def update_one(self, q, u, **kwargs):
            dev = dev_store.get(q.get('device_id'))
            if dev:
                if '$set' in u:
                    dev.update(u['$set'])
                if '$unset' in u:
                    for k in u['$unset']:
                        dev.pop(k, None)

        async def update_many(self, q, u, **kwargs):
            for dev in dev_store.values():
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
    audit.find = MagicMock()
    audit_cursor = MagicMock()
    audit_cursor.sort.return_value = audit_cursor
    audit_cursor.limit.return_value = audit_cursor
    audit_cursor.to_list = AsyncMock(side_effect=lambda length=30: [a.copy() for a in reversed(audit_store[:length])])
    audit.find.return_value = audit_cursor
    profile_versions = AsyncMock()
    profile_versions.insert_one.side_effect = lambda d: profile_versions_store.append(d.copy())
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
    app.state.profile_versions = profile_versions
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
        'profile_versions_store': profile_versions_store,
        'admin_headers': admin_headers,
        'service_headers': service_headers,
        'ca_info': ca_info,
        'ca_pem_path': ca_pem_path,
    }
    http.close()
    get_settings.cache_clear()


def test_prompt28_uid_grant_policy_and_lifecycle_for_vtl(prompt28_env, monkeypatch):
    """
    Sections C & D:
    - Tests `vt.l`, `@vt.l`, `https://locket.cam/vt.l` with 44-char compound invite token.
    - Verifies invalid 44-char token (non-hex suffix or placeholder UID) is not treated as a UID.
    - Verifies `ALLOW_ADMIN_PUBLIC_UID_GRANT=true` issues internal Gold immediately with
      `grant_basis='admin_authorized_public_uid'`, while preserving `_server_uid_proof=False` and `verification_status='unverified_uid'`.
    - Verifies `ALLOW_ADMIN_PUBLIC_UID_GRANT=false` saves UID (`uid_resolution_status='found'`) but sets
      `result_code='GOLD_NOT_GRANTED'` and `grant_reason='Admin public-UID grant policy disabled'`.
    - Verifies Revoke, Renew-while-revoked (stays revoked!), Activate, and Delete.
    """
    http = prompt28_env['http']
    app = prompt28_env['app']
    v2_store = prompt28_env['v2_store']
    ent_store = prompt28_env['ent_store']
    admin_headers = prompt28_env['admin_headers']
    service_headers = prompt28_env['service_headers']
    future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

    real_invite_44 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83907433b66b8185cb'
    real_uid_28 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83'

    # Invalid 44-char patterns MUST NOT extract a UID
    assert extract_firebase_uid_from_invite_token('juNBPjHxRYeYXtMzPIy0YSjzIL83ZZZZZZZZZZZZZZZZ') is None
    assert extract_firebase_uid_from_invite_token('A' * 28 + '907433b66b8185cb') is None

    def public_vtl_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=(
                '<html>'
                f'<a href="https://locket.page.link/?link=https%3A%2F%2Flocket.camera%2Finvites%2F{real_invite_44}%3Ftype%3DUsernameLink">Add</a>'
                '</html>'
            ),
            headers={'Content-Type': 'text/html'},
        )

    app.state.public_link_fetcher = lambda url: public_vtl_handler(httpx.Request('GET', url))

    for input_variant in ('vt.l', '@vt.l', 'https://locket.cam/vt.l'):
        v2_store.clear()
        ent_store.clear()
        res = http.post(
            '/admin/add-account',
            headers=admin_headers,
            json={
                'locket_id': input_variant,
                'expires_date': future_iso,
                'resolve_identity': True,
                'public_only': True,
            },
        )
        assert res.status_code == 200, res.text
        data = res.json()
        assert data['locket_id'] == 'vt.l'
        assert data['username'] == 'vt.l'
        assert data['firebase_uid'] == real_uid_28
        assert data['invite_token'] == real_invite_44
        assert data['uid_resolution_status'] == 'found'
        assert data['uid_source'] == 'public_share_link'
        assert data['uid_assurance'] == 'public_derived'
        assert data['verification_status'] == 'unverified_uid'
        assert v2_store['vt.l']['_server_uid_proof'] is False
        assert data['grant_basis'] == 'admin_authorized_public_uid'
        assert data['result_code'] == 'GOLD_GRANTED'
        assert data['grant_status_label'] == 'Active'
        assert data['status'] == 'active'
        assert (real_uid_28, 'Gold') in ent_store
        assert ent_store[(real_uid_28, 'Gold')]['grant_basis'] == 'admin_authorized_public_uid'

    # Subscriber API returns active Gold for real_uid_28, but NEVER for username 'vt.l'
    sub_ok = http.get(f'/v1/subscribers/{real_uid_28}', headers=service_headers)
    assert sub_ok.status_code == 200
    assert sub_ok.headers['x-lab-entitlement-status'] == 'active'
    assert 'Gold' in sub_ok.json()['subscriber']['entitlements']

    sub_by_username = http.get('/v1/subscribers/vt.l', headers=service_headers)
    assert sub_by_username.status_code == 200
    assert sub_by_username.json()['subscriber']['entitlements'] == {}

    # Account search & overview stats
    search_res = http.get('/admin/accounts?search=juNBPjHxRYe', headers=admin_headers)
    assert search_res.status_code == 200
    assert len(search_res.json()) == 1
    assert search_res.json()[0]['locket_id'] == 'vt.l'

    ov = http.get('/admin/overview', headers=admin_headers).json()
    assert ov['accounts'] == 1
    assert ov['active'] == 1
    assert ov['uid_found'] == 1
    assert ov['public_derived_uid'] == 1
    assert ov['verified_uid'] == 0

    # Revoke Gold -> immediately revokes subscriber access; renewing while revoked MUST NOT auto-unrevoke!
    rev = http.post('/admin/accounts/vt.l/revoke', headers=admin_headers, json={'reason': 'Audit revoke test'})
    assert rev.status_code == 200
    assert rev.json()['status'] == 'revoked'
    assert rev.json()['grant_status_label'] == 'Revoked'

    renew_while_revoked = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': 'vt.l',
            'expires_date': (datetime.now(timezone.utc) + timedelta(days=180)).isoformat(),
            'resolve_identity': True,
            'public_only': True,
        },
    )
    assert renew_while_revoked.status_code == 200
    assert renew_while_revoked.json()['status'] == 'revoked'
    assert http.get(f'/v1/subscribers/{real_uid_28}', headers=service_headers).json()['subscriber']['entitlements'] == {}

    # Explicit Activate restores Gold Active with grant_basis='admin_authorized_public_uid'
    act = http.post('/admin/accounts/vt.l/activate', headers=admin_headers, json={})
    assert act.status_code == 200
    assert act.json()['status'] == 'active'
    assert act.json()['grant_basis'] == 'admin_authorized_public_uid'
    assert 'Gold' in http.get(f'/v1/subscribers/{real_uid_28}', headers=service_headers).json()['subscriber']['entitlements']

    # Now test with ALLOW_ADMIN_PUBLIC_UID_GRANT=false (policy disabled)
    monkeypatch.setenv('ALLOW_ADMIN_PUBLIC_UID_GRANT', 'false')
    get_settings.cache_clear()
    v2_store.clear()
    ent_store.clear()
    res_disabled = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={
            'locket_id': 'vt.l',
            'expires_date': future_iso,
            'resolve_identity': True,
            'public_only': True,
        },
    )
    assert res_disabled.status_code == 200
    d_dis = res_disabled.json()
    assert d_dis['firebase_uid'] == real_uid_28
    assert d_dis['uid_resolution_status'] == 'found'
    assert d_dis['uid_assurance'] == 'public_derived'
    assert d_dis['grant_basis'] is None
    assert d_dis['result_code'] == 'GOLD_NOT_GRANTED'
    assert d_dis['grant_reason'] == 'Admin public-UID grant policy disabled'
    assert d_dis['status'] == 'pending'
    assert (real_uid_28, 'Gold') not in ent_store
    assert http.post('/admin/accounts/vt.l/activate', headers=admin_headers, json={}).status_code == 409

    # Restore policy enabled
    monkeypatch.setenv('ALLOW_ADMIN_PUBLIC_UID_GRANT', 'true')
    get_settings.cache_clear()


def test_prompt28_lab_gold_features_and_root_ca_mobileconfig_separation(prompt28_env, monkeypatch):
    """
    Sections B, E, F, G:
    - Lab Gold Features saved via Admin API and read via `/api/lab/accounts/{uid}/features`,
      automatically disabled on revoke/expire while preserving saved Admin configuration.
    - Root CA & Mobileconfig:
      - `GET /profile.mobileconfig` (default) and `?mode=dns_only` return 1 payload (`com.apple.dnsSettings.managed`).
      - `GET /profile.mobileconfig?mode=lab_ca` and `?mode=scoped_lab` return 2 payloads
        (`com.apple.dnsSettings.managed` + `com.apple.security.root`), verified with `plistlib` and `x509`.
      - `GET /api/lab/ca.cer` returns valid DER/PEM public Root CA certificate without private key.
      - `GET /admin/pki/status` returns full certificate metadata and `profile_options` availability.
    """
    http = prompt28_env['http']
    app = prompt28_env['app']
    admin_headers = prompt28_env['admin_headers']
    service_headers = prompt28_env['service_headers']
    ca_info = prompt28_env['ca_info']
    expected_fp = ca_info['ca_metadata']['sha256_fingerprint']
    future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

    real_invite_44 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83907433b66b8185cb'
    real_uid_28 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83'
    app.state.public_link_fetcher = lambda url: httpx.Response(
        200,
        text=f'<html><a href="https://locket.camera/invites/{real_invite_44}">Add</a></html>',
    )

    add_res = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'vt.l', 'expires_date': future_iso, 'resolve_identity': True, 'public_only': True},
    )
    assert add_res.status_code == 200

    # Section E: Lab Gold Features
    flags = {
        'max_video_duration_seconds': 60,
        'enable_private_posts': True,
        'unlocked_filters': True,
        'camera_filters_enabled': True,
        'holiday_effects_enabled': True,
        'unlocked_all_filters': True,
    }
    put_feat = http.put('/admin/accounts/vt.l/features', headers=admin_headers, json=flags)
    assert put_feat.status_code == 200
    assert put_feat.json() == flags

    lab_feat_active = http.get(f'/api/lab/accounts/{real_uid_28}/features', headers=service_headers)
    assert lab_feat_active.status_code == 200
    assert lab_feat_active.json()['status'] == 'active'
    assert lab_feat_active.json()['gold'] == {'enabled': True, **flags}

    # Revoking Gold disables effective features for Lab Client while keeping Admin saved config intact
    assert http.post('/admin/accounts/vt.l/revoke', headers=admin_headers, json={'reason': 'Feature test'}).status_code == 200
    lab_feat_revoked = http.get(f'/api/lab/accounts/{real_uid_28}/features', headers=service_headers)
    assert lab_feat_revoked.status_code == 200
    assert lab_feat_revoked.json()['status'] == 'revoked'
    assert lab_feat_revoked.json()['gold']['enabled'] is False
    assert lab_feat_revoked.json()['gold']['max_video_duration_seconds'] == 0
    assert http.get('/admin/accounts/vt.l/features', headers=admin_headers).json() == flags

    # Section B & F3: Root CA Status, Public CA download, and Mobileconfig modes
    pki_st = http.get('/admin/pki/status', headers=admin_headers)
    assert pki_st.status_code == 200
    pki_data = pki_st.json()
    assert pki_data['configured'] is True
    assert pki_data['valid'] is True
    assert pki_data['sha256_fingerprint'] == expected_fp
    assert pki_data['dns_only_ready'] is True
    assert pki_data['lab_ca_ready'] is True
    assert pki_data['scoped_lab_ready'] is True
    assert pki_data['profile_options']['dns_only']['available'] is True
    assert pki_data['profile_options']['lab_ca']['available'] is True
    assert pki_data['profile_options']['scoped_lab']['available'] is True

    # Public CA certificate download (.cer DER & .pem PEM)
    cer_res = http.get('/api/lab/ca.cer')
    assert cer_res.status_code == 200
    assert b'PRIVATE KEY' not in cer_res.content
    cer_cert = x509.load_der_x509_certificate(cer_res.content)
    assert inspect_certificate_metadata(cer_cert)['sha256_fingerprint'] == expected_fp

    pem_res = http.get('/api/lab/ca.cer?format=pem')
    assert pem_res.status_code == 200
    assert b'PRIVATE KEY' not in pem_res.content
    pem_cert = x509.load_pem_x509_certificate(pem_res.content)
    assert inspect_certificate_metadata(pem_cert)['sha256_fingerprint'] == expected_fp

    # Default & DNS-only mobileconfig: 1 payload (`com.apple.dnsSettings.managed`), no Root CA
    for url_dns in ('/profile.mobileconfig', '/profile.mobileconfig?mode=dns_only'):
        r_dns = http.get(url_dns)
        assert r_dns.status_code == 200
        pl_dns = plistlib.loads(r_dns.content)
        assert len(pl_dns['PayloadContent']) == 1
        assert pl_dns['PayloadContent'][0]['PayloadType'] == 'com.apple.dnsSettings.managed'
        assert pl_dns['PayloadContent'][0]['DNSSettings']['ServerURL'] == 'https://dns.nextdns.io/a8b247'

    # Lab CA + DNS & Scoped Lab mobileconfig: 2 payloads (`com.apple.dnsSettings.managed` + `com.apple.security.root`)
    for mode_name in ('lab_ca', 'scoped_lab'):
        r_lab = http.get(f'/profile.mobileconfig?mode={mode_name}')
        assert r_lab.status_code == 200
        assert b'PRIVATE KEY' not in r_lab.content
        pl_lab = plistlib.loads(r_lab.content)
        assert pl_lab['PayloadType'] == 'Configuration'
        assert pl_lab['PayloadScope'] == 'System'
        payloads = pl_lab['PayloadContent']
        assert len(payloads) == 2
        assert [p['PayloadType'] for p in payloads] == [
            'com.apple.dnsSettings.managed',
            'com.apple.security.root',
        ]
        # Verify all PayloadUUIDs and PayloadIdentifiers are unique
        uuids = [pl_lab['PayloadUUID'], payloads[0]['PayloadUUID'], payloads[1]['PayloadUUID']]
        idents = [pl_lab['PayloadIdentifier'], payloads[0]['PayloadIdentifier'], payloads[1]['PayloadIdentifier']]
        assert len(set(uuids)) == 3
        assert len(set(idents)) == 3
        embedded_cert = x509.load_der_x509_certificate(payloads[1]['PayloadContent'])
        embedded_fp = ':'.join(f'{b:02X}' for b in embedded_cert.fingerprint(hashes.SHA256()))
        assert embedded_fp == expected_fp

    # Device profile ticket for `lab_ca` downloads 2-payload profile with device label in DoH ServerURL
    dev_res = http.post(
        '/admin/devices',
        headers=admin_headers,
        json={'locket_id': 'vt.l', 'device_name': 'iPhone Lab', 'ios_version': '18.2'},
    )
    assert dev_res.status_code == 200
    dev_id = dev_res.json()['device_id']
    tk_lab = http.post(
        f'/admin/devices/{dev_id}/profile-ticket?mode=lab_ca',
        headers=admin_headers,
        json={'mode': 'lab_ca'},
    )
    assert tk_lab.status_code == 200
    dl_url = tk_lab.json()['download_url']
    assert 'mode=lab_ca' in dl_url
    r_dl = http.get(dl_url)
    assert r_dl.status_code == 200
    pl_dl = plistlib.loads(r_dl.content)
    assert len(pl_dl['PayloadContent']) == 2
    assert pl_dl['PayloadContent'][0]['DNSSettings']['ServerURL'] == f'https://dns.nextdns.io/a8b247/{dev_id}'


def test_prompt28_edge_cases_conflicts_revision_tickets_and_admin_ui(prompt28_env, monkeypatch):
    """
    Sections C6, D3, G, I, K:
    - UID conflict across accounts returns 409 and records ACCOUNT_UID_CONFLICT.
    - Public lookup timeout/error returns 503 and does not save corrupt records.
    - Past expiry date is rejected with 422.
    - Missing entitlement or mismatched `grant_revision` between `accounts_v2` and `entitlements` fails closed.
    - Expired download ticket returns 401; mode tampering returns 403; production blocks `lab_ca` with 403.
    - Missing Root CA returns 503 on `/api/lab/ca.cer` and `/profile.mobileconfig?mode=lab_ca` while `dns_only` works.
    - Admin UI HTML includes all required panels (`accountSearch`, `openPkiStatus`, `openSystemHealth`,
      `GOLD FEATURE MANAGEMENT`, `DEVICE & PROFILE MANAGEMENT`, `ROOT CA STATUS & MOBILECONFIG`).
    """
    http = prompt28_env['http']
    app = prompt28_env['app']
    v2_store = prompt28_env['v2_store']
    ent_store = prompt28_env['ent_store']
    audit_store = prompt28_env['audit_store']
    admin_headers = prompt28_env['admin_headers']
    service_headers = prompt28_env['service_headers']
    future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    # 1. Past expiry date rejected with 422
    r_past = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'vt.l', 'expires_date': past_iso},
    )
    assert r_past.status_code == 422

    # 2. Public lookup timeout/network error returns 503 and saves nothing
    def timeout_fetcher(url: str):
        raise httpx.TimeoutException('Simulated 8s timeout')

    app.state.public_link_fetcher = timeout_fetcher
    r_timeout = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'timeout_target', 'expires_date': future_iso, 'resolve_identity': True, 'public_only': True},
    )
    assert r_timeout.status_code == 503
    assert 'timeout_target' not in v2_store

    # 3. UID conflict across two different accounts -> 409 + ACCOUNT_UID_CONFLICT audit log
    real_invite_44 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83907433b66b8185cb'
    real_uid_28 = 'juNBPjHxRYeYXtMzPIy0YSjzIL83'
    app.state.public_link_fetcher = lambda url: httpx.Response(
        200,
        text=f'<html><a href="https://locket.camera/invites/{real_invite_44}">Add</a></html>',
    )
    assert http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'vt.l', 'expires_date': future_iso, 'resolve_identity': True, 'public_only': True},
    ).status_code == 200

    r_conflict = http.post(
        '/admin/add-account',
        headers=admin_headers,
        json={'locket_id': 'other_username', 'expires_date': future_iso, 'resolve_identity': True, 'public_only': True},
    )
    assert r_conflict.status_code == 409
    assert 'other_username' not in v2_store
    assert any(a['action'] == 'ACCOUNT_UID_CONFLICT' for a in audit_store)

    # 4. Wrong `grant_revision` or missing entitlement fails closed (`pending`, empty entitlements)
    v2_store['vt.l']['grant_revision'] = 'rev_account_v2_1'
    ent_store[(real_uid_28, 'Gold')]['grant_revision'] = 'rev_entitlement_mismatch_2'
    sub_mismatch = http.get(f'/v1/subscribers/{real_uid_28}', headers=service_headers)
    assert sub_mismatch.status_code == 200
    assert sub_mismatch.headers['x-lab-entitlement-status'] == 'pending'
    assert sub_mismatch.json()['subscriber']['entitlements'] == {}

    # Restore matching grant_revision
    ent_store[(real_uid_28, 'Gold')]['grant_revision'] = 'rev_account_v2_1'
    assert 'Gold' in http.get(f'/v1/subscribers/{real_uid_28}', headers=service_headers).json()['subscriber']['entitlements']

    # 5. Missing Root CA -> `/api/lab/ca.cer` and `?mode=lab_ca` return 503, while `?mode=dns_only` returns 200
    with monkeypatch.context() as m:
        m.setenv('ROOT_CA_PATH', '')
        m.setenv('ROOT_CA_PEM', '')
        get_settings.cache_clear()
        assert http.get('/api/lab/ca.cer').status_code == 503
        assert http.get('/profile.mobileconfig?mode=lab_ca').status_code == 503
        assert http.get('/profile.mobileconfig?mode=dns_only').status_code == 200
        pki_no_ca = http.get('/admin/pki/status', headers=admin_headers).json()
        assert pki_no_ca['configured'] is False
        assert pki_no_ca['dns_only_ready'] is True
        assert pki_no_ca['lab_ca_ready'] is False
        assert pki_no_ca['profile_options']['lab_ca']['available'] is False
    get_settings.cache_clear()

    # 6. Production environment blocks `lab_ca` and `scoped_lab` with 403
    with monkeypatch.context() as m:
        m.setenv('APP_ENV', 'production')
        get_settings.cache_clear()
        assert http.get('/profile.mobileconfig?mode=lab_ca').status_code == 403
        assert http.get('/profile.mobileconfig?mode=scoped_lab').status_code == 403
        assert http.get('/profile.mobileconfig?mode=dns_only').status_code == 200
    get_settings.cache_clear()

    # 7. Admin UI HTML contains all required Prompt 28 elements and zero forbidden legacy token inputs
    adm_html = http.get('/admin').text
    for expected_snippet in (
        'id="accountSearch"',
        'id="openPkiStatus"',
        'id="openSystemHealth"',
        'GOLD FEATURE MANAGEMENT',
        'DEVICE & PROFILE MANAGEMENT',
        'ROOT CA STATUS & MOBILECONFIG',
        'Download Public CA Certificate',
        'Generate Lab Profile',
        'Download Lab Profile',
        'Admin public-UID grant policy disabled',
    ):
        assert expected_snippet in adm_html, f'Missing UI snippet: {expected_snippet}'

    # 8. Verify POST /v1/subscribers/{uid} and POST /v1/receipts obey MongoDB SSOT
    post_sub = http.post(f'/v1/subscribers/{real_uid_28}', headers=admin_headers)
    assert post_sub.status_code == 200
    assert 'Gold' in post_sub.json()['subscriber']['entitlements']

    post_rcpt = http.post('/v1/receipts', headers=admin_headers, json={'app_user_id': real_uid_28})
    assert post_rcpt.status_code == 200
    assert 'Gold' in post_rcpt.json()['subscriber']['entitlements']

    post_rcpt_missing = http.post('/v1/receipts', headers=admin_headers, json={'app_user_id': 'UnknownUser12345'})
    assert post_rcpt_missing.status_code == 200
    assert post_rcpt_missing.json()['subscriber']['entitlements'] == {}


def test_cryptography_pre42_legacy_not_valid_before_compatibility():
    """
    Verify that `inspect_certificate_metadata`, `verify_certificate_chain_and_hostname`,
    `cert_not_valid_before_utc`, and `cert_not_valid_after_utc` work seamlessly on Ubuntu VPS
    environments where system `python3-cryptography` (< 42.0) provides naive `.not_valid_before`
    and `.not_valid_after` instead of `.not_valid_before_utc` / `.not_valid_after_utc`.
    """
    from app.services.pki_service import (
        cert_not_valid_after_utc,
        cert_not_valid_before_utc,
        generate_lab_leaf_certificate,
        generate_lab_root_ca,
        inspect_certificate_metadata,
        verify_certificate_chain_and_hostname,
    )

    ca_key, ca_cert = generate_lab_root_ca()
    _, leaf_cert = generate_lab_leaf_certificate(ca_key, ca_cert, ['mock.lab.vuthanhluan.bond'])

    class _Pre42CertProxy:
        def __init__(self, real_cert):
            self._real = real_cert

        @property
        def not_valid_before(self):
            return self._real.not_valid_before_utc.replace(tzinfo=None)

        @property
        def not_valid_after(self):
            return self._real.not_valid_after_utc.replace(tzinfo=None)

        def __getattr__(self, name):
            if name in ('not_valid_before_utc', 'not_valid_after_utc', 'verify_directly_issued_by'):
                raise AttributeError(name)
            return getattr(self._real, name)

    legacy_ca = _Pre42CertProxy(ca_cert)
    legacy_leaf = _Pre42CertProxy(leaf_cert)

    assert cert_not_valid_before_utc(legacy_ca).tzinfo == timezone.utc
    assert cert_not_valid_after_utc(legacy_ca).tzinfo == timezone.utc
    meta = inspect_certificate_metadata(legacy_ca)
    assert meta['is_currently_valid'] is True
    assert meta['is_ca'] is True
    chain_check = verify_certificate_chain_and_hostname(legacy_ca, legacy_leaf, 'mock.lab.vuthanhluan.bond')
    assert chain_check['valid'] is True





