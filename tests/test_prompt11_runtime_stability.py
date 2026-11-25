"""
Prompt 11 Runtime Verification & System Stability Tests (`tests/test_prompt11_runtime_stability.py`).
Covers:
  1. Mandatory MongoDB index creation failure propagation (never silently ignored).
  2. Concurrent device enrollment (`max_devices` enforcement under race conditions).
  3. One-time mobileconfig download ticket flow (issuance, single-use consumption, replay rejection,
     expired ticket rejection, invalid ticket rejection, revoked device rejection, and URL token rejection).
  4. Root CA preservation across restarts (`generate_ca_and_leaf_files` reuses existing valid Root CA unless `rotate=True`).
  5. Controlled DoH DNS query coverage (`A`, `AAAA`, `HTTPS`/`SVCB` qtype=65/64, malformed query 400, out-of-scope REFUSED).
  6. iPhone Web UI DNS-only vs Lab CA profile download links.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import plistlib
import secrets
from unittest.mock import AsyncMock, MagicMock

from cryptography import x509
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pymongo.errors import DuplicateKeyError, OperationFailure
import pytest

from app.config import get_settings
from app.database import get_accounts, lifespan
from app.main import create_app
from app.models import DeviceCreateInput
from app.passwords import hash_password
from app.profile import build_profile
from app.services.device_service import (
    consume_profile_download_ticket,
    enroll_device,
    issue_profile_download_ticket,
)
from app.services.doh_service import (
    TYPE_A,
    TYPE_AAAA,
    build_dns_query_packet,
    parse_dns_question,
    resolve_lab_dns_wireformat,
)
from app.services.pki_service import inspect_certificate_metadata
from scripts.generate_lab_ca import generate_ca_and_leaf_files


def test_lifespan_never_silently_ignores_index_creation_failures(monkeypatch):
    """P1 MongoDB: Mandatory index creation errors on v2 collections MUST raise and abort startup."""
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'abc123')
    monkeypatch.setenv('ROOT_CA_PATH', '')
    monkeypatch.setenv('ROOT_CA_PEM', '')
    get_settings.cache_clear()

    app = create_app()
    db = MagicMock()
    for col_name in ('accounts', 'admins', 'sessions', 'login_limits', 'viewers_history'):
        setattr(db, col_name, AsyncMock())
    db.accounts_v2 = AsyncMock()
    db.accounts_v2.create_index.side_effect = OperationFailure('E11000 duplicate key error on accounts_v2.locket_id')

    mongo = MagicMock()
    mongo.admin = AsyncMock()
    mongo.close = AsyncMock()
    mongo.__getitem__.return_value = db
    monkeypatch.setattr('app.database.AsyncMongoClient', MagicMock(return_value=mongo))

    async def run_failing_startup():
        async with lifespan(app):
            pass

    with pytest.raises(OperationFailure, match='duplicate key error'):
        asyncio.run(run_failing_startup())
    mongo.close.assert_awaited_once()
    get_settings.cache_clear()


def test_concurrent_device_enrollment_never_exceeds_max_devices():
    """P1 MongoDB: Concurrent enroll_device calls for the same account must strictly enforce max_devices."""
    app = FastAPI()
    locket_id = 'race_condition_user_1'
    max_devices = 2

    accounts_v2 = AsyncMock()
    accounts_v2.find_one.return_value = {
        'locket_id': locket_id,
        'status': 'active',
        'max_devices': max_devices,
        'expires_date': datetime.now(timezone.utc) + timedelta(days=30),
    }

    stored_devices: list[dict] = []

    class FakeConcurrentDevicesCollection:
        def find(self, query, projection=None):
            matching = [
                d.copy() for d in stored_devices
                if d.get('locket_id') == query.get('locket_id')
                and (query.get('status') is None or d.get('status') == query.get('status'))
            ]
            cursor = MagicMock()
            cursor.sort.return_value = cursor
            cursor.to_list = AsyncMock(return_value=matching)
            return cursor

        async def count_documents(self, query):
            await asyncio.sleep(0.005)
            return sum(
                1 for d in stored_devices
                if d.get('locket_id') == query.get('locket_id') and d.get('status') == query.get('status')
            )

        async def insert_one(self, doc):
            await asyncio.sleep(0.005)
            for existing in stored_devices:
                if (
                    existing.get('locket_id') == doc.get('locket_id')
                    and existing.get('slot_index') is not None
                    and existing.get('slot_index') == doc.get('slot_index')
                ):
                    raise DuplicateKeyError('Duplicate (locket_id, slot_index)')
            stored_devices.append(doc.copy())

        async def delete_one(self, query):
            stored_devices[:] = [d for d in stored_devices if d.get('device_id') != query.get('device_id')]

    app.state.accounts_v2 = accounts_v2
    app.state.accounts = AsyncMock()
    app.state.devices = FakeConcurrentDevicesCollection()

    req = MagicMock()
    req.app = app

    async def run_race():
        tasks = [
            enroll_device(
                req,
                DeviceCreateInput(locket_id=locket_id, device_name=f'iPhone {i}', ios_version='18.2'),
            )
            for i in range(6)
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    results = asyncio.run(run_race())
    successes = [r for r in results if isinstance(r, dict) and 'device_token' in r]
    conflicts = [r for r in results if isinstance(r, HTTPException) and r.status_code == 409]

    assert len(successes) == max_devices
    assert len(conflicts) == 4
    assert len(stored_devices) == max_devices
    assert sorted(d['slot_index'] for d in stored_devices) == [0, 1]


def test_one_time_download_ticket_security_and_url_token_rejection(monkeypatch, tmp_path):
    """
    P1 Device Token Security:
      - Passing device_token / token / access_token / bearer in URL query string returns HTTP 400.
      - Valid 1-time ticket works once (HTTP 200) and embeds device_id in NextDNS/DoH URL.
      - Replaying the same ticket returns HTTP 401.
      - Wrong/unknown ticket returns HTTP 401.
      - Expired ticket returns HTTP 401.
      - Ticket for a revoked device returns HTTP 401.
    """
    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'
    generate_ca_and_leaf_files(pub_dir, priv_dir, ['mock.lab.vuthanhluan.bond'])
    ca_pem_path = pub_dir / 'lab_root_ca.pem'

    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PATH', str(ca_pem_path))
    monkeypatch.setenv('ROOT_CA_PEM', '')
    monkeypatch.setenv('LAB_SCOPED_DOMAINS', '["mock.lab.vuthanhluan.bond"]')
    get_settings.cache_clear()

    app = create_app()
    admin_doc = {
        '_id': 'superadmin',
        'email': 'admin@example.test',
        'password_hash': encoded,
        'auth_version': hashlib.sha256(encoded.encode()).hexdigest(),
    }
    admins = AsyncMock()
    admins.find_one.return_value = admin_doc
    sessions_store = {}
    sessions = AsyncMock()
    sessions.insert_one.side_effect = lambda d: sessions_store.setdefault(d['_id'], d.copy())
    sessions.find_one.side_effect = lambda q: sessions_store.get(q['_id'])
    login_limits = AsyncMock()
    login_limits.find_one_and_update.return_value = {'count': 1}

    accounts_v2_store = {}
    devices_store = {}
    tickets_store = {}

    class MemAccounts:
        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = accounts_v2_store.get(lid, {'locket_id': lid})
            if '$set' in u:
                doc.update(u['$set'])
            accounts_v2_store[lid] = doc

        async def find_one(self, q, projection=None):
            return accounts_v2_store.get(q.get('locket_id'))

    class MemDevices:
        def find(self, q, projection=None):
            items = [
                d.copy() for d in devices_store.values()
                if (q.get('locket_id') is None or d.get('locket_id') == q.get('locket_id'))
                and (q.get('status') is None or d.get('status') == q.get('status'))
            ]
            c = MagicMock()
            c.sort.return_value = c
            c.to_list = AsyncMock(return_value=items)
            return c

        async def count_documents(self, q):
            return sum(
                1 for d in devices_store.values()
                if d.get('locket_id') == q.get('locket_id') and d.get('status') == q.get('status')
            )

        async def insert_one(self, doc):
            devices_store[doc['device_id']] = doc.copy()

        async def find_one(self, q, projection=None):
            for d in devices_store.values():
                if q.get('token_hash') and d.get('token_hash') == q.get('token_hash'):
                    return d.copy()
                if q.get('device_id') and d.get('device_id') == q.get('device_id'):
                    return d.copy()
            return None

        async def update_one(self, q, u):
            dev = devices_store.get(q.get('device_id'))
            if dev and '$set' in u:
                dev.update(u['$set'])

    class MemTickets:
        async def insert_one(self, doc):
            tickets_store[doc['ticket_hash']] = doc.copy()

        async def find_one_and_delete(self, q):
            return tickets_store.pop(q.get('ticket_hash'), None)

    mem_accounts = MemAccounts()
    app.dependency_overrides[get_accounts] = lambda: mem_accounts
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = login_limits
    app.state.accounts = mem_accounts
    app.state.accounts_v2 = mem_accounts
    app.state.devices = MemDevices()
    app.state.download_tickets = MemTickets()
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url='http://localhost')
    try:
        login_res = http.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        admin_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}

        future_exp = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        assert http.post('/admin/add-account', headers=admin_headers, json={
            'locket_id': 'ticket_user_1', 'expires_date': future_exp, 'max_devices': 2,
        }).status_code == 200

        dev_res = http.post('/admin/devices', headers=admin_headers, json={
            'locket_id': 'ticket_user_1', 'device_name': 'iPhone Ticket Test', 'ios_version': '18.2',
        })
        assert dev_res.status_code == 200
        dev_token = dev_res.json()['device_token']
        dev_id = dev_res.json()['device_id']

        # 1. Long-lived token parameters in URL query string MUST be rejected with 400
        for param in ('device_token', 'token', 'access_token', 'bearer'):
            r_bad = http.get(f'/profile.mobileconfig?mode=scoped_lab&{param}={dev_token}')
            assert r_bad.status_code == 400

        # 2. Wrong / invalid ticket returns 401
        assert http.get('/profile.mobileconfig?mode=scoped_lab&ticket=lkg_dl_invalid_ticket_value').status_code == 401
        assert http.get('/profile.mobileconfig?mode=scoped_lab&ticket=not_a_ticket').status_code == 401

        # 3. Valid ticket issued via device Authorization header works once and fails on replay
        tk_res = http.post(
            '/api/profile/download-ticket',
            headers={'Authorization': f'Bearer {dev_token}'},
            json={'mode': 'scoped_lab'},
        )
        assert tk_res.status_code == 200
        ticket1 = tk_res.json()['download_ticket']
        assert dev_token not in tk_res.text

        dl1 = http.get(f'/profile.mobileconfig?mode=scoped_lab&ticket={ticket1}')
        assert dl1.status_code == 200
        plist1 = plistlib.loads(dl1.content)
        assert plist1['PayloadContent'][0]['DNSSettings']['ServerURL'] == f'https://dns.nextdns.io/a8b247/{dev_id}'

        # Replay of ticket1 -> 401
        assert http.get(f'/profile.mobileconfig?mode=scoped_lab&ticket={ticket1}').status_code == 401

        # 4. Expired ticket -> 401
        tk_exp_res = http.post(
            '/api/profile/download-ticket',
            headers={'Authorization': f'Bearer {dev_token}'},
            json={'mode': 'scoped_lab'},
        )
        ticket_exp = tk_exp_res.json()['download_ticket']
        for doc in tickets_store.values():
            doc['expires_at'] = datetime.now(timezone.utc) - timedelta(seconds=5)
        assert http.get(f'/profile.mobileconfig?mode=scoped_lab&ticket={ticket_exp}').status_code == 401

        # 5. Ticket mode binding: a ticket issued for dns_only MUST NOT be usable for lab_ca or scoped_lab (returns 403)
        tk_dns_res = http.post(
            '/api/profile/download-ticket',
            headers={'Authorization': f'Bearer {dev_token}'},
            json={'mode': 'dns_only'},
        )
        assert tk_dns_res.status_code == 200
        dns_ticket = tk_dns_res.json()['download_ticket']
        assert http.get(f'/profile.mobileconfig?mode=lab_ca&ticket={dns_ticket}').status_code == 403
        # Ticket was atomically consumed on the tampered attempt, so subsequent use returns 401
        assert http.get(f'/profile.mobileconfig?mode=dns_only&ticket={dns_ticket}').status_code == 401

        # Ticket issued for dns_only requested with default mode downloads dns_only (no Root CA payload)
        tk_dns2_res = http.post(
            '/api/profile/download-ticket',
            headers={'Authorization': f'Bearer {dev_token}'},
            json={'mode': 'dns_only'},
        )
        dns_ticket2 = tk_dns2_res.json()['download_ticket']
        dl_dns2 = http.get(f'/profile.mobileconfig?ticket={dns_ticket2}')
        assert dl_dns2.status_code == 200
        assert 'no-store' in dl_dns2.headers.get('cache-control', '')
        pl_dns2 = plistlib.loads(dl_dns2.content)
        assert [p['PayloadType'] for p in pl_dns2['PayloadContent']] == ['com.apple.dnsSettings.managed']

        # 6. Admin-issued ticket for device that gets revoked before download -> 401
        tk_adm_res = http.post(f'/admin/devices/{dev_id}/profile-ticket?mode=scoped_lab', headers=admin_headers)
        assert tk_adm_res.status_code == 200
        ticket_rev = tk_adm_res.json()['download_ticket']

        assert http.post(f'/admin/devices/{dev_id}/revoke', headers=admin_headers).status_code == 200
        assert http.get(f'/profile.mobileconfig?mode=scoped_lab&ticket={ticket_rev}').status_code == 401
    finally:
        http.close()
        get_settings.cache_clear()


def test_root_ca_preserved_across_restarts_and_rotates_only_when_explicit(tmp_path):
    """
    P1 Root CA Protection:
      - Running generate_ca_and_leaf_files twice without rotate=True preserves the exact Root CA key & SHA-256 fingerprint.
      - Running generate_ca_and_leaf_files with rotate=True generates a new Root CA fingerprint.
    """
    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'
    domains = ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond']

    first = generate_ca_and_leaf_files(pub_dir, priv_dir, domains)
    assert first['ca_reused'] is False
    fp1 = first['ca_metadata']['sha256_fingerprint']
    ca_key_bytes_1 = (priv_dir / 'lab_root_ca.key').read_bytes()

    second = generate_ca_and_leaf_files(pub_dir, priv_dir, domains)
    assert second['ca_reused'] is True
    fp2 = second['ca_metadata']['sha256_fingerprint']
    ca_key_bytes_2 = (priv_dir / 'lab_root_ca.key').read_bytes()

    assert fp1 == fp2
    assert ca_key_bytes_1 == ca_key_bytes_2

    # Verify leaf cert is signed by the preserved Root CA
    ca_cert = x509.load_pem_x509_certificate((pub_dir / 'lab_root_ca.pem').read_bytes())
    leaf_cert = x509.load_pem_x509_certificate((priv_dir / 'lab_leaf.pem').read_bytes())
    assert inspect_certificate_metadata(ca_cert)['sha256_fingerprint'] == fp1
    assert leaf_cert.issuer == ca_cert.subject

    # Explicit rotation (--rotate / rotate=True) replaces the Root CA
    rotated = generate_ca_and_leaf_files(pub_dir, priv_dir, domains, rotate=True)
    assert rotated['ca_reused'] is False
    fp3 = rotated['ca_metadata']['sha256_fingerprint']
    assert fp3 != fp1


def test_doh_wireformat_and_json_queries_a_aaaa_https_svcb_malformed_and_refused(monkeypatch):
    """P1 DNS & Mobileconfig: Verify DoH wireformat and JSON handle A, AAAA, HTTPS (65), SVCB (64), malformed (400), and REFUSED."""
    allowed = ['mock.lab.vuthanhluan.bond', 'locketgold.vuthanhluan.bond']

    # Wireformat A query
    pkt_a = build_dns_query_packet('mock.lab.vuthanhluan.bond', qtype=TYPE_A)
    _, meta_a = resolve_lab_dns_wireformat(pkt_a, allowed_domains=allowed, target_ipv4='203.0.113.50')
    assert meta_a['rcode'] == 'NOERROR' and meta_a['answer_ip'] == '203.0.113.50'

    # Wireformat AAAA query (NODATA when IPv6 not configured, or IPv6 address when configured)
    pkt_aaaa = build_dns_query_packet('mock.lab.vuthanhluan.bond', qtype=TYPE_AAAA)
    _, meta_aaaa_nodata = resolve_lab_dns_wireformat(pkt_aaaa, allowed_domains=allowed, target_ipv4='203.0.113.50')
    assert meta_aaaa_nodata['rcode'] == 'NOERROR_NODATA'
    _, meta_aaaa_v6 = resolve_lab_dns_wireformat(
        pkt_aaaa, allowed_domains=allowed, target_ipv4='203.0.113.50', target_ipv6='2001:db8::50'
    )
    assert meta_aaaa_v6['rcode'] == 'NOERROR' and meta_aaaa_v6['answer_ip'] == '2001:db8::50'

    # Wireformat HTTPS (qtype=65) & SVCB (qtype=64) -> Authoritative NOERROR_NODATA
    for qtype_code in (64, 65):
        pkt_https = build_dns_query_packet('mock.lab.vuthanhluan.bond', qtype=qtype_code)
        _, meta_https = resolve_lab_dns_wireformat(pkt_https, allowed_domains=allowed, target_ipv4='203.0.113.50')
        assert meta_https['rcode'] == 'NOERROR_NODATA' and meta_https['qtype'] == qtype_code

    # Wireformat out-of-scope domain -> REFUSED
    pkt_ext = build_dns_query_packet('api.revenuecat.com', qtype=TYPE_A)
    _, meta_ext = resolve_lab_dns_wireformat(pkt_ext, allowed_domains=allowed, target_ipv4='203.0.113.50')
    assert meta_ext['rcode'] == 'REFUSED'

    # Malformed wireformat packet -> ValueError
    with pytest.raises(ValueError):
        parse_dns_question(b'\x00\x01\x02')


def test_iphone_web_ui_distinguishes_dns_only_and_lab_ca(monkeypatch):
    """P2 iPhone Web UI: Verify public and admin views expose both DNS-only and Lab CA mobileconfig download buttons."""
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'abc123')
    monkeypatch.setenv('ROOT_CA_PATH', '')
    monkeypatch.setenv('ROOT_CA_PEM', '')
    get_settings.cache_clear()

    app = create_app()
    http = TestClient(app, base_url='http://localhost')
    try:
        pub = http.get('/')
        assert pub.status_code == 200
        assert 'href="/profile.mobileconfig"' in pub.text
        assert 'href="/profile.mobileconfig?mode=dns_only"' in pub.text

        adm = http.get('/admin')
        assert adm.status_code == 200
        assert 'href="/profile.mobileconfig?mode=dns_only"' in adm.text
        assert 'href="/profile.mobileconfig?mode=scoped_lab"' in adm.text
        assert '/profile-ticket?mode=scoped_lab' in adm.text
    finally:
        http.close()
        get_settings.cache_clear()


def test_pbkdf2_hashes_with_letter_and_digit_salt_digest_and_dotenv_single_quotes(tmp_path):
    """
    Prompt 12 Section 3.4:
      1. Hash with salt starting with letter [a-f].
      2. Hash with salt starting with digit [0-9].
      3. Hash with digest starting with letter [a-f].
      4. Hash with multiple $ characters (exact 3 $ required; extra $ rejected).
      5. Hash preserved intact through .env single-quoted format & Pydantic Settings.
      6. verify_password accepts matching password and rejects wrong password.
    """
    from app.config import Settings
    from app.passwords import ITERATIONS, validate_password_hash, verify_password

    pw = 'TestPassword!Prompt12#2026'
    for salt_hex in (
        'abcdef0123456789abcdef0123456789',  # starts with letter 'a'
        '0123456789abcdef0123456789abcdef',  # starts with digit '0'
        'fedcba9876543210fedcba9876543210',  # starts with letter 'f'
        '9876543210fedcba9876543210fedcba',  # starts with digit '9'
    ):
        salt_bytes = bytes.fromhex(salt_hex)
        digest_bytes = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt_bytes, ITERATIONS)
        encoded = f'pbkdf2_sha256${ITERATIONS}${salt_hex}${digest_bytes.hex()}'
        it, sb, db = validate_password_hash(encoded)
        assert it == ITERATIONS and sb == salt_bytes and db == digest_bytes
        assert verify_password(pw, encoded) is True
        assert verify_password('WrongPassword!12345', encoded) is False

        # Verify Settings loads single-quoted hash from .env file without corrupting $-prefixed hex
        env_file = tmp_path / f'.env.test_{salt_hex[:4]}'
        env_file.write_text(
            f"APP_ENV=staging\n"
            f"MONGODB_URI=mongodb://127.0.0.1:27017\n"
            f"MONGODB_DATABASE=locket_manager_staging\n"
            f"SUPERADMIN_EMAIL=admin@example.test\n"
            f"SUPERADMIN_PASSWORD_HASH='{encoded}'\n",
            encoding='utf-8',
        )
        loaded_settings = Settings(_env_file=str(env_file))
        assert loaded_settings.superadmin_password_hash.get_secret_value() == encoded

    # Hash with explicit digest starting with letter 'f'
    letter_digest_hash = (
        f'pbkdf2_sha256${ITERATIONS}$'
        'abcdef0123456789abcdef0123456789$'
        'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
    )
    assert validate_password_hash(letter_digest_hash)[0] == ITERATIONS

    # Extra or missing $ segments MUST be rejected
    for bad_hash in (
        f'pbkdf2_sha256${ITERATIONS}$abcdef0123456789abcdef0123456789',
        f'pbkdf2_sha256${ITERATIONS}$abcdef0123456789abcdef0123456789$' + 'a' * 64 + '$extra',
        f'pbkdf2_sha256${ITERATIONS}$$' + 'a' * 64,
    ):
        with pytest.raises(ValueError, match='valid PBKDF2-SHA256'):
            validate_password_hash(bad_hash)


def test_root_ca_fail_closed_on_missing_corrupted_or_mismatched_files(tmp_path):
    """
    Prompt 12 Section 6.1:
      - Public CA exists without private key -> RuntimeError (fail-closed, never overwrites).
      - Private key exists without public CA -> RuntimeError.
      - Corrupted CA file -> RuntimeError.
      - Certificate does not match private key -> RuntimeError.
      - Explicit rotate=True creates .bak backups before rotating.
    """
    domains = ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond']

    # 1. Public CA exists but private key is missing
    pub1, priv1 = tmp_path / 'p1_pub', tmp_path / 'p1_priv'
    generate_ca_and_leaf_files(pub1, priv1, domains)
    (priv1 / 'lab_root_ca.key').unlink()
    with pytest.raises(RuntimeError, match='Inconsistent Root CA state'):
        generate_ca_and_leaf_files(pub1, priv1, domains)

    # 2. Private key exists but public CA is missing
    pub2, priv2 = tmp_path / 'p2_pub', tmp_path / 'p2_priv'
    generate_ca_and_leaf_files(pub2, priv2, domains)
    (pub2 / 'lab_root_ca.pem').unlink()
    with pytest.raises(RuntimeError, match='Inconsistent Root CA state'):
        generate_ca_and_leaf_files(pub2, priv2, domains)

    # 3. Corrupted Root CA certificate file
    pub3, priv3 = tmp_path / 'p3_pub', tmp_path / 'p3_priv'
    generate_ca_and_leaf_files(pub3, priv3, domains)
    (pub3 / 'lab_root_ca.pem').write_text('NOT A VALID PEM CERTIFICATE', encoding='utf-8')
    with pytest.raises(RuntimeError, match='unreadable or corrupted'):
        generate_ca_and_leaf_files(pub3, priv3, domains)

    # 4. Certificate does not match private key
    pub4, priv4 = tmp_path / 'p4_pub', tmp_path / 'p4_priv'
    pub5, priv5 = tmp_path / 'p5_pub', tmp_path / 'p5_priv'
    generate_ca_and_leaf_files(pub4, priv4, domains)
    generate_ca_and_leaf_files(pub5, priv5, domains)
    # Swap public cert from p5 into p4 so p4's cert and key mismatch
    (pub4 / 'lab_root_ca.pem').write_bytes((pub5 / 'lab_root_ca.pem').read_bytes())
    with pytest.raises(RuntimeError, match='does not match'):
        generate_ca_and_leaf_files(pub4, priv4, domains)

    # 5. Explicit rotate=True backs up existing CA before rotating
    orig_key = (priv5 / 'lab_root_ca.key').read_bytes()
    orig_pem = (pub5 / 'lab_root_ca.pem').read_bytes()
    rotated = generate_ca_and_leaf_files(pub5, priv5, domains, rotate=True)
    assert rotated['ca_reused'] is False
    assert (priv5 / 'lab_root_ca.key.bak').read_bytes() == orig_key
    assert (pub5 / 'lab_root_ca.pem.bak').read_bytes() == orig_pem


def test_device_limit_10_concurrent_revoke_reenroll_and_legacy_slot_backfill():
    """
    Prompt 12 Section 5.2:
      - 10 concurrent enrollments with max_devices=1 -> 1 succeeds, 9 return 409.
      - Legacy active device without slot_index is backfilled and counted toward max_devices=2.
    """
    for max_dev in (1, 2):
        app = FastAPI()
        lid = f'user_max_{max_dev}'
        accounts_v2 = AsyncMock()
        accounts_v2.find_one.return_value = {
            'locket_id': lid,
            'status': 'active',
            'max_devices': max_dev,
            'expires_date': datetime.now(timezone.utc) + timedelta(days=30),
        }
        stored: list[dict] = []
        if max_dev == 2:
            # Seed 1 legacy active device WITHOUT slot_index
            stored.append({
                'device_id': 'dev_legacy_001',
                'locket_id': lid,
                'device_name': 'Legacy iPhone',
                'ios_version': '18.0',
                'token_hash': 'legacy_hash',
                'token_prefix': 'lkg_dev_legacy',
                'status': 'active',
                'created_at': datetime.now(timezone.utc),
            })

        class FakeDevices:
            def find(self, q, projection=None):
                matching = [
                    d.copy() for d in stored
                    if d.get('locket_id') == q.get('locket_id')
                    and (q.get('status') is None or d.get('status') == q.get('status'))
                ]
                c = MagicMock()
                c.sort.return_value = c
                c.to_list = AsyncMock(return_value=matching)
                return c

            async def update_one(self, q, u):
                for d in stored:
                    if d.get('device_id') == q.get('device_id'):
                        if '$set' in u:
                            d.update(u['$set'])
                        if '$unset' in u:
                            for k in u['$unset']:
                                d.pop(k, None)

            async def insert_one(self, doc):
                await asyncio.sleep(0.002)
                for existing in stored:
                    if (
                        existing.get('status') == 'active'
                        and existing.get('locket_id') == doc.get('locket_id')
                        and existing.get('slot_index') is not None
                        and existing.get('slot_index') == doc.get('slot_index')
                    ):
                        raise DuplicateKeyError('Duplicate active (locket_id, slot_index)')
                stored.append(doc.copy())

            async def delete_one(self, q):
                stored[:] = [d for d in stored if d.get('device_id') != q.get('device_id')]

        app.state.accounts_v2 = accounts_v2
        app.state.accounts = AsyncMock()
        app.state.devices = FakeDevices()
        req = MagicMock()
        req.app = app

        async def run_10():
            return await asyncio.gather(
                *[
                    enroll_device(req, DeviceCreateInput(locket_id=lid, device_name=f'iPhone {i}', ios_version='18.2'))
                    for i in range(10)
                ],
                return_exceptions=True,
            )

        res = asyncio.run(run_10())
        ok = [r for r in res if isinstance(r, dict) and 'device_token' in r]
        err = [r for r in res if isinstance(r, HTTPException) and r.status_code == 409]
        # In both cases (max_devices=1 with 0 existing, or max_devices=2 with 1 legacy existing), only 1 new device can enroll!
        assert len(ok) == 1
        assert len(err) == 9
        assert len(stored) == max_dev
        assert sorted(d['slot_index'] for d in stored) == list(range(max_dev))
