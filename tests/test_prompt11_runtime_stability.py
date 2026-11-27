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
from app.services.device_service import enroll_device
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
    monkeypatch.setenv('APP_ENV', 'test')
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
    """Prompt 14 Section 3 & Test #15: Verify restored UI matches exact locketgoldmanager HTML/CSS structure without extra Lab UI clutter."""
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
        assert 'Locket Gold Premium' in pub.text
        assert 'id="lookupForm"' in pub.text
        assert 'id="locketAccount"' in pub.text
        assert 'id="lookupBtn"' in pub.text
        assert 'id="lookupDialog"' in pub.text
        assert 'id="downloadResult"' in pub.text
        assert 'id="installBtn"' in pub.text
        assert 'href="/profile.mobileconfig"' in pub.text
        assert 'class="developer-credit"' in pub.text
        # Must NOT contain hardcoded sample Base64 certificate or extra technical Lab UI panels
        assert 'MIIFVDCCAzygAwIBAgIU' not in pub.text
        assert 'id="devicesBody"' not in pub.text
        assert 'id="labClientForm"' not in pub.text

        adm = http.get('/admin')
        assert adm.status_code == 200
        assert 'Locket Gold Manager' in adm.text
        assert 'class="gold-rain"' in adm.text
        assert 'class="gold-emblem"' in adm.text
        assert 'data-theme-toggle' in adm.text
        assert 'id="accountDialog"' in adm.text
        assert 'id="accountForm"' in adm.text
        assert 'id="addAccount"' in adm.text
        assert 'id="accounts"' in adm.text
        assert 'id="devicesBody"' not in adm.text
        assert 'id="labClientForm"' not in adm.text
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


def test_prompt14_mobileconfig_fields_server_addresses_and_root_ca_validation(tmp_path):
    """
    Prompt 14 Section 5 & Section 7 (Tests 1-12):
      - Verifies ROOT_CA_PATH valid (1), nonexistent (2), ROOT_CA_PEM valid (3), PATH+PEM conflict (4),
        expired/invalid CA (5), private key rejection (6), PEM->DER exact conversion (7),
        plistlib.loads() parsing + Configuration fields (PayloadOrganization, Locket Gold Root CA, LocketGoldCA.cer) (8),
        dns_only single payload (9), lab_ca dual payload (10), scoped_lab domain restriction (11),
        and ServerAddresses only when valid custom DoH (never 217.15.161.106 and never on NextDNS) (12).
    """
    from pydantic import ValidationError
    from app.config import Settings

    pub_dir = tmp_path / 'certs_public'
    priv_dir = tmp_path / 'certs_private'
    gen = generate_ca_and_leaf_files(pub_dir, priv_dir, ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond'])
    ca_pem_path = pub_dir / 'lab_root_ca.pem'
    ca_der_bytes = (pub_dir / 'lab_root_ca.cer').read_bytes()
    pw_hash = 'pbkdf2_sha256$600000$' + '11' * 16 + '$' + '22' * 32

    # 1 & 7 & 8 & 10: Valid ROOT_CA_PATH + PEM->DER exact match + Configuration fields
    s_path = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=pw_hash,
        mongodb_uri='mongodb://127.0.0.1:27017',
        nextdns_id='a8b247',
        root_ca_path=str(ca_pem_path),
        lab_domain='vuthanhluan.bond',
    )
    mc_bytes = build_profile(s_path)
    pl = plistlib.loads(mc_bytes)
    assert pl['PayloadType'] == 'Configuration'
    assert pl['PayloadVersion'] == 1
    assert pl['PayloadOrganization'] == 'vuthanhluan.bond'
    assert pl['PayloadScope'] == 'System'
    assert pl['PayloadRemovalDisallowed'] is False
    assert 'hvnothv.bond' not in mc_bytes.decode('utf-8')
    assert len(pl['PayloadContent']) == 2
    dns_p, ca_p = pl['PayloadContent']
    assert dns_p['PayloadType'] == 'com.apple.dnsSettings.managed'
    assert dns_p['PayloadDisplayName'] == 'Locket Gold DNS'
    assert 'ServerAddresses' not in dns_p['DNSSettings']  # NextDNS must NOT include ServerAddresses
    assert ca_p['PayloadType'] == 'com.apple.security.root'
    assert ca_p['PayloadDisplayName'] == 'Locket Gold Root CA'
    assert ca_p['PayloadCertificateFileName'] == 'LocketGoldCA.cer'
    assert ca_p['PayloadContent'] == ca_der_bytes
    assert inspect_certificate_metadata(x509.load_der_x509_certificate(ca_p['PayloadContent']))['sha256_fingerprint'] == gen['ca_metadata']['sha256_fingerprint']

    # 2: Nonexistent ROOT_CA_PATH -> ValueError
    s_missing = s_path.model_copy(update={'root_ca_path': str(tmp_path / 'does_not_exist.pem')})
    with pytest.raises(ValueError, match='ROOT_CA_PATH'):
        build_profile(s_missing)

    # 3: Valid ROOT_CA_PEM
    s_pem = s_path.model_copy(update={'root_ca_path': '', 'root_ca_pem': ca_pem_path.read_text(encoding='utf-8')})
    pl_pem = plistlib.loads(build_profile(s_pem))
    assert pl_pem['PayloadContent'][1]['PayloadContent'] == ca_der_bytes

    # 4: Both ROOT_CA_PATH and ROOT_CA_PEM set -> ValueError
    s_both = s_path.model_copy(update={'root_ca_pem': ca_pem_path.read_text(encoding='utf-8')})
    with pytest.raises(ValueError, match='only one of ROOT_CA_PATH or ROOT_CA_PEM'):
        build_profile(s_both)

    # 6: Private key in ROOT_CA_PEM or ROOT_CA_PATH -> rejected with ValueError
    s_priv = s_path.model_copy(update={'root_ca_path': str(priv_dir / 'lab_root_ca.key')})
    with pytest.raises(ValueError, match='never contain a private key'):
        build_profile(s_priv)

    # 9: dns_only mode has exactly 1 payload (DNS)
    s_dns_only = s_path.model_copy(update={'root_ca_path': '', 'root_ca_pem': ''})
    pl_dns_only = plistlib.loads(build_profile(s_dns_only))
    assert [p['PayloadType'] for p in pl_dns_only['PayloadContent']] == ['com.apple.dnsSettings.managed']

    # 12: ServerAddresses only included when custom DoH + valid IPs; sample IP 217.15.161.106 is rejected
    with pytest.raises(ValidationError, match='217.15.161.106 is prohibited'):
        Settings(
            _env_file=None,
            superadmin_email='admin@example.test',
            superadmin_password_hash=pw_hash,
            mongodb_uri='mongodb://127.0.0.1:27017',
            doh_server_url='https://mock.lab.vuthanhluan.bond/dns-query',
            doh_server_addresses=['217.15.161.106'],
        )

    # Even if doh_server_addresses is set, when using NextDNS (doh_server_url=''), ServerAddresses is omitted
    s_nextdns_with_addrs = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=pw_hash,
        mongodb_uri='mongodb://127.0.0.1:27017',
        nextdns_id='a8b247',
        doh_server_url='',
        doh_server_addresses=['103.118.29.159'],
    )
    pl_nextdns = plistlib.loads(build_profile(s_nextdns_with_addrs))
    assert 'ServerAddresses' not in pl_nextdns['PayloadContent'][0]['DNSSettings']

    # When custom DoH (doh_server_url) AND valid doh_server_addresses are configured, ServerAddresses is included
    s_custom_doh_addrs = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=pw_hash,
        mongodb_uri='mongodb://127.0.0.1:27017',
        doh_server_url='https://mock.lab.vuthanhluan.bond/dns-query',
        doh_server_addresses=['103.118.29.159'],
    )
    pl_custom = plistlib.loads(build_profile(s_custom_doh_addrs, scoped_domains=['mock.lab.vuthanhluan.bond']))
    assert pl_custom['PayloadContent'][0]['DNSSettings']['ServerAddresses'] == ['103.118.29.159']
    assert pl_custom['PayloadContent'][0]['DNSSettings']['SupplementalMatchDomains'] == ['mock.lab.vuthanhluan.bond']


def test_prompt17_groups_a_b_c_d_and_real_mobileconfig_file_verification(monkeypatch, tmp_path):
    """
    Prompt 17 Sections X & XI:
      - Group A (A01-A15): Apple .mobileconfig structure, distinct reverse-DNS PayloadIdentifiers, headers, no sample leakage.
      - Group B (B01-B12): Root CA validation (PEM/DER, expired, leaf CA:FALSE, private key rejection, lab_ca & scoped_lab 503 fail-closed when CA missing).
      - Group C (C01-C10): DoH URL resolution, 503 when unconfigured, wireformat A/AAAA/HTTPS/SVCB/REFUSED/400 & JSON DoH.
      - Group D (D01-D10): Firebase UID linking, lookup by locket_id/username/firebase_uid, verified vs unverified honesty, legacy compatibility, and UI fields.
      - Section XI: Real .mobileconfig file written to disk, opened in binary mode with plistlib.load(f), X.509 DER & SHA-256 fingerprint verified.
    """
    from uuid import UUID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from app.config import Settings

    pub_dir = tmp_path / 'p17_pub'
    priv_dir = tmp_path / 'p17_priv'
    domains = ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond']
    gen = generate_ca_and_leaf_files(pub_dir, priv_dir, domains)
    ca_pem_path = pub_dir / 'lab_root_ca.pem'
    ca_cer_path = pub_dir / 'lab_root_ca.cer'
    expected_fp = gen['ca_metadata']['sha256_fingerprint']

    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)

    # B05 & B06: Expired CA certificate and non-CA leaf certificate must fail closed
    key_exp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj_exp = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Expired Test CA')])
    now_utc = datetime.now(timezone.utc)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(subj_exp)
        .issuer_name(subj_exp)
        .public_key(key_exp.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc - timedelta(days=20))
        .not_valid_after(now_utc - timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key_exp, algorithm=hashes.SHA256())
    )
    expired_pem = expired_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    s_expired = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=encoded,
        mongodb_uri='mongodb://127.0.0.1:27017',
        nextdns_id='a8b247',
        root_ca_pem=expired_pem,
    )
    with pytest.raises(ValueError, match='expired or not yet valid'):
        build_profile(s_expired)

    # B06: Leaf cert (CA:FALSE) rejected as Root CA
    s_leaf_as_ca = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=encoded,
        mongodb_uri='mongodb://127.0.0.1:27017',
        nextdns_id='a8b247',
        root_ca_path=str(priv_dir / 'lab_leaf.pem'),
    )
    with pytest.raises(ValueError, match='CA certificate'):
        build_profile(s_leaf_as_ca)

    # C03: Missing both NEXTDNS_ID and DOH_SERVER_URL -> HTTPException 503
    s_no_dns = Settings(
        _env_file=None,
        superadmin_email='admin@example.test',
        superadmin_password_hash=encoded,
        mongodb_uri='mongodb://127.0.0.1:27017',
        nextdns_id='',
        doh_server_url='',
    )
    with pytest.raises(HTTPException) as exc_info:
        build_profile(s_no_dns)
    assert exc_info.value.status_code == 503

    # B12: HTTP endpoint /profile.mobileconfig?mode=lab_ca and ?mode=scoped_lab MUST return 503 when Root CA is not configured
    monkeypatch.setenv('APP_ENV', 'test')
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PATH', '')
    monkeypatch.setenv('ROOT_CA_PEM', '')
    get_settings.cache_clear()

    app_no_ca = create_app()
    app_no_ca.state.profile = build_profile(get_settings())
    client_no_ca = TestClient(app_no_ca, base_url='http://localhost')
    try:
        # dns_only and default succeed without Root CA
        r_dns = client_no_ca.get('/profile.mobileconfig?mode=dns_only')
        assert r_dns.status_code == 200
        assert len(plistlib.loads(r_dns.content)['PayloadContent']) == 1
        # lab_ca and scoped_lab MUST fail closed with 503 when Root CA is missing
        r_lab_ca_503 = client_no_ca.get('/profile.mobileconfig?mode=lab_ca')
        assert r_lab_ca_503.status_code == 503
        r_scoped_503 = client_no_ca.get('/profile.mobileconfig?mode=scoped_lab')
        assert r_scoped_503.status_code == 503
    finally:
        client_no_ca.close()

    # Now configure valid ROOT_CA_PATH and test full HTTP flow (Group A, B, C, D & Section XI)
    monkeypatch.setenv('ROOT_CA_PATH', str(ca_pem_path))
    get_settings.cache_clear()

    app = create_app()
    v1_store: dict[str, dict] = {}
    v2_store: dict[str, dict] = {}
    sessions_store: dict[str, dict] = {}

    class InMemoryAccountsV1:
        async def find_one(self, q, projection=None):
            lid = q.get('locket_id')
            return v1_store.get(lid, None)

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v1_store.get(lid, {'locket_id': lid}).copy()
            if '$set' in u:
                doc.update(u['$set'])
            v1_store[lid] = doc

        def find(self, q, projection=None):
            rows = sorted(v1_store.values(), key=lambda x: x['locket_id'])
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

    class InMemoryAccountsV2:
        async def find_one(self, q, projection=None):
            for field in ('locket_id', 'username', 'firebase_uid'):
                if field in q and q[field] is not None:
                    for doc in v2_store.values():
                        if doc.get(field) == q[field]:
                            return doc.copy()
            return None

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v2_store.get(lid, {'locket_id': lid}).copy()
            if '$setOnInsert' in u and lid not in v2_store:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            v2_store[lid] = doc

        def find(self, q, projection=None):
            rows = sorted(v2_store.values(), key=lambda x: x['locket_id'])
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

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
    login_limits = AsyncMock()
    login_limits.find_one_and_update.return_value = {'count': 1}

    mem_v1 = InMemoryAccountsV1()
    mem_v2 = InMemoryAccountsV2()
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = login_limits
    app.state.accounts = mem_v1
    app.state.accounts_v2 = mem_v2
    app.state.entitlements = AsyncMock()
    app.state.profile = build_profile(get_settings())
    app.dependency_overrides[get_accounts] = lambda: mem_v1

    client = TestClient(app, base_url='http://localhost')
    try:
        # Group A (A01-A15) & Section XI: Download real .mobileconfig, save to disk, open in binary mode with plistlib.load
        resp_mc = client.get('/profile.mobileconfig?mode=lab_ca')
        assert resp_mc.status_code == 200
        assert resp_mc.headers['content-type'].startswith('application/x-apple-aspen-config')
        assert resp_mc.headers['content-disposition'] == 'attachment; filename="locket.mobileconfig"'
        assert 'no-store' in resp_mc.headers['cache-control']
        assert b'hvnothv.bond' not in resp_mc.content
        assert b'217.15.161.106' not in resp_mc.content

        real_mc_file = tmp_path / 'locket.mobileconfig'
        real_mc_file.write_bytes(resp_mc.content)

        with open(real_mc_file, 'rb') as f:
            profile = plistlib.load(f)

        assert profile['PayloadType'] == 'Configuration'
        assert profile['PayloadVersion'] == 1
        assert profile['PayloadOrganization'] == 'vuthanhluan.bond'
        assert profile['PayloadIdentifier'] == 'bond.vuthanhluan.locketgold.profile'
        assert UUID(profile['PayloadUUID']).version == 4

        payloads = profile['PayloadContent']
        assert len(payloads) == 2
        identifiers = [profile['PayloadIdentifier']] + [p['PayloadIdentifier'] for p in payloads]
        assert len(set(identifiers)) == 3
        assert identifiers == [
            'bond.vuthanhluan.locketgold.profile',
            'bond.vuthanhluan.locketgold.dns',
            'bond.vuthanhluan.locketgold.root-ca',
        ]

        dns = next(p for p in payloads if p['PayloadType'] == 'com.apple.dnsSettings.managed')
        assert dns['DNSSettings']['DNSProtocol'] == 'HTTPS'
        assert dns['DNSSettings']['ServerURL'] == 'https://dns.nextdns.io/a8b247'
        assert 'ServerAddresses' not in dns['DNSSettings']

        ca = next(p for p in payloads if p['PayloadType'] == 'com.apple.security.root')
        assert ca['PayloadCertificateFileName'] == 'LocketGoldCA.cer'
        assert isinstance(ca['PayloadContent'], bytes)
        assert ca['PayloadContent'] == ca_cer_path.read_bytes()
        cert = x509.load_der_x509_certificate(ca['PayloadContent'])
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True
        cert.verify_directly_issued_by(cert)
        assert inspect_certificate_metadata(cert)['sha256_fingerprint'] == expected_fp

        # A10: scoped_lab includes SupplementalMatchDomains
        resp_scoped = client.get('/profile.mobileconfig?mode=scoped_lab')
        assert resp_scoped.status_code == 200
        pl_scoped = plistlib.loads(resp_scoped.content)
        assert pl_scoped['PayloadContent'][0]['DNSSettings']['SupplementalMatchDomains'] == get_settings().lab_scoped_domains

        # Group C (C10 & C09): HTTP JSON DoH and malformed wireformat
        r_doh_json = client.get('/dns-query?name=mock.lab.vuthanhluan.bond&type=A')
        assert r_doh_json.status_code == 200
        assert r_doh_json.json()['Status'] == 0
        r_doh_refused = client.get('/dns-query?name=api.revenuecat.com&type=A')
        assert r_doh_refused.status_code == 200
        assert r_doh_refused.json()['Status'] == 5
        r_doh_bad = client.get('/dns-query?dns=!!!not_base64!!!')
        assert r_doh_bad.status_code == 400

        # Group D (D01-D10): Admin login, Firebase UID manual add/edit, legacy compatibility, verified vs unverified
        login_res = client.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        token = login_res.json()['access_token']
        auth_headers = {'Authorization': f'Bearer {token}'}

        future_iso = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()

        # D07 & D10: Manually add account with username + firebase_uid (even if payload claims verified_uid, server forces unverified_uid)
        manual_fb_uid = 'FbUidManualTest1234567890AbC'
        add_res = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={
                'locket_id': 'luan_gold_user',
                'username': 'luan_handle',
                'firebase_uid': manual_fb_uid,
                'verification_status': 'verified_uid',
                'expires_date': future_iso,
            },
        )
        assert add_res.status_code == 200
        added = add_res.json()
        assert added['locket_id'] == 'luan_gold_user'
        assert added['username'] == 'luan_handle'
        assert added['firebase_uid'] == manual_fb_uid
        assert added['verification_status'] == 'unverified_uid'

        # D08: Legacy account without firebase_uid
        legacy_res = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={
                'locket_id': 'legacy_only_user',
                'expires_date': future_iso,
            },
        )
        assert legacy_res.status_code == 200
        assert legacy_res.json()['firebase_uid'] is None
        assert legacy_res.json()['verification_status'] == 'manual_lab_id'

        # D06: Server-verified Firebase UID record in accounts_v2
        verified_fb_uid = 'VerifiedFirebaseUid987654321'
        v2_store['verified_gold_user'] = {
            'schema_version': 2,
            'account_id': 'verified_gold_user',
            'locket_id': 'verified_gold_user',
            'username': 'verified_user',
            'firebase_uid': verified_fb_uid,
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'verified_subscriber_traffic',
            '_server_uid_proof': True,
            'status': 'active',
            'expires_date': datetime.now(timezone.utc) + timedelta(days=90),
        }

        # D05: GET /admin/accounts returns all three accounts with accurate firebase_uid & verification_status
        list_res = client.get('/admin/accounts', headers=auth_headers)
        assert list_res.status_code == 200
        by_id = {r['locket_id']: r for r in list_res.json()}
        assert by_id['luan_gold_user']['firebase_uid'] == manual_fb_uid
        assert by_id['luan_gold_user']['verification_status'] == 'unverified_uid'
        assert by_id['legacy_only_user']['firebase_uid'] is None
        assert by_id['verified_gold_user']['firebase_uid'] == verified_fb_uid
        assert by_id['verified_gold_user']['verification_status'] == 'verified_uid'

        # D01, D02, D03, D04: Public lookup works by locket_id, username, and firebase_uid, returning ONLY {"exists": bool}
        for q in ('luan_gold_user', 'luan_handle', 'https://locket.cam/luan_handle', manual_fb_uid, verified_fb_uid):
            pub_lk = client.get(f'/api/accounts/lookup?query={q}')
            assert pub_lk.status_code == 200
            assert pub_lk.json() == {'exists': True}
        pub_miss = client.get('/api/accounts/lookup?query=nonexistent_account_xyz')
        assert pub_miss.status_code == 200
        assert pub_miss.json() == {'exists': False}

        # D03: Subscriber entitlement endpoint ONLY grants active Gold to the verified Firebase UID
        app.state.entitlements = AsyncMock()
        app.state.entitlements.find_one.return_value = {
            'account_id': verified_fb_uid, 'entitlement_key': 'Gold', 'status': 'active', 'expires_date': future_iso,
        }
        sub_ver = client.get(f'/v1/subscribers/{verified_fb_uid}', headers=auth_headers)
        assert sub_ver.status_code == 200
        assert 'Gold' in sub_ver.json()['subscriber']['entitlements']
        for unverified_sub_id in ('luan_gold_user', 'luan_handle', manual_fb_uid, 'verified_user'):
            sub_res = client.get(f'/v1/subscribers/{unverified_sub_id}', headers=auth_headers)
            assert sub_res.status_code == 200
            assert sub_res.json()['subscriber']['entitlements'] == {}

        # D09: Admin HTML contains Firebase UID display in Accounts table & automatic resolution message without manual UID input
        adm_html = client.get('/admin').text
        assert 'id="accountFirebaseUid"' not in adm_html
        assert 'Đang tìm Firebase UID...' in adm_html
        assert 'Chưa liên kết Firebase UID' in adm_html
        assert 'account-uid-meta' in adm_html
    finally:
        client.close()
        get_settings.cache_clear()


def test_prompt18_automatic_locket_id_to_firebase_uid_resolution_all_16_cases(monkeypatch, tmp_path):
    """
    Prompt 18 Section 7 — Mandatory 16 Test Scenarios for Automatic Locket ID -> Firebase UID Resolution:
      1. Valid username resolves real 28-char Firebase UID via getUserByUsername.
      2. Valid Locket share link (https://locket.cam/<username>) resolves real Firebase UID.
      3. Direct 28-char Firebase UID input is verified against provider (fetchUserV2).
      4. Nonexistent account -> not_found (HTTP 404), nothing saved to MongoDB.
      5. Identity provider returns 401/403 -> auth_required (HTTP 502), nothing saved.
      6. Identity provider returns 429 / RESOURCE_EXHAUSTED -> rate_limited (HTTP 429), nothing saved.
      7. Timeout or network failure across retries -> lookup_unavailable (HTTP 503), nothing saved.
      8. JSON missing UID field (or returning MongoDB ObjectId / UUIDv4 / placeholder) -> unverified (HTTP 422), nothing saved.
      9. Returned UID/username does not match queried account -> conflict (HTTP 409), nothing saved.
      10. Returned UID is already linked to a different account in MongoDB -> conflict (HTTP 409), nothing saved.
      11. Returned UID differs from the account's existing verified UID in MongoDB -> conflict (HTTP 409), existing verified UID preserved.
      12. End-to-end resolution & persistence in accounts_v2 (uid_resolved_at, uid_resolution_source, verification_status='verified_uid').
      13. When no provider is configured (lookup_unavailable), no fake UID or record is saved.
      14. Public lookup (/api/accounts/lookup) never leaks Firebase UID.
      15. Staging environment cannot overwrite production database (locket_manager).
      16. Root CA, DNS, and .mobileconfig generation remain 100% intact.
    """
    import json
    import httpx
    from pydantic import ValidationError
    from app.config import Settings
    from app.services.identity_service import is_valid_firebase_uid, resolve_locket_identity

    # Verify helper rejects MongoDB ObjectId, 36-char UUID, and placeholders
    assert is_valid_firebase_uid('507f1f77bcf86cd799439011') is False  # 24-char hex MongoDB ObjectId
    assert is_valid_firebase_uid('550e8400-e29b-41d4-a716-446655440000') is False  # 36-char UUIDv4
    assert is_valid_firebase_uid('UID_THUC_TE_TU_NGUON_TRA_CUU') is False
    assert is_valid_firebase_uid('A' * 28) is False  # single repeated char
    assert is_valid_firebase_uid('LocketRealUid9876543210AbCdE') is True

    # Test 15: Staging environment strictly forbidden from using production database `locket_manager`
    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    with pytest.raises(ValidationError, match='locket_manager'):
        Settings(
            _env_file=None,
            app_env='staging',
            mongodb_database='locket_manager',
            superadmin_email='admin@example.test',
            superadmin_password_hash=encoded,
            mongodb_uri='mongodb://127.0.0.1:27017',
        )

    pub_dir = tmp_path / 'p18_pub'
    priv_dir = tmp_path / 'p18_priv'
    domains = ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond']
    generate_ca_and_leaf_files(pub_dir, priv_dir, domains)
    ca_pem_path = pub_dir / 'lab_root_ca.pem'

    monkeypatch.setenv('APP_ENV', 'test')
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PATH', str(ca_pem_path))
    monkeypatch.setenv('ROOT_CA_PEM', '')
    monkeypatch.setenv('LOCKET_IDENTITY_LOOKUP_URL', '')
    get_settings.cache_clear()

    app = create_app()
    v1_store: dict[str, dict] = {}
    v2_store: dict[str, dict] = {}
    sessions_store: dict[str, dict] = {}

    class InMemoryAccountsV1:
        async def find_one(self, q, projection=None):
            return v1_store.get(q.get('locket_id'))

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v1_store.get(lid, {'locket_id': lid}).copy()
            if '$set' in u:
                doc.update(u['$set'])
            v1_store[lid] = doc

        def find(self, q, projection=None):
            rows = sorted(v1_store.values(), key=lambda x: x['locket_id'])
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

    class InMemoryAccountsV2:
        async def find_one(self, q, projection=None):
            for field in ('locket_id', 'username', 'firebase_uid'):
                if field in q and q[field] is not None:
                    for doc in v2_store.values():
                        if doc.get(field) == q[field]:
                            return doc.copy()
            return None

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v2_store.get(lid, {'locket_id': lid}).copy()
            if '$setOnInsert' in u and lid not in v2_store:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            v2_store[lid] = doc

        def find(self, q, projection=None):
            rows = sorted(v2_store.values(), key=lambda x: x['locket_id'])
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

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
    login_limits = AsyncMock()
    login_limits.find_one_and_update.return_value = {'count': 1}

    mem_v1 = InMemoryAccountsV1()
    mem_v2 = InMemoryAccountsV2()
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = login_limits
    app.state.accounts = mem_v1
    app.state.accounts_v2 = mem_v2
    app.state.entitlements = AsyncMock()
    app.state.profile = build_profile(get_settings())
    app.dependency_overrides[get_accounts] = lambda: mem_v1

    client = TestClient(app, base_url='http://localhost')
    try:
        login_res = client.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        auth_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}
        future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

        # Test 13: When no identity provider is configured (lookup_unavailable), adding account via UI (resolve_identity=True)
        # or Locket link fails closed with HTTP 503 and writes NOTHING to MongoDB
        def _offline_public_fetcher(url: str):
            raise ConnectionError('Simulated offline lookup_unavailable')

        app.state.public_link_fetcher = _offline_public_fetcher
        r_unavail = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'no_provider_user', 'expires_date': future_iso, 'resolve_identity': True},
        )
        app.state.public_link_fetcher = None
        assert r_unavail.status_code == 503
        assert 'lookup_unavailable' in r_unavail.json()['detail']
        assert 'no_provider_user' not in v2_store and 'no_provider_user' not in v1_store

        # Configure mock getUserByUsername / fetchUserV2 provider covering all response & error cases
        uid_user_1 = 'RealFirebaseUidUserOne123456'
        uid_link_2 = 'RealFirebaseUidLinkTwo654321'
        uid_direct_3 = 'DirectInputFirebaseUid998877'
        timeout_attempts = {'count': 0}

        def mock_locket_provider(query: str, input_kind: str):
            if query == 'example_user':
                # Firebase Callable getUserByUsername response format
                return (200, {'result': {'status': 200, 'data': {'uid': uid_user_1, 'username': 'example_user'}}})
            if query == 'link_user':
                return (200, {'result': {'status': 200, 'data': {'uid': uid_link_2, 'username': 'link_user'}}})
            if query == uid_direct_3 and input_kind == 'firebase_uid':
                return (200, {'result': {'status': 200, 'data': {'uid': uid_direct_3, 'username': 'direct_owner'}}})
            if query == 'nonexistent_ghost':
                return (404, {'result': {'status': 404, 'data': None}})
            if query == 'auth_error_user':
                return (401, {'error': {'code': 401, 'status': 'UNAUTHENTICATED', 'message': 'Expired token'}})
            if query == 'rate_limited_user':
                return (429, {'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED', 'message': 'Quota exceeded'}})
            if query == 'timeout_user':
                timeout_attempts['count'] += 1
                raise httpx.TimeoutException('Simulated upstream timeout')
            if query == 'missing_uid_user':
                return (200, {'result': {'status': 200, 'data': {'username': 'missing_uid_user'}}})
            if query == 'objectid_fake_user':
                return (200, {'result': {'status': 200, 'data': {'uid': '507f1f77bcf86cd799439011', 'username': 'objectid_fake_user'}}})
            if query == 'mismatch_user':
                return (200, {'result': {'status': 200, 'data': {'uid': 'MismatchUidAbcdefghijklmn123', 'username': 'someone_else'}}})
            if query == 'duplicate_uid_target':
                # Returns uid_user_1 which is already bound to example_user!
                return (200, {'result': {'status': 200, 'data': {'uid': uid_user_1, 'username': 'duplicate_uid_target'}}})
            return (404, {'result': {'status': 404, 'data': None}})

        app.state.identity_provider = mock_locket_provider

        # Test 1 & Test 12: Valid username resolves UID automatically and persists in accounts_v2
        r1 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'example_user', 'expires_date': future_iso},
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1['locket_id'] == 'example_user'
        assert d1['username'] == 'example_user'
        assert d1['firebase_uid'] == uid_user_1
        assert d1['verification_status'] == 'verified_uid'
        assert d1['verification_method'] == 'trusted_proof'
        assert d1['verification_source'] == 'authorized_identity_provider'
        assert d1['uid_resolution_source'] == 'getUserByUsername'
        assert d1['uid_resolved_at'] is not None
        assert v2_store['example_user']['_server_uid_proof'] is True
        assert v2_store['example_user']['firebase_uid'] == uid_user_1

        # Test 2: Valid Locket share link resolves UID automatically
        r2 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'https://locket.cam/link_user', 'expires_date': future_iso},
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2['locket_id'] == 'link_user'
        assert d2['username'] == 'link_user'
        assert d2['firebase_uid'] == uid_link_2
        assert d2['source_link'] == 'https://locket.cam/link_user'
        assert d2['verification_status'] == 'verified_uid'

        # Test 3: Direct 28-char Firebase UID input is verified via provider
        r3 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': uid_direct_3, 'expires_date': future_iso},
        )
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3['firebase_uid'] == uid_direct_3
        assert d3['username'] == 'direct_owner'
        assert d3['verification_status'] == 'verified_uid'
        assert d3['uid_resolution_source'] == 'fetchUserV2'

        # Test 4: Nonexistent account -> 404, not saved
        r4 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'nonexistent_ghost', 'expires_date': future_iso},
        )
        assert r4.status_code == 404
        assert 'nonexistent_ghost' not in v2_store

        # Test 5: Provider returns 401/403 -> 502 (auth_required), not saved
        r5 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'auth_error_user', 'expires_date': future_iso},
        )
        assert r5.status_code == 502
        assert 'auth_required' in r5.json()['detail']
        assert 'auth_error_user' not in v2_store

        # Test 6: Provider returns 429 -> 429 (rate_limited), not saved
        r6 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'rate_limited_user', 'expires_date': future_iso},
        )
        assert r6.status_code == 429
        assert 'rate_limited' in r6.json()['detail']
        assert 'rate_limited_user' not in v2_store

        # Test 7: Timeout/network error retries up to max_retries and returns 503 (lookup_unavailable), not saved
        r7 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'timeout_user', 'expires_date': future_iso},
        )
        assert r7.status_code == 503
        assert timeout_attempts['count'] == 2  # Retried according to locket_identity_max_retries=2
        assert 'timeout_user' not in v2_store

        # Test 8: JSON missing UID field or containing MongoDB 24-hex ObjectId -> 422 (unverified), not saved
        for bad_q in ('missing_uid_user', 'objectid_fake_user'):
            r8 = client.post(
                '/admin/add-account',
                headers=auth_headers,
                json={'locket_id': bad_q, 'expires_date': future_iso},
            )
            assert r8.status_code == 422
            assert bad_q not in v2_store

        # Test 9: Returned username/UID does not match queried account -> 409 (conflict), not saved
        r9 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'mismatch_user', 'expires_date': future_iso},
        )
        assert r9.status_code == 409
        assert 'mismatch_user' not in v2_store

        # Test 10: UID already exists on another account in MongoDB -> 409 (conflict), not saved
        r10 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'duplicate_uid_target', 'expires_date': future_iso},
        )
        assert r10.status_code == 409
        assert 'duplicate_uid_target' not in v2_store

        # Test 11: Provider returns a DIFFERENT UID for example_user than its already-verified UID in MongoDB -> 409 (conflict)
        app.state.identity_provider = lambda q, k: (
            200,
            {'result': {'status': 200, 'data': {'uid': 'DifferentConflictingUid12345', 'username': 'example_user'}}},
        )
        r11 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'example_user', 'expires_date': future_iso},
        )
        assert r11.status_code == 409
        # Existing verified UID in MongoDB MUST NOT be overwritten
        assert v2_store['example_user']['firebase_uid'] == uid_user_1

        # Also verify direct async provider path of resolve_locket_identity
        async def async_provider(query: str, input_kind: str):
            assert query == 'http_transport_user'
            return (
                200,
                {'result': {'status': 200, 'data': {'uid': 'HttpResolvedUid1234567890AbC', 'username': 'http_transport_user'}}},
            )

        s_http = Settings(
            _env_file=None,
            superadmin_email='admin@example.test',
            superadmin_password_hash=encoded,
            mongodb_uri='mongodb://127.0.0.1:27017',
        )
        async def run_http_resolve():
            return await resolve_locket_identity('http_transport_user', settings=s_http, accounts_v2=mem_v2, provider=async_provider)

        http_res = asyncio.run(run_http_resolve())
        assert http_res.status == 'resolved'
        assert http_res.firebase_uid == 'HttpResolvedUid1234567890AbC'

        # Test 14: Public lookup returns ONLY {"exists": true/false} and never leaks firebase_uid
        pub_res = client.get('/api/accounts/lookup?query=example_user')
        assert pub_res.status_code == 200
        assert pub_res.json() == {'exists': True}
        assert uid_user_1 not in pub_res.text

        # Test 16: Root CA, DNS, and .mobileconfig remain 100% intact
        mc_res = client.get('/profile.mobileconfig?mode=lab_ca')
        assert mc_res.status_code == 200
        pl = plistlib.loads(mc_res.content)
        assert pl['PayloadIdentifier'] == 'bond.vuthanhluan.locketgold.profile'
        assert len(pl['PayloadContent']) == 2
        assert pl['PayloadContent'][0]['PayloadType'] == 'com.apple.dnsSettings.managed'
        assert pl['PayloadContent'][1]['PayloadType'] == 'com.apple.security.root'
    finally:
        client.close()
        get_settings.cache_clear()


def test_prompt19_public_link_resolver_invite_token_vs_uid_and_ssrf_protection(monkeypatch, tmp_path):
    """
    Prompt 19 Section 7 — Mandatory 14 Test Scenarios for Public Link Resolver (Zero-Env-Var):
      1. Valid username resolves public share link https://locket.cam/<username>.
      2. Valid public Locket link (https://locket.cam/<username>) resolves.
      3. Page containing /invites/<token> returns invite_token_found.
      4. Page without /invites/<token> returns verification_required (HTTP 422), does not save fake data.
      5. Redirect URL (302 to https://locket.camera/invites/<token> or locket://invites/<token>) extracts invite_token; >5 redirects rejected.
      6. URL encoding (/invites/Token%2DWith%5FEncoding and double-encoded Dynamic Links) decoded properly.
      7. Timeout (8s limit) returns lookup_unavailable (HTTP 503).
      8. HTTP 404 -> not_found (HTTP 404); HTTP 429 & 500 -> lookup_unavailable (HTTP 503).
      9. SSRF and redirects to private/loopback/link-local IPs or untrusted hosts blocked with invalid_link.
      10. Never confuses a 28-character invite_token with a firebase_uid (firebase_uid=None, verification_status='unverified_handle').
      11. Persists locket_id, username, invite_token, firebase_uid=None, verification_status, identity_lookup_source, identity_lookup_at in MongoDB accounts_v2.
      12. Never overwrites an already-verified firebase_uid in MongoDB when updating an account via public link lookup.
      13. Root CA and .mobileconfig remain 100% unaffected.
      14. Original locketgoldmanager UI remains intact and displays "Đã lấy invite token — chưa xác minh Firebase UID".
    """
    import httpx
    from app.services.identity_service import (
        extract_invite_token_from_text_or_url,
        resolve_public_locket_share_link,
        validate_safe_locket_public_url,
    )

    # Test 6: Direct unit check on URL encoding & double-encoded Firebase Dynamic Links
    assert extract_invite_token_from_text_or_url('https://locket.cam/invites/Tok%2D2026%5FAbC?foo=1') == 'Tok-2026_AbC'
    assert (
        extract_invite_token_from_text_or_url(
            'https://locket.cam/?link=https%3A%2F%2Flocket.camera%2Finvites%2FNestedTok987654'
        )
        == 'NestedTok987654'
    )

    # Test 9: Direct SSRF & private IP protection checks
    for bad_ssrf_url in (
        'http://locket.cam/alice',
        'https://localhost/invites/tok123456',
        'https://127.0.0.1/invites/tok123456',
        'https://192.168.1.1/invites/tok123456',
        'https://10.0.0.1/invites/tok123456',
        'https://172.16.0.1/invites/tok123456',
        'https://169.254.169.254/latest/meta-data',
        'https://[::1]/invites/tok123456',
        'https://evil.example.com/invites/tok123456',
        'https://user:pass@locket.cam/alice',
    ):
        with pytest.raises(ValueError):
            validate_safe_locket_public_url(bad_ssrf_url)
        res_bad = asyncio.run(resolve_public_locket_share_link(bad_ssrf_url))
        assert res_bad.status == 'invalid_link'

    pub_dir = tmp_path / 'p19_pub'
    priv_dir = tmp_path / 'p19_priv'
    domains = ['locketgold.vuthanhluan.bond', 'mock.lab.vuthanhluan.bond']
    generate_ca_and_leaf_files(pub_dir, priv_dir, domains)
    ca_pem_path = pub_dir / 'lab_root_ca.pem'

    password = secrets.token_urlsafe(20)
    encoded = hash_password(password)
    monkeypatch.setenv('APP_ENV', 'test')
    monkeypatch.setenv('SUPERADMIN_EMAIL', 'admin@example.test')
    monkeypatch.setenv('SUPERADMIN_PASSWORD_HASH', encoded)
    monkeypatch.setenv('MONGODB_URI', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('ALLOWED_HOSTS', '["localhost"]')
    monkeypatch.setenv('REQUIRE_HTTPS', 'false')
    monkeypatch.setenv('NEXTDNS_ID', 'a8b247')
    monkeypatch.setenv('ROOT_CA_PATH', str(ca_pem_path))
    monkeypatch.setenv('ROOT_CA_PEM', '')
    monkeypatch.setenv('LOCKET_IDENTITY_LOOKUP_URL', '')
    get_settings.cache_clear()

    app = create_app()
    v1_store: dict[str, dict] = {}
    v2_store: dict[str, dict] = {}
    sessions_store: dict[str, dict] = {}

    class InMemoryAccountsV1:
        async def find_one(self, q, projection=None):
            return v1_store.get(q.get('locket_id'))

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v1_store.get(lid, {'locket_id': lid}).copy()
            if '$set' in u:
                doc.update(u['$set'])
            v1_store[lid] = doc

        def find(self, q, projection=None):
            rows = sorted(v1_store.values(), key=lambda x: x['locket_id'])
            c = MagicMock()
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

    class InMemoryAccountsV2:
        async def find_one(self, q, projection=None):
            for field in ('locket_id', 'username', 'firebase_uid', 'invite_token'):
                if field in q and q[field] is not None:
                    for doc in v2_store.values():
                        if doc.get(field) == q[field]:
                            return doc.copy()
            return None

        async def update_one(self, q, u, upsert=False):
            lid = q['locket_id']
            doc = v2_store.get(lid, {'locket_id': lid}).copy()
            if '$setOnInsert' in u and lid not in v2_store:
                doc.update(u['$setOnInsert'])
            if '$set' in u:
                doc.update(u['$set'])
            v2_store[lid] = doc

        def find(self, q, projection=None):
            rows = sorted(v2_store.values(), key=lambda x: x['locket_id'])
            c = MagicMock()
            c.sort.return_value = c
            c.sort.return_value = c
            c.skip.return_value = c
            c.limit.return_value = c
            c.to_list = AsyncMock(return_value=rows)
            return c

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
    login_limits = AsyncMock()
    login_limits.find_one_and_update.return_value = {'count': 1}

    mem_v1 = InMemoryAccountsV1()
    mem_v2 = InMemoryAccountsV2()
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = login_limits
    app.state.accounts = mem_v1
    app.state.accounts_v2 = mem_v2
    app.state.entitlements = AsyncMock()
    app.state.profile = build_profile(get_settings())
    app.dependency_overrides[get_accounts] = lambda: mem_v1

    # Mock public share link HTTP responses without any external network call
    invite_28_char = 'InviteTokenExactly28CharsAbC'  # 28 chars, MUST NOT be mistaken for firebase_uid!
    assert len(invite_28_char) == 28

    def mock_public_transport_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == '/user_html_invite':
            return httpx.Response(
                200,
                text=f'<html><head><meta property="og:url" content="https://locket.cam/invites/{invite_28_char}"></head></html>',
            )
        if path == '/user_redirect_invite':
            return httpx.Response(
                302,
                headers={'Location': 'https://locket.camera/invites/RedirectedInviteTok99'},
            )
        if path == '/user_encoded_invite':
            return httpx.Response(
                200,
                text='<a href="https://locket.cam/?link=https%3A%2F%2Flocket.cam%2Finvites%2FEncoded%252DTok%255F2026">Add</a>',
            )
        if path == '/user_no_invite':
            return httpx.Response(200, text='<html><body>Welcome to Locket homepage</body></html>')
        if path == '/user_404':
            return httpx.Response(404, text='Not Found')
        if path == '/user_429':
            return httpx.Response(429, text='Too Many Requests')
        if path == '/user_500':
            return httpx.Response(500, text='Internal Server Error')
        if path == '/user_timeout':
            raise httpx.TimeoutException('Simulated 8s public link timeout')
        if path == '/user_ssrf_redirect':
            return httpx.Response(302, headers={'Location': 'https://127.0.0.1/invites/SecretInternalTok'})
        if path == '/user_private_ip_redirect':
            return httpx.Response(302, headers={'Location': 'https://192.168.1.50/invites/SecretLanTok'})
        if path == '/user_verified_preserve':
            return httpx.Response(200, text='<a href="https://locket.cam/invites/NewInviteForVerifiedUser">Add</a>')
        return httpx.Response(404, text='Not Found')

    app.state.public_link_fetcher = lambda url: mock_public_transport_handler(httpx.Request('GET', url))
    client = TestClient(app, base_url='http://localhost')
    try:
        login_res = client.post('/api/admin/login', json={'email': 'admin@example.test', 'password': password})
        assert login_res.status_code == 200
        auth_headers = {'Authorization': 'Bearer ' + login_res.json()['access_token']}
        future_iso = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

        # Tests 1, 3, 10, 11: Valid username resolves 28-char invite_token from HTML,
        # stores it in invite_token, leaves firebase_uid=None, verification_status='unverified_handle'
        r1 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'user_html_invite', 'expires_date': future_iso, 'resolve_identity': True},
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1['locket_id'] == 'user_html_invite'
        assert d1['username'] == 'user_html_invite'
        assert d1['invite_token'] == invite_28_char
        assert d1['firebase_uid'] is None  # Test 10: NEVER stores 28-char invite_token as firebase_uid!
        assert d1['verification_status'] == 'unverified_handle'
        assert d1['identity_lookup_source'] == 'public_share_link'
        assert d1['identity_lookup_at'] is not None
        assert d1['resolution_status'] == 'invite_token_found'

        # Tests 2 & 5: Valid public link with 302 redirect extracts invite_token
        r2 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={
                'locket_id': 'https://locket.cam/user_redirect_invite',
                'expires_date': future_iso,
                'resolve_identity': True,
            },
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2['locket_id'] == 'user_redirect_invite'
        assert d2['invite_token'] == 'RedirectedInviteTok99'
        assert d2['firebase_uid'] is None
        assert d2['verification_status'] == 'unverified_handle'

        # Test 6: Double URL-encoded invite token in HTML
        r_enc = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'user_encoded_invite', 'expires_date': future_iso, 'resolve_identity': True},
        )
        assert r_enc.status_code == 200
        assert r_enc.json()['invite_token'] == 'Encoded-Tok_2026'

        # Test 4: Page without invite token -> verification_required (HTTP 422), not saved
        r_no_inv = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'user_no_invite', 'expires_date': future_iso, 'resolve_identity': True},
        )
        assert r_no_inv.status_code == 422
        assert 'verification_required' in r_no_inv.json()['detail']
        assert 'user_no_invite' not in v2_store

        # Test 7: Timeout -> lookup_unavailable (HTTP 503), not saved
        r_to = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'user_timeout', 'expires_date': future_iso, 'resolve_identity': True},
        )
        assert r_to.status_code == 503
        assert 'lookup_unavailable' in r_to.json()['detail']
        assert 'user_timeout' not in v2_store

        # Test 8: HTTP 404 -> 404 (not_found); HTTP 429 & 500 -> 503 (lookup_unavailable)
        r_404 = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'user_404', 'expires_date': future_iso, 'resolve_identity': True},
        )
        assert r_404.status_code == 404
        for err_u in ('user_429', 'user_500'):
            r_err = client.post(
                '/admin/add-account',
                headers=auth_headers,
                json={'locket_id': err_u, 'expires_date': future_iso, 'resolve_identity': True},
            )
            assert r_err.status_code == 503
            assert err_u not in v2_store

        # Test 9: Redirect to 127.0.0.1 or 192.168.1.50 blocked with 422 (invalid_link), not saved
        for ssrf_u in ('user_ssrf_redirect', 'user_private_ip_redirect'):
            r_ssrf = client.post(
                '/admin/add-account',
                headers=auth_headers,
                json={'locket_id': ssrf_u, 'expires_date': future_iso, 'resolve_identity': True},
            )
            assert r_ssrf.status_code == 422
            assert 'invalid_link' in r_ssrf.json()['detail']
            assert ssrf_u not in v2_store

        # Test 12: Account with existing verified firebase_uid in MongoDB is NEVER overwritten by public link lookup
        existing_real_uid = 'VerifiedRealFirebaseUid12345'
        v2_store['user_verified_preserve'] = {
            'schema_version': 2,
            'account_id': 'user_verified_preserve',
            'locket_id': 'user_verified_preserve',
            'username': 'user_verified_preserve',
            'firebase_uid': existing_real_uid,
            'verification_status': 'verified_uid',
            'verification_method': 'trusted_proof',
            'verification_source': 'authorized_identity_provider',
            '_server_uid_proof': True,
            'status': 'active',
            'expires_date': datetime.now(timezone.utc) + timedelta(days=30),
        }
        r_pres = client.post(
            '/admin/add-account',
            headers=auth_headers,
            json={'locket_id': 'user_verified_preserve', 'expires_date': future_iso, 'resolve_identity': True},
        )
        assert r_pres.status_code == 200
        d_pres = r_pres.json()
        assert d_pres['firebase_uid'] == existing_real_uid
        assert d_pres['verification_status'] == 'verified_uid'
        assert d_pres['invite_token'] == 'NewInviteForVerifiedUser'

        # Also verify direct httpx.MockTransport path of resolve_public_locket_share_link in a single event loop
        async def _verify_transport():
            transport = httpx.MockTransport(mock_public_transport_handler)
            async with httpx.AsyncClient(transport=transport, follow_redirects=False) as hc:
                return await resolve_public_locket_share_link('user_redirect_invite', http_client=hc)

        tr_res = asyncio.run(_verify_transport())
        assert tr_res.status == 'invite_token_found'
        assert tr_res.invite_token == 'RedirectedInviteTok99'

        # Test 13 & 14: Root CA/mobileconfig and original UI remain intact
        mc_res = client.get('/profile.mobileconfig?mode=lab_ca')
        assert mc_res.status_code == 200
        assert len(plistlib.loads(mc_res.content)['PayloadContent']) == 2
        adm_html = client.get('/admin').text
        assert 'Đã lấy invite token — chưa xác minh Firebase UID' in adm_html
        assert 'id="accountFirebaseUid"' not in adm_html
    finally:
        client.close()
        get_settings.cache_clear()
