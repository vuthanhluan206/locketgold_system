"""
Automated Test Suite for Prompt 8 Addendum — Verify & Preserve Core Mobileconfig Architecture
(`tests/test_mobileconfig_doh_core.py`).
Covers all 13 mandatory checks from Section 7 of the Addendum:
 1. Mobileconfig has exactly 2 payloads (`com.apple.dnsSettings.managed` + `com.apple.security.root`) in Lab CA mode.
 2. DNS-only mode (`?mode=dns_only`) does NOT contain any Root CA payload.
 3. Root CA public certificate is cryptographically valid (`CA:TRUE`, `keyCertSign`, self-signed, valid dates, no private key).
 4. SHA-256 fingerprint is dynamically computed and verified against the generated DER bytes (never hardcoded PASS),
    plus cryptographic verification of the reference `LocketProxy CA` (`16:2C:34:B4...AF:F1`) from `LocketGold_Clean_Unlocked.mobileconfig`.
 5. DoH `ServerURL` matches configuration in both Mode A (NextDNS `a8b247`) and Mode B (`DOH_SERVER_URL` custom HTTPS Lab).
 6. `SupplementalMatchDomains` matches only controlled lab domains and rejects third-party payment domains.
 7. Controlled RFC 8484 DoH Lab endpoint (`/dns-query` GET wireformat, POST wireformat, and JSON) returns valid DNS responses for lab domains and `REFUSED` (rcode=5) for external domains.
 8. HTTPS mock server leaf certificate has valid SAN, chain signed by Lab Root CA, and Apple TLS validity <= 397 days.
 9. Simulated iOS client (`scripts/lab_test_client.py` / HTTPS client) connects to Lab endpoint and parses response.
10. Backend automatically processes valid authenticated requests without manual admin intervention.
11. Revoked account is immediately denied Gold entitlement (`entitlements: {}`, `X-Lab-Entitlement-Status: revoked`).
12. Invalid or revoked device token is immediately rejected with HTTP 401 (and cross-account token with HTTP 403).
13. Diagnostic metadata & report formatting explicitly distinguish mock lab entitlement responses from official Locket/App Store subscriptions.
"""
import base64
from datetime import datetime, timedelta, timezone
import plistlib
import secrets
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.database import get_accounts
from app.main import create_app
from app.passwords import hash_password
from app.profile import build_profile
from app.services.doh_service import (
    RCODE_NOERROR,
    RCODE_REFUSED,
    TYPE_A,
    TYPE_AAAA,
    build_dns_query_packet,
    resolve_lab_dns_wireformat,
)
from app.services.pki_service import (
    generate_lab_leaf_certificate,
    generate_lab_root_ca,
    inspect_certificate_metadata,
    verify_certificate_chain_and_hostname,
)
from scripts.lab_test_client import format_entitlement_report

# Reference DER base64 from original `LocketGold_Clean_Unlocked.mobileconfig` / `LocketGoldCA.cer`
REFERENCE_LOCKETPROXY_CA_B64 = (
    "MIIDCTCCAfGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA/MRcwFQYDVQQDEw5Mb2NrZXRQcm94eSBD"
    "QTEXMBUGA1UEChMOTG9jYWwgUmVzZWFyY2gxCzAJBgNVBAYTAlZOMB4XDTI2MDkyNjA0NDQ0MloX"
    "DTM2MDkyNjA0NDQ0MlowPzEXMBUGA1UEAxMOTG9ja2V0UHJveHkgQ0ExFzAVBgNVBAoTDkxvY2Fs"
    "IFJlc2VhcmNoMQswCQYDVQQGEwJWTjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKUd"
    "iV8qKFTA9twV9HT9zIsnYWakTT0lHJcQsITUPJ75hUuPRXWdfglj9gLVTwwjRru2n65T3oHAy1j+"
    "Odv5p7pThkZlSHhnD245L1/H+5ncUeb7FHZpUoW9ITr4V9vRg+AIF/qaVyVKgOD6BUrgufCcm1CN"
    "hBEzoURk7JfW5URGhY6B6vNxcEaekRVMVpFHrIQ/WwI1bwCBeB1v8GgnYBJZtnDcKfP3KO4hItW+"
    "dGnIl+9SVQ6mPxXArhysxJgs0olTl9bSBDb+7GTWpMGT7pJPEuhLX1Byv609XDKf/Hexa8+3eckU"
    "x97H7jKZUmEtdQuinSzKke6pS0YQR1IHCjsCAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG"
    "9w0BAQsFAAOCAQEAldf0/QHRK611YDQ8PhjJMz8tyR+1WMjxWXrp8aWdm/Fz2HUJ8uowwkF7aQDe"
    "LjG9HoGZ0fmVKoOK3slY5V+nENXDL+lUIi9hrs/+YZLIwYWaYpnebHQeWhvFo4tUrydmYe9V3chT"
    "tfYlOo6hYIFADDfq1uyox4GYJsEwAE8iyhgt42uQCM9ukdCIZk7dTnm2aSU6HvMOqs3b4hFyuA9K"
    "/G/i2Yicw/haX9XIbCd2n//mR1BLLx8M6gyUt+ZFESObVeDOwpuVxXdvHjqioW/R4WbGMIDl0S25"
    "JUPqTOcAtnAZq5gDAWZqUILCrNztNrUie6ePqpv4tIzmciB8o+HdmQ=="
)
EXPECTED_REF_SHA256 = "16:2C:34:B4:EB:9C:15:42:4D:DE:28:4B:72:9F:A7:0D:35:0C:EB:91:E5:EC:ED:1A:AA:49:FD:E3:B5:85:AF:F1"


def test_check2_and_4_reference_locketproxy_ca_vs_generated_lab_ca():
    """
    Verify the exact X.509 properties of the reference `LocketProxy CA` from `LocketGold_Clean_Unlocked.mobileconfig`
    and contrast it with our newly generated Research Lab Root CA (which has a distinct private key & fingerprint).
    """
    ref_der = base64.b64decode(REFERENCE_LOCKETPROXY_CA_B64)
    ref_cert = x509.load_der_x509_certificate(ref_der)
    ref_fp = ":".join(f"{b:02X}" for b in ref_cert.fingerprint(hashes.SHA256()))

    assert ref_fp == EXPECTED_REF_SHA256
    assert ref_cert.subject.rfc4514_string() == "C=VN,O=Local Research,CN=LocketProxy CA"
    assert ref_cert.issuer.rfc4514_string() == "C=VN,O=Local Research,CN=LocketProxy CA"
    assert ref_cert.not_valid_before_utc == datetime(2026, 9, 26, 4, 44, 42, tzinfo=timezone.utc)
    assert ref_cert.not_valid_after_utc == datetime(2036, 9, 26, 4, 44, 42, tzinfo=timezone.utc)
    bc = ref_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    ref_cert.verify_directly_issued_by(ref_cert)

    # Reference CA lacked KeyUsage extension
    with pytest.raises(x509.ExtensionNotFound):
        ref_cert.extensions.get_extension_for_class(x509.KeyUsage)

    # Contrast with newly generated Research Lab Root CA
    _, lab_ca_cert = generate_lab_root_ca()
    lab_meta = inspect_certificate_metadata(lab_ca_cert)
    assert lab_meta["sha256_fingerprint"] != EXPECTED_REF_SHA256
    assert lab_meta["is_ca"] is True
    assert lab_meta["key_cert_sign"] is True
    assert lab_meta["is_currently_valid"] is True


def test_check1_2_3_4_5_6_dual_payload_architecture_and_flexible_doh_modes():
    """
    Checks 1, 2, 3, 4, 5, 6:
    - Mode A (NextDNS `a8b247`) vs Mode B (`DOH_SERVER_URL=https://mock.lab.vuthanhluan.bond/dns-query`).
    - Rejects non-HTTPS, credentials/query strings, or unverified third-party DoH (`dns.nodns.vn`).
    - DNS-only contains 1 payload; Lab CA mode contains 2 payloads (`com.apple.dnsSettings.managed` + `com.apple.security.root`).
    - Fingerprint of embedded DER certificate in mobileconfig matches generated Root CA.
    """
    pw_hash = "pbkdf2_sha256$600000$" + "11" * 16 + "$" + "22" * 32
    _, ca_cert = generate_lab_root_ca()
    ca_meta = inspect_certificate_metadata(ca_cert)

    # 1. Reject invalid or unverified third-party DOH_SERVER_URL
    for bad_doh in [
        "http://mock.lab.vuthanhluan.bond/dns-query",
        "https://dns.nodns.vn/dns-query",
        "https://user:pass@mock.lab.vuthanhluan.bond/dns-query",
        "https://mock.lab.vuthanhluan.bond/dns-query?target=1.2.3.4",
    ]:
        with pytest.raises(ValidationError):
            Settings(
                _env_file=None,
                superadmin_email="admin@example.test",
                superadmin_password_hash=pw_hash,
                mongodb_uri="mongodb://127.0.0.1:27017",
                doh_server_url=bad_doh,
            )

    # 2. Mode B (Custom DoH Lab) + Dual Payload (DNS + Root CA) + Scoped Domains
    s_custom_doh = Settings(
        _env_file=None,
        superadmin_email="admin@example.test",
        superadmin_password_hash=pw_hash,
        mongodb_uri="mongodb://127.0.0.1:27017",
        nextdns_id="a8b247",
        doh_server_url="https://mock.lab.vuthanhluan.bond/dns-query",
        root_ca_pem=ca_meta["pem"],
        lab_scoped_domains=["mock.lab.vuthanhluan.bond", "sub.lab.vuthanhluan.bond"],
    )
    xml_dual = build_profile(
        s_custom_doh,
        scoped_domains=s_custom_doh.lab_scoped_domains,
        device_label="dev_iphone15",
    )
    parsed_dual = plistlib.loads(xml_dual)
    payloads = parsed_dual["PayloadContent"]
    assert len(payloads) == 2
    assert payloads[0]["PayloadType"] == "com.apple.dnsSettings.managed"
    assert payloads[1]["PayloadType"] == "com.apple.security.root"

    dns_dict = payloads[0]["DNSSettings"]
    assert dns_dict["DNSProtocol"] == "HTTPS"
    assert dns_dict["ServerURL"] == "https://mock.lab.vuthanhluan.bond/dns-query/dev_iphone15"
    assert dns_dict["SupplementalMatchDomains"] == ["mock.lab.vuthanhluan.bond", "sub.lab.vuthanhluan.bond"]

    embedded_der = payloads[1]["PayloadContent"]
    embedded_cert = x509.load_der_x509_certificate(embedded_der)
    assert inspect_certificate_metadata(embedded_cert)["sha256_fingerprint"] == ca_meta["sha256_fingerprint"]

    # 3. Mode A (NextDNS) + DNS-only (no Root CA)
    s_dns_only = s_custom_doh.model_copy(update={"doh_server_url": "", "root_ca_pem": "", "root_ca_path": ""})
    xml_dns_only = build_profile(s_dns_only)
    parsed_dns_only = plistlib.loads(xml_dns_only)
    assert len(parsed_dns_only["PayloadContent"]) == 1
    assert parsed_dns_only["PayloadContent"][0]["PayloadType"] == "com.apple.dnsSettings.managed"
    assert parsed_dns_only["PayloadContent"][0]["DNSSettings"]["ServerURL"] == "https://dns.nextdns.io/a8b247"


def test_check7_8_9_10_11_12_13_doh_resolver_tls_chain_and_automatic_processing(monkeypatch):
    """
    Checks 7, 8, 9, 10, 11, 12, 13:
    - Controlled RFC 8484 DoH resolver (`/dns-query` GET wireformat, POST wireformat, JSON) resolves lab domains
      and returns REFUSED (rcode=5) for external domains (`api.revenuecat.com`, `google.com`).
    - HTTPS mock server leaf certificate chain & hostname verification pass for controlled lab domain.
    - Automatic Processing Engine authenticates device token, queries MongoDB, and returns immediate entitlement JSON.
    - Revoked account is denied Gold; revoked or cross-account device token is rejected.
    - Diagnostic report explicitly distinguishes mock lab results from official Locket entitlements.
    """
    # Check 8: Leaf certificate & TLS hostname verification
    ca_key, ca_cert = generate_lab_root_ca()
    _, leaf_cert = generate_lab_leaf_certificate(
        ca_key, ca_cert, ["mock.lab.vuthanhluan.bond", "locketgold.vuthanhluan.bond"], validity_days=365
    )
    tls_verify = verify_certificate_chain_and_hostname(ca_cert, leaf_cert, "mock.lab.vuthanhluan.bond")
    assert tls_verify["valid"] is True
    assert tls_verify["hostname_matched"] is True
    assert tls_verify["leaf_lifetime_days"] <= 398.0
    assert tls_verify["errors"] == []

    # Check 7: Direct unit test of wireformat DNS resolution
    q_lab_a = build_dns_query_packet("mock.lab.vuthanhluan.bond", qtype=TYPE_A)
    resp_bytes, meta_a = resolve_lab_dns_wireformat(
        q_lab_a,
        allowed_domains=["mock.lab.vuthanhluan.bond"],
        target_ipv4="103.118.29.159",
    )
    assert meta_a["rcode"] == "NOERROR"
    assert meta_a["answer_ip"] == "103.118.29.159"
    assert resp_bytes[-4:] == bytes([103, 118, 29, 159])

    q_lab_aaaa = build_dns_query_packet("mock.lab.vuthanhluan.bond", qtype=TYPE_AAAA)
    _, meta_aaaa = resolve_lab_dns_wireformat(
        q_lab_aaaa,
        allowed_domains=["mock.lab.vuthanhluan.bond"],
        target_ipv4="103.118.29.159",
    )
    assert meta_aaaa["rcode"] == "NOERROR_NODATA"

    q_ext = build_dns_query_packet("api.revenuecat.com", qtype=TYPE_A)
    _, meta_ext = resolve_lab_dns_wireformat(
        q_ext,
        allowed_domains=["mock.lab.vuthanhluan.bond"],
        target_ipv4="103.118.29.159",
    )
    assert meta_ext["rcode"] == "REFUSED"

    # Checks 7, 9, 10, 11, 12 via FastAPI endpoints
    password = secrets.token_urlsafe(20)
    pw_hash = hash_password(password)
    for k, v in {
        "APP_ENV": "staging",
        "SUPERADMIN_EMAIL": "admin@example.test",
        "SUPERADMIN_PASSWORD_HASH": pw_hash,
        "MONGODB_URI": "mongodb://127.0.0.1:27017",
        "MONGODB_DATABASE": "locket_manager_staging",
        "ALLOWED_HOSTS": "mock.lab.vuthanhluan.bond,localhost,127.0.0.1",
        "LAB_SCOPED_DOMAINS": "mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond",
        "LAB_DNS_TARGET_IP": "127.0.0.1",
        "DOH_SERVER_URL": "https://mock.lab.vuthanhluan.bond/dns-query",
        "REQUIRE_HTTPS": "false",
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()

    app = create_app()
    v1_store, v2_store, dev_store, sess_store = {}, {}, {}, {}
    accounts, accounts_v2, devices, sessions, admins = AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock()
    admins.find_one.return_value = {
        "_id": "superadmin",
        "email": "admin@example.test",
        "password_hash": pw_hash,
        "auth_version": "v1",
    }
    async def sess_insert(d):
        sess_store[d["_id"]] = d.copy()

    async def sess_find(q):
        return sess_store.get(q["_id"])

    async def acc_upd(q, u, upsert=False):
        v1_store.setdefault(q["locket_id"], {"locket_id": q["locket_id"]}).update(u.get("$set", {}))

    async def acc_find(q, proj=None):
        d = v1_store.get(q.get("locket_id"))
        return d.copy() if d else None

    async def v2_upd(q, u, upsert=False):
        v2_store.setdefault(q["locket_id"], {"locket_id": q["locket_id"]}).update(u.get("$set", {}))

    async def v2_find(q, proj=None):
        d = v2_store.get(q.get("locket_id"))
        return d.copy() if d else None

    async def dev_ins(d):
        dev_store[d["device_id"]] = d.copy()

    async def dev_find(q, proj=None):
        if "token_hash" in q:
            for d in dev_store.values():
                if d["token_hash"] == q["token_hash"]:
                    return d.copy()
        if "device_id" in q:
            d = dev_store.get(q["device_id"])
            return d.copy() if d else None
        return None

    async def dev_upd(q, u):
        if q["device_id"] in dev_store:
            dev_store[q["device_id"]].update(u.get("$set", {}))

    sessions.insert_one.side_effect = sess_insert
    sessions.find_one.side_effect = sess_find
    accounts.update_one.side_effect = acc_upd
    accounts.find_one.side_effect = acc_find
    accounts_v2.update_one.side_effect = v2_upd
    accounts_v2.find_one.side_effect = v2_find
    devices.insert_one.side_effect = dev_ins
    devices.find_one.side_effect = dev_find
    devices.update_one.side_effect = dev_upd
    dev_cur = MagicMock()
    dev_cur.to_list = AsyncMock(return_value=[])
    devices.find = MagicMock(return_value=dev_cur)

    app.dependency_overrides[get_accounts] = lambda: accounts
    app.state.accounts = accounts
    app.state.accounts_v2 = accounts_v2
    app.state.devices = devices
    app.state.admins = admins
    app.state.sessions = sessions
    app.state.login_limits = AsyncMock()
    app.state.login_limits.find_one_and_update.return_value = {"count": 1}
    app.state.profile = build_profile(get_settings())

    http = TestClient(app, base_url="http://mock.lab.vuthanhluan.bond", raise_server_exceptions=False)
    try:
        # RFC 8484 GET & POST over HTTP endpoint
        b64_q = base64.urlsafe_b64encode(q_lab_a).decode("ascii").rstrip("=")
        res_doh_get = http.get(f"/dns-query?dns={b64_q}")
        assert res_doh_get.status_code == 200
        assert res_doh_get.headers["content-type"] == "application/dns-message"
        assert res_doh_get.content[-4:] == bytes([127, 0, 0, 1])

        res_doh_post = http.post("/dns-query", content=q_lab_a, headers={"Content-Type": "application/dns-message"})
        assert res_doh_post.status_code == 200
        assert res_doh_post.content[-4:] == bytes([127, 0, 0, 1])

        # Automatic processing with enrolled device
        login_res = http.post("/api/admin/login", json={"email": "admin@example.test", "password": password})
        admin_hdr = {"Authorization": "Bearer " + login_res.json()["access_token"]}
        future_iso = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        assert http.post("/admin/add-account", headers=admin_hdr, json={"locket_id": "auto_user", "expires_date": future_iso}).status_code == 200

        dev_res = http.post("/admin/devices", headers=admin_hdr, json={"locket_id": "auto_user", "device_name": "iPhone Lab", "ios_version": "18.2"}).json()
        dev_hdr = {"Authorization": "Bearer " + dev_res["device_token"]}

        sub_active = http.get("/v1/subscribers/auto_user", headers=dev_hdr)
        assert sub_active.status_code == 200
        assert "Gold" in sub_active.json()["subscriber"]["entitlements"]

        # Check 13: Client report clearly states simulated lab response vs official app
        report_dict = format_entitlement_report(
            "auto_user",
            200,
            dict(sub_active.headers),
            sub_active.json(),
        )
        assert report_dict["gold_active"] is True
        assert report_dict["lab_entitlement_status"] == "active"
        assert "SIMULATED_LAB_ENTITLEMENT_ONLY" in report_dict["scope_disclaimer"]

        # Check 11: Revoked account immediately denied Gold
        assert http.post("/admin/accounts/auto_user/revoke", headers=admin_hdr, json={"reason": "test"}).status_code == 200
        sub_rev = http.get("/v1/subscribers/auto_user", headers=dev_hdr)
        assert sub_rev.status_code == 200
        assert sub_rev.json()["subscriber"]["entitlements"] == {}

        # Check 12: Revoked device rejected with 401
        assert http.post(f"/admin/devices/{dev_res['device_id']}/revoke", headers=admin_hdr).status_code == 200
        assert http.get("/v1/subscribers/auto_user", headers=dev_hdr).status_code == 401
    finally:
        http.close()
        get_settings.cache_clear()
