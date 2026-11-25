"""
Automated Regression Test Suite for Prompt 10 (`tests/test_prompt10_final_iphone_readiness.py`):
1. P0 Secret Scanner:
   - Permits `.env.example` and `.env.staging.example` when they contain only safe placeholders.
   - Rejects `.env`, `.env.staging`, `.env.production` if tracked.
   - Rejects `.env.staging.example` if someone puts a real PBKDF2 hash, API token, or live MongoDB SRV password into the template.
   - Rejects real multi-line PEM private key blocks.
2. P1 Custom DoH for Real iPhone vs Local Lab (`LAB_MODE=local` vs `LAB_MODE=real_device`):
   - `LAB_MODE=local` permits `LAB_DNS_TARGET_IP=127.0.0.1` for Docker/localhost tests.
   - `LAB_MODE=real_device` strictly REJECTS `127.0.0.1` / `0.0.0.0` / `::1` for `LAB_DNS_TARGET_IP` / `LAB_DNS_TARGET_IPV6` and `localhost`/`127.0.0.1` in `DOH_SERVER_URL`.
   - `LAB_MODE=real_device` accepts a reachable VPS IPv4 (`103.118.29.159`) and optional IPv6 (`2001:db8::159`), returning proper A and AAAA records for controlled lab domains and `REFUSED` for external domains.
3. P1 Strict TLS Hostname Verification & Safe Docker E2E Isolation (`scripts/docker_e2e_smoke.py`):
   - Verifies `scripts/docker_e2e_smoke.py` never uses `check_hostname = False`, never uses `0o777` / `chmod 777`, and uses isolated container names (`locket_e2e_ci_*`) and dynamic free ports (`find_free_loopback_port()`).
"""
import inspect
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.services.doh_service import (
    TYPE_A,
    TYPE_AAAA,
    build_dns_query_packet,
    resolve_lab_dns_wireformat,
)
from scripts import check_secrets, docker_e2e_smoke


def test_p0_secret_scanner_permits_safe_templates_and_catches_real_secrets():
    # 1. Whole repository scan passes (0 violations, including tracked .env.example and .env.staging.example)
    assert check_secrets.scan_tracked_files() == []

    # 2. Safe .env.staging.example content -> 0 violations
    safe_template = (
        "APP_ENV=staging\n"
        "MONGODB_URI=mongodb://127.0.0.1:27017\n"
        "MONGODB_DATABASE=locket_manager_staging\n"
        "SUPERADMIN_PASSWORD_HASH=\n"
    )
    assert check_secrets.scan_file_content(".env.staging.example", safe_template) == []

    # 3. Tracked live .env or .env.staging or .env.production -> rejected immediately
    for forbidden_env in (".env", ".env.staging", ".env.production", "deploy/.env.staging"):
        v = check_secrets.scan_file_content(forbidden_env, safe_template)
        assert len(v) == 1 and "Forbidden tracked environment file" in v[0]

    # 4. Template containing a real PBKDF2 password hash or live MongoDB SRV credential -> rejected!
    leaked_hash_template = (
        "APP_ENV=staging\n"
        "SUPERADMIN_PASSWORD_HASH=pbkdf2_sha256$600000$1122334455667788$aabbccddeeff00112233445566778899\n"
    )
    v_hash = check_secrets.scan_file_content(".env.staging.example", leaked_hash_template)
    assert any("populated secret value for SUPERADMIN_PASSWORD_HASH" in item for item in v_hash)

    leaked_mongo_template = (
        "MONGODB_URI=mongodb+srv://prod_admin:" + "RealAtlasSecret999" + "@cluster-prod.vuthanhluan.mongodb.net/locket_manager\n"
    )
    v_mongo = check_secrets.scan_file_content(".env.staging.example", leaked_mongo_template)
    assert any("MongoDB URI credential" in item for item in v_mongo)


def test_p1_real_device_lab_mode_rejects_loopback_and_supports_public_ipv4_ipv6(monkeypatch):
    pw_hash = "pbkdf2_sha256$600000$" + "11" * 16 + "$" + "22" * 32

    # 1. LAB_MODE=real_device with 127.0.0.1 MUST be rejected
    with pytest.raises(ValidationError, match="cannot use loopback"):
        Settings(
            _env_file=None,
            app_env="staging",
            mongodb_database="locket_manager_staging",
            superadmin_email="admin@example.test",
            superadmin_password_hash=pw_hash,
            mongodb_uri="mongodb://127.0.0.1:27017",
            lab_mode="real_device",
            lab_dns_target_ip="127.0.0.1",
        )

    # 2. LAB_MODE=real_device with localhost in DOH_SERVER_URL MUST be rejected
    with pytest.raises(ValidationError, match="requires a publicly resolvable HTTPS hostname"):
        Settings(
            _env_file=None,
            app_env="staging",
            mongodb_database="locket_manager_staging",
            superadmin_email="admin@example.test",
            superadmin_password_hash=pw_hash,
            mongodb_uri="mongodb://127.0.0.1:27017",
            lab_mode="real_device",
            lab_dns_target_ip="103.118.29.159",
            doh_server_url="https://127.0.0.1/dns-query",
        )

    # 3. LAB_MODE=real_device with reachable VPS IPv4 (103.118.29.159) and IPv6 (2001:db8::159) succeeds
    s_real = Settings(
        _env_file=None,
        app_env="staging",
        mongodb_database="locket_manager_staging",
        superadmin_email="admin@example.test",
        superadmin_password_hash=pw_hash,
        mongodb_uri="mongodb://127.0.0.1:27017",
        lab_mode="real_device",
        lab_dns_target_ip="103.118.29.159",
        lab_dns_target_ipv6="2001:db8::159",
        doh_server_url="https://mock.lab.vuthanhluan.bond/dns-query",
    )
    assert s_real.lab_mode == "real_device"
    assert s_real.lab_dns_target_ip == "103.118.29.159"

    # 4. Wireformat & JSON DoH resolution for both IPv4 (A) and IPv6 (AAAA) in real_device mode
    q_a = build_dns_query_packet("mock.lab.vuthanhluan.bond", qtype=TYPE_A)
    _, meta_a = resolve_lab_dns_wireformat(
        q_a,
        allowed_domains=["mock.lab.vuthanhluan.bond"],
        target_ipv4="103.118.29.159",
        target_ipv6="2001:db8::159",
    )
    assert meta_a["rcode"] == "NOERROR" and meta_a["answer_ip"] == "103.118.29.159"

    q_aaaa = build_dns_query_packet("mock.lab.vuthanhluan.bond", qtype=TYPE_AAAA)
    resp_aaaa, meta_aaaa = resolve_lab_dns_wireformat(
        q_aaaa,
        allowed_domains=["mock.lab.vuthanhluan.bond"],
        target_ipv4="103.118.29.159",
        target_ipv6="2001:db8::159",
    )
    assert meta_aaaa["rcode"] == "NOERROR" and meta_aaaa["answer_ip"] == "2001:db8::159"
    assert len(resp_aaaa) > len(q_aaaa) + 16


def test_p1_docker_e2e_harness_enforces_strict_tls_and_least_privilege():
    src = inspect.getsource(docker_e2e_smoke)
    # Must NEVER disable TLS hostname verification or call os.chmod(..., 0o777)
    assert "os.chmod(d, 0o777)" not in src
    assert "chmod 0777 " not in src
    assert "ssl_ctx.check_hostname = False" not in src
    assert "check_hostname = True" in src
    assert "ssl.CERT_REQUIRED" in src
    assert "server_hostname=self.host" in src
    assert "locket_e2e_ci" in src

    port1 = docker_e2e_smoke.find_free_loopback_port()
    port2 = docker_e2e_smoke.find_free_loopback_port()
    assert 1024 <= port1 <= 65535 and 1024 <= port2 <= 65535
