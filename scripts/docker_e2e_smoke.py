"""
Automated 20-Step Docker Runtime End-to-End Verification Suite (`scripts/docker_e2e_smoke.py`).
Hardened for Prompt 10 (P1 TLS Hostname Verification & P1 Safe Docker E2E Isolation):
  - Uses minimal directory permissions (`0755` for public/backups, `0700` for private keys)
    and container UID `10001:10001` ownership inside a dedicated temporary E2E workspace.
  - Uses an isolated Docker Compose project (`locket_e2e_ci`), distinct container names (`locket_e2e_ci_*`),
    and dynamically allocated free loopback ports (`find_free_loopback_port()`).
  - Enforces strict TLS SNI and SAN hostname matching (`check_hostname = True`, `verify_mode = ssl.CERT_REQUIRED`).
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from app.passwords import hash_password
from app.services.pki_service import inspect_certificate_metadata, verify_certificate_chain_and_hostname

ROOT = Path(__file__).resolve().parent.parent


def find_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _LabPinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPSConnection that routes the underlying TCP socket to `127.0.0.1:target_port`
    while preserving the real TLS hostname (`self.host`, e.g. `mock.lab.vuthanhluan.bond`)
    for TLS Server Name Indication (SNI) and `ssl.SSLContext.check_hostname = True` SAN verification.
    """
    def __init__(self, host: str, *, target_ip: str, target_port: int, context: ssl.SSLContext, timeout: float = 10.0):
        super().__init__(host, port=target_port, timeout=timeout, context=context)
        self._target_ip = target_ip
        self._target_port = target_port

    def connect(self):
        raw_sock = socket.create_connection((self._target_ip, self._target_port), self.timeout)
        # Critical: server_hostname=self.host triggers both TLS SNI and RFC 6125 SAN hostname verification!
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)


def https_req_with_strict_sni_and_hostname_verification(
    url: str,
    *,
    target_ip: str,
    target_port: int,
    ca_pem_path: Path,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes, dict]:
    """
    Execute an HTTPS request to `url` (e.g. `https://mock.lab.vuthanhluan.bond/api/health`)
    connecting over TCP to `(target_ip, target_port)` with strict TLS certificate chain,
    SNI, validity, and SAN hostname verification enabled (`check_hostname=True`, `CERT_REQUIRED`).
    Returns `(status_code, response_headers_dict, response_body_bytes, peer_tls_info)`.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Expected https:// URL with hostname, got {url}")

    ssl_ctx = ssl.create_default_context(cafile=str(ca_pem_path))
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    conn = _LabPinnedHTTPSConnection(
        parsed.hostname,
        target_ip=target_ip,
        target_port=target_port,
        context=ssl_ctx,
        timeout=timeout,
    )
    try:
        conn.connect()
        der_peer = conn.sock.getpeercert(binary_form=True)
        peer_cert = x509.load_der_x509_certificate(der_peer)
        ca_cert = x509.load_pem_x509_certificate(ca_pem_path.read_bytes())
        chain_check = verify_certificate_chain_and_hostname(ca_cert, peer_cert, parsed.hostname)

        path_with_query = parsed.path or "/"
        if parsed.query:
            path_with_query += f"?{parsed.query}"

        hdrs = dict(headers or {})
        hdrs.setdefault("Host", parsed.hostname)
        body_bytes = None
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"

        conn.request(method, path_with_query, body=body_bytes, headers=hdrs)
        resp = conn.getresponse()
        resp_body = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, resp_body, chain_check
    finally:
        conn.close()


def run_cmd(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=capture, check=check)


def http_req(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def wait_for_container_healthy(container_name: str, timeout_sec: int = 90) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        res = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_name],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        status = res.stdout.strip()
        if status == "healthy":
            print(f"  [OK] Container {container_name} is healthy.", flush=True)
            return
        time.sleep(2)
    logs = subprocess.run(["docker", "logs", container_name], cwd=ROOT, text=True, capture_output=True)
    raise RuntimeError(f"Container {container_name} did not become healthy in {timeout_sec}s:\n{logs.stdout}\n{logs.stderr}")


def main() -> int:
    # Create an isolated temporary workspace for E2E volumes so we never collide with live staging or use 0777
    e2e_temp_root = Path(tempfile.mkdtemp(prefix="locket_e2e_vol_"))
    backups_dir = e2e_temp_root / "backups"
    certs_pub_dir = e2e_temp_root / "certs_public"
    certs_priv_dir = e2e_temp_root / "certs_private"
    backups_dir.mkdir(parents=True, exist_ok=True)
    certs_pub_dir.mkdir(parents=True, exist_ok=True)
    certs_priv_dir.mkdir(parents=True, exist_ok=True)

    # Set least-privilege permissions (0755 for public/backups, 0700 for private keys — NEVER 0777!)
    try:
        os.chmod(e2e_temp_root, 0o755)
        os.chmod(backups_dir, 0o755)
        os.chmod(certs_pub_dir, 0o755)
        os.chmod(certs_priv_dir, 0o700)
    except OSError:
        pass

    http_port = find_free_loopback_port()
    https_port = find_free_loopback_port()
    http_lab_port = find_free_loopback_port()
    base_http = f"http://127.0.0.1:{http_port}"

    admin_email = "staging-e2e@example.test"
    admin_password = secrets.token_urlsafe(24) if "secrets" in sys.modules else "StagingE2ePassword!2026"
    admin_hash = hash_password(admin_password)

    env_staging_path = e2e_temp_root / ".env.e2e"
    compose_e2e_file = e2e_temp_root / "compose.e2e.isolated.yaml"

    env_staging_path.write_text(
        f"""APP_ENV=staging
MONGODB_URI=mongodb://mongo_e2e:27017
MONGODB_DATABASE=locket_manager_staging
NEXTDNS_ID=a8b247
DOH_SERVER_URL=https://mock.lab.vuthanhluan.bond/dns-query
LAB_MODE=local
LAB_DNS_TARGET_IP=127.0.0.1
ROOT_CA_PATH=/app/certs_public/lab_root_ca.pem
ROOT_CA_PEM=
SUPERADMIN_EMAIL={admin_email}
SUPERADMIN_PASSWORD_HASH={admin_hash}
ADMIN_PATH=/admin
ALLOWED_HOSTS=["locketgold.vuthanhluan.bond","mock.lab.vuthanhluan.bond","sub.lab.vuthanhluan.bond","localhost","127.0.0.1","[::1]"]
LAB_DOMAIN=locketgold.vuthanhluan.bond
LAB_SCOPED_DOMAINS=["mock.lab.vuthanhluan.bond","sub.lab.vuthanhluan.bond","locketgold.vuthanhluan.bond"]
REQUIRE_HTTPS=false
TRUSTED_PROXY_CIDRS=["172.16.0.0/12","127.0.0.1/32"]
ENABLE_RESEARCH_PROXY=false
""",
        encoding="utf-8",
    )

    compose_e2e_file.write_text(
        f"""services:
  mongo_e2e:
    image: mongo:7.0
    container_name: locket_e2e_ci_mongo
    command: ["mongod", "--quiet", "--logpath", "/dev/null"]
    healthcheck:
      test: ["CMD", "mongosh", "--quiet", "--eval", "db.adminCommand('ping').ok"]
      interval: 5s
      timeout: 5s
      retries: 10

  chown_init:
    image: alpine:3.20
    container_name: locket_e2e_ci_chown
    user: "0:0"
    volumes:
      - {backups_dir.as_posix()}:/mnt/backups
      - {certs_pub_dir.as_posix()}:/mnt/certs_public
      - {certs_priv_dir.as_posix()}:/mnt/certs_private
    command: ["sh", "-c", "chown -R 10001:10001 /mnt/backups /mnt/certs_public /mnt/certs_private && chmod 0755 /mnt/backups /mnt/certs_public && chmod 0750 /mnt/certs_private"]

  ca_init:
    build:
      context: {ROOT.as_posix()}
    container_name: locket_e2e_ci_ca_init
    user: "10001:10001"
    volumes:
      - {certs_pub_dir.as_posix()}:/app/certs_public
      - {certs_priv_dir.as_posix()}:/app/certs_private
    command:
      - python
      - -m
      - scripts.generate_lab_ca
      - --out-public
      - /app/certs_public
      - --out-private
      - /app/certs_private
      - --domains
      - locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond

  api:
    build:
      context: {ROOT.as_posix()}
    container_name: locket_e2e_ci_api
    env_file:
      - {env_staging_path.as_posix()}
    environment:
      - APP_ENV=staging
    ports:
      - "127.0.0.1:{http_port}:8000"
    volumes:
      - {backups_dir.as_posix()}:/app/backups
      - {certs_pub_dir.as_posix()}:/app/certs_public:ro
    depends_on:
      - mongo_e2e
    mem_limit: 256m
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=3)"]
      interval: 5s
      timeout: 5s
      retries: 10

  lab_https:
    image: caddy:2-alpine
    container_name: locket_e2e_ci_lab_https
    ports:
      - "127.0.0.1:{https_port}:8443"
      - "127.0.0.1:{http_lab_port}:8081"
    volumes:
      - {(ROOT / 'Caddyfile.lab').as_posix()}:/etc/caddy/Caddyfile:ro
      - {certs_priv_dir.as_posix()}:/etc/caddy/certs:ro
      - e2e_ci_caddy_data:/data
      - e2e_ci_caddy_config:/config
    depends_on:
      - api
    mem_limit: 64m

volumes:
  e2e_ci_caddy_data:
  e2e_ci_caddy_config:
""",
        encoding="utf-8",
    )

    compose_base = [
        "docker", "compose",
        "-p", "locket_e2e_ci",
        "-f", str(compose_e2e_file),
    ]

    try:
        print("=== [PRE-STEP] Setting UID 10001 volume ownership (no 0777) & generating Lab Root CA ===", flush=True)
        run_cmd(compose_base + ["build", "api", "ca_init"])
        run_cmd(compose_base + ["run", "--rm", "chown_init"])
        run_cmd(compose_base + ["run", "--rm", "ca_init"])

        ca_pem_file = certs_pub_dir / "lab_root_ca.pem"
        assert ca_pem_file.is_file(), "Public Root CA PEM not created on host!"
        assert (certs_priv_dir / "lab_leaf.key").is_file(), "Private Leaf Key not created on host!"
        ca_cert = x509.load_pem_x509_certificate(ca_pem_file.read_bytes())
        expected_ca_fp = inspect_certificate_metadata(ca_cert)["sha256_fingerprint"]

        print("=== [SCENARIO 1 & 2] Starting isolated MongoDB + API + HTTPS Lab containers & awaiting healthy ===", flush=True)
        run_cmd(compose_base + ["up", "-d", "mongo_e2e", "api", "lab_https"])
        wait_for_container_healthy("locket_e2e_ci_mongo", timeout_sec=60)
        wait_for_container_healthy("locket_e2e_ci_api", timeout_sec=60)

        print("=== [SCENARIO 3 & 4] Verifying /api/health and /api/ready ===", flush=True)
        st, _, body = http_req(f"{base_http}/api/health")
        assert st == 200, f"/api/health returned {st}: {body}"
        health_json = json.loads(body)
        assert health_json["database"] == "locket_manager_staging"
        assert health_json["nextdns_id"] == "a8b247"
        assert health_json["root_ca_loaded"] is True
        assert health_json["root_ca_sha256"] == expected_ca_fp

        st, _, body = http_req(f"{base_http}/api/ready")
        assert st == 200, f"/api/ready returned {st}: {body}"
        ready_json = json.loads(body)
        assert ready_json["status"] == "ready" and ready_json["mongodb_connected"] is True

        print("=== [SCENARIO 5] Verifying Admin login ===", flush=True)
        st, _, body = http_req(
            f"{base_http}/api/admin/login",
            method="POST",
            json_body={"email": admin_email, "password": admin_password},
        )
        assert st == 200, f"Admin login failed ({st}): {body}"
        admin_token = json.loads(body)["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        print("=== [SCENARIO 6] Adding test accounts ===", flush=True)
        future_exp = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        for uid in ("e2e_user_1", "e2e_user_2"):
            st, _, body = http_req(
                f"{base_http}/admin/add-account",
                method="POST",
                headers=admin_headers,
                json_body={
                    "locket_id": uid,
                    "username": uid,
                    "expires_date": future_exp,
                    "max_devices": 1,
                },
            )
            assert st == 200, f"Add account {uid} failed ({st}): {body}"

        print("=== [SCENARIO 7 & 8] Verifying Account Lookup by username and Locket link ===", flush=True)
        st, _, body = http_req(f"{base_http}/api/accounts/lookup?query=e2e_user_1")
        assert st == 200 and json.loads(body) == {"exists": True}

        link_q = urllib.parse.quote("https://locket.cam/e2e_user_1", safe="")
        st, _, body = http_req(f"{base_http}/api/accounts/lookup?query={link_q}")
        assert st == 200 and json.loads(body) == {"exists": True}

        st, _, body = http_req(f"{base_http}/admin/accounts/lookup?query={link_q}", headers=admin_headers)
        assert st == 200
        adm_lookup = json.loads(body)
        assert adm_lookup["exists"] is True
        assert adm_lookup["internal_identifier"] == "e2e_user_1"
        assert adm_lookup["verification_status"] == "unverified_handle"

        print("=== [SCENARIO 9] Verifying data persistence directly in MongoDB ===", flush=True)
        db_check = run_cmd([
            "docker", "exec", "locket_e2e_ci_api",
            "python", "-c",
            "import asyncio; from pymongo import AsyncMongoClient; "
            "async def chk():\n"
            "  c = AsyncMongoClient('mongodb://mongo_e2e:27017'); db = c['locket_manager_staging']\n"
            "  d2 = await db.accounts_v2.find_one({'locket_id': 'e2e_user_1'})\n"
            "  d1 = await db.accounts.find_one({'locket_id': 'e2e_user_1'})\n"
            "  assert d2 is not None and d1 is not None\n"
            "  await c.close()\n"
            "asyncio.run(chk())"
        ])
        assert db_check.returncode == 0

        print("=== [SCENARIO 10, 11 & 12] Enrolling device, testing cross-account 403, concurrent requests & active entitlement ===", flush=True)
        st, _, body = http_req(
            f"{base_http}/admin/devices",
            method="POST",
            headers=admin_headers,
            json_body={"locket_id": "e2e_user_1", "device_name": "iPhone E2E", "ios_version": "18.2"},
        )
        assert st == 200, f"Device enroll failed ({st}): {body}"
        dev_info = json.loads(body)
        dev_token = dev_info["device_token"]
        dev_id = dev_info["device_id"]
        dev_headers = {"Authorization": f"Bearer {dev_token}"}

        # Cross-account access (Scenario 11) -> MUST return 403
        st_cross, _, _ = http_req(f"{base_http}/v1/subscribers/e2e_user_2", headers=dev_headers)
        assert st_cross == 403, f"Expected 403 on cross-account access, got {st_cross}"

        # Concurrent automatic entitlement processing (8 concurrent requests)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(http_req, f"{base_http}/v1/subscribers/e2e_user_1", headers=dev_headers)
                for _ in range(8)
            ]
            for fut in futures:
                st_c, hdrs_c, body_c = fut.result()
                assert st_c == 200
                assert hdrs_c.get("x-lab-entitlement-status") == "active"
                assert "Gold" in json.loads(body_c)["subscriber"]["entitlements"]

        print("=== [SCENARIO 13, 14 & 15] Revoking account & revoking device token ===", flush=True)
        st_rev, _, _ = http_req(
            f"{base_http}/admin/accounts/e2e_user_1/revoke",
            method="POST",
            headers=admin_headers,
            json_body={"reason": "E2E revocation test"},
        )
        assert st_rev == 200

        st_after, hdrs_after, body_after = http_req(f"{base_http}/v1/subscribers/e2e_user_1", headers=dev_headers)
        assert st_after == 200
        assert hdrs_after.get("x-lab-entitlement-status") == "revoked"
        assert json.loads(body_after)["subscriber"]["entitlements"] == {}

        # Revoke device token (Scenario 15) -> 401
        st_dev_rev, _, _ = http_req(
            f"{base_http}/admin/devices/{dev_id}/revoke",
            method="POST",
            headers=admin_headers,
        )
        assert st_dev_rev == 200
        st_unauth, _, _ = http_req(f"{base_http}/v1/subscribers/e2e_user_1", headers=dev_headers)
        assert st_unauth == 401

        print("=== [SCENARIO 16] Verifying Mobileconfig modes & STRICT TLS SNI/Hostname Verification against Caddy Lab ===", flush=True)
        # 16a. dns_only
        st_dns, hdrs_dns, body_dns = http_req(f"{base_http}/profile.mobileconfig?mode=dns_only")
        assert st_dns == 200
        assert "application/x-apple-aspen-config" in hdrs_dns.get("content-type", "")
        assert "locket.mobileconfig" in hdrs_dns.get("content-disposition", "")
        plist_dns = plistlib.loads(body_dns)
        assert [p["PayloadType"] for p in plist_dns["PayloadContent"]] == ["com.apple.dnsSettings.managed"]
        assert plist_dns["PayloadContent"][0]["DNSSettings"]["ServerURL"] == "https://mock.lab.vuthanhluan.bond/dns-query"

        # 16b. lab_ca & scoped_lab
        for mode in ("lab_ca", "scoped_lab"):
            st_m, _, body_m = http_req(f"{base_http}/profile.mobileconfig?mode={mode}")
            assert st_m == 200
            pl_m = plistlib.loads(body_m)
            assert [p["PayloadType"] for p in pl_m["PayloadContent"]] == [
                "com.apple.dnsSettings.managed",
                "com.apple.security.root",
            ]
            assert "mock.lab.vuthanhluan.bond" in pl_m["PayloadContent"][0]["DNSSettings"]["SupplementalMatchDomains"]
            der_cert = x509.load_der_x509_certificate(pl_m["PayloadContent"][1]["PayloadContent"])
            assert inspect_certificate_metadata(der_cert)["sha256_fingerprint"] == expected_ca_fp

        # 16c. Strict TLS SNI & SAN Hostname Verification (`check_hostname=True`, `CERT_REQUIRED`) over Caddy Lab
        for valid_host in ("mock.lab.vuthanhluan.bond", "sub.lab.vuthanhluan.bond", "locketgold.vuthanhluan.bond"):
            st_tls, _, body_tls, tls_meta = https_req_with_strict_sni_and_hostname_verification(
                f"https://{valid_host}/api/health",
                target_ip="127.0.0.1",
                target_port=https_port,
                ca_pem_path=ca_pem_file,
            )
            assert st_tls == 200 and json.loads(body_tls)["status"] == "ok"
            assert tls_meta["valid"] is True and tls_meta["hostname_matched"] is True

        # Prove that an unlisted hostname FAILS strict TLS SAN hostname verification
        rejected_wrong_host = False
        try:
            https_req_with_strict_sni_and_hostname_verification(
                "https://unlisted.lab.vuthanhluan.bond/api/health",
                target_ip="127.0.0.1",
                target_port=https_port,
                ca_pem_path=ca_pem_file,
            )
        except ssl.SSLError:
            rejected_wrong_host = True
        assert rejected_wrong_host is True, "Strict TLS hostname check MUST reject hostname not in Leaf SAN!"

        # 16d. Verify Controlled RFC 8484 DoH Lab endpoint over strict HTTPS Caddy Lab
        st_doh_ok, _, body_doh_ok, _ = https_req_with_strict_sni_and_hostname_verification(
            "https://mock.lab.vuthanhluan.bond/dns-query?name=mock.lab.vuthanhluan.bond&type=A",
            target_ip="127.0.0.1",
            target_port=https_port,
            ca_pem_path=ca_pem_file,
        )
        assert st_doh_ok == 200
        doh_ok_json = json.loads(body_doh_ok)
        assert doh_ok_json["Status"] == 0 and len(doh_ok_json["Answer"]) == 1

        st_doh_ref, _, body_doh_ref, _ = https_req_with_strict_sni_and_hostname_verification(
            "https://mock.lab.vuthanhluan.bond/dns-query?name=api.revenuecat.com&type=A",
            target_ip="127.0.0.1",
            target_port=https_port,
            ca_pem_path=ca_pem_file,
        )
        assert st_doh_ref == 200
        assert json.loads(body_doh_ref)["Status"] == 5  # REFUSED

        print("=== [SCENARIO 17] Simulating MongoDB outage & verifying HTTP 503 fail-closed ===", flush=True)
        run_cmd(["docker", "pause", "locket_e2e_ci_mongo"])
        try:
            st_outage, _, _ = http_req(f"{base_http}/api/ready", timeout=8.0)
            assert st_outage == 503, f"Expected 503 during DB outage, got {st_outage}"
        finally:
            run_cmd(["docker", "unpause", "locket_e2e_ci_mongo"])
        st_rec, _, _ = http_req(f"{base_http}/api/ready", timeout=8.0)
        assert st_rec == 200

        print("=== [SCENARIO 18] Restarting API container & verifying persistence ===", flush=True)
        run_cmd(["docker", "restart", "locket_e2e_ci_api"])
        wait_for_container_healthy("locket_e2e_ci_api", timeout_sec=60)
        st_post_restart, _, body_post_restart = http_req(f"{base_http}/api/accounts/lookup?query=e2e_user_2")
        assert st_post_restart == 200 and json.loads(body_post_restart) == {"exists": True}

        print("=== [SCENARIO 19] Verifying persistent host backup & collection rollback ===", flush=True)
        host_backup_file = backups_dir / "e2e_staging_snapshot.json"
        run_cmd(compose_base + [
            "run", "--rm", "api",
            "python", "-m", "scripts.migrate_db",
            "--backup", "/app/backups/e2e_staging_snapshot.json",
            "--dry-run",
        ])
        assert host_backup_file.is_file() and host_backup_file.stat().st_size > 0, "Backup file missing on host after --rm container!"
        run_cmd(compose_base + [
            "run", "--rm", "api",
            "python", "-m", "scripts.migrate_db",
            "--verify-backup", "/app/backups/e2e_staging_snapshot.json",
        ])

        st_del, _, _ = http_req(f"{base_http}/admin/accounts/e2e_user_2", method="DELETE", headers=admin_headers)
        assert st_del == 204
        run_cmd(compose_base + [
            "run", "--rm", "api",
            "python", "-m", "scripts.migrate_db",
            "--rollback", "/app/backups/e2e_staging_snapshot.json",
            "--mode", "partial",
        ])
        st_restored, _, body_restored = http_req(f"{base_http}/api/accounts/lookup?query=e2e_user_2")
        assert st_restored == 200 and json.loads(body_restored) == {"exists": True}

        print("=== [ALL 20 DOCKER E2E SCENARIOS PASSED WITH STRICT TLS HOSTNAME VERIFICATION] ===", flush=True)
        return 0
    finally:
        print("=== [SCENARIO 20] Cleaning up isolated E2E test containers & temporary workspace ===", flush=True)
        subprocess.run(
            compose_base + ["down", "-v"],
            cwd=ROOT,
            check=False,
        )
        shutil.rmtree(e2e_temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
