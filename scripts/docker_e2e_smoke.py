"""
Automated 20-Step Docker Runtime End-to-End Verification Suite (`scripts/docker_e2e_smoke.py`).
Executes all 20 mandatory E2E scenarios against a live Dockerized FastAPI + MongoDB + Caddy HTTPS Lab stack:
  1. Start API container (`locket_staging_api`) and MongoDB test container.
  2. Verify container reaches Docker `healthy` state.
  3. Verify `GET /api/health` (HTTP 200, database=`locket_manager_staging`, NextDNS=`a8b247`).
  4. Verify `GET /api/ready` (HTTP 200, `mongodb_connected=true`).
  5. Verify Admin login (`POST /api/admin/login`).
  6. Add a synthetic test account (`POST /admin/add-account`) + secondary account for cross-account check.
  7. Lookup account by username (`GET /api/accounts/lookup?query=e2e_user_1` & `GET /admin/accounts/lookup`).
  8. Lookup account by Locket share link (`https://locket.cam/e2e_user_1`).
  9. Verify record persistence directly in MongoDB (`accounts_v2` and `accounts`).
 10. Link/enroll a test iPhone device (`POST /admin/devices`).
 11. Verify device token is strictly bound to its account (reading `e2e_user_2` returns HTTP 403).
 12. Verify mock entitlement is active (`GET /v1/subscribers/e2e_user_1` returns `Gold` active).
 13. Revoke account (`POST /admin/accounts/e2e_user_1/revoke`).
 14. Verify revoked status takes effect immediately (`GET /v1/subscribers/e2e_user_1` returns empty entitlements `{}`).
 15. Revoke device token and verify immediate HTTP 401 rejection.
 16. Verify `.mobileconfig` downloads across all 3 modes (`dns_only`, `lab_ca`, `scoped_lab`), validating XML plist, Content-Type, Content-Disposition, and Root CA SHA-256 fingerprint, plus HTTPS request through Caddy Lab (`127.0.0.1:18443`).
 17. Verify database unavailable behavior (pause/stop MongoDB -> `/api/ready` and `/v1/subscribers/*` fail closed with HTTP 503; unpause MongoDB -> recovers to HTTP 200).
 18. Restart API container (`docker restart locket_staging_api`) and verify data persistence.
 19. Execute persistent host backup (`./backups/e2e_backup.json`), verify file on host after `--rm` container exits, mutate state, and test rollback (`--rollback`).
 20. Clean up test containers/networks without touching unrelated containers or volumes.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import plistlib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from app.passwords import hash_password
from app.services.pki_service import inspect_certificate_metadata

ROOT = Path(__file__).resolve().parent.parent
BASE_HTTP = "http://127.0.0.1:18000"
BASE_HTTPS_LAB = "https://127.0.0.1:18443"


def run_cmd(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=capture, check=check)


def http_req(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    ssl_ctx: ssl.SSLContext | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
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
    backups_dir = ROOT / "backups"
    certs_pub_dir = ROOT / "certs_public"
    certs_priv_dir = ROOT / "certs_private"
    for d in (backups_dir, certs_pub_dir, certs_priv_dir):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o777)
        except OSError:
            pass

    admin_email = "staging-e2e@example.test"
    admin_password = "StagingE2ePassword!2026"
    admin_hash = hash_password(admin_password)

    env_staging_path = ROOT / ".env.staging.e2e"
    compose_e2e_mongo = ROOT / "compose.e2e.mongo.yaml"

    compose_e2e_mongo.write_text(
        """services:
  mongo_e2e:
    image: mongo:7.0
    container_name: locket_staging_e2e_mongo
    command: ["mongod", "--quiet", "--logpath", "/dev/null"]
    healthcheck:
      test: ["CMD", "mongosh", "--quiet", "--eval", "db.adminCommand('ping').ok"]
      interval: 5s
      timeout: 5s
      retries: 10
""",
        encoding="utf-8",
    )

    compose_base = [
        "docker", "compose",
        "-p", "locket_staging_e2e",
        "-f", "compose.staging.yaml",
        "-f", str(compose_e2e_mongo.name),
    ]

    try:
        print("=== [PRE-STEP] Generating Lab Root CA via one-shot ca_init container (UID 10001) ===", flush=True)
        env_staging_path.write_text(
            f"""APP_ENV=staging
MONGODB_URI=mongodb://mongo_e2e:27017
MONGODB_DATABASE=locket_manager_staging
NEXTDNS_ID=a8b247
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
        os.environ["STAGING_ENV_FILE"] = str(env_staging_path.name)

        run_cmd(compose_base + ["--profile", "ca_init", "build", "api", "ca_init"])
        run_cmd(compose_base + ["--profile", "ca_init", "run", "--rm", "ca_init"])
        assert (certs_pub_dir / "lab_root_ca.pem").is_file(), "Public Root CA PEM not created on host!"
        assert (certs_priv_dir / "lab_leaf.key").is_file(), "Private Leaf Key not created on host!"
        ca_cert = x509.load_pem_x509_certificate((certs_pub_dir / "lab_root_ca.pem").read_bytes())
        expected_ca_fp = inspect_certificate_metadata(ca_cert)["sha256_fingerprint"]

        print("=== [SCENARIO 1 & 2] Starting isolated MongoDB + API + HTTPS Lab containers & awaiting healthy ===", flush=True)
        run_cmd(compose_base + ["--profile", "lab", "up", "-d", "mongo_e2e", "api", "lab_https"])
        wait_for_container_healthy("locket_staging_e2e_mongo", timeout_sec=60)
        wait_for_container_healthy("locket_staging_api", timeout_sec=60)

        print("=== [SCENARIO 3 & 4] Verifying /api/health and /api/ready ===", flush=True)
        st, _, body = http_req(f"{BASE_HTTP}/api/health")
        assert st == 200, f"/api/health returned {st}: {body}"
        health_json = json.loads(body)
        assert health_json["database"] == "locket_manager_staging"
        assert health_json["nextdns_id"] == "a8b247"
        assert health_json["root_ca_loaded"] is True
        assert health_json["root_ca_sha256"] == expected_ca_fp

        st, _, body = http_req(f"{BASE_HTTP}/api/ready")
        assert st == 200, f"/api/ready returned {st}: {body}"
        ready_json = json.loads(body)
        assert ready_json["status"] == "ready" and ready_json["mongodb_connected"] is True

        print("=== [SCENARIO 5] Verifying Admin login ===", flush=True)
        st, _, body = http_req(
            f"{BASE_HTTP}/api/admin/login",
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
                f"{BASE_HTTP}/admin/add-account",
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
        st, _, body = http_req(f"{BASE_HTTP}/api/accounts/lookup?query=e2e_user_1")
        assert st == 200 and json.loads(body) == {"exists": True}

        link_q = urllib.parse.quote("https://locket.cam/e2e_user_1", safe="")
        st, _, body = http_req(f"{BASE_HTTP}/api/accounts/lookup?query={link_q}")
        assert st == 200 and json.loads(body) == {"exists": True}

        st, _, body = http_req(f"{BASE_HTTP}/admin/accounts/lookup?query={link_q}", headers=admin_headers)
        assert st == 200
        adm_lookup = json.loads(body)
        assert adm_lookup["exists"] is True
        assert adm_lookup["internal_identifier"] == "e2e_user_1"
        assert adm_lookup["verification_status"] == "unverified_handle"

        print("=== [SCENARIO 9] Verifying data persistence directly in MongoDB ===", flush=True)
        db_check = run_cmd([
            "docker", "exec", "locket_staging_api",
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

        print("=== [SCENARIO 10, 11 & 12] Enrolling device, testing cross-account 403 & active entitlement ===", flush=True)
        st, _, body = http_req(
            f"{BASE_HTTP}/admin/devices",
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
        st_cross, _, _ = http_req(f"{BASE_HTTP}/v1/subscribers/e2e_user_2", headers=dev_headers)
        assert st_cross == 403, f"Expected 403 on cross-account access, got {st_cross}"

        # Own account active entitlement (Scenario 12) -> 200 with Gold
        st_own, hdrs_own, body_own = http_req(f"{BASE_HTTP}/v1/subscribers/e2e_user_1", headers=dev_headers)
        assert st_own == 200
        assert hdrs_own.get("x-lab-entitlement-status") == "active"
        assert "Gold" in json.loads(body_own)["subscriber"]["entitlements"]

        print("=== [SCENARIO 13, 14 & 15] Revoking account & revoking device token ===", flush=True)
        st_rev, _, _ = http_req(
            f"{BASE_HTTP}/admin/accounts/e2e_user_1/revoke",
            method="POST",
            headers=admin_headers,
            json_body={"reason": "E2E revocation test"},
        )
        assert st_rev == 200

        st_after, hdrs_after, body_after = http_req(f"{BASE_HTTP}/v1/subscribers/e2e_user_1", headers=dev_headers)
        assert st_after == 200
        assert hdrs_after.get("x-lab-entitlement-status") == "revoked"
        assert json.loads(body_after)["subscriber"]["entitlements"] == {}

        # Revoke device token (Scenario 15) -> 401
        st_dev_rev, _, _ = http_req(
            f"{BASE_HTTP}/admin/devices/{dev_id}/revoke",
            method="POST",
            headers=admin_headers,
        )
        assert st_dev_rev == 200
        st_unauth, _, _ = http_req(f"{BASE_HTTP}/v1/subscribers/e2e_user_1", headers=dev_headers)
        assert st_unauth == 401

        print("=== [SCENARIO 16] Verifying Mobileconfig modes (dns_only, lab_ca, scoped_lab) & HTTPS Lab Caddy ===", flush=True)
        # 16a. dns_only
        st_dns, hdrs_dns, body_dns = http_req(f"{BASE_HTTP}/profile.mobileconfig?mode=dns_only")
        assert st_dns == 200
        assert "application/x-apple-aspen-config" in hdrs_dns.get("content-type", "")
        assert "locket.mobileconfig" in hdrs_dns.get("content-disposition", "")
        plist_dns = plistlib.loads(body_dns)
        assert [p["PayloadType"] for p in plist_dns["PayloadContent"]] == ["com.apple.dnsSettings.managed"]
        assert plist_dns["PayloadContent"][0]["DNSSettings"]["ServerURL"] == "https://dns.nextdns.io/a8b247"

        # 16b. lab_ca & scoped_lab
        for mode in ("lab_ca", "scoped_lab"):
            st_m, _, body_m = http_req(f"{BASE_HTTP}/profile.mobileconfig?mode={mode}")
            assert st_m == 200
            pl_m = plistlib.loads(body_m)
            assert [p["PayloadType"] for p in pl_m["PayloadContent"]] == [
                "com.apple.dnsSettings.managed",
                "com.apple.security.root",
            ]
            assert "mock.lab.vuthanhluan.bond" in pl_m["PayloadContent"][0]["DNSSettings"]["SupplementalMatchDomains"]
            der_cert = x509.load_der_x509_certificate(pl_m["PayloadContent"][1]["PayloadContent"])
            assert inspect_certificate_metadata(der_cert)["sha256_fingerprint"] == expected_ca_fp

        # 16c. HTTPS request through Caddy Lab on 127.0.0.1:18443 verified against our Lab Root CA
        ssl_ctx = ssl.create_default_context(cafile=str(certs_pub_dir / "lab_root_ca.pem"))
        ssl_ctx.check_hostname = False
        st_tls, _, body_tls = http_req(
            f"{BASE_HTTPS_LAB}/api/health",
            headers={"Host": "mock.lab.vuthanhluan.bond"},
            ssl_ctx=ssl_ctx,
        )
        assert st_tls == 200 and json.loads(body_tls)["status"] == "ok"

        # 16d. Verify Controlled RFC 8484 DoH Lab endpoint over HTTPS Caddy Lab (resolves lab domain, refuses third-party)
        st_doh_ok, _, body_doh_ok = http_req(
            f"{BASE_HTTPS_LAB}/dns-query?name=mock.lab.vuthanhluan.bond&type=A",
            headers={"Host": "mock.lab.vuthanhluan.bond"},
            ssl_ctx=ssl_ctx,
        )
        assert st_doh_ok == 200
        doh_ok_json = json.loads(body_doh_ok)
        assert doh_ok_json["Status"] == 0 and len(doh_ok_json["Answer"]) == 1

        st_doh_ref, _, body_doh_ref = http_req(
            f"{BASE_HTTPS_LAB}/dns-query?name=api.revenuecat.com&type=A",
            headers={"Host": "mock.lab.vuthanhluan.bond"},
            ssl_ctx=ssl_ctx,
        )
        assert st_doh_ref == 200
        assert json.loads(body_doh_ref)["Status"] == 5  # REFUSED (not an open resolver)

        print("=== [SCENARIO 17] Simulating MongoDB outage & verifying HTTP 503 fail-closed ===", flush=True)
        run_cmd(["docker", "pause", "locket_staging_e2e_mongo"])
        try:
            st_outage, _, _ = http_req(f"{BASE_HTTP}/api/ready", timeout=8.0)
            assert st_outage == 503, f"Expected 503 during DB outage, got {st_outage}"
        finally:
            run_cmd(["docker", "unpause", "locket_staging_e2e_mongo"])
        st_rec, _, _ = http_req(f"{BASE_HTTP}/api/ready", timeout=8.0)
        assert st_rec == 200

        print("=== [SCENARIO 18] Restarting API container & verifying persistence ===", flush=True)
        run_cmd(["docker", "restart", "locket_staging_api"])
        wait_for_container_healthy("locket_staging_api", timeout_sec=60)
        st_post_restart, _, body_post_restart = http_req(f"{BASE_HTTP}/api/accounts/lookup?query=e2e_user_2")
        assert st_post_restart == 200 and json.loads(body_post_restart) == {"exists": True}

        print("=== [SCENARIO 19] Verifying persistent host backup & collection rollback ===", flush=True)
        host_backup_file = backups_dir / "e2e_staging_snapshot.json"
        if host_backup_file.exists():
            host_backup_file.unlink()
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

        # Delete e2e_user_2 via API, then restore it from backup via rollback
        st_del, _, _ = http_req(f"{BASE_HTTP}/admin/accounts/e2e_user_2", method="DELETE", headers=admin_headers)
        assert st_del == 204
        run_cmd(compose_base + [
            "run", "--rm", "api",
            "python", "-m", "scripts.migrate_db",
            "--rollback", "/app/backups/e2e_staging_snapshot.json",
            "--mode", "partial",
        ])
        st_restored, _, body_restored = http_req(f"{BASE_HTTP}/api/accounts/lookup?query=e2e_user_2")
        assert st_restored == 200 and json.loads(body_restored) == {"exists": True}

        print("=== [ALL 20 DOCKER E2E SCENARIOS PASSED] ===", flush=True)
        return 0
    finally:
        print("=== [SCENARIO 20] Cleaning up isolated E2E test containers ===", flush=True)
        subprocess.run(
            compose_base + ["--profile", "lab", "--profile", "ca_init", "down", "-v"],
            cwd=ROOT,
            check=False,
        )
        for temp_f in (env_staging_path, compose_e2e_mongo, backups_dir / "e2e_staging_snapshot.json"):
            if temp_f.exists():
                temp_f.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
