# BÁO CÁO KẾT QUẢ KIỂM THỬ CI TRÊN GITHUB ACTIONS & LOCAL (`CI_TEST_RESULTS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh kiểm thử:** `fix/security-staging-readiness` (Pull Request #1)
**Ngày thực thi & xác minh trên GitHub Actions:** 2026-11-25

---

## 1. KẾT QUẢ CHẠY THỰC TẾ TRÊN GITHUB ACTIONS (`ubuntu-latest`)

- **Workflow:** `CI — Security, Parity & Staging Gate` (`.github/workflows/ci.yml`)
- **Verified Commit SHA:** `8b46706531ea83510f760cca378449cad228c06a` (cùng bản cập nhật báo cáo mới nhất trên PR #1)
- **GitHub Actions Run URLs (100% SUCCESS):**
  - Run `pull_request`: https://github.com/vuthanhluan206/locketgold_system/actions/runs/45471428165 (`conclusion=success`)
  - Run `push`: https://github.com/vuthanhluan206/locketgold_system/actions/runs/45471412733 (`conclusion=success`)

### Bảng kết quả từng Job & Step trên GitHub Actions Runner (`ubuntu-latest`)

| Job | Step | Nội dung kiểm tra | Kết quả thực tế trên GitHub Actions |
| :--- | :---: | :--- | :---: |
| **Job 1: `Python Compile, Lint, Secret Scan & Pytest Suite`** | 1–4 | Checkout repository, Set up Python 3.12, Install dependencies & `ruff` | **PASS (`success`)** |
| **Job 1** | 5 | `python -m scripts.check_secrets` (Quét PEM private key blocks, file `.env`/`.key`/`.pem` và live MongoDB URI credentials) | **PASS (`success`)** |
| **Job 1** | 6 | `python -m py_compile` (Biên dịch kiểm tra cú pháp toàn bộ `app/`, `scripts/`, `tests/`, `index.py`) | **PASS (`success`)** |
| **Job 1** | 7 | `ruff check app scripts tests --select E9,F63,F7,F82` (Phân tích tĩnh lỗi cú pháp & biến) | **PASS (`success`)** |
| **Job 1** | 8 | `pytest -v` (125 bài kiểm thử: **124 PASSED, 1 SKIPPED, 0 FAILED**) | **PASS (`success`)** |
| **Job 2: `Docker Build, Compose Config & Staging Smoke Gate`** | 3 | Kiểm tra cấu hình `docker compose -f compose.yaml config`, `compose.staging.yaml config`, `compose.lab.yaml config` | **PASS (`success`)** |
| **Job 2** | 4 | `docker build -t locketgold-staging:ci .` và kiểm tra container chạy dưới non-root user `uid=10001` | **PASS (`success`)** |

---

## 2. KẾT QUẢ THỰC THI BỘ KIỂM THỬ PYTEST CHI TIẾT (125 TESTS)

| Tập kiểm thử (`tests/*.py`) | Tổng số | PASSED | SKIPPED | FAILED | Trạng thái |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `tests/test_account_lookup.py` (13 kịch bản Account Lookup, UUID Resolution & Chống giả mạo `verified_uid` từ Admin) | 28 | 28 | 0 | 0 | **PASS** |
| `tests/test_admin_protection.py` (Turnstile, Rate Limit, Trusted Proxy IP) | 16 | 16 | 0 | 0 | **PASS** |
| `tests/test_app.py` (Auth, Sessions, CSP, Input Validation, Fail-Closed, HTTPS) | 25 | 25 | 0 | 0 | **PASS** |
| `tests/test_auth_entrypoint.py` (Turnstile pre-login check) | 1 | 1 | 0 | 0 | **PASS** |
| `tests/test_icons.py` (Static assets & private path isolation) | 4 | 4 | 0 | 0 | **PASS** |
| `tests/test_lab_regression.py` (Zero-Guessing UID, PKI, E2E Device & Revocation) | 6 | 6 | 0 | 0 | **PASS** |
| `tests/test_mongodb_integration.py` (Real external MongoDB daemon test) | 1 | 0 | 1 | 0 | **SKIPPED** (Chỉ chạy khi đặt `TEST_MONGODB_URI`) |
| `tests/test_phase3_https_lab.py` (X.509 Chain, Redaction, 4 Entitlement States) | 3 | 3 | 0 | 0 | **PASS** |
| `tests/test_phase4_full_audit.py` (Bytecode compile, Grace Period, Backup/Rollback, UI) | 4 | 4 | 0 | 0 | **PASS** |
| `tests/test_profile.py` (Apple `.mobileconfig` XML plist & X.509 CA validation) | 12 | 12 | 0 | 0 | **PASS** |
| `tests/test_prompt6_production_readiness.py` (Legacy env vars, Staging ports, Controlled Migration) | 6 | 6 | 0 | 0 | **PASS** |
| `tests/test_prompt7_security_and_staging.py` (P1 Device Auth, P1 DB Consistency & Canonical Expiry Precedence, P1 HTTPS/Ready, P1 Proxy Gate, CA CLI, 10.5k Backup, Secret Scanner) | 9 | 9 | 0 | 0 | **PASS** |
| `tests/test_proxy.py` (Research Proxy isolation, header stripping, redirect block) | 10 | 10 | 0 | 0 | **PASS** |
| **TỔNG CỘNG** | **125** | **124** | **1** | **0** | **124 PASSED / 1 SKIPPED / 0 FAILED** |

---

## 3. CÁC BÀI KIỂM THỬ BỔ SUNG ĐÃ XÁC MINH TRONG ĐỢT SỬA LỖI CI & BLOCKERS

1. `tests/test_prompt7_security_and_staging.py::test_blocker_a_secret_scanner_distinguishes_code_from_real_private_keys`: **PASSED**
   - Xác minh `scripts/check_secrets.py` trả về `0` vi phạm trên toàn bộ repository, phát hiện chính xác khối PEM private key nhiều dòng thực sự (`REAL_PRIVATE_KEY_BLOCK_RE`) và không nhận diện nhầm chuỗi kiểm tra một dòng trong mã nguồn.
2. `tests/test_prompt7_security_and_staging.py::test_blocker_b_canonical_expiry_precedence_and_partial_write_failures`: **PASSED**
   - Xác minh trong `merge_canonical_and_legacy_account(doc_v2, doc_v1)`: ngày hết hạn `expires_date` trong `accounts_v2` luôn có quyền ưu tiên tuyệt đối (bản ghi legacy `accounts` có ngày hết hạn cũ hơn hoặc khác biệt không bao giờ ghi đè được `accounts_v2`).
   - Xác minh thứ tự ưu tiên trạng thái rõ ràng (`revoked` > `pending` > `active` / `expired` theo `accounts_v2`) và lỗi ghi một phần ở bước 3 (`entitlements.update_one`) trả về ngay **HTTP `503 Service Unavailable`**.
3. `tests/test_account_lookup.py::test_admin_cannot_spoof_verified_uid_metadata_via_add_account`: **PASSED**
   - Xác minh khi Admin gửi `POST /admin/add-account` kèm chuỗi 28 ký tự và tự điền `"verification_status": "verified_uid"`, `"verification_method": "trusted_proof"`, `"verification_source": "verified_subscriber_traffic"`, backend tự động bác bỏ cờ tự nhận này, lưu `_server_uid_proof: False` và trả về trung thực `verification_status="unverified_uid"`, `uid_verified=False`.
