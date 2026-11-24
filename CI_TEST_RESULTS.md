# BÁO CÁO KẾT QUẢ KIỂM THỬ CI & LOCAL (`CI_TEST_RESULTS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh kiểm thử:** `fix/security-staging-readiness`
**Ngày thực thi:** 2026-11-25

---

## 1. KẾT QUẢ THỰC THI BỘ KIỂM THỬ TỰ ĐỘNG (`pytest`)

Lệnh thực thi:
```powershell
& "C:\Users\fpt\AppData\Local\Python\bin\python.exe" -m pytest -v
```

| Hạng mục kiểm thử | Tổng số | PASSED | SKIPPED | FAILED | Trạng thái |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `tests/test_account_lookup.py` (**12 kịch bản Account Lookup & UUID Resolution từ `locketgoldmanager`**) | 27 | 27 | 0 | 0 | **PASS** |
| `tests/test_admin_protection.py` (Turnstile, Rate Limit, Trusted Proxy IP) | 16 | 16 | 0 | 0 | **PASS** |
| `tests/test_app.py` (Auth, Sessions, CSP, Input Validation, Fail-Closed, HTTPS) | 25 | 25 | 0 | 0 | **PASS** |
| `tests/test_auth_entrypoint.py` (Turnstile pre-login check) | 1 | 1 | 0 | 0 | **PASS** |
| `tests/test_icons.py` (Static assets & private path isolation) | 4 | 4 | 0 | 0 | **PASS** |
| `tests/test_lab_regression.py` (Zero-Guessing UID, PKI, E2E Device & Revocation) | 6 | 6 | 0 | 0 | **PASS** |
| `tests/test_mongodb_integration.py` (Real external MongoDB daemon test) | 1 | 0 | 1 | 0 | **SKIPPED** (Không đặt `TEST_MONGODB_URI` trong sandbox) |
| `tests/test_phase3_https_lab.py` (X.509 Chain, Redaction, 4 Entitlement States) | 3 | 3 | 0 | 0 | **PASS** |
| `tests/test_phase4_full_audit.py` (Bytecode compile, Grace Period, Backup/Rollback, UI) | 4 | 4 | 0 | 0 | **PASS** |
| `tests/test_profile.py` (Apple `.mobileconfig` XML plist & X.509 CA validation) | 12 | 12 | 0 | 0 | **PASS** |
| `tests/test_prompt6_production_readiness.py` (Legacy env vars, Staging ports, Controlled Migration) | 6 | 6 | 0 | 0 | **PASS** |
| `tests/test_prompt7_security_and_staging.py` (**P1 Device Auth, P1 DB Consistency, P1 HTTPS/Ready, P1 Proxy Gate, CA CLI, 10.5k Backup**) | 7 | 7 | 0 | 0 | **PASS** |
| `tests/test_proxy.py` (Research Proxy isolation, header stripping, redirect block) | 10 | 10 | 0 | 0 | **PASS** |
| **TỔNG CỘNG** | **122** | **121** | **1** | **0** | **121 PASSED / 1 SKIPPED / 0 FAILED** |

---

## 2. CHI TIẾT 7 BÀI KIỂM THỬ MỚI TRONG `tests/test_prompt7_security_and_staging.py`

1. `test_p1_device_authorization_cross_account_access_blocked`: **PASSED**
   - Xác minh Device Token của `account_A` đọc `/v1/subscribers/account_A` trả về HTTP `200` (có quyền `Gold`).
   - Xác minh Device Token của `account_A` truy cập `/v1/subscribers/account_B`, `/api/lab/subscribers/account_B`, hoặc gửi `{"locket_id": "account_B"}` vào `POST /api/lab/inspect` đều bị chặn ngay lập tức với **HTTP `403 Forbidden`**.
   - Xác minh `service_token` và `admin_session` truy cập được cả hai tài khoản theo đúng chính sách phân quyền.
   - Xác minh thu hồi tài khoản (`revoke`) ngừng cấp `Gold` ngay lập tức và thu hồi thiết bị chặn truy cập với **HTTP `401 Unauthorized`**.
2. `test_p1_mongodb_consistency_no_swallowed_errors_and_revoked_precedence`: **PASSED**
   - Xác minh bản ghi legacy trong `accounts` (có `expires_date` ở tương lai và không có trường `status`) **không bao giờ ghi đè** trạng thái `revoked` trong `accounts_v2`.
   - Xác minh tài khoản chỉ nằm trong `accounts_v2` (`v2_only_user`) hiển thị đầy đủ trong `GET /admin/accounts` và xóa được qua `DELETE /admin/accounts/v2_only_user` (HTTP `204`).
   - Xác minh khi `accounts_v2.update_one` gặp lỗi `PyMongoError`, các API `POST /admin/add-account` và `POST /admin/accounts/{id}/revoke` trả về ngay **HTTP `503 Service Unavailable`** (không nuốt lỗi).
3. `test_p1_https_behind_trusted_caddy_and_readiness_probe`: **PASSED**
   - Xác minh khi `REQUIRE_HTTPS=true`, request HTTP từ client không thuộc `TRUSTED_PROXY_CIDRS` bị từ chối với HTTP `400` ngay cả khi giả mạo header `X-Forwarded-Proto: https`.
   - Xác minh endpoint `GET /api/ready` kiểm tra thực tế kết nối MongoDB (trả về HTTP `200` khi DB phản hồi và HTTP `503` khi DB lỗi).
4. `test_p1_research_proxy_disabled_in_production_and_blocks_third_party_payment_domains`: **PASSED**
   - Xác minh `/proxy/*` trả về **HTTP `403 Forbidden`** khi `ENABLE_RESEARCH_PROXY=false` (mặc định).
   - Xác minh `Settings` từ chối khởi động nếu `LAB_SCOPED_DOMAINS` chứa tên miền của dịch vụ thanh toán bên thứ ba (`api.revenuecat.com`).
5. `test_section6_generate_lab_ca_cli_flags_and_third_party_domain_rejection`: **PASSED**
   - Xác minh `python -m scripts.generate_lab_ca --out-public ... --out-private ... --domains ...` tách biệt hoàn toàn thư mục public (không chứa `.key`) và thư mục private, đồng thời từ chối tên miền `api.revenuecat.com`.
6. `test_section7_persistent_backup_verification_and_no_10k_truncation`: **PASSED**
   - Xác minh sao lưu và kiểm tra file backup trên đĩa (`verify_backup_file_on_disk`) với **10.500 bản ghi**, không bị cắt cụt ở 10.000 bản ghi.
7. `test_section8_identity_verification_rejects_client_supplied_trusted_proof`: **PASSED**
   - Xác minh `POST /admin/verify-link` trả về **HTTP `422`** nếu client cố tình gửi `"trusted_proof": true` trong JSON request, và trả về `verification_status="unverified_uid"`, `verification_source="regex_28char_format_only"` cho chuỗi 28 ký tự chưa qua xác minh độc lập.

---

## 3. CẤU HÌNH GITHUB ACTIONS CI (`.github/workflows/ci.yml`)

Workflow [`.github/workflows/ci.yml`](file:///e:/locketgold/.github/workflows/ci.yml) được kích hoạt tự động trên mọi lệnh `push` (`main`, `fix/**`) và `pull_request` về `main`, bao gồm 2 job:
1. **`test-and-verify`**:
   - Quét toàn bộ `git ls-files` đảm bảo không có file `.env`, `.key`, `.pem`, `.cer`, `.der`, `.zip`, `.rar` hoặc chuỗi `-----BEGIN PRIVATE KEY-----`.
   - Kiểm tra biên dịch Python bytecode (`python -m py_compile`).
   - Phân tích tĩnh bằng `ruff check`.
   - Chạy toàn bộ 95 bài kiểm thử `pytest -v`.
2. **`docker-staging-gate`**:
   - Kiểm tra cấu hình `docker compose -f compose.yaml config`, `docker compose -f compose.staging.yaml config`, `docker compose -f compose.yaml -f compose.lab.yaml config`.
   - Build Docker image thực tế (`docker build -t locketgold-staging:ci .`) và xác minh container chạy dưới quyền non-root user `uid=10001`.
