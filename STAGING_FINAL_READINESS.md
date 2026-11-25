# ĐÁNH GIÁ NGHIỆM THU CUỐI CÙNG TRƯỚC KHI TRIỂN KHAI VPS STAGING & IPHONE THẬT (`STAGING_FINAL_READINESS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh hoàn thiện:** `fix/final-core-iphone-readiness`
**Ngày đánh giá:** 2026-11-25

---

## 1. ĐỐI CHIẾU 12 ĐIỀU KIỆN HOÀN THÀNH BẮT BUỘC (PROMPT 8 + ADDENDUM + PROMPT 10)

| STT | Điều kiện nghiệm thu | Trạng thái | Bằng chứng xác minh thực tế |
| :---: | :--- | :---: | :--- |
| 1 | **Secret Scanner PASS (Cho phép `.env.example` & `.env.staging.example` an toàn, bắt secrets thật)** | **PASS** | `python -m scripts.check_secrets` đạt 0 vi phạm; `test_p0_secret_scanner_permits_safe_templates_and_catches_real_secrets` chứng minh chặn `.env.staging` thật và chặn `.env.staging.example` nếu bị chèn hash/URI thật. |
| 2 | **Python Compile & Ruff Static Analysis PASS** | **PASS** | Toàn bộ file `.py` trong `app/`, `scripts/`, `tests/` biên dịch sạch và vượt qua `ruff check --select E9,F63,F7,F82`. |
| 3 | **Pytest Suite PASS (136+ bài kiểm thử)** | **PASS** | Toàn bộ unit, regression, device auth, DB consistency, account lookup, dual-payload mobileconfig, RFC 8484 DoH và real-device IP guard đều PASS. |
| 4 | **Docker Build & Non-Root UID `10001` Volume Permissions PASS** | **PASS** | `Dockerfile` tạo sẵn `/app/backups`, `/app/certs_public`, `/app/certs_private` cho UID `10001:10001`. `compose.staging.yaml` có service `ca_init` (`10001:10001`) và `api` chỉ mount `certs_public:ro`. |
| 5 | **Docker Runtime E2E (20 Kịch bản thực tế trên Container thật) PASS** | **PASS** | `python -m scripts.docker_e2e_smoke` chạy trực tiếp trong GitHub Actions job `docker-staging-gate` với FastAPI + MongoDB 7.0 + Caddy 2 HTTPS Lab. |
| 6 | **TLS SNI & SAN Hostname Verification (`check_hostname=True`) PASS** | **PASS** | Đã xóa bỏ hoàn toàn `check_hostname = False`. `_LabPinnedHTTPSConnection` xác thực đầy đủ Root CA chain, SNI và SAN hostname (`mock.lab.vuthanhluan.bond`), đồng thời chặn hostname không nằm trong SAN (`SSLError`). |
| 7 | **Cô lập Docker E2E An toàn (Không dùng `chmod 0777`, không đụng cổng Staging)** | **PASS** | Dùng thư mục tạm riêng với quyền `0755`/`0750`, project `locket_e2e_ci`, container `locket_e2e_ci_*` và cổng loopback cấp phát động. |
| 8 | **Bảo toàn Kiến trúc 2 Payload (`.mobileconfig`) & Kiểm chứng DER `LocketProxy CA`** | **PASS** | Kiểm chứng trực tiếp DER của `LocketProxy CA` (`16:2C:34:B4...AF:F1`) và phân biệt rõ với chứng chỉ mới do Lab tự sinh. Hỗ trợ đủ `dns_only` (1 payload) và `lab_ca` / `scoped_lab` (2 payloads). |
| 9 | **Custom DoH cho Local Lab vs Real iPhone (`LAB_MODE=local` vs `real_device`) PASS** | **PASS** | Khi `LAB_MODE=real_device`, hệ thống từ chối `127.0.0.1` trong `LAB_DNS_TARGET_IP` và `DOH_SERVER_URL`, bắt buộc dùng IPv4 thực của VPS (`103.118.29.159`). Endpoint `/dns-query` chỉ phân giải domain của Lab, trả `REFUSED` cho domain ngoài. |
| 10 | **MongoDB Staging Isolation (`locket_manager_staging`) & Reconciliation PASS** | **PASS** | Khi `APP_ENV=staging`, từ chối khởi động nếu `MONGODB_DATABASE=locket_manager`. Có `staging_preflight.py`, `seed_staging_db.py` và `migrate_db.py --reconcile` (không bao giờ kích hoạt lại tài khoản `revoked`). |
| 11 | **Tài liệu Triển khai VPS & Chuẩn bị iPhone thật khớp 100% với Code** | **PASS** | Đã cập nhật [DEPLOY_STAGING.md](file:///e:/locketgold/DEPLOY_STAGING.md) và tạo mới [REAL_IPHONE_STAGING_SETUP.md](file:///e:/locketgold/REAL_IPHONE_STAGING_SETUP.md) với đầy đủ 12 bước từ chuẩn bị VPS, cài đặt qua Safari, bật Full Trust tới gỡ bỏ cấu hình. |
| 12 | **GitHub Actions CI Xanh 100% (`conclusion=success`)** | **PASS** | Cả 2 job (`test-and-verify` và `docker-staging-gate` chạy 20 bước Docker E2E thật) đều đạt `success` trên GitHub Actions. |

---

## 2. PHÂN LOẠI TRẠNG THÁI NGHIỆM THU TRUNG THỰC (HONEST READINESS CLASSIFICATION)

Theo đúng tiêu chuẩn nghiệm thu của mục XIII (Prompt 8) và mục 10 (Prompt 10):

1. **`CI READY` — ĐẠT (`VERIFIED`)**: Toàn bộ mã nguồn, secret scan, ruff lint, 136+ bài kiểm thử pytest và 20 kịch bản Docker Runtime E2E (FastAPI + MongoDB + Caddy HTTPS Lab với `check_hostname=True`) đã chạy thành công trên GitHub Actions.
2. **`READY FOR VPS TESTING` — ĐẠT (`VERIFIED`)**: Hệ thống đã sẵn sàng 100% để quản trị viên triển khai lên thư mục `/opt/locketgold_staging` trên VPS `103.118.29.159` theo đúng 12 bước copy/paste trong [DEPLOY_STAGING.md](file:///e:/locketgold/DEPLOY_STAGING.md) và [REAL_IPHONE_STAGING_SETUP.md](file:///e:/locketgold/REAL_IPHONE_STAGING_SETUP.md) mà không gây ảnh hưởng tới dịch vụ Production đang chạy trên cổng 80/443 hay database `locket_manager`.
3. **`VPS STAGING VERIFIED` & `IPHONE VERIFIED` — CHƯA ĐÁNH DẤU (`PENDING OPERATOR EXECUTION ON LIVE VPS & PHYSICAL IPHONE`)**: Vì quy tắc an toàn cấm tuyệt đối việc tự ý kết nối/thao tác lên VPS production từ môi trường phát triển và việc cài đặt `.mobileconfig` + bật Full Trust bắt buộc phải thực hiện thủ công trên thiết bị iPhone vật lý, hai trạng thái này được giữ nguyên ở mức chờ người vận hành nghiệm thu thực tế.
