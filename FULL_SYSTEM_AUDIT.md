# FULL SYSTEM AUDIT REPORT — KIỂM TOÁN KỸ THUẬT TOÀN DIỆN

**Ngày kiểm toán:** 24/11/2026  
**Hệ thống:** Locket Gold Research & Entitlement Lab (`v2.0.0`)  
**Môi trường mục tiêu:** `locketgold.vuthanhluan.bond` | Database: `locket_manager` | NextDNS: `a8b247` | VPS Ubuntu (~1 GB RAM)

---

## 1. KIỂM TOÁN LUỒNG NGHIỆP VỤ END-TO-END (15 BƯỚC)

Toàn bộ quy trình 15 bước từ khi Admin đăng nhập cho đến khi thu hồi quyền đã được kiểm tra xuyên suốt qua mã nguồn và kiểm thử tích hợp tự động (`tests/test_lab_regression.py` & `tests/test_phase3_https_lab.py`):

1. **Admin đăng nhập (`POST /api/admin/login`):** Kiểm tra rate-limit 2 lớp (`SecurityMiddleware` + MongoDB `login_limits`), xác minh Turnstile (nếu bật), băm mật khẩu `PBKDF2-HMAC-SHA256` (600,000 vòng) và cấp Bearer session token 48-byte (lưu SHA-256 digest trong `sessions`).
2. **Thêm link tài khoản Locket (`POST /admin/verify-link`):** Admin nhập `https://locket.cam/<username>`, `@<handle>`, hoặc UID 28 ký tự.
3. **Kiểm tra định dạng link (`app/services/identity_service.py`):** Chỉ chấp nhận tên miền `locket.cam` / `locket.camera` hợp lệ, từ chối mọi tên miền lạ hoặc ký tự độc hại.
4. **Xác minh UUID theo chính sách Zero-Guessing:** Nếu người dùng chỉ dán link chia sẻ công khai `https://locket.cam/<username>`, hệ thống trả về `verification_status: "unverified_handle"` và thông báo rõ link công khai không chứa Firebase UID nội bộ. Chỉ khi đầu vào là UID 28 ký tự chuẩn mới gán `verification_status: "verified_uid"`.
5. **Lưu tài khoản vào MongoDB (`POST /admin/add-account`):** Ghi đồng thời (dual-write) vào `accounts` (giữ tương thích ngược 100%) và `accounts_v2` (schema v2 đầy đủ) cùng `entitlements`, sử dụng unique index trên `locket_id` để chống trùng lặp.
6. **Cấu hình trạng thái entitlement thử nghiệm:** Hỗ trợ các trạng thái `active`, `pending`, `revoked`, `expired` và `grace_period_expires_date`.
7. **Liên kết thiết bị (`POST /admin/devices`):** Kiểm tra giới hạn `max_devices` của tài khoản, sinh mã `device_id` (`dev_*`) và `device_token` (`lkg_dev_*`), chỉ lưu `token_hash` (SHA-256) trong collection `devices`.
8. **Tạo `.mobileconfig` (`GET /profile.mobileconfig`):** Sinh cấu hình XML Plist chứa payload DoH (`https://dns.nextdns.io/a8b247` hoặc `https://dns.nextdns.io/a8b247/<device_id>`) và payload Root CA của Lab (DER).Lưu phiên bản vào `profile_versions`.
9. **Cài cấu hình trên iPhone thử nghiệm:** Tải trực tiếp với MIME `application/x-apple-aspen-config` qua Safari, không dùng Blob JS cứng.
10. **Xác minh NextDNS và Root CA Lab (`GET /api/health`, `GET /admin/pki/status`):** Cung cấp SHA-256 fingerprint của Root CA và trạng thái NextDNS ID `a8b247` để đối chiếu với `test.nextdns.io` và iOS Certificate Trust Settings.
11. **Kiểm tra HTTPS Research Lab (`GET /api/lab/subscribers/{id}`, `POST /api/lab/inspect`):** Xác thực bằng `device_token` (`lkg_dev_*`), `SUBSCRIBER_API_TOKEN` hoặc phiên Admin.
12. **Client thử nghiệm nhận trạng thái entitlement (`scripts/lab_test_client.py` & Interactive UI Client):** Hiển thị rõ `lab_entitlement_state` (`active`, `expired`, `revoked`, `none`) và chi tiết `entitlements.Gold`.
13. **Ghi nhật ký và kết quả (`lab_requests`, `audit`, `test_results`):** Tự động che mờ toàn bộ token/password/cookie thành `***REDACTED***` trước khi ghi vào MongoDB.
14. **Admin gia hạn hoặc thu hồi (`POST /admin/accounts/{id}/revoke`, `POST /admin/accounts/{id}/activate`, `POST /admin/devices/{id}/revoke`):** Cập nhật trực tiếp vào cả `accounts` và `accounts_v2`, ghi `audit` log.
15. **Client nhận trạng thái cập nhật ngay lập tức:** Không lưu cache trạng thái entitlement; ngay ở request tiếp theo sau khi Admin bấm Revoke, API trả về `entitlements: {}` và header `X-Lab-Entitlement-State: revoked`.

---

## 2. KIỂM TOÁN BACKEND FASTAPI

- **Cấu trúc Package & Imports:** Phân tách rõ ràng theo tầng `app/config.py`, `app/models.py`, `app/database.py`, `app/security.py`, `app/middleware.py`, `app/profile.py`, `app/services/*`, `app/routers/*`. Kiểm tra `py_compile` trên toàn bộ 23 file Python đạt 100% không lỗi cú pháp.
- **Dependencies (`requirements.txt`, `pyproject.toml`):** Đã đồng bộ hoàn toàn giữa `requirements.txt` và `pyproject.toml` (`fastapi`, `uvicorn[standard]`, `pymongo`, `dnspython`, `pydantic-settings`, `cryptography`, `httpx`). Đã xóa bỏ gói lỗi `httpx2` trong `requirements-dev.txt`.
- **Environment Validation (`app/config.py`):** Sử dụng `NoDecode` kết hợp validator tùy chỉnh cho `ALLOWED_HOSTS`, `TRUSTED_PROXY_CIDRS` và `LAB_SCOPED_DOMAINS`, chấp nhận cả JSON array (`["a","b"]`) lẫn chuỗi phân tách dấu phẩy (`a,b`), chấm dứt hoàn toàn lỗi crash khi khởi động do cấu hình `.env`.
- **Security Headers & Request Limits (`app/middleware.py`):**
  - Giới hạn body `8 KiB` (timeout 5s) cho toàn bộ API quản trị/đăng nhập; `50 MiB` (timeout 60s) cho `/proxy/*`.
  - Mọi phản hồi đều gắn `Content-Security-Policy` với `nonce` ngẫu nhiên từng request (không dùng `unsafe-inline`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, và `Strict-Transport-Security` khi chạy HTTPS.
  - Không bật wildcard CORS, không lộ `/openapi.json` hay `/docs`.

---

## 3. KIỂM TOÁN CƠ SỞ DỮ LIỆU MONGODB (`locket_manager`)

- **Bảo toàn dữ liệu cũ:** Giữ nguyên database `locket_manager` và collection `accounts`. Mọi thao tác thêm/sửa/thu hồi/kích hoạt từ Admin Dashboard đều cập nhật đồng bộ cả `accounts` và `accounts_v2`.
- **Indexes:**
  - `accounts`: `locket_id` (`unique: True`)
  - `accounts_v2`: `locket_id` (`unique: True`)
  - `admins`: `email` (`unique: True`)
  - `sessions`: `expires_at` (TTL `expireAfterSeconds: 0`)
  - `login_limits`: `expires_at` (TTL `expireAfterSeconds: 0`)
  - `devices`: `device_id` (`unique: True`), `token_hash` (`unique: True`)
  - `entitlements`: `(account_id, entitlement_key)` (`unique: True`)
  - `audit`: `(timestamp: -1)`
  - `lab_requests`: `timestamp` (TTL 7 ngày `expireAfterSeconds: 604800`)
- **Migration, Backup & Rollback (`scripts/migrate_db.py`):** Hỗ trợ đầy đủ 4 chế độ `--dry-run`, `--backup <file.json>`, `--apply` và `--rollback <file.json>`. Đã kiểm chứng tự động bằng unit test `test_database_migration_backup_and_rollback`.

---

## 4. KIỂM TOÁN DNS, ROOT CA VÀ MOBILECONFIG

- **NextDNS DoH (`a8b247`):** Payload `com.apple.dnsSettings.managed` được tạo với `DNSProtocol = "HTTPS"` và `ServerURL = "https://dns.nextdns.io/a8b247"` (hoặc gắn hậu tố `/<device_id>` khi tải kèm `device_token` để phân biệt thiết bị trên NextDNS Logs).
- **Chế độ Split-DNS (`?mode=scoped_lab`):** Nhúng mảng `SupplementalMatchDomains` chỉ định các tên miền thử nghiệm của Lab (`mock.lab.vuthanhluan.bond`, `sub.lab.vuthanhluan.bond`, `locketgold.vuthanhluan.bond`).
- **Kiểm định X.509 (`app/services/pki_service.py`):**
  - Chứng chỉ Lab Root CA tự sinh có `BasicConstraints(ca=True, path_length=0)` (critical), `KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True)` (critical), `NotBefore = now - 7 days`, `NotAfter = now + 3650 days`.
  - Chứng chỉ Lab Leaf Cert có `BasicConstraints(ca=False)`, `ExtendedKeyUsage(serverAuth)`, `SubjectAlternativeName` và thời hạn $\le 397$ ngày (tuân thủ giới hạn 398 ngày của Apple iOS HT210176).
  - Hàm `verify_certificate_chain_and_hostname()` kiểm tra chữ ký mật mã học, thời hạn và khớp tên miền theo chuẩn RFC 6125.

---

## 5. KIỂM TOÁN DOCKER, CADDY VÀ VPS (~1 GB RAM)

- **Phân bổ RAM hợp lý cho VPS 1 GB:**
  - Không chạy container `mongo:8.0` trên VPS (sử dụng MongoDB Atlas qua `mongodb+srv://`).
  - Container `api` (FastAPI 1 worker): giới hạn `mem_limit: 384m`, chạy dưới quyền non-root user `appuser` (UID 10001), có healthcheck tự động gọi `http://127.0.0.1:8000/api/health`.
  - Container `caddy` (Caddy 2 Alpine): giới hạn `mem_limit: 128m`, quản lý cổng `80/443` và chứng chỉ Let's Encrypt cho `locketgold.vuthanhluan.bond`.
  - Container tùy chọn `lab_https` (`compose.lab.yaml`): giới hạn `mem_limit: 64m`, chỉ bind vào `127.0.0.1:8443` và `127.0.0.1:8081` với chứng chỉ Lab Leaf Cert, tuyệt đối không gây xung đột cổng `80/443` với Caddy chính.
