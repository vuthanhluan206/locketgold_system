# SECURITY REVIEW REPORT — RÀ SOÁT BẢO MẬT TOÀN HỆ THỐNG

**Ngày rà soát:** 24/11/2026  
**Phạm vi:** Mã nguồn FastAPI, cấu hình Docker/Caddy, quản lý khóa X.509 PKI, cơ chế xác thực MongoDB, giao diện Web SPA và nhật ký hệ thống.

---

## 1. KIỂM TRA QUẢN LÝ BÍ MẬT & KHÓA RIÊNG (SECRETS & PKI HYGIENE)

- **Không có thông tin bí mật cứng (Hardcoded Secrets) trong mã nguồn:**
  - Đã quét toàn bộ thư mục `app/`, `scripts/`, `web/`, `tests/`, `.env.example`, `Dockerfile`, `compose*.yaml`, `Caddyfile*`.
  - Không có mật khẩu quản trị, không có MongoDB Atlas URI thật, không có Cloudflare Turnstile secret key và không có Private Key chứng chỉ nào bị nhúng trong mã nguồn.
- **Bảo vệ Private Key của Root CA:**
  - `.gitignore`, `.dockerignore` và `.vercelignore` đều chặn `*.pem`, `*.key`, `*.cer`, `*.der`, `*.p12`, `*.pfx`, `.env` và `.env.*`.
  - Script `scripts/generate_lab_ca.py` lưu khóa riêng với quyền hạn `0600` (`os.chmod(ca_key_path, 0o600)`).
  - Hàm `load_validated_root_ca()` trong `app/profile.py` kiểm tra `if b'PRIVATE KEY' in raw: raise ValueError('Root CA must never contain a private key')`, đảm bảo quản trị viên không bao giờ vô tình phát tán khóa riêng bên trong file `.mobileconfig`.

---

## 2. KIỂM TRA XÁC THỰC, PHÂN QUYỀN & CHỐNG TẤN CÔNG (AUTHN / AUTHZ)

- **Chống lộ thông tin đăng nhập và Brute-Force:**
  - Mật khẩu Superadmin bắt buộc từ 12–256 ký tự, băm bằng `PBKDF2-HMAC-SHA256` với **600,000 vòng** và salt 16-byte ngẫu nhiên.
  - Khi đăng nhập với email không tồn tại, `app/auth.py#L57` vẫn thực hiện phép băm `PBKDF2` giả trong worker thread và dùng `secrets.compare_digest` để chống tấn công đo thời gian (Timing Attack).
  - Bộ đếm giới hạn tốc độ đăng nhập trong MongoDB (`login_limits`) được kiểm tra **trước khi** gọi `verify_password`, ngăn chặn tấn công làm cạn kiệt CPU (CPU Exhaustion DoS).
- **Quản lý Phiên và Token Thiết bị:**
  - Cả `access_token` của Admin (64 ký tự URL-safe) lẫn `device_token` của iPhone (`lkg_dev_*`) đều **chỉ lưu mã băm SHA-256** trong cơ sở dữ liệu (`sessions` và `devices`). Ngay cả khi cơ sở dữ liệu bị đọc trộm (Read-only DB compromise), kẻ tấn công không thể khôi phục được Bearer token để mạo danh phiên Admin hay thiết bị.
- **Chống rò rỉ Token lên Upstream (`app/locket_modifier.py#L84-L93`):**
  - Trước khi chuyển tiếp bất kỳ request nào trong `/proxy`, hệ thống kiểm tra xem Bearer token có trùng với `SUBSCRIBER_API_TOKEN` hoặc nằm trong bảng `sessions` của Admin hay không. Nếu trùng, chặn ngay lập tức với `HTTP 401` để token nội bộ không bao giờ bị gửi ra mạng ngoài.

---

## 3. KIỂM TRA CHE MỜ DỮ LIỆU NHẠY CẢM TRONG LOGS (LOG REDACTION)

- Module `app/services/lab_inspector_service.py` tự động lọc mọi bản ghi trước khi lưu vào `lab_requests`:
  - **Headers bị che mờ:** `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Admin-Token`, `CF-Turnstile-Response` và mọi header chứa từ khóa `token`, `secret`, `password`.
  - **JSON Body bị che mờ đệ quy:** `password`, `password_hash`, `access_token`, `refresh_token`, `id_token`, `device_token`, `turnstile_token`, `secret`, `api_token`, `token`.
  - Đã được kiểm chứng tự động trong `tests/test_phase3_https_lab.py::test_sensitive_data_redaction_in_headers_and_payloads`.

---

## 4. KIỂM TRA GIAO DIỆN WEB & CHỐNG XSS / CSRF / CLICKJACKING

- **CSP Nonce Động (`app/middleware.py`):** Mỗi HTTP response sinh một chuỗi `nonce` 24-byte mới (`secrets.token_urlsafe(24)`), gắn header `Content-Security-Policy: default-src 'none'; script-src 'nonce-...'` và loại bỏ hoàn toàn `unsafe-inline`.
- **An toàn DOM Manipulation (`web/index.html`):** Toàn bộ dữ liệu tài khoản, thiết bị và nhật ký hiển thị trên Admin Dashboard đều được gán qua `element.textContent`, tuyệt đối không sử dụng `innerHTML`, ngăn chặn hoàn toàn Stored/Reflected XSS.
- **Tách biệt HTML Public và Admin (`app/routers/management.py#L103-L110`):** Khi người dùng truy cập trang chủ `/`, server cắt bỏ hoàn toàn khối `<!-- ADMIN_START --> ... <!-- ADMIN_END -->` trước khi gửi về trình duyệt.
