# SECURITY ANALYSIS — LOCKET GOLD RESEARCH SYSTEM

## 1. Kiến trúc Bảo mật & Ranh giới Tin cậy (Trust Boundaries)

1. **Quản lý Mật khẩu & Phiên Quản trị (Admin Authentication):**
   - Mật khẩu của Superadmin không bao giờ lưu ở dạng văn bản thuần (plaintext). Hệ thống sử dụng `PBKDF2-HMAC-SHA256` với **600,000 vòng lặp** và salt ngẫu nhiên 16 byte (`app/passwords.py`).
   - Phiên đăng nhập sinh token ngẫu nhiên 48 byte (`secrets.token_urlsafe(48)`). Chỉ mã băm `SHA-256` của token được lưu trong collection `sessions` và `devices` (`app/security.py`, `app/services/device_service.py`).
   - Khi đổi mật khẩu và chạy `python -m app.bootstrap --sync-db`, trường `auth_version` thay đổi làm toàn bộ phiên cũ bị thu hồi ngay lập tức.

2. **Chống Brute-Force & Bảo vệ Tài nguyên (Rate Limiting & Request Bounds):**
   - Giới hạn kích thước body: `8 KiB` (timeout 5 giây) cho toàn bộ API quản trị/đăng nhập, kể cả request gửi dạng `Transfer-Encoding: chunked` (`app/middleware.py`).
   - Giới hạn tốc độ đăng nhập 2 lớp: In-Memory RateLimiter ở middleware VÀ bộ đếm nguyên tử dùng chung trong MongoDB `login_limits` (10 lần/IP/phút, 30 lần/toàn cục/phút; 60 request/phút cho các thao tác Admin).
   - Hỗ trợ xác minh Cloudflare Turnstile server-side (`app/turnstile.py`) kiểm tra cả `success`, `hostname` và `action == "admin-login"` trước khi kiểm tra mật khẩu.

3. **Bảo mật Chứng chỉ Số X.509 & Khóa riêng (PKI Isolation):**
   - Khóa riêng (`lab_root_ca.key`) được sinh bởi `scripts/generate_lab_ca.py` chỉ lưu ở thư mục bảo mật (`chmod 0600`) và bị loại trừ tuyệt đối trong `.gitignore`, `.dockerignore` và `.vercelignore`.
   - Bộ sinh cấu hình iOS (`app/profile.py`) kiểm tra nghiêm ngặt: từ chối mọi chứng chỉ chứa chuỗi `PRIVATE KEY`, từ chối chứng chỉ hết hạn hoặc chưa tới hạn (`NotBefore <= now < NotAfter`), từ chối chứng chỉ không có `BasicConstraints(ca=True)` hoặc không phải chứng chỉ Root CA tự ký.

4. **Chính sách Fail-Closed cho Entitlement & Proxy:**
   - Đã loại bỏ hoàn toàn lỗi mặc định cấp quyền (`2029-12-31`) khi tài khoản không tồn tại trong database.
   - Chặn chuyển hướng (`NoRedirect`) trong `app/locket_modifier.py` để không bao giờ rò rỉ header `Authorization` sang tên miền khác, đồng thời chặn không cho Admin Session Token hay Service Token bị gửi nhầm lên upstream.
