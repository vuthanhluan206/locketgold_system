# IMPLEMENTATION PLAN — LOCKET GOLD RESEARCH SYSTEM

**Ngày lập kế hoạch:** 24/11/2026  
**Căn cứ:** Kết quả kiểm toán từ [SOURCE_AUDIT.md](file:///e:/locketgold/SOURCE_AUDIT.md), phân tích cơ chế từ [CORE_MECHANISM_ANALYSIS.md](file:///e:/locketgold/CORE_MECHANISM_ANALYSIS.md) và thiết kế kiến trúc từ [ARCHITECTURE.md](file:///e:/locketgold/ARCHITECTURE.md).

---

## 1. LỘ TRÌNH LẬP TRÌNH THEO CÁC MODULE ĐỘC LẬP

Để đảm bảo hệ thống sạch sẽ, có tính hệ thống, dễ kiểm thử và không viết dồn vào một file khổng lồ, quá trình triển khai mã nguồn (Giai đoạn 2+) được chia thành 6 bước theo cấu trúc phân tầng `Config -> Domain Models -> Repositories/Migration -> Services -> Routers/UI -> Deployment & Tests`:

### Bước 1: Chuẩn hóa Cấu hình, Dependencies & PKI Lab Generator
- **Tệp thực hiện:**
  - `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`: Thêm `dnspython>=2.6` (bắt buộc cho `mongodb+srv://` của MongoDB Atlas) và `httpx>=0.27` vào dependencies chuẩn; xóa bỏ gói lỗi `httpx2`.
  - `app/config.py`:
    - Hỗ trợ parse `ALLOWED_HOSTS` linh hoạt cả định dạng JSON array (`["a.com","b.com"]`) lẫn chuỗi phân tách dấu phẩy (`a.com,b.com`) bằng kiểu `str | list[str]` để triệt tiêu lỗi `JSONDecodeError` của Pydantic Settings.
    - Bổ sung cấu hình `NEXTDNS_ID` (mặc định `a8b247`), `LAB_DOMAIN`, `LAB_CA_DIR`, và `LAB_CLIENT_PUBLIC_KEY`.
  - `app/services/pki_service.py` & `scripts/generate_lab_ca.py`:
    - Sinh cặp khóa ECDSA P-256 / RSA-2048 và chứng chỉ **Lab Root CA** chuẩn RFC 5280 (`BasicConstraints: CA=TRUE`, `KeyUsage: keyCertSign, cRLSign, digitalSignature`, `NotBefore = now - 7 days`, `NotAfter = now + 10 years`).
    - Lưu khóa riêng an toàn bên ngoài web root, cung cấp hàm kiểm tra fingerprint SHA-256 và xuất chứng chỉ công khai DER/PEM.

### Bước 2: Thiết kế Domain Models, Database Lifecycle & Migration Script
- **Tệp thực hiện:**
  - `app/models.py`:
    - Định nghĩa rõ enum `EntitlementStatus` (`active`, `expired`, `revoked`, `pending`, `unauthorized`) và `VerificationStatus` (`verified_uid`, `unverified_handle`, `manual_lab_id`).
    - Định nghĩa Pydantic models cho `AccountInput`, `AccountV2Output`, `LinkVerifyInput`, `LinkVerifyOutput`, `DeviceCreateInput`, `DeviceOutput`, `AuditLogEntry`, `TestResultInput`.
  - `app/database.py`:
    - Khởi tạo `AsyncMongoClient` kết nối tới database `locket_manager` với đầy đủ các collections: `accounts` (legacy), `accounts_v2`, `entitlements`, `devices`, `admins`, `sessions`, `login_limits`, `audit`, `lab_requests`, `test_results`, `profile_versions`.
    - Thực hiện **Automatic Non-Destructive Sync** khi khởi động: mọi bản ghi cũ trong `accounts` chưa có trong `accounts_v2` đều được tự động ánh xạ sang `accounts_v2` mà không làm mất dữ liệu.
  - `scripts/migrate_db.py`:
    - Công cụ CLI độc lập hỗ trợ backup JSON và migrate hai chiều giữa `accounts` và `accounts_v2`.

### Bước 3: Xây dựng Các Core Services (Identity, Entitlement, Device, Profile)
- **Tệp thực hiện:**
  - `app/services/identity_service.py`:
    - Phân tích URL `https://locket.cam/<username>`, `@<username>`, hoặc `UID` trực tiếp.
    - Kiểm tra chống trùng tài khoản; báo rõ trạng thái xác minh UUID thay vì tự suy đoán.
  - `app/services/entitlement_service.py`:
    - Single Source of Truth tính toán trạng thái thuê bao (`active`, `expired`, `revoked`, `pending`, `unauthorized`).
    - Sinh phản hồi `subscriber_response` chuẩn xác: **Tuyệt đối không cấp `Gold` cho tài khoản `None`, `expired`, `revoked`, hoặc `pending`**.
  - `app/services/device_service.py`:
    - Liên kết thiết bị với `account_id`, kiểm tra hạn mức `max_devices`, sinh `device_token` (`lkg_dev_...`), lưu SHA-256 hash và hỗ trợ thu hồi thiết bị tức thì.
  - `app/services/profile_service.py`:
    - Sinh cấu hình `.mobileconfig` cho NextDNS (`https://dns.nextdns.io/a8b247`), hỗ trợ tùy chọn nhúng Lab Root CA và `SupplementalMatchDomains` cho domain kiểm thử của Lab.

### Bước 4: Refactor API Routers & Authenticated Lab Inspector
- **Tệp thực hiện:**
  - `app/routers/management.py`:
    - Bổ sung đầy đủ các API quản trị: `/admin/verify-link`, `/admin/add-account`, `/admin/accounts`, `/admin/accounts/{id}/revoke`, `/admin/accounts/{id}/activate`, `/admin/devices`, `/admin/logs`, `/admin/stats`, `/admin/test-results`.
  - `app/routers/subscribers.py`:
    - Hỗ trợ xác thực bằng `Admin Session`, `SUBSCRIBER_API_TOKEN`, hoặc `Device Enrollment Token` (`lkg_dev_...`).
    - Ghi nhận mỗi lần kiểm tra vào `lab_requests` để Admin quan sát trực tiếp từ Dashboard khi thử nghiệm trên iPhone.
  - `app/locket_modifier.py`:
    - Loại bỏ toàn bộ kết nối MongoDB đồng bộ, loại bỏ dữ liệu `viewers` giả và loại bỏ việc mặc định cấp Gold cho tài khoản không tồn tại.
    - Sửa `/proxy/install` dùng chung bộ sinh `.mobileconfig` chuẩn của `profile_service.py`.

### Bước 5: Nâng cấp Admin Dashboard & Public Lab Portal (`web/index.html`)
- **Tệp thực hiện:**
  - `web/index.html`:
    - **Public View (`/`):** Sửa nút tải cấu hình thành liên kết HTTP trực tiếp tới `/profile.mobileconfig` (loại bỏ hoàn toàn đoạn JS tạo Blob chứa NextDNS ID cứng `8f4cb9` và chứng chỉ cứng). Hiển thị hướng dẫn kiểm tra NextDNS (`test.nextdns.io`) và trạng thái cấu hình Lab.
    - **Admin View (`/admin`):**
      - Giữ nguyên giao diện bảo mật với CSP Nonce và Dark/Light mode.
      - Thêm công cụ **Xác minh Link / Identifier** (`https://locket.cam/...` hoặc UID).
      - Hiển thị bảng Tài khoản với đầy đủ cột: `Account / UID`, `Verification`, `Expires At`, `Status` (`Active / Expired / Revoked / Pending`), `Devices`, và các nút thao tác: **Edit**, **Revoke / Activate**, **Link Device**, **Download Lab Profile**, **Check Mock API**, **Delete**.
      - Thêm bảng **Quản lý Thiết bị (Devices)** và **Nhật ký Kiểm thử / Audit Logs** ngay trên Dashboard.

### Bước 6: Cấu hình Docker Compose, Caddyfile & Bộ Kiểm thử Tự động (Pytest)
- **Tệp thực hiện:**
  - `Dockerfile`, `compose.yaml`, `Caddyfile`, `.env.example`, `DEPLOY_VPS.md`, `IPHONE_TEST_PLAN.md`, `KNOWN_LIMITATIONS.md`, `SECURITY_ANALYSIS.md`.
  - **Bộ kiểm thử (`tests/`):**
    - Kiểm thử toàn bộ 68+ unit/integration tests hiện có VÀ bổ sung bộ Regression Tests cho toàn bộ 11 lỗi lịch sử (kiểm tra tài khoản không tồn tại trả về `{}` thay vì `2029-12-31`, kiểm tra `revoke` có hiệu lực ngay lập tức, kiểm tra `ALLOWED_HOSTS` dạng chuỗi và JSON, kiểm tra `KeyError: status`, kiểm tra thiết bị bị thu hồi bị chặn `401/403`, kiểm tra X.509 Root CA validation).

---

## 2. MA TRẬN KIỂM THỬ NGHIỆM THU (TEST MATRIX)

| Cấp độ | Kịch bản kiểm thử | Kết quả kỳ vọng |
|---|---|---|
| **Unit Test** | Tài khoản không tồn tại (`account = None`) gọi `subscriber_response` | `entitlements == {}`, `subscriptions == {}`, `status == "unauthorized"` |
| **Unit Test** | Tài khoản còn hạn nhưng `status == "revoked"` | `entitlements == {}`, không cấp quyền Gold |
| **Unit Test** | Parse `ALLOWED_HOSTS="locketgold.vuthanhluan.bond,localhost"` | Thành công, trả về `["locketgold.vuthanhluan.bond", "localhost"]` |
| **Unit Test** | Xác minh link `https://locket.cam/testuser` khi không có UID xác thực | Trả về `verification_status = "unverified_handle"`, cảnh báo rõ không tự gán làm UID đã xác minh |
| **Unit Test** | Sinh `.mobileconfig` với `NEXTDNS_ID=a8b247` và Lab Root CA | XML Plist hợp lệ, `ServerURL = https://dns.nextdns.io/a8b247`, DER cert tự ký còn hạn và có `KeyUsage: keyCertSign` |
| **Integration Test** | Admin Login -> Add Account -> Link Device -> Call `/v1/subscribers/{id}` bằng Device Token -> Revoke Account -> Call lại `/v1/subscribers/{id}` | Lần 1 nhận `entitlements.Gold` active; sau khi Revoke nhận `entitlements: {}` ngay lập tức; ghi đầy đủ vào `audit` và `lab_requests` |
| **Regression Test** | Kiểm tra `/` Public HTML không chứa script inline tạo Blob cứng `8f4cb9` | `href="/profile.mobileconfig"` tồn tại, không có `<script` trên trang `/` |
