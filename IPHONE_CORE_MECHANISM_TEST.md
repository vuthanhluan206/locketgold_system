# HƯỚNG DẪN KIỂM THỬ BA KỊCH BẢN CỐT LÕI TRÊN IPHONE (`IPHONE_CORE_MECHANISM_TEST.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Ngày cập nhật:** 2026-11-25

---

## 1. BA KỊCH BẢN KIỂM THỬ ĐỘC LẬP TRÊN IPHONE

Tài liệu này hướng dẫn kiểm thử độc lập từng mắt xích của kiến trúc 2 payload (`com.apple.dnsSettings.managed` và `com.apple.security.root`) trên thiết bị iPhone thử nghiệm.

---

### Kịch bản A: Kiểm thử DNS-Only (`?mode=dns_only`)

**Mục tiêu:** Chứng minh iOS nhận diện và sử dụng cấu hình DNS-over-HTTPS mà không cần cài đặt bất kỳ chứng chỉ Root CA nào.

1. **Cài đặt cấu hình:**
   - Mở trình duyệt **Safari** trên iPhone, truy cập:
     `https://locketgold.vuthanhluan.bond/profile.mobileconfig?mode=dns_only`
   - Vào **Cài đặt** $\rightarrow$ **Đã tải về hồ sơ** $\rightarrow$ nhấn **Cài đặt**.
   - Xác nhận trong chi tiết hồ sơ chỉ có **1 payload duy nhất** là `DNS Settings` (`https://dns.nextdns.io/a8b247`), hoàn toàn không có mục `Root Certificate`.
2. **Kiểm tra trên Wi-Fi và 4G/5G:**
   - Trên mạng **Wi-Fi**: Mở Safari truy cập `https://test.nextdns.io`, kiểm tra `status: "ok"`, `protocol: "DOH"`, `profile: "a8b247"`.
   - Tắt Wi-Fi, bật **4G/5G**: Tải lại `https://test.nextdns.io`, xác nhận `protocol: "DOH"` vẫn hoạt động.
3. **Gỡ cấu hình:**
   - Vào **Cài đặt** $\rightarrow$ **Cài đặt chung** $\rightarrow$ **Quản lý VPN & Thiết bị** $\rightarrow$ chọn `Locket Gold DNS` $\rightarrow$ **Xóa hồ sơ**.

---

### Kịch bản B: Kiểm thử Root CA Lab & TLS Handshake (`?mode=lab_ca`)

**Mục tiêu:** Chứng minh iOS xác thực thành công chuỗi chứng chỉ X.509 (Root CA $\rightarrow$ Server Leaf Certificate) và SAN hostname khi người dùng bật Full Trust cho Lab Root CA.

1. **Cài đặt và bật Full Trust trên iPhone thử nghiệm:**
   - Tải hồ sơ Lab CA qua Safari: `https://<staging-host>/profile.mobileconfig?mode=lab_ca`.
   - Cài đặt hồ sơ trong **Cài đặt** $\rightarrow$ **Đã tải về hồ sơ**.
   - Vào **Cài đặt** $\rightarrow$ **Cài đặt chung** $\rightarrow$ **Giới thiệu** $\rightarrow$ **Cài đặt tin cậy chứng nhận (Certificate Trust Settings)** $\rightarrow$ bật công tắc Full Trust cho **`LocketGold Research Lab Root CA`**.
2. **Kiểm tra Fingerprint và Kết nối HTTPS tới Server Lab:**
   - Đối chiếu SHA-256 fingerprint trong hồ sơ khớp với giá trị `root_ca_sha256` tại `GET /api/health`.
   - Mở Safari truy cập endpoint HTTPS của Lab do bạn sở hữu (ví dụ `https://mock.lab.vuthanhluan.bond:8443/api/health`).
   - Xác nhận Safari kết nối HTTPS thành công (biểu tượng ổ khóa hợp lệ, không báo lỗi `NET::ERR_CERT_AUTHORITY_INVALID` hay lỗi lệch SAN hostname) và hiển thị JSON `{"status": "ok", ...}`.
3. **Gỡ bỏ Root CA ngay sau khi kiểm thử:**
   - Vào **Quản lý VPN & Thiết bị** $\rightarrow$ **Xóa hồ sơ**. Kiểm tra lại trong *Certificate Trust Settings* để xác nhận chứng chỉ `LocketGold Research Lab Root CA` đã biến mất hoàn toàn.

---

### Kịch bản C: Kiểm thử Khép kín DNS + Root CA + HTTPS Mock Lab + Automatic Processing

**Mục tiêu:** Kiểm tra luồng tự động hoàn chỉnh từ phân giải Split-DNS (`SupplementalMatchDomains`) $\rightarrow$ kết nối TLS tới Mock Server $\rightarrow$ FastAPI tự động xác thực `device_token` và truy vấn MongoDB `locket_manager_staging` $\rightarrow$ trả về JSON `CustomerInfo` tức thì mà không cần Admin xử lý thủ công.

1. **Cấu hình môi trường Real Device Lab trên VPS Staging (`.env.staging`):**
   ```dotenv
   APP_ENV=staging
   MONGODB_DATABASE=locket_manager_staging
   LAB_MODE=real_device
   LAB_DNS_TARGET_IP=103.118.29.159
   DOH_SERVER_URL=https://mock.lab.vuthanhluan.bond/dns-query
   LAB_SCOPED_DOMAINS=["mock.lab.vuthanhluan.bond","sub.lab.vuthanhluan.bond"]
   ROOT_CA_PATH=/app/certs_public/lab_root_ca.pem
   ```
2. **Đăng ký tài khoản thử nghiệm & thiết bị iPhone:**
   - Trong Admin Dashboard Staging, tạo tài khoản `iphone_scenario_c` với thời hạn trong tương lai (`status='active'`).
   - Liên kết thiết bị iPhone để nhận mã `device_token` (`lkg_dev_...`).
3. **Tải hồ sơ gắn riêng với thiết bị (`device_token`):**
   - Tải hồ sơ qua Safari:
     `https://<staging-host>/profile.mobileconfig?mode=scoped_lab&device_token=lkg_dev_...`
   - Cài đặt hồ sơ và bật Full Trust cho Lab Root CA.
4. **Thực thi truy vấn tới Mock Lab và kiểm tra xử lý tự động:**
   - Khi client thử nghiệm trên iPhone (hoặc `scripts/lab_test_client.py`) gọi `GET https://mock.lab.vuthanhluan.bond/v1/subscribers/iphone_scenario_c` kèm `Authorization: Bearer lkg_dev_...`:
     - Trình phân giải DoH trả về `103.118.29.159` cho `mock.lab.vuthanhluan.bond` (các tên miền ngoài danh sách giữ nguyên DNS bình thường).
     - Backend tự động xác thực `device_token`, kiểm tra `device_doc['locket_id'] == 'iphone_scenario_c'`, đọc trạng thái từ `locket_manager_staging` và trả về ngay JSON có `entitlements.Gold` (`X-Lab-Entitlement-Status: active`).
   - Khi Admin chuyển trạng thái tài khoản sang **Revoked**: lần gọi tiếp theo từ iPhone tự động nhận `entitlements: {}` (`X-Lab-Entitlement-Status: revoked`).
5. **Nguyên tắc ranh giới trung thực:**
   - Kết quả thành công của Kịch bản C chứng minh toàn bộ chuỗi **Split-DNS DoH + Custom Root CA + TLS SNI/SAN + Automatic MongoDB Entitlement Engine** hoạt động chính xác trên tên miền Lab do bạn kiểm soát (`mock.lab.vuthanhluan.bond`).
   - Kết quả này **không** được sử dụng làm bằng chứng rằng ứng dụng Locket chính thức từ App Store đã chấp nhận quyền thuê bao giả lập.
