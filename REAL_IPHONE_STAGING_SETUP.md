# HƯỚNG DẪN CÀI ĐẶT & KIỂM THỬ STAGING TRỰC TIẾP TRÊN IPHONE THẬT (`REAL_IPHONE_STAGING_SETUP.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Hạ tầng VPS:** Ubuntu VPS `103.118.29.159` (~1 GB RAM), tên miền chính `locketgold.vuthanhluan.bond`, NextDNS ID `a8b247`
**Database Staging Cô Lập:** `locket_manager_staging` (Tuyệt đối tách biệt khỏi database production `locket_manager`)

---

## 1. PHÂN ĐỊNH RÕ 3 CẤP ĐỘ XÁC MINH (VERIFICATION BOUNDARIES)

| Cấp độ | Phạm vi đã kiểm chứng | Trạng thái hiện tại |
| :--- | :--- | :---: |
| **1. `CI READY`** | Secret Scanner, Python Compile, Ruff Lint, 141 bài kiểm thử Pytest (Device Auth, MongoDB Consistency, Account Lookup, Dual-Payload Mobileconfig, RFC 8484 DoH, Real Device IP Guard). | **VERIFIED ON GITHUB ACTIONS** |
| **2. `DOCKER RUNTIME E2E VERIFIED`** | Khởi chạy thật container FastAPI + MongoDB + Caddy HTTPS Lab trên runner Linux, kiểm tra 20 kịch bản E2E, kiểm tra TLS SNI + SAN hostname (`check_hostname=True`), backup & rollback trên đĩa host. | **VERIFIED ON GITHUB ACTIONS** |
| **3. `IPHONE VERIFIED`** | Thao tác tải `.mobileconfig` qua trình duyệt Safari trên thiết bị iPhone vật lý, bật công tắc **Certificate Trust Settings** trên iOS và kiểm tra qua mạng Wi-Fi / 4G / 5G. | **PENDING REAL DEVICE RUN BY OPERATOR** (Không bao giờ tự tuyên bố `IPHONE VERIFIED` từ CI) |

---

## 2. CHUẨN BỊ VPS & BACKUP CẤU HÌNH PRODUCTION (BƯỚC 1–2)

### Bước 1: Kiểm tra tài nguyên VPS và Backup Production (Không dừng Production)

SSH vào VPS `103.118.29.159` và kiểm tra RAM cùng các cổng đang mở:

```bash
free -m
ss -tulpn | grep -E ':(80|443|18000|18443)\b'
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Bước 2: Clone mã nguồn đã nghiệm thu vào `/opt/locketgold_staging` và tạo `.env.staging`

Không ghi đè vào thư mục production đang chạy:

```bash
sudo mkdir -p /opt/locketgold_staging
sudo chown $USER:$USER /opt/locketgold_staging
git clone --branch main https://github.com/vuthanhluan206/locketgold_system.git /opt/locketgold_staging
cd /opt/locketgold_staging
mkdir -p backups certs_public certs_private
sudo chown -R 10001:10001 backups certs_public certs_private
chmod 0755 backups certs_public
chmod 0750 certs_private
cp .env.staging.example .env.staging
```

Chỉnh sửa `/opt/locketgold_staging/.env.staging`:
- Đặt `APP_ENV=staging` và `MONGODB_DATABASE=locket_manager_staging`.
- Khi kiểm thử với **iPhone thật từ bên ngoài VPS** (`LAB_MODE=real_device`):
  ```dotenv
  APP_ENV=staging
  MONGODB_DATABASE=locket_manager_staging
  NEXTDNS_ID=a8b247
  LAB_MODE=real_device
  LAB_DNS_TARGET_IP=103.118.29.159
  ALLOWED_HOSTS=["locketgold.vuthanhluan.bond","mock.lab.vuthanhluan.bond","sub.lab.vuthanhluan.bond","localhost","127.0.0.1"]
  LAB_SCOPED_DOMAINS=["mock.lab.vuthanhluan.bond","sub.lab.vuthanhluan.bond"]
  ```
  *(Lưu ý kiến trúc quan trọng: Trong chế độ `LAB_MODE=real_device`, nếu cấu hình `LAB_DNS_TARGET_IP=127.0.0.1`, ứng dụng sẽ từ chối khởi động ngay để ngăn iPhone phân giải tên miền Lab về chính loopback của điện thoại).*

### Bước 3: Chạy Preflight & Tạo Chứng chỉ Lab bằng `ca_init` (UID 10001)

```bash
docker compose -p locket_staging -f compose.staging.yaml build api ca_init
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.staging_preflight --ping --backup-dir /app/backups
docker compose -p locket_staging -f compose.staging.yaml --profile ca_init run --rm ca_init
ls -la certs_public/lab_root_ca.pem certs_private/lab_leaf.pem certs_private/lab_leaf.key
```

---

## 3. CẤU HÌNH TÊN MIỀN HTTPS STAGING & KIỂM TRA TLS CÔNG KHAI (BƯỚC 3–4)

Để iPhone thật bên ngoài Internet kết nối được tới môi trường Staging mà không tắt container Production trên cổng 80/443:

1. **Tạo bản ghi DNS `A` cho tên miền Lab thuộc quyền kiểm soát của bạn:**
   - Trên bảng điều khiển DNS của `vuthanhluan.bond`, trỏ bản ghi `A` (DNS-only, tắt đám mây cam Cloudflare proxy nếu dùng chứng chỉ Lab CA riêng):
     - `mock.lab.vuthanhluan.bond` $\rightarrow$ `103.118.29.159`
     - `sub.lab.vuthanhluan.bond` $\rightarrow$ `103.118.29.159`
2. **Cách iPhone phân giải hostname của chính DoH Server (DoH Bootstrap Resolution):**
   - Khi iPhone cài payload `com.apple.dnsSettings.managed` với `ServerURL`:
     - **Chế độ A (NextDNS):** `https://dns.nextdns.io/a8b247` — iOS phân giải `dns.nextdns.io` qua DNS hệ thống và xác thực TLS bằng Apple System Trust Store có sẵn (không cần cài Root CA).
     - **Chế độ B (Custom DoH Lab):** `https://mock.lab.vuthanhluan.bond/dns-query` — iOS phân giải `mock.lab.vuthanhluan.bond` lần đầu qua bản ghi DNS `A` công khai (`103.118.29.159`) để thiết lập kết nối HTTPS DoH.
3. **Khởi động Staging API và kiểm tra chứng chỉ:**
   ```bash
   docker compose -p locket_staging -f compose.staging.yaml --profile lab up -d api lab_https
   curl -fsS http://127.0.0.1:18000/api/health | jq .
   curl -fsS http://127.0.0.1:18000/api/ready | jq .
   ```

---

## 4. KỊCH BẢN KIỂM THỬ TRÊN IPHONE THẬT (BƯỚC 5–10)

### Kịch bản A: Cài đặt & Kiểm thử DNS-Only Profile (Bước 5–7)

1. Mở trình duyệt **Safari** trên iPhone (bắt buộc dùng Safari, không dùng trình duyệt trong ứng dụng khác) và truy cập URL tải cấu hình DNS-only:
   - `https://<staging-host>/profile.mobileconfig?mode=dns_only`
2. Chọn **Cho phép (Allow)** khi Safari hỏi *"Trang web này đang cố gắng tải về một hồ sơ cấu hình"*.
3. Mở **Cài đặt (Settings)** $\rightarrow$ nhấn **Đã tải về hồ sơ (Profile Downloaded)** $\rightarrow$ nhấn **Cài đặt (Install)** ở góc phải trên cùng $\rightarrow$ nhập mã khóa iPhone $\rightarrow$ hoàn tất.
4. Vào **Cài đặt** $\rightarrow$ **Cài đặt chung (General)** $\rightarrow$ **Quản lý VPN & Thiết bị (VPN & Device Management)** $\rightarrow$ kiểm tra mục **DNS** đã chọn **`Locket Gold DNS`**.
5. **Kiểm tra trên cả Wi-Fi và 4G/5G:**
   - Mở Safari truy cập `https://test.nextdns.io`: kiểm tra `status: "ok"`, `protocol: "DOH"`, `profile: "a8b247"`.
   - Tắt Wi-Fi trên iPhone để chuyển sang **4G/5G** và tải lại `https://test.nextdns.io` để xác nhận hồ sơ DoH vẫn hoạt động nhất quán trên mạng di động.

### Kịch bản B: Cài đặt Root CA Lab & Bật Full Trust (Bước 8)

> **Lưu ý an toàn:** Chỉ cài Root CA Lab trên thiết bị iPhone dành cho kiểm thử Research Lab và phải gỡ bỏ ngay sau khi hoàn tất phiên thử nghiệm.

1. Trong `/opt/locketgold_staging/.env.staging`, đặt `ROOT_CA_PATH=/app/certs_public/lab_root_ca.pem` và khởi động lại `locket_staging_api`.
2. Trên Safari iPhone, tải hồ sơ 2 payload (DNS + Root CA):
   - `https://<staging-host>/profile.mobileconfig?mode=lab_ca`
3. Cài đặt hồ sơ trong **Cài đặt** $\rightarrow$ **Đã tải về hồ sơ**.
4. **Bật Full Trust thủ công cho Root CA:**
   - Vào **Cài đặt (Settings)** $\rightarrow$ **Cài đặt chung (General)** $\rightarrow$ **Giới thiệu (About)** $\rightarrow$ kéo xuống cuối chọn **Cài đặt tin cậy chứng nhận (Certificate Trust Settings)**.
   - Tại mục *"Bật tin cậy hoàn toàn cho các chứng nhận gốc" (Enable full trust for root certificates)*, gạt nút công tắc sang màu xanh cho **`LocketGold Research Lab Root CA`** và chọn **Tiếp tục (Continue)**.
5. Đối chiếu SHA-256 fingerprint hiển thị tại `GET /api/health` (`root_ca_sha256`) trùng khớp với chứng chỉ vừa cài.

### Kịch bản C: Kiểm thử Automatic API Processing (`active` / `expired` / `revoked`) (Bước 9–10)

Hệ thống xử lý hoàn toàn tự động (Automatic Processing Engine) — **Admin không cần ngồi canh request trên Dashboard để duyệt tay**:

1. **Tạo tài khoản và cấp Device Token trên Staging:**
   - Đăng nhập trang Admin Staging, thêm tài khoản `iphone_lab_tester` (hoặc chạy `docker exec locket_staging_api python -m scripts.seed_staging_db`).
   - Nhấn **+ Link Device** để sinh `device_token` (`lkg_dev_...`) gắn riêng cho `iphone_lab_tester`.
2. **Kiểm tra trạng thái `ACTIVE`:**
   - Khi iPhone/Lab Client gửi request kèm `Authorization: Bearer lkg_dev_...` tới `/v1/subscribers/iphone_lab_tester`, FastAPI tự động đối chiếu MongoDB `locket_manager_staging` và trả về ngay lập tức JSON `CustomerInfo` có `entitlements.Gold` (`X-Lab-Entitlement-Status: active`).
3. **Kiểm tra trạng thái `REVOKED` & `EXPIRED`:**
   - Nhấn nút **Revoke** trên tài khoản `iphone_lab_tester` trong Admin Dashboard.
   - Gọi lại endpoint `/v1/subscribers/iphone_lab_tester` từ iPhone: ngay lập tức nhận `entitlements: {}` (`X-Lab-Entitlement-Status: revoked`).
   - Nhấn **Revoke Device** trên thiết bị: request tiếp theo từ thiết bị đó bị từ chối ngay với **HTTP `401 Unauthorized`**.

---

## 5. GHI NHẬN LỖI CHẨN ĐOÁN & GỠ BỎ CẤU HÌNH SAU KIỂM THỬ (BƯỚC 11–12)

1. **Xem log chẩn đoán đã che dữ liệu nhạy cảm (`***REDACTED***`):**
   - Gọi `GET /admin/logs` hoặc xem mục **"3. Recent Redacted Request/Response Logs"** trên Admin Dashboard (mọi header `Authorization`, `Cookie`, `device_token` đều đã được che tự động).
2. **Gỡ bỏ hoàn toàn cấu hình khỏi iPhone sau khi thử nghiệm (Bước 12):**
   - Vào **Cài đặt (Settings)** $\rightarrow$ **Cài đặt chung (General)** $\rightarrow$ **Quản lý VPN & Thiết bị (VPN & Device Management)**.
   - Chọn hồ sơ **`Locket Gold DNS`** $\rightarrow$ nhấn **Xóa hồ sơ (Remove Profile)** $\rightarrow$ nhập mã khóa iPhone $\rightarrow$ xác nhận **Xóa**.
   - Ngay khi xóa hồ sơ, cả cấu hình DNS-over-HTTPS lẫn chứng chỉ Root CA Lab đều bị gỡ bỏ hoàn toàn khỏi hệ thống iOS.
