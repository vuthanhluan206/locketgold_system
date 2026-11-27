# HƯỚNG DẪN TRIỂN KHAI STAGING TRÊN UBUNTU VPS (`DEPLOY_STAGING.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Hạ tầng mục tiêu:** Ubuntu VPS (`103.118.29.159`, ~1 GB RAM, tên miền production `locketgold.vuthanhluan.bond`, NextDNS ID `a8b247`, MongoDB Atlas)
**Trạng thái các lệnh:** Toàn bộ cấu hình Docker Compose, quyền ghi UID `10001`, khởi tạo chứng chỉ `ca_init` và 20 bước E2E đã được kiểm chứng tự động trên Linux container runner (`ubuntu-latest`); các lệnh SSH trực tiếp trên VPS `103.118.29.159` được thiết kế sẵn sàng để người vận hành copy/paste thực thi (`READY FOR VPS TESTING`).

---

## 1. NGUYÊN TẮC CÔ LẬP STAGING VỚI PRODUCTION ĐANG CHẠY TRÊN VPS

1. **Không chạm cổng 80/443 của Production**: Container Caddy của hệ thống cũ đang giữ cổng `80` và `443`. Stack `compose.staging.yaml` chỉ bind vào loopback `127.0.0.1:18000:8000` (Core API) và tùy chọn `127.0.0.1:18443:8443` (`--profile lab`), tuyệt đối không gây xung đột cổng.
2. **Không dùng nhầm `.env` hay Database `locket_manager` của Production**:
   - `compose.staging.yaml` nạp biến môi trường từ `.env.staging` (`${STAGING_ENV_FILE:-.env.staging}`) và gắn cứng `APP_ENV=staging`.
   - Khi `APP_ENV=staging`, ứng dụng sẽ **từ chối khởi động ngay lập tức** nếu `MONGODB_DATABASE=locket_manager`. Bắt buộc sử dụng `MONGODB_DATABASE=locket_manager_staging`.
3. **Phân quyền tối thiểu UID `10001` (Không chạy FastAPI bằng root, không dùng `chmod 0777`)**:
   - Container `api` chạy dưới user `appuser` (`10001:10001`), chỉ mount `./certs_public:/app/certs_public:ro` (chỉ đọc chứng chỉ công khai, **không mount** `certs_private`) và `./backups:/app/backups`.
   - Chứng chỉ Root CA và Leaf được tạo trước bằng container one-shot `ca_init` (`--profile ca_init`, `user: "10001:10001"`).

---

## 2. QUY TRÌNH 12 BƯỚC COPY/PASTE TRIỂN KHAI STAGING TRÊN VPS

### Bước 1: Kiểm tra RAM và các cổng đang sử dụng trên VPS

```bash
free -m
ss -tulpn | grep -E ':(80|443|18000|18443|18081)\b'
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Bước 2: Clone mã nguồn vào thư mục `/opt/locketgold_staging` (Tách biệt khỏi thư mục Production)

```bash
sudo mkdir -p /opt/locketgold_staging
sudo chown $USER:$USER /opt/locketgold_staging
git clone --branch main https://github.com/vuthanhluan206/locketgold_system.git /opt/locketgold_staging
cd /opt/locketgold_staging
git rev-parse HEAD
```

### Bước 3: Tạo thư mục Volume với quyền tối thiểu cho UID `10001`

```bash
mkdir -p backups certs_public certs_private
sudo chown -R 10001:10001 backups certs_public certs_private
chmod 0755 backups certs_public
chmod 0750 certs_private
```

### Bước 4: Tạo file cấu hình `.env.staging` riêng biệt

```bash
cp .env.staging.example .env.staging
nano .env.staging
```

Đảm bảo các giá trị sau trong `.env.staging`:
- `APP_ENV=staging`
- `MONGODB_DATABASE=locket_manager_staging` (Khuyến nghị tạo user MongoDB Atlas chỉ có quyền `readWrite` trên database `locket_manager_staging`).
- `NEXTDNS_ID=a8b247`
- Nếu kiểm thử Mode A (Core Staging qua loopback / SSH tunnel): `REQUIRE_HTTPS=false`, `TRUSTED_PROXY_CIDRS=[]`, `LAB_MODE=local`.
- Nếu kiểm thử với iPhone thật từ bên ngoài (`LAB_MODE=real_device`): đặt `LAB_DNS_TARGET_IP=103.118.29.159` (không được đặt `127.0.0.1`).

### Bước 5: Build Docker Image Staging & Chạy Kiểm tra Preflight

```bash
docker compose -p locket_staging -f compose.staging.yaml build api ca_init
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.staging_preflight --ping --backup-dir /app/backups
```

*(Lệnh `staging_preflight` sẽ xác nhận `database: "locket_manager_staging"`, `production_database_protected: true`, `backup_dir_writable: true`, `mongodb_ping: "ok"` mà không in mật khẩu hay URI thật ra màn hình).*

### Bước 6: Khởi động Core Staging API (`locket_staging_api`)

```bash
docker compose -p locket_staging -f compose.staging.yaml up -d api
docker compose -p locket_staging -f compose.staging.yaml ps
```

### Bước 7: Kiểm tra Health và Readiness Probes trên Loopback `127.0.0.1:18000`

```bash
curl -fsS http://127.0.0.1:18000/api/health | jq .
curl -fsS http://127.0.0.1:18000/api/ready | jq .
```

### Bước 8: Nạp dữ liệu thử nghiệm mẫu vào `locket_manager_staging` & Kiểm thử Tra cứu

```bash
docker exec locket_staging_api python -m scripts.seed_staging_db
curl -fsS "http://127.0.0.1:18000/api/accounts/lookup?query=https://locket.cam/staging_active_user" | jq .
curl -fsS "http://127.0.0.1:18000/api/accounts/lookup?query=nonexistent_user" | jq .
```

### Bước 9 (Tùy chọn): Khởi tạo Chứng chỉ Lab bằng `ca_init` & Bật HTTPS Research Lab (`--profile lab`)

```bash
# 1. Chạy one-shot container ca_init (UID 10001) để sinh Root CA (certs_public/) và Leaf TLS (certs_private/)
docker compose -p locket_staging -f compose.staging.yaml --profile ca_init run --rm ca_init
ls -la certs_public/lab_root_ca.pem certs_private/lab_leaf.pem certs_private/lab_leaf.key

# 2. Đặt ROOT_CA_PATH=/app/certs_public/lab_root_ca.pem trong .env.staging rồi bật cả api và lab_https
sed -i 's|^ROOT_CA_PATH=.*|ROOT_CA_PATH=/app/certs_public/lab_root_ca.pem|' .env.staging
docker compose -p locket_staging -f compose.staging.yaml --profile lab up -d api lab_https
```

### Bước 10: Kiểm tra Mobileconfig (3 chế độ) & Xác thực TLS SNI/Hostname của HTTPS Lab

```bash
# 1. Tải thử 3 chế độ mobileconfig
curl -fsSI "http://127.0.0.1:18000/profile.mobileconfig?mode=dns_only"
curl -fsSI "http://127.0.0.1:18000/profile.mobileconfig?mode=lab_ca"
curl -fsSI "http://127.0.0.1:18000/profile.mobileconfig?mode=scoped_lab"

# 2. Kiểm tra kết nối HTTPS tới Caddy Lab (127.0.0.1:18443) với xác thực đầy đủ Root CA + SNI + SAN hostname (KHÔNG dùng -k!)
curl -fsS --cacert ./certs_public/lab_root_ca.pem --resolve mock.lab.vuthanhluan.bond:18443:127.0.0.1 https://mock.lab.vuthanhluan.bond:18443/api/health | jq .
```

### Bước 11: Kiểm tra Sao lưu bền vững trên Host (`./backups`), UID Entitlement Audit & Reconciliation

```bash
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --backup /app/backups/staging_snapshot.json --dry-run
ls -lh ./backups/staging_snapshot.json
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --verify-backup /app/backups/staging_snapshot.json
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --uid-entitlements --dry-run
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --reconcile --dry-run
```

### Áp dụng và rollback migration UID trên staging

Sau khi duyệt dry-run, dùng một tên backup mới trên volume bền vững. CLI ghi bản trước và sau của từng document ở `accounts_v2` và `entitlements`, kiểm tra checksum rồi áp dụng trong transaction trên MongoDB replica set hoặc Atlas. Dừng ghi quản trị trong cửa sổ migration. Các lệnh rollback dùng chính file của lần áp dụng.

```bash
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --uid-entitlements --apply --backup /app/backups/prompt27-uid-01.json
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --uid-entitlements --dry-run
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --uid-entitlements --rollback /app/backups/prompt27-uid-01.json --dry-run
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --uid-entitlements --rollback /app/backups/prompt27-uid-01.json
```

Rollback kiểm tra dữ liệu hiện tại với journal. Nếu quản trị viên đã sửa document sau migration, transaction dừng để bảo toàn thay đổi đó.

### Bước 12: Dừng môi trường Staging an toàn (Không ảnh hưởng Production)

> **Lưu ý an toàn:** Không bao giờ chạy `docker system prune --volumes` trên VPS. Chỉ hạ đúng project `locket_staging`:

```bash
docker compose -p locket_staging -f compose.staging.yaml --profile lab --profile ca_init down
```

---

## 3. LUỒNG ADD ACCOUNT TỰ ĐỘNG & GOLD MANAGEMENT SSOT THEO VERIFIED UID

Hệ thống Admin Dashboard chỉ có **một luồng `Add Account` duy nhất**:

1. Quản trị viên mở `Add Account`, nhập `Locket ID / Username` (ví dụ `vt.l` hoặc `https://locket.cam/vt.l`), chọn `Expires at` và nhấn `Save account`.
2. Backend (`POST /admin/add-account`) tự động chuẩn hóa định danh, kiểm tra `accounts_v2` xem đã có Firebase UID đã xác minh (`verified_uid`, `_server_uid_proof=True`) chưa, và tra cứu trang chia sẻ công khai `https://locket.cam/<username>` (không dùng phiên đăng nhập Locket, không yêu cầu Firebase ID Token hay Refresh Token).
3. Nếu tài khoản có Firebase UID đã xác minh (`verified_uid`):
   - Lưu vào `accounts_v2` với `account_id = <VERIFIED_FIREBASE_UID>`, `firebase_uid = <VERIFIED_FIREBASE_UID>`, `status = "active"`.
   - Liên kết quyền Gold trong `entitlements` với khóa `account_id = <VERIFIED_FIREBASE_UID>`.
4. Nếu chỉ có username hoặc `invite_token` từ trang công khai mà chưa có bằng chứng xác minh Firebase UID:
   - Lưu vào `accounts_v2` với `firebase_uid = null`, `verification_status = "unverified_handle"`, `status = "pending"`.
   - **Không tạo quyền Gold active** cho đến khi UID được xác minh.

Index `unique_firebase_uid_string` ngăn hai account giữ cùng một Firebase UID; giá trị `null` được bỏ qua.
