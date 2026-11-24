# HƯỚNG DẪN TRIỂN KHAI STAGING KHÔNG XUNG ĐỘT CỔNG (`DEPLOY_STAGING.md`)

Tài liệu này hướng dẫn triển khai và kiểm thử bản mã nguồn `locketgold_system` ở chế độ **Staging** ngay trên VPS `103.118.29.159` (~1 GB RAM) **trong khi hệ thống `locket.gold` cũ vẫn đang chạy bình thường trên cổng 80 và 443**.

---

## 1. KIẾN TRÚC CÔ LẬP STAGING (`compose.staging.yaml`) & BẢO VỆ DATABASE PRODUCTION

1. **Không xung đột cổng 80/443**:
   - Container `locket_staging_api` chỉ bind vào loopback `127.0.0.1:18000:8000` (`mem_limit: 256m`).
   - Container tùy chọn `locket_staging_lab_https` được đặt trong `profiles: ["lab"]` và chỉ bind vào loopback `127.0.0.1:18443:8443` và `127.0.0.1:18081:8081` (`mem_limit: 64m`). Khi chạy lệnh `docker compose -p locket_staging -f compose.staging.yaml up -d`, chỉ có `api` khởi động nên **không bắt buộc** phải tạo trước chứng chỉ Lab nếu chỉ kiểm thử API/DNS-only.
2. **Bảo vệ tuyệt đối Database Production (`locket_manager`)**:
   - **QUY TẮC BẮT BUỘC:** Khi chạy các bài kiểm thử Staging có thao tác ghi dữ liệu (thêm/sửa/xóa tài khoản thử nghiệm, enroll thiết bị, test rollback), **TUYỆT ĐỐI KHÔNG** đặt `MONGODB_DATABASE=locket_manager` (database production).
   - Phải đặt tên database riêng cho Staging trong file `.env.staging` (hoặc `.env` của thư mục staging):
     ```dotenv
     MONGODB_DATABASE=locket_manager_staging
     ```
   - Chỉ khi chạy lệnh kiểm tra `scripts/migrate_db.py --dry-run` (chế độ chỉ đọc 100%, không ghi) hoặc khi thực hiện Cutover chính thức theo `DEPLOY_PRODUCTION.md` mới trỏ về `MONGODB_DATABASE=locket_manager`.

---

## 2. CÁC BƯỚC TRIỂN KHAI STAGING TRÊN VPS

### Bước 1: Clone mã nguồn vào thư mục Staging riêng

```bash
sudo mkdir -p /opt/locketgold_v2
sudo chown $USER:$USER /opt/locketgold_v2
git clone -b fix/security-staging-readiness https://github.com/vuthanhluan206/locketgold_system.git /opt/locketgold_v2
cd /opt/locketgold_v2
mkdir -p backups certs_public certs_private
```

### Bước 2: Chuẩn bị file `.env` cho Staging (Cô lập Database Test)

```bash
cp .env.example .env
nano .env
```

Các thiết lập quan trọng trong `/opt/locketgold_v2/.env` khi chạy Staging:
- `MONGODB_DATABASE=locket_manager_staging` (Cô lập hoàn toàn khỏi `locket_manager` production khi test ghi dữ liệu).
- `REQUIRE_HTTPS=true` và `TRUSTED_PROXY_CIDRS=["127.0.0.1/32","172.16.0.0/12"]`:
  - Các health/readiness probes từ loopback (`http://127.0.0.1:8000/api/health` và `/api/ready`) được phép đi qua HTTP nội bộ.
  - Các request đi qua Caddy Reverse Proxy (kèm `X-Forwarded-Proto: https` từ dải IP `TRUSTED_PROXY_CIDRS`) được nhận diện là HTTPS hợp lệ và không bao giờ gặp lỗi HTTP `400` hay `502`.
- `ENABLE_RESEARCH_PROXY=false` (mặc định tắt proxy bên thứ ba).
- `ALLOWED_HOSTS=["locketgold.vuthanhluan.bond","localhost","127.0.0.1","[::1]"]`.

### Bước 3: Khởi chạy Core Staging Stack (Không cần bật Lab CA tùy chọn)

```bash
docker compose -p locket_staging -f compose.staging.yaml up -d --build
```

Kiểm tra trạng thái container và probes:

```bash
docker compose -p locket_staging -f compose.staging.yaml ps
curl -fsS http://127.0.0.1:18000/api/health | jq .
curl -fsS http://127.0.0.1:18000/api/ready | jq .
```

### Bước 4 (Tùy chọn): Sinh chứng chỉ Research Lab & Bật `--profile lab`

Nếu muốn kiểm thử thêm listener HTTPS Lab trên `127.0.0.1:18443` và tải profile `?mode=lab_ca`:

```bash
# 1. Sinh Root CA (public: certs_public/, private: certs_private/)
docker exec locket_staging_api python -m scripts.generate_lab_ca --out-public /app/certs_public --out-private /app/certs_private --domains locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond,sub.lab.vuthanhluan.bond

# 2. Khởi chạy thêm container lab_https qua profile "lab"
docker compose -p locket_staging -f compose.staging.yaml --profile lab up -d
```

---

## 3. KIỂM THỬ XÁC MINH TRÊN STAGING (SMOKE TESTS)

### 3.1. Kiểm tra Liveness (`/api/health`) và MongoDB Readiness (`/api/ready`)

```bash
curl -fsS http://127.0.0.1:18000/api/health | jq .
curl -fsS http://127.0.0.1:18000/api/ready | jq .
```

### 3.2. Kiểm tra HTTPS Forwarding (Mô phỏng Caddy -> FastAPI với `REQUIRE_HTTPS=true`)

```bash
curl -fsSI -H "Host: locketgold.vuthanhluan.bond" -H "X-Forwarded-Proto: https" http://127.0.0.1:18000/
curl -fsSI -H "Host: locketgold.vuthanhluan.bond" -H "X-Forwarded-Proto: https" "http://127.0.0.1:18000/profile.mobileconfig?mode=dns_only"
curl -fsS -H "Host: locketgold.vuthanhluan.bond" -H "X-Forwarded-Proto: https" "http://127.0.0.1:18000/api/accounts/lookup?query=https://locket.cam/testuser" | jq .
```

### 3.3. Kiểm tra Sao lưu bền vững trên `./backups` (Không mất file sau khi container `--rm` kết thúc)

```bash
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --backup /app/backups/staging_test_backup.json --dry-run
ls -lh ./backups/staging_test_backup.json
docker compose -p locket_staging -f compose.staging.yaml run --rm api python -m scripts.migrate_db --verify-backup /app/backups/staging_test_backup.json
```

### 3.4. Dọn dẹp Staging sau khi kiểm thử

```bash
docker compose -p locket_staging -f compose.staging.yaml --profile lab down
```
