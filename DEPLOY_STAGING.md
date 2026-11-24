# HƯỚNG DẪN TRIỂN KHAI STAGING KHÔNG XUNG ĐỘT CỔNG (`DEPLOY_STAGING.md`)

Tài liệu này hướng dẫn triển khai và kiểm thử bản mã nguồn `locketgold_v2_fixed` ở chế độ **Staging** ngay trên VPS `103.118.29.159` (~1 GB RAM) **trong khi hệ thống `locket.gold` cũ vẫn đang chạy bình thường trên cổng 80 và 443**.

---

## 1. KIẾN TRÚC CÔ LẬP STAGING (`compose.staging.yaml`)

Trên VPS hiện tại, container Caddy cũ đang giữ các cổng `0.0.0.0:80` và `0.0.0.0:443`. Nếu chạy trực tiếp `compose.yaml` (Production), Docker sẽ báo lỗi xung đột cổng (`bind: address already in use`).

Do đó, `compose.staging.yaml` được thiết kế với các đặc tính cô lập hoàn toàn:
- **Tên project & container riêng biệt**: `locket_staging_api` và `locket_staging_lab_https`.
- **Chỉ bind vào Loopback (`127.0.0.1`) trên cổng cao**:
  - FastAPI Staging API: `127.0.0.1:18000 -> 8000` (`mem_limit: 256m`)
  - HTTPS Research Lab Listener: `127.0.0.1:18443 -> 8443` và `127.0.0.1:18081 -> 8081` (`mem_limit: 64m`)
- **Không chiếm cổng 80/443**: Dịch vụ cũ tại `https://locketgold.vuthanhluan.bond` không bị gián đoạn một giây nào trong suốt quá trình kiểm thử Staging.

---

## 2. CÁC BƯỚC TRIỂN KHAI STAGING TRÊN VPS

### Bước 1: Giải nén mã nguồn vào thư mục Staging riêng

Không ghi đè lên thư mục của hệ thống cũ đang chạy. Tạo thư mục mới `/opt/locketgold_v2`:

```bash
sudo mkdir -p /opt/locketgold_v2
sudo chown $USER:$USER /opt/locketgold_v2
cd /opt/locketgold_v2
unzip ~/locketgold_v2_fixed.zip -d /opt/locketgold_v2
```

### Bước 2: Chuẩn bị file `.env` và chứng chỉ Lab (nếu thử nghiệm HTTPS Lab)

```bash
cp .env.example .env
nano .env
```

Lưu ý cấu hình trong `.env`:
- Hệ thống hỗ trợ cả tên biến mới (`SUPERADMIN_EMAIL`, `SUPERADMIN_PASSWORD_HASH`, `MONGODB_URI`) lẫn tên biến cũ trên VPS (`ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`, `MONGO_URI`). Nếu khai báo cả hai thì giá trị phải giống hệt nhau.
- Đặt `ALLOWED_HOSTS=["locketgold.vuthanhluan.bond","localhost","127.0.0.1","[::1]"]`.
- Tạo chứng chỉ Root CA và Leaf Certificate cho Research Lab (khoá riêng lưu trong `certs_private/`, chứng chỉ công khai lưu trong `certs_public/`):

```bash
python3 -m scripts.generate_lab_ca --out-public certs_public --out-private certs_private
```

### Bước 3: Khởi chạy Staging Stack

```bash
docker compose -p locket_staging -f compose.staging.yaml up -d --build
```

Kiểm tra trạng thái container và dung lượng RAM tiêu thụ:

```bash
docker compose -p locket_staging -f compose.staging.yaml ps
docker stats --no-stream locket_staging_api locket_staging_lab_https
```

---

## 3. KIỂM THỬ XÁC MINH TRÊN STAGING (SMOKE TESTS)

### 3.1. Kiểm tra Health Endpoint

```bash
curl -fsS http://127.0.0.1:18000/api/health | jq .
```

Kết quả mong đợi:
```json
{
  "status": "ok",
  "database": "locket_manager",
  "nextdns_configured": true,
  "nextdns_id": "a8b247",
  "profile_ready": true
}
```

### 3.2. Kiểm tra tải cấu hình `.mobileconfig` (DNS-only và Scoped Lab)

```bash
# Chế độ Production DNS-only (chỉ có NextDNS a8b247, không chứa Root CA)
curl -fsSI "http://127.0.0.1:18000/profile.mobileconfig?mode=dns_only"

# Chế độ Scoped Lab (NextDNS + SupplementalMatchDomains)
curl -fsSI "http://127.0.0.1:18000/profile.mobileconfig?mode=scoped_lab"
```

### 3.3. Kiểm tra Dry-Run Migration (không ghi DB)

```bash
docker exec -it locket_staging_api python -m scripts.migrate_db --dry-run
```

### 3.4. Gỡ bỏ Staging sau khi kiểm thử xong (để chuẩn bị Cutover sang Production)

```bash
docker compose -p locket_staging -f compose.staging.yaml down
```
