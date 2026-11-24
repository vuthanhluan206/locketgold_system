# HƯỚNG DẪN CHUYỂN ĐỔI (CUTOVER) LÊN PRODUCTION AN TOÀN (`DEPLOY_PRODUCTION.md`)

Tài liệu này hướng dẫn quy trình chuyển đổi (cutover) từ hệ thống `locket.gold` cũ sang bản `locketgold_v2_fixed` trên VPS `103.118.29.159` (`locketgold.vuthanhluan.bond`) với thời gian gián đoạn tối thiểu và bảo toàn tuyệt đối chứng chỉ Let's Encrypt cũng như dữ liệu MongoDB.

---

## 1. DANH SÁCH KIỂM TRA TRƯỚC KHI CUTOVER (PRE-CUTOVER CHECKLIST)

Trước khi dừng container cũ trên cổng 80/443, đảm bảo bạn đã hoàn tất 5 mục sau:
1. [x] Đã chạy thành công toàn bộ bước kiểm thử Staging trên cổng nội bộ `127.0.0.1:18000` theo `DEPLOY_STAGING.md` (`/api/health` và `/api/ready` đều trả HTTP 200).
2. [x] Đã xuất bản sao lưu MongoDB JSON trực tiếp ra volume bền vững `./backups` trên host và xác minh sau khi container kết thúc:
   ```bash
   mkdir -p /opt/locketgold_v2/backups
   docker exec locket_staging_api python -m scripts.migrate_db --backup /app/backups/backup_cutover.json --dry-run
   docker exec locket_staging_api python -m scripts.migrate_db --verify-backup /app/backups/backup_cutover.json
   ls -lh /opt/locketgold_v2/backups/backup_cutover.json
   ```
3. [x] Đã kiểm tra dung lượng RAM và Swap của VPS (`free -m` đảm bảo còn trống tối thiểu 300 MB hoặc đã bật 1 GB Swap).
4. [x] Trong file `/opt/locketgold_v2/.env`:
   - `REQUIRE_HTTPS=true`
   - `ENABLE_RESEARCH_PROXY=false` (bắt buộc tắt proxy trong production)
   - `TRUSTED_PROXY_CIDRS=["172.16.0.0/12"]` (tin cậy mạng bridge nội bộ của container Caddy đứng trước FastAPI)
   - `ALLOWED_HOSTS=["locketgold.vuthanhluan.bond","localhost","127.0.0.1"]`
   - Để trống `ROOT_CA_PATH=` và `ROOT_CA_PEM=` trên Production để phát cấu hình NextDNS thuần túy (`?mode=dns_only` / `default`).

---

## 2. QUY TRÌNH CUTOVER TỪ BẢN CŨ SANG BẢN MỚI

### Bước 1: Dừng stack Staging và Build sẵn Image Production

```bash
cd /opt/locketgold_v2
docker compose -p locket_staging -f compose.staging.yaml down
docker compose -f compose.yaml build
```

### Bước 2: Thực hiện Migration dữ liệu `accounts` -> `accounts_v2` với Backup bền vững trên `./backups`

```bash
mkdir -p /opt/locketgold_v2/backups
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --backup /app/backups/pre_prod_migration.json --apply
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --verify-backup /app/backups/pre_prod_migration.json
```

### Bước 3: Dừng hệ thống `locket.gold` cũ (Giải phóng cổng 80 và 443)

> **CẢNH BÁO QUAN TRỌNG:** Chỉ dùng `docker compose down` trên thư mục cũ. **TUYỆT ĐỐI KHÔNG** chạy `docker system prune --volumes` hoặc `docker compose down -v` để giữ nguyên dữ liệu volume của bản cũ phòng trường hợp cần rollback nhanh!

```bash
cd ~/locket.gold
docker compose down
```

### Bước 4: Khởi chạy Production Stack mới trên cổng 80/443

```bash
cd /opt/locketgold_v2
docker compose -f compose.yaml up -d
```

---

## 3. KIỂM TRA HẬU TRIỂN KHAI (POST-DEPLOYMENT VERIFICATION)

1. **Kiểm tra Liveness & Readiness Check qua HTTPS tên miền chính thức:**
   ```bash
   curl -fsS https://locketgold.vuthanhluan.bond/api/health | jq .
   curl -fsS https://locketgold.vuthanhluan.bond/api/ready | jq .
   ```
2. **Kiểm tra tải file `.mobileconfig`:**
   ```bash
   curl -fsSI https://locketgold.vuthanhluan.bond/profile.mobileconfig
   ```
3. **Kiểm tra Research Proxy đã bị khóa an toàn trên Production (trả HTTP 403):**
   ```bash
   curl -i https://locketgold.vuthanhluan.bond/proxy/v1/subscribers/test
   ```
