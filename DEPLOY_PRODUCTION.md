# HƯỚNG DẪN CHUYỂN ĐỔI (CUTOVER) LÊN PRODUCTION AN TOÀN (`DEPLOY_PRODUCTION.md`)

Tài liệu này hướng dẫn quy trình chuyển đổi (cutover) từ hệ thống `locket.gold` cũ sang bản `locketgold_v2_fixed` trên VPS `103.118.29.159` (`locketgold.vuthanhluan.bond`) với thời gian gián đoạn tối thiểu và bảo toàn tuyệt đối chứng chỉ Let's Encrypt cũng như dữ liệu MongoDB.

---

## 1. DANH SÁCH KIỂM TRA TRƯỚC KHI CUTOVER (PRE-CUTOVER CHECKLIST)

Trước khi dừng container cũ trên cổng 80/443, đảm bảo bạn đã hoàn tất 4 mục sau:
1. [x] Đã chạy thành công toàn bộ bước kiểm thử trên cổng nội bộ `127.0.0.1:18000` theo `DEPLOY_STAGING.md`.
2. [x] Đã xuất bản sao lưu MongoDB JSON kèm mã băm SHA-256:
   ```bash
   docker exec -it locket_staging_api python -m scripts.migrate_db --backup /tmp/backup_cutover.json --dry-run
   docker cp locket_staging_api:/tmp/backup_cutover.json ~/backup_cutover_$(date +%Y%m%d).json
   ```
3. [x] Đã kiểm tra dung lượng RAM và Swap của VPS (`free -m` đảm bảo còn trống tối thiểu 300 MB hoặc đã bật 1 GB Swap).
4. [x] Trong file `/opt/locketgold_v2/.env`:
   - `REQUIRE_HTTPS=true`
   - `ALLOWED_HOSTS=["locketgold.vuthanhluan.bond","localhost","127.0.0.1"]`
   - Nếu chạy Production chỉ phát cấu hình NextDNS thuần túy, để trống `ROOT_CA_PATH=` và `ROOT_CA_PEM=`. (Nếu muốn bật song song tính năng tải profile Lab CA qua `?mode=lab_ca`, trỏ `ROOT_CA_PATH=/app/certs_public/lab_root_ca.pem`).

---

## 2. QUY TRÌNH CUTOVER TỪ BẢN CŨ SANG BẢN MỚI

### Bước 1: Dừng stack Staging (nếu đang bật) và Build sẵn Image Production

Build sẵn image trước khi dừng bản cũ để thời gian chuyển cổng chỉ mất vài giây:

```bash
cd /opt/locketgold_v2
docker compose -p locket_staging -f compose.staging.yaml down
docker compose -f compose.yaml build
```

### Bước 2: Thực hiện Migration dữ liệu `accounts` -> `accounts_v2`

```bash
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --backup /tmp/pre_prod_migration.json --apply
```

Kiểm tra dòng thông báo `Post-migration verification: {"legacy_count": ..., "v2_count": ..., "missing_in_v2": [], "verified": true}`.

### Bước 3: Dừng hệ thống `locket.gold` cũ (Giải phóng cổng 80 và 443)

> **CẢNH BÁO QUAN TRỌNG:** Chỉ dùng `docker compose down` trên thư mục cũ. **TUYỆT ĐỐI KHÔNG** chạy `docker system prune --volumes` hoặc `docker compose down -v` trên thư mục cũ để giữ nguyên dữ liệu volume của bản cũ phòng trường hợp cần rollback nhanh!

```bash
cd ~/locket.gold   # (Hoặc đường dẫn thư mục chứa bản cũ đang chạy)
docker compose down
```

### Bước 4: Khởi chạy Production Stack mới trên cổng 80/443

```bash
cd /opt/locketgold_v2
docker compose -f compose.yaml up -d
```

*(Tùy chọn)* Nếu muốn bật thêm listener HTTPS Research Lab trên cổng nội bộ `127.0.0.1:8443` mà không ảnh hưởng cổng 80/443:

```bash
docker compose -f compose.yaml -f compose.lab.yaml up -d
```

---

## 3. KIỂM TRA HẬU TRIỂN KHAI (POST-DEPLOYMENT VERIFICATION)

1. **Kiểm tra Health Check qua HTTPS tên miền chính thức:**
   ```bash
   curl -fsS https://locketgold.vuthanhluan.bond/api/health | jq .
   ```
2. **Kiểm tra tải file `.mobileconfig`:**
   ```bash
   curl -fsSI https://locketgold.vuthanhluan.bond/profile.mobileconfig
   ```
   Đảm bảo trả về `HTTP/2 200` và `content-type: application/x-apple-aspen-config`.
3. **Kiểm tra đăng nhập Admin Dashboard:**
   Truy cập `https://locketgold.vuthanhluan.bond/admin`, đăng nhập bằng tài khoản Superadmin, kiểm tra danh sách tài khoản cũ hiển thị đầy đủ trạng thái `ACTIVE` / `EXPIRED` / `REVOKED`.
