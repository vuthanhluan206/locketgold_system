# HƯỚNG DẪN ROLLBACK KHẨN CẤP CHO DOCKER & MONGODB (`ROLLBACK_GUIDE.md`)

Tài liệu này quy định quy trình khôi phục (rollback) an toàn ở cả hai tầng: **Tầng Container/Reverse Proxy (Docker & Caddy)** và **Tầng Cơ sở dữ liệu (MongoDB `accounts_v2`)**.

---

## 1. PHÂN BIỆT ROLLBACK COLLECTION (`accounts_v2`) VỚI KHÔI PHỤC TOÀN BỘ DATABASE

| Phương thức | Phạm vi tác động | Khi nào sử dụng |
| :--- | :--- | :--- |
| **Collection Rollback (`scripts/migrate_db.py --rollback`)** | Chỉ khôi phục collection `accounts_v2` từ file JSON snapshot đã xác minh SHA-256. Giữ nguyên `accounts` (v1), `admins`, `sessions`, `audit` và `devices`. | Khi cần hoàn tác một đợt migration `accounts` $\rightarrow$ `accounts_v2` hoặc khôi phục trạng thái thuê bao trong `accounts_v2` mà không làm đăng xuất Admin hay mất audit log. |
| **Full Database Restore (`mongorestore` / Atlas Point-in-Time Snapshot)** | Khôi phục toàn bộ các collection trong database `locket_manager`. | Chỉ dùng trong thảm họa toàn diện cấp độ cluster trên MongoDB Atlas Console. |

---

## 2. ROLLBACK TẦNG CONTAINER (QUAY VỀ BẢN `locket.gold` CŨ TRONG 15 GIÂY)

Vì quy trình triển khai mới **bảo toàn 100% collection `accounts` cũ** và không xóa volume của bản cũ:

```bash
cd /opt/locketgold_v2
docker compose -f compose.yaml down

cd ~/locket.gold
docker compose up -d
```

> **Lưu ý an toàn:** Không bao giờ chạy `docker system prune --volumes` hoặc `docker volume rm` để tránh làm mất chứng chỉ TLS Let's Encrypt trong volume `caddy_data`.

---

## 3. ROLLBACK TẦNG COLLECTION `accounts_v2` (`scripts/migrate_db.py`)

### Bước 1: Xác minh tính toàn vẹn của file Backup trên đĩa Host (`./backups`)

```bash
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --verify-backup /app/backups/pre_prod_migration.json
```

### Bước 2: Xem trước kế hoạch Rollback (Dry-Run Preview)

```bash
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --rollback /app/backups/pre_prod_migration.json --mode partial --dry-run
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --rollback /app/backups/pre_prod_migration.json --mode full --dry-run
```

### Bước 3A: Chế độ Partial Rollback (`--mode partial` — Mặc định, Không xóa bản ghi mới)

Chỉ upsert lại các bản ghi có trong snapshot, giữ nguyên các tài khoản mới được tạo sau thời điểm backup:

```bash
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --rollback /app/backups/pre_prod_migration.json --mode partial
```

### Bước 3B: Chế độ Full Collection State Rollback (`--mode full --confirm-destructive`)

Đưa collection `accounts_v2` quay về **chính xác 100% trạng thái tại thời điểm chụp snapshot** (bao gồm xóa các bản ghi phát sinh sau snapshot). Bắt buộc phải truyền cờ `--confirm-destructive`:

```bash
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --rollback /app/backups/pre_prod_migration.json --mode full --confirm-destructive
```
