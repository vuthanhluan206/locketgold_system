# HƯỚNG DẪN ROLLBACK KHẨN CẤP CHO DOCKER & MONGODB (`ROLLBACK_GUIDE.md`)

Tài liệu này quy định quy trình khôi phục (rollback) an toàn ở cả hai tầng: **Tầng Container/Reverse Proxy (Docker & Caddy)** và **Tầng Cơ sở dữ liệu (MongoDB `accounts_v2`)**.

---

## 1. ROLLBACK TẦNG CONTAINER (QUAY VỀ BẢN `locket.gold` CŨ TRONG 15 GIÂY)

Vì quy trình triển khai mới **bảo toàn 100% collection `accounts` cũ** và không xóa volume của bản cũ:

### Bước 1: Hạ container bản v2 mới trên cổng 80/443

```bash
cd /opt/locketgold_v2
docker compose -f compose.yaml down
```

### Bước 2: Bật lại container bản cũ

```bash
cd ~/locket.gold
docker compose up -d
```

> **Lưu ý an toàn:** Không bao giờ chạy `docker system prune --volumes` hoặc `docker volume rm` để tránh làm mất chứng chỉ TLS Let's Encrypt đã cấp trong volume `caddy_data`.

---

## 2. ROLLBACK TẦNG CƠ SỞ DỮ LIỆU MONGODB (`scripts/migrate_db.py`)

Công cụ `scripts/migrate_db.py` đã được thiết kế lại với cơ chế **kiểm tra mã băm toàn vẹn SHA-256 (`snapshot_sha256`)** và phân tách rõ 2 chế độ Rollback để tránh xóa nhầm dữ liệu mới phát sinh:

### 2.1. Xem trước kế hoạch Rollback (Dry-Run Preview)

Trước khi thực hiện rollback từ file snapshot `backup_before_apply.json`, luôn chạy lệnh xem trước (`--dry-run`):

```bash
python -m scripts.migrate_db --rollback backup_before_apply.json --mode partial --dry-run
python -m scripts.migrate_db --rollback backup_before_apply.json --mode full --dry-run
```

Công cụ sẽ kiểm tra chữ ký `snapshot_sha256` của file backup và in ra bản xem trước:
```json
{
  "mode": "full",
  "snapshot_records_count": 10,
  "current_records_count": 12,
  "to_upsert_count": 10,
  "to_delete_count": 2,
  "extra_ids_created_after_snapshot": ["new_user_1", "new_user_2"]
}
```

### 2.2. Chế độ 1: Partial Rollback (`--mode partial` — Mặc định, Không xóa bản ghi mới)

Sử dụng khi bạn chỉ muốn khôi phục lại trạng thái của các bản ghi có trong file snapshot mà **không muốn xóa** các tài khoản thử nghiệm mới được tạo thêm sau thời điểm tạo snapshot:

```bash
python -m scripts.migrate_db --rollback backup_before_apply.json --mode partial
```

- **Hành vi:** Upsert lại toàn bộ các bản ghi trong `snapshot['accounts_v2']`. Các bản ghi mới tạo sau snapshot được giữ nguyên.

### 2.3. Chế độ 2: Full Collection State Rollback (`--mode full --confirm-destructive`)

Sử dụng khi bạn muốn đưa collection `accounts_v2` quay về **chính xác 100% trạng thái tại thời điểm chụp snapshot** (bao gồm cả việc xóa bỏ các bản ghi được tạo thêm sau thời điểm chụp snapshot):

```bash
python -m scripts.migrate_db --rollback backup_before_apply.json --mode full --confirm-destructive
```

- **Cơ chế bảo vệ hai lớp:** Nếu trong `accounts_v2` hiện tại có bất kỳ bản ghi nào phát sinh sau snapshot (`extra_ids_created_after_snapshot` khác rỗng) mà bạn không truyền cờ `--confirm-destructive`, công cụ sẽ **tự động từ chối xóa** và báo lỗi yêu cầu xác nhận rõ ràng.
