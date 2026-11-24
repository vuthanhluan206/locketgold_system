# HƯỚNG DẪN SAO LƯU & MIGRATION MONGODB CÓ KIỂM SOÁT (`MIGRATION_GUIDE.md`)

Tài liệu này hướng dẫn quy trình sao lưu bền vững trên host disk, kiểm tra thử (`--dry-run`), thực thi migration (`--apply`) và hậu kiểm dữ liệu từ collection `accounts` (v1) sang `accounts_v2` (v2) trên database `locket_manager` mà **không làm mất hay biến đổi bất kỳ dữ liệu hiện có nào**.

---

## 1. NGUYÊN TẮC AN TOÀN DỮ LIỆU

1. **Không tự động chạy khi khởi động ứng dụng**: FastAPI `lifespan` không bao giờ tự động chạy migration. Mọi thao tác chuyển đổi schema chỉ diễn ra khi người vận hành chủ động gọi CLI `scripts/migrate_db.py`.
2. **Không bao giờ lưu bản sao lưu duy nhất vào `/tmp` của container `--rm`**: Trong `compose.yaml` và `compose.staging.yaml`, thư mục `./backups` trên host đã được mount trực tiếp vào `/app/backups` trong container. Mọi file backup phải được ghi vào `/app/backups/...` và xác minh sự tồn tại trên host bằng `--verify-backup`.
3. **Không giới hạn 10.000 bản ghi**: Hàm `_fetch_all_documents()` đọc toàn bộ tài liệu từ `accounts` và `accounts_v2` mà không bị cắt cụt ở 10.000 bản ghi.
4. **Không ghi đè dữ liệu mới hơn (Conflict Protection)**: Nếu một `locket_id` đã tồn tại trong `accounts_v2` với trạng thái `revoked`, `pending` hoặc có `expires_date` khác với bản ghi cũ trong `accounts`, công cụ sẽ **bỏ qua không ghi đè** và báo cáo vào danh sách `conflict`.

---

## 2. QUY TRÌNH 4 BƯỚC THỰC HIỆN MIGRATION TRÊN VPS

### Bước 1: Xuất bản sao lưu JSON bền vững lên thư mục `./backups` trên Host

```bash
mkdir -p ./backups
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --backup /app/backups/backup_pre_migration.json --dry-run
```

### Bước 2: Xác minh file Backup đã tồn tại bền vững trên Host sau khi container kết thúc

Ngay sau khi container `run --rm` kết thúc, kiểm tra file trên host:

```bash
ls -lh ./backups/backup_pre_migration.json
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --verify-backup /app/backups/backup_pre_migration.json
```

**Kết quả mong đợi:**
- In ra `Backup verification PASSED` với `size_bytes > 0`, `accounts_count`, `accounts_v2_count`, `snapshot_sha256` và `"verified": true`.

### Bước 3: Áp dụng Migration có kiểm soát (`--apply`)

Sau khi đã xác minh file backup trên host:

```bash
docker compose -f compose.yaml run --rm api python -m scripts.migrate_db --backup /app/backups/backup_before_apply.json --apply
```

### Bước 4: Xác minh sau Migration (Post-Migration Verification)

Khi chạy `--apply`, công cụ tự động gọi hàm `verify_post_migration(db)` để kiểm tra toàn bộ bản ghi hợp lệ từ `accounts` đã có mặt trong `accounts_v2` (`"verified": true`, `"missing_in_v2": []`).
