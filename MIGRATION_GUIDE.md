# HƯỚNG DẪN SAO LƯU & MIGRATION MONGODB CÓ KIỂM SOÁT (`MIGRATION_GUIDE.md`)

Tài liệu này hướng dẫn quy trình sao lưu, kiểm tra thử (`--dry-run`), thực thi migration (`--apply`) và hậu kiểm dữ liệu từ collection `accounts` (v1) sang `accounts_v2` (v2) trên database `locket_manager` mà **không làm mất hay biến đổi bất kỳ dữ liệu hiện có nào**.

---

## 1. NGUYÊN TẮC AN TOÀN DỮ LIỆU

1. **Không tự động chạy khi khởi động ứng dụng**: FastAPI `lifespan` đã được gỡ bỏ hoàn toàn việc tự động chạy migration. Mọi thao tác chuyển đổi schema chỉ diễn ra khi người vận hành chủ động gọi CLI `scripts/migrate_db.py`.
2. **Bảo toàn 100% collection `accounts` cũ**: Quá trình migration chỉ đọc từ `accounts` và ghi bổ sung sang `accounts_v2`. Collection `accounts` gốc không bị xóa hay sửa đổi.
3. **Không ghi đè dữ liệu mới hơn (Conflict Protection)**: Nếu một `locket_id` đã tồn tại trong `accounts_v2` với trạng thái `revoked`, `pending` hoặc có `expires_date` khác với bản ghi cũ trong `accounts`, công cụ sẽ **bỏ qua không ghi đè** và báo cáo vào danh sách `conflict`.
4. **Bắt buộc tạo Snapshot có mã băm SHA-256 trước khi ghi**: Mọi file backup JSON đều chứa trường `snapshot_sha256` để đảm bảo tính toàn vẹn khi cần rollback.

---

## 2. QUY TRÌNH 4 BƯỚC THỰC HIỆN MIGRATION TRÊN VPS

### Bước 1: Xuất bản sao lưu JSON (kèm mã kiểm tra SHA-256)

Chạy lệnh sau từ thư mục dự án (hoặc bên trong container `locket_staging_api` / `locket_lab_api`):

```bash
python -m scripts.migrate_db --backup backup_pre_migration_$(date +%Y%m%d_%H%M%S).json --dry-run
```

**Kết quả mong đợi:**
- File JSON được tạo ra trên đĩa, bên trong chứa `exported_at`, `schema_version: 2`, `snapshot_sha256`, toàn bộ danh sách `accounts` và `accounts_v2`.
- Đồng thời in báo cáo `Migration report (dry_run=True)` mà chưa thực hiện bất kỳ lệnh ghi nào vào database.

### Bước 2: Kiểm tra báo cáo Dry-Run (`--dry-run`)

```bash
python -m scripts.migrate_db --dry-run
```

**Ý nghĩa các chỉ số trong báo cáo:**
- `total_legacy`: Tổng số bản ghi hiện có trong collection `accounts`.
- `inserted`: Số bản ghi hợp lệ sẽ được thêm mới vào `accounts_v2`.
- `skipped`: Số bản ghi đã tồn tại đồng nhất trong `accounts_v2` (bỏ qua an toàn).
- `invalid`: Số bản ghi trong `accounts` bị thiếu `locket_id`, sai định dạng ký tự (`ACCOUNT_ID_REGEX`) hoặc `expires_date` không thể phân tích.
- `conflict`: Số bản ghi đã tồn tại trong `accounts_v2` nhưng có trạng thái hoặc ngày hết hạn khác với `accounts` (được bảo vệ, không bị ghi đè).

### Bước 3: Áp dụng Migration có kiểm soát (`--apply`)

Sau khi đã có file backup ở Bước 1 và kiểm tra chỉ số `invalid` / `conflict` ở Bước 2:

```bash
python -m scripts.migrate_db --backup backup_before_apply.json --apply
```

### Bước 4: Xác minh sau Migration (Post-Migration Verification)

Khi chạy `--apply`, công cụ sẽ tự động gọi hàm `verify_post_migration(db)` và in ra kết quả:

```json
{
  "legacy_count": 10,
  "v2_count": 10,
  "missing_in_v2": [],
  "verified": true
}
```

Nếu `"verified": true` và `"missing_in_v2": []`, toàn bộ các bản ghi hợp lệ từ `accounts` đã có mặt đầy đủ trong `accounts_v2`.
