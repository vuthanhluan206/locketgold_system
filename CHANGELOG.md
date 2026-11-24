# NHẬT KÝ THAY ĐỔI HỆ THỐNG (`CHANGELOG.md`)

Tài liệu này ghi lại đầy đủ các thay đổi kỹ thuật qua các giai đoạn, đặc biệt là các bản sửa lỗi sẵn sàng triển khai thực tế (Prompt 6 — Production Readiness) trong gói `locketgold_v2_fixed.zip`.

---

## [2.1.0-production-ready] — 2026-11-25 (Prompt 6 Fixes)

### 1. Cấu hình & Tương thích Biến môi trường (`app/config.py`, `.env.example`)
- **Bổ sung `AliasChoices` tương thích ngược với VPS hiện tại**:
  - `superadmin_email` chấp nhận `SUPERADMIN_EMAIL` hoặc `ADMIN_EMAIL`.
  - `superadmin_password_hash` chấp nhận `SUPERADMIN_PASSWORD_HASH` hoặc `ADMIN_PASSWORD_HASH`.
  - `mongodb_uri` chấp nhận `MONGODB_URI` hoặc `MONGO_URI`.
- **Phát hiện xung đột biến môi trường (`check_legacy_admin_conflicts`)**:
  - Nếu người vận hành khai báo đồng thời cả `SUPERADMIN_EMAIL` và `ADMIN_EMAIL` (hoặc cả `SUPERADMIN_PASSWORD_HASH` và `ADMIN_PASSWORD_HASH`) với hai giá trị khác nhau, hệ thống dừng khởi động ngay với thông báo lỗi rõ ràng để tránh đăng nhập nhầm tài khoản.
  - Đảm bảo không bao giờ ghi nội dung password hash ra stdout/stderr hoặc thông báo lỗi `ValidationError`.

### 2. Kiến trúc Docker Staging Không Xung Đột Cổng (`compose.staging.yaml`)
- Tạo mới file `compose.staging.yaml` dành riêng cho bước kiểm thử song song trên VPS `103.118.29.159` trong khi hệ thống cũ vẫn đang giữ cổng `80` và `443`:
  - Container `locket_staging_api` chỉ bind vào loopback `127.0.0.1:18000:8000` (`mem_limit: 256m`).
  - Container `locket_staging_lab_https` chỉ bind vào loopback `127.0.0.1:18443:8443` và `127.0.0.1:18081:8081` (`mem_limit: 64m`).
  - Không bao giờ chạm tới cổng `80` hoặc `443` và dùng volume riêng (`staging_lab_caddy_data`, `staging_lab_caddy_config`).

### 3. Gỡ bỏ Auto-Migration lúc Startup & Nâng cấp CLI Migration (`app/database.py`, `scripts/migrate_db.py`)
- **Loại bỏ tự động ghi DB khi khởi động**: Xoá lệnh gọi `await sync_legacy_accounts_to_v2(db)` ra khỏi `lifespan(app)` trong `app/database.py`.
- **Hàm `run_controlled_migration(db, dry_run=...)`**:
  - Kiểm tra tính hợp lệ của từng bản ghi trong `accounts` (định dạng `locket_id` theo `ACCOUNT_ID_REGEX` và trường `expires_date`).
  - Phát hiện bản ghi trùng lặp (`skipped`) và xung đột (`conflict`): nếu bản ghi trong `accounts_v2` đã bị `revoked`/`pending` hoặc có `expires_date` khác với bản ghi legacy, hệ thống giữ nguyên bản ghi `accounts_v2` và ghi nhận vào `conflict_records` chứ không ghi đè.
  - Bổ sung hàm `verify_post_migration(db)` đối chiếu số lượng bản ghi sau khi chạy `--apply`.

### 4. Công cụ Rollback An toàn với Kiểm tra Toàn vẹn SHA-256 (`scripts/migrate_db.py`)
- Mỗi bản sao lưu xuất ra bởi `export_backup_to_dict(db)` đều đi kèm mã băm `snapshot_sha256` tính trên dữ liệu chuẩn hóa của `accounts` và `accounts_v2`.
- Hàm `verify_snapshot_integrity(snapshot)` tự động chặn quá trình rollback nếu file JSON bị sửa đổi hoặc hỏng.
- Bổ sung `preview_rollback(db, snapshot, mode='partial'|'full')` và nâng cấp `restore_rollback_from_dict(db, snapshot, mode='partial'|'full', confirm_destructive=False)`:
  - `mode='partial'` (mặc định): Chỉ khôi phục/upsert các bản ghi có trong snapshot, giữ nguyên các tài khoản mới được tạo sau thời điểm backup.
  - `mode='full'`: Khôi phục chính xác trạng thái collection `accounts_v2` tại thời điểm backup (bao gồm cả việc xóa các bản ghi phát sinh sau snapshot). Bắt buộc phải truyền `--confirm-destructive` (`confirm_destructive=True`) nếu có bản ghi cần xóa.

### 5. Đánh giá Định danh Trung thực (`app/models.py`, `app/services/identity_service.py`)
- Mở rộng `VerificationStatus` thêm trạng thái `'unverified_uid'` và `VerificationMethod` thêm `'trusted_proof'`, `'format_only_uid'`.
- Khi nhập một chuỗi 28 ký tự alphanumeric khớp định dạng Firebase UID nhưng không có bằng chứng xác thực từ nguồn tin cậy (`trusted_proof=False`), hệ thống trả về:
  - `uid_verified=False`
  - `verification_status='unverified_uid'`
  - `verification_method='format_only_uid'`
- Chỉ khi `trusted_proof=True` mới trả về `uid_verified=True` và `verification_status='verified_uid'`.

### 6. Cấu hình Mobileconfig & Tự kiểm tra Plist (`app/profile.py`, `app/routers/management.py`)
- Hỗ trợ 4 chế độ tải profile tại `/profile.mobileconfig?mode=default|dns_only|lab_ca|scoped_lab`.
- Mọi dữ liệu XML sinh ra bởi `build_profile()` đều được kiểm tra ngược bằng `plistlib.loads()` trước khi trả về cho thiết bị iOS.
