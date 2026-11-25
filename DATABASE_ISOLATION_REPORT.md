# BÁO CÁO CÔ LẬP DATABASE STAGING & NHẤT QUÁN DỮ LIỆU (`DATABASE_ISOLATION_REPORT.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Database Production được bảo vệ:** `locket_manager`
**Database Staging cô lập:** `locket_manager_staging`
**Ngày cập nhật:** 2026-11-25

---

## 1. BỐN LỚP CHỐT CHẶN BẢO VỆ DATABASE PRODUCTION (`locket_manager`)

Để đảm bảo quá trình kiểm thử Staging, chạy E2E và seed dữ liệu mẫu **không bao giờ** ghi đè, xóa hoặc làm biến đổi dữ liệu khách hàng thật trong `locket_manager`:

1. **Chốt chặn cấp độ Ứng dụng (`app/config.py` — `Settings.deployment_hosts`)**:
   - Khi `APP_ENV=staging` (được gắn cứng trong `compose.staging.yaml` và `.env.staging.example`), nếu `MONGODB_DATABASE` có giá trị là `locket_manager`, Pydantic `Settings` ném `ValidationError` ngay lập tức và **từ chối khởi động container**.
2. **Chốt chặn cấp độ Preflight (`scripts/staging_preflight.py`)**:
   - Kiểm tra `MONGODB_DATABASE != 'locket_manager'` và bắt buộc tên database kết thúc bằng `_staging` hoặc `_test` (hoặc bắt đầu bằng `locket_test_`).
   - Ẩn toàn bộ thông tin xác thực trong URI (`mask_mongodb_uri()` trả về `mongodb+srv://***@host`), kiểm tra quyền ghi của UID `10001` trên thư mục `/app/backups` và thực hiện lệnh `ping` kiểm tra kết nối.
3. **Chốt chặn cấp độ Seeder (`scripts/seed_staging_db.py`)**:
   - Hàm `assert_safe_staging_db_name()` từ chối chạy (`RuntimeError: SAFETY ABORT`) nếu tên database là `locket_manager` hoặc không có hậu tố `_staging`/`_test`.
   - Chỉ tạo 3 bản ghi thử nghiệm tổng hợp (`staging_active_user`, `staging_expired_user`, `staging_revoked_user`), không chứa bất kỳ dữ liệu người dùng thật nào.
4. **Chốt chặn cấp độ Migration & Rollback (`scripts/migrate_db.py`)**:
   - Khi `APP_ENV=staging` và `dry_run=False`, `run_migration_cli()` từ chối thực hiện thao tác ghi nếu phát hiện `MONGODB_DATABASE == 'locket_manager'`.

---

## 2. XỬ LÝ LỖI GHI GIỮA CHỪNG & CƠ CHẾ ĐỐI SOÁT (`scripts/migrate_db.py --reconcile`)

### 2.1. Công bố rõ giới hạn về Atomicity trên nhiều Collection
- Hệ thống duy trì `accounts_v2` (Canonical Store), `accounts` (Legacy Mirror) và `entitlements` (Gold Projection).
- Trên các cụm MongoDB độc lập hoặc khi không mở multi-document transaction cho từng request đơn lẻ, nếu xảy ra sự cố đứt kết nối mạng ngay giữa bước ghi số 1 (`accounts`), bước 2 (`accounts_v2`) và bước 3 (`entitlements`), API sẽ lập tức ném lỗi `PyMongoError` và trả về **HTTP `503 Service Unavailable`** (không bao giờ báo HTTP 200 thành công giả), nhưng dữ liệu giữa 3 collection có thể tạm thời lệch nhau ở bản ghi đó.

### 2.2. Cơ chế phát hiện và đồng bộ phục hồi (`reconcile_collections`)
Chúng tôi đã xây dựng lệnh `python -m scripts.migrate_db --reconcile` (`--dry-run` hoặc `--apply`) với quy tắc **Fail-Closed Revocation**:
- **Không bao giờ tự động khôi phục trạng thái `active` cho tài khoản đã bị `revoked`**: Nếu một tài khoản bị đánh dấu `revoked` ở **bất kỳ** collection nào (`accounts_v2` hoặc `accounts`) do lệnh thu hồi trước đó bị ngắt giữa chừng, trình đối soát sẽ lan truyền trạng thái `revoked` sang toàn bộ các collection còn lại.
- Đồng bộ `expires_date` chuẩn từ `accounts_v2` sang `accounts` và `entitlements`.
- Đã được kiểm chứng tự động qua `tests/test_prompt8_staging_hardening.py::test_problem7_mongodb_reconciliation_never_reactivates_revoked_accounts` (PASSED).
