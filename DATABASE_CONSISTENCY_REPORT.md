# BÁO CÁO TÍNH NHẤT QUÁN CƠ SỞ DỮ LIỆU MONGODB (`DATABASE_CONSISTENCY_REPORT.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Database mục tiêu:** `locket_manager`
**Ngày báo cáo:** 2026-11-25

---

## 1. QUY ĐỊNH NGUỒN DỮ LIỆU CHÍNH THỨC DUY NHẤT (CANONICAL SOURCE OF TRUTH)

Để đảm bảo khả năng tương thích ngược 100% với cấu trúc cũ mà vẫn hỗ trợ đầy đủ vòng đời thuê bao và thiết bị của Research Lab, kiến trúc lưu trữ trong database `locket_manager` được quy định chặt chẽ như sau:

| Collection | Vai trò trong kiến trúc | Quy tắc đọc / ghi |
| :--- | :--- | :--- |
| **`accounts_v2`** | **Canonical Store (Nguồn sự thật chính thức duy nhất)** | Lưu trữ đầy đủ `locket_id`, `status` (`active`, `expired`, `revoked`, `pending`), `expires_date`, `revoked_at`, `revoke_reason`, `verification_status`, `verification_method`, `max_devices`, `updated_at`. Mọi thao tác Admin (`add-account`, `revoke`, `activate`, `delete`) **bắt buộc** phải ghi thành công vào `accounts_v2` (nếu collection được cấu hình). |
| **`accounts`** | **Legacy Compatibility Mirror (Bản chiếu tương thích ngược)** | Được cập nhật đồng bộ cùng `accounts_v2` (bao gồm cả trường `status` và `revoked_at`) để nếu người vận hành rollback container về bản `locket.gold` v1 cũ thì dữ liệu vẫn đọc được ngay mà không bị mất tài khoản mới. |
| **`entitlements`** | **Entitlement Audit Projection** | Lưu bản ghi chi tiết quyền `Gold` (`com.locket.gold.yearly`) gắn với `account_id`. |
| **`devices`** | **Device Authorization Registry** | Lưu `device_id`, `locket_id`, `token_hash` (SHA-256), `status` (`active` / `revoked`). Ràng buộc trực tiếp `device_token` với đúng 1 `locket_id`. |

---

## 2. QUY TẮC HỢP NHẤT & ƯU TIÊN TRẠNG THÁI (`merge_canonical_and_legacy_account`)

Hàm `merge_canonical_and_legacy_account(doc_v2, doc_v1)` trong [app/services/entitlement_service.py](file:///e:/locketgold/app/services/entitlement_service.py) thực thi 4 bất biến (invariants) sau trên mọi API (`GET /admin/accounts`, `GET /v1/subscribers/{id}`, `GET /api/lab/subscribers/{id}`, `/proxy/*`):

1. **Bất biến Thu hồi (Revocation Precedence Invariant):**
   - Nếu `doc_v2` có `status == 'revoked'` hoặc `revoked_at != None` hoặc `is_active == False`, trạng thái sau hợp nhất **luôn luôn là `'revoked'`**.
   - Một bản ghi cũ trong `accounts` (`doc_v1`) chỉ có `expires_date` ở tương lai và không có trường `status` **không bao giờ** có thể ghi đè hoặc kích hoạt lại một tài khoản đã bị `revoked` trong `accounts_v2`.
2. **Bất biến Không bỏ sót tài khoản (`v2-only` Visibility Invariant):**
   - `GET /admin/accounts` lấy tập hợp hợp nhất `all_ids = sorted(set(v1_map.keys()) | set(v2_map.keys()))`. Các tài khoản chỉ tồn tại trong `accounts_v2` luôn hiển thị đầy đủ trên Admin Dashboard và có thể được kích hoạt, thu hồi hoặc xóa (`DELETE /admin/accounts/{id}`) bình thường.
3. **Bất biến Không nuốt lỗi ghi (No Silent Write Failure Invariant):**
   - Toàn bộ các khối `try ... except Exception: pass` quanh lệnh `accounts_v2.update_one()`, `accounts_v2.delete_one()`, `entitlements.update_one()` trong [app/routers/management.py](file:///e:/locketgold/app/routers/management.py) đã được gỡ bỏ.
   - Nếu bất kỳ lệnh ghi bắt buộc nào gặp lỗi kết nối, hết thời gian chờ hoặc lỗi quyền ghi (`PyMongoError`), API dừng ngay và trả về **HTTP `503 Service Unavailable`** thông qua global exception handler trong [app/main.py](file:///e:/locketgold/app/main.py).
4. **Bất biến Không tự động biến đổi DB khi Startup (Zero Startup Mutation Invariant):**
   - Hàm `lifespan(app)` trong [app/database.py](file:///e:/locketgold/app/database.py) chỉ kiểm tra kết nối (`ping`), khởi tạo index và đảm bảo tài khoản `superadmin` tồn tại (`$setOnInsert`). Tuyệt đối không chạy migration tự động khi container khởi động.

---

## 3. KIỂM THỬ MÔ PHỎNG LỖI GHI & ĐỐI CHIẾU TRẠNG THÁI

Các kịch bản đã được kiểm thử tự động trong `tests/test_prompt7_security_and_staging.py`:
- **Kịch bản 1 (Legacy Active vs Canonical Revoked):** Bản ghi `revoked_user` có `expires_date = now + 120 days` trong `accounts` (không có trường `status`) nhưng có `status = 'revoked'` trong `accounts_v2` $\rightarrow$ `/v1/subscribers/revoked_user` trả về `X-Lab-Entitlement-Status: revoked` và `entitlements: {}`.
- **Kịch bản 2 (Tài khoản chỉ nằm trong `accounts_v2`):** Bản ghi `v2_only_user` chỉ có trong `accounts_v2` $\rightarrow$ `GET /admin/accounts` trả về đầy đủ `v2_only_user` và `DELETE /admin/accounts/v2_only_user` xóa sạch trả về HTTP `204`.
- **Kịch bản 3 (Lỗi ghi trên `accounts_v2` giữa chừng):** Giả lập `accounts_v2.update_one` ném `PyMongoError('WriteConcernError')` khi gọi `POST /admin/add-account` và `POST /admin/accounts/{id}/revoke` $\rightarrow$ API trả về ngay HTTP `503 Service Unavailable`, không báo thành công giả và không làm lộ chuỗi `'WriteConcernError'` ra response JSON.
- **Kịch bản 4 (Sao lưu & Migration trên tập dữ liệu > 10.000 bản ghi):** Kiểm thử `export_backup_to_dict()` và `verify_backup_file_on_disk()` với `10.500` bản ghi, xác nhận không bị cắt cụt ở mốc 10.000 bản ghi và mã băm `snapshot_sha256` khớp tuyệt đối.
