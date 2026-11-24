# ĐÁNH GIÁ MỨC ĐỘ SẴN SÀNG TRIỂN KHAI CUỐI CÙNG (`FINAL_READINESS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_v2_fixed.zip`)
**Ngày đánh giá:** 2026-11-25
**Hạ tầng mục tiêu:** Ubuntu VPS (`103.118.29.159`, ~1 GB RAM, tên miền `locketgold.vuthanhluan.bond`, MongoDB Atlas `locket_manager`, NextDNS ID `a8b247`)

---

## 1. BẢNG ĐÁNH GIÁ KỸ THUẬT TRUNG THỰC THEO TỪNG HẠNG MỤC

| Hạng mục kiểm định | Trạng thái | Bằng chứng kỹ thuật đã xác minh |
| :--- | :---: | :--- |
| **1. Tương thích Biến môi trường VPS (`.env`)** | **READY (VERIFIED)** | `app/config.py` hỗ trợ song song `SUPERADMIN_EMAIL` / `ADMIN_EMAIL`, `SUPERADMIN_PASSWORD_HASH` / `ADMIN_PASSWORD_HASH`, `MONGODB_URI` / `MONGO_URI`. Tự động chặn nếu khai báo xung đột và không bao giờ in password hash ra log. |
| **2. Triển khai Staging không xung đột cổng 80/443** | **READY (VERIFIED)** | `compose.staging.yaml` chỉ bind loopback `127.0.0.1:18000:8000` và `127.0.0.1:18443:8443` với tên container riêng (`locket_staging_*`), chạy song song an toàn khi Caddy cũ đang chiếm cổng 80/443. |
| **3. An toàn Cơ sở dữ liệu & Migration có kiểm soát** | **READY (VERIFIED)** | Đã gỡ bỏ hoàn toàn auto-migration khỏi FastAPI startup (`app/database.py:lifespan`). Migration chỉ chạy qua CLI `scripts/migrate_db.py` với `--dry-run`, `--backup`, phát hiện bản ghi lỗi/xung đột (không ghi đè dữ liệu mới hơn trong `accounts_v2`) và hậu kiểm `verify_post_migration()`. |
| **4. Công cụ Rollback phân tách Partial vs Full** | **READY (VERIFIED)** | `scripts/migrate_db.py` tính và kiểm tra mã băm `snapshot_sha256` trước khi rollback. Hỗ trợ `--mode partial` (mặc định, không xóa bản ghi mới) và `--mode full` (khôi phục đúng 100% trạng thái cũ, bắt buộc có `--confirm-destructive`). |
| **5. Chứng chỉ X.509 Research Lab & `.mobileconfig`** | **READY (VERIFIED)** | Tách biệt rõ khoá riêng (`certs_private/`) và chứng chỉ công khai (`certs_public/`). Hỗ trợ tải profile DNS-only (`?mode=dns_only` cho Production) và profile Lab CA (`?mode=lab_ca` / `?mode=scoped_lab` cho Research Lab). Mọi file `.mobileconfig` đều qua kiểm tra `plistlib.loads()`. |
| **6. Xác minh Định danh Trung thực (Zero-Guessing Policy)** | **READY (VERIFIED)** | `app/services/identity_service.py` phân loại rõ: link `locket.cam/<username>` là `unverified_handle`; chuỗi 28 ký tự không có bằng chứng xác thực ngoài là `unverified_uid` (`format_only_uid`, `uid_verified=False`); chỉ khi có `trusted_proof=True` mới nhận `verified_uid`. |
| **7. Nhất quán Entitlement & Fail-Closed** | **READY (VERIFIED)** | Mọi trạng thái `active`, `expired`, `revoked`, `pending`, `unauthorized` dùng chung `compute_entitlement_status()`. Không có fallback năm 2029. Khi MongoDB lỗi kết nối/xác thực, endpoint trả về HTTP `503 Service Unavailable`. |
| **8. Bộ Kiểm thử Tự động (Automated Test Suite)** | **READY (87/87 PASSED)** | 87/87 bài kiểm thử chạy thực tế bằng `pytest` đều PASS với 0 warning (1 bài test tích hợp daemon MongoDB ngoại vi được skip an toàn khi không đặt `TEST_MONGODB_URI`). |

---

## 2. PHÂN ĐỊNH RÕ RÀNG GIỮA CƠ CHẾ ĐÃ CHỨNG MINH VÀ GIẢ THUYẾT NGHIÊN CỨU

1. **Những gì hệ thống này ĐÃ CHỨNG MINH & ĐẢM BẢO 100% (`VERIFIED`):**
   - Quản lý tài khoản thử nghiệm, thiết bị iOS, thu hồi quyền tức thì và ghi nhận nhật ký đã che dữ liệu nhạy cảm trên database `locket_manager`.
   - Sinh cấu hình `.mobileconfig` chuẩn Apple cho NextDNS DoH (`https://dns.nextdns.io/a8b247`) kèm hoặc không kèm Root CA của Research Lab.
   - Mô phỏng chính xác cấu trúc JSON phản hồi thuê bao (`CustomerInfo`) trên các endpoint thuộc quyền kiểm soát của Lab (`/v1/subscribers/{account_id}`).
2. **Những gì KHÔNG KHẲNG ĐỊNH / GIỚI HẠN KỸ THUẬT THỰC TẾ:**
   - Một phản hồi JSON mô phỏng `Gold` từ Research Lab **không đồng nghĩa** với việc ứng dụng Locket chính thức từ App Store thực sự mở khóa tính năng Gold trên hệ thống máy chủ thực của nhà phát triển Locket / RevenueCat.
   - Việc cài đặt cấu hình NextDNS thuần túy (`?mode=dns_only`) chỉ định tuyến truy vấn DNS qua NextDNS, hoàn toàn không tự cấp quyền thuê bao trong ứng dụng.

---

## 3. KẾT LUẬN PHÊ DUYỆT TRIỂN KHAI (FINAL VERDICT)

- **Phân loại mức độ sẵn sàng:** **READY FOR STAGING & CONTROLLED PRODUCTION CUTOVER**
- Toàn bộ mã nguồn, cấu hình Docker (`compose.yaml`, `compose.staging.yaml`, `compose.lab.yaml`), công cụ migration/rollback (`scripts/migrate_db.py`), bộ test tự động (`tests/`) và 8 tài liệu vận hành đã được đóng gói sạch sẽ vào `locketgold_v2_fixed.zip` (không chứa file `.env` thật, không chứa private key `.key` hay dữ liệu nhạy cảm).
