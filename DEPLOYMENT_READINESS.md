# DEPLOYMENT READINESS ASSESSMENT — ĐÁNH GIÁ MỨC ĐỘ SẴN SÀNG TRIỂN KHAI

**Ngày đánh giá:** 24/11/2026  
**Hệ thống:** Locket Gold Research & Entitlement Lab (`v2.0.0`)  
**Môi trường mục tiêu:** `https://locketgold.vuthanhluan.bond` (VPS Ubuntu `103.118.29.159`, ~1 GB RAM, MongoDB Atlas `locket_manager`, NextDNS `a8b247`)

---

## 1. KẾT LUẬN ĐÁNH GIÁ CHÍNH THỨC

> [!IMPORTANT]
> **KẾT LUẬN: `CONDITIONALLY READY` (Sẵn sàng triển khai và chạy thử nghiệm trên VPS với các giới hạn môi trường thực tế được ghi rõ bên dưới)**

### Lý do chọn `CONDITIONALLY READY` (Trung thực theo Tiêu chí Nghiệm thu Mục XI & XII):
1. **Toàn bộ phần mềm, kiến trúc, cơ sở dữ liệu và 81 bài kiểm thử tự động tại local đã đạt 100% (`VERIFIED`):**
   - 0 lỗi cú pháp Python (`py_compile` trên toàn bộ 23 file `.py`).
   - 81/81 kịch bản Unit, Integration, PKI/TLS Hostname Verification, Log Redaction, Migration Backup/Rollback và Regression Tests đã chạy thực tế và đạt `PASSED` (0 lỗi P0/P1/P2).
   - Toàn bộ 12 lỗi trong mã nguồn cũ (đặc biệt là lỗi P0 tự cấp quyền Gold tới năm 2029 cho tài khoản không tồn tại và lỗi hardcode NextDNS `8f4cb9` ở trang chủ) đã được khắc phục triệt để.
2. **Điều kiện bắt buộc cần thực hiện trên môi trường VPS & iPhone vật lý (`NOT VERIFIED` từ máy local sandbox):**
   - Môi trường kiểm toán local hiện tại chạy trong sandbox không có kết nối mạng ra VPS `103.118.29.159`, không giữ thông tin đăng nhập MongoDB Atlas production của bạn, và không kết nối trực tiếp với thiết bị iPhone vật lý.
   - Do đó, trước khi chuyển trạng thái sang `READY` hoàn toàn trên production, quản trị viên cần thực hiện danh sách kiểm tra 5 bước trên VPS Ubuntu và iPhone thật ở Mục 2 bên dưới.

---

## 2. CHECKLIST TRIỂN KHAI & ROLLBACK TRÊN VPS UBUNTU (`103.118.29.159`)

### 2.1. Các bước triển khai an toàn (Không mất dữ liệu `locket_manager`)

1. **Sao lưu dữ liệu MongoDB hiện có trước khi nâng cấp:**
   ```bash
   cd /opt/locketgold
   source .venv/bin/activate
   python -m scripts.migrate_db --dry-run --backup ./backup_before_v2.json
   ```
2. **Áp dụng Migration không phá hủy sang `accounts_v2`:**
   ```bash
   python -m scripts.migrate_db --apply
   ```
3. **Khởi tạo chứng chỉ Root CA riêng cho Research Lab (lưu khóa riêng `0600` ngoài web root):**
   ```bash
   python -m scripts.generate_lab_ca --out-dir ./certs_private --domains "locketgold.vuthanhluan.bond,mock.lab.vuthanhluan.bond"
   ```
   *(Nếu muốn nhúng chứng chỉ công khai này vào `.mobileconfig`, đặt `ROOT_CA_PATH=/app/certs_private/lab_root_ca.pem` và mount `./certs_private/lab_root_ca.pem:/app/certs_private/lab_root_ca.pem:ro` trong `compose.yaml`, tuyệt đối không mount file `.key` vào container `api`).*
4. **Khởi chạy Docker Compose chính (Caddy 80/443 + FastAPI 8000):**
   ```bash
   docker compose up -d --build
   curl -s https://locketgold.vuthanhluan.bond/api/health
   ```
5. **(Tùy chọn) Khởi chạy thêm listener HTTPS Lab trên cổng 8443 mà không đụng tới cổng 80/443:**
   ```bash
   docker compose -f compose.yaml -f compose.lab.yaml up -d
   ```

### 2.2. Quy trình Rollback khẩn cấp (Nếu cần quay về phiên bản cũ)

1. **Rollback dữ liệu `accounts_v2` từ bản sao lưu JSON:**
   ```bash
   python -m scripts.migrate_db --rollback ./backup_before_v2.json
   ```
   *(Lưu ý: Collection `accounts` gốc luôn được giữ nguyên 100% nên phiên bản code cũ vẫn đọc được ngay lập tức mà không cần biến đổi lại).*
2. **Rollback container Docker:**
   ```bash
   git checkout <previous_commit_sha>
   docker compose up -d --build
   ```

---

## 3. TỔNG HỢP CÁC GIỚI HẠN KỸ THUẬT CÒN TỒN TẠI (KNOWN LIMITATIONS)

1. **Ranh giới của Mock Entitlement Service:** Phản hồi JSON từ `/v1/subscribers/{account_id}` và `/api/lab/subscribers/{account_id}` chỉ phản ánh trạng thái trong database `locket_manager` của Research Lab cho mục đích nghiên cứu giao thức và kiểm thử client. Hệ thống không giả mạo biên lai thanh toán App Store và không sửa đổi dữ liệu trên máy chủ của Locket Labs hay RevenueCat.
2. **Giới hạn của Link chia sẻ công khai (`https://locket.cam/<username>`):** Link công khai chỉ chứa `username` (handle), không chứa Firebase UID 28 ký tự đã được xác thực mật mã. Hệ thống luôn đánh dấu rõ là `unverified_handle` để quản trị viên biết và cung cấp UID chính xác khi cần.
3. **Yêu cầu thao tác thủ công trên iOS:** Tệp `.mobileconfig` chưa ký CMS sẽ hiển thị *"Not Signed"* khi cài đặt trên iPhone, và việc bật Full Trust cho chứng chỉ Root CA của Lab trong *Settings → General → About → Certificate Trust Settings* luôn phải được người dùng gạt tay trên thiết bị.
