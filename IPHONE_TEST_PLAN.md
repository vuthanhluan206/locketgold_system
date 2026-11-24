# KẾ HOẠCH KIỂM THỬ THỰC TẾ TRÊN IPHONE — `IPHONE_TEST_PLAN.md`

Tài liệu này quy định quy trình 8 bước kiểm thử độc lập trên thiết bị iPhone thật đối với hệ thống `locketgold.vuthanhluan.bond` và cấu hình NextDNS `a8b247`.

---

## Quy trình 8 Bước Kiểm thử

### Bước 1: Đăng ký Tài khoản & Thiết bị trên Admin Dashboard
1. Mở `https://locketgold.vuthanhluan.bond/admin` và đăng nhập tài khoản quản trị.
2. Tại mục **1. Account Link & Identifier Verification**, dán link tài khoản hoặc UID để kiểm tra trạng thái xác minh (`verified_uid`, `unverified_handle`, `manual_lab_id`).
3. Bấm **+ Add / Renew Account** để thêm tài khoản kiểm thử với ngày hết hạn trong tương lai.
4. Bấm **+ Link Device**, nhập ID tài khoản và tên iPhone để nhận mã `device_token` (`lkg_dev_...`).

### Bước 2: Cài đặt Cấu hình NextDNS (`.mobileconfig`) trên iPhone
1. Mở trình duyệt **Safari** trên iPhone, truy cập `https://locketgold.vuthanhluan.bond/`.
2. Bấm **Tải về cấu hình (.mobileconfig)** &rarr; chọn **Cho phép (Allow)**.
3. Mở ứng dụng **Cài đặt (Settings)** &rarr; **Đã tải về hồ sơ (Profile Downloaded)** &rarr; nhấn **Cài đặt (Install)** và nhập mật mã màn hình.
4. Vào **Cài đặt** &rarr; **Cài đặt chung** &rarr; **Quản lý VPN & thiết bị** &rarr; xác nhận mục **DNS** đang chọn **Locket Gold DNS**.

### Bước 3: Xác minh Kết nối DoH qua `test.nextdns.io`
1. Mở Safari trên iPhone và truy cập `https://test.nextdns.io`.
2. Kiểm tra kết quả JSON hiển thị:
   - `"status": "ok"`
   - `"protocol": "DOH"`
   - `"profile": "a8b247"`
3. Mở bảng điều khiển NextDNS (`my.nextdns.io/a8b247/logs`) và xác nhận các truy vấn DNS từ iPhone được ghi nhận theo thời gian thực.

### Bước 4: Cài đặt và Kiểm tra Root CA trong Research Lab (Khi kiểm thử TLS Lab)
1. Nếu hồ sơ có kèm payload `Root CA` của Research Lab, vào **Cài đặt** &rarr; **Cài đặt chung** &rarr; **Giới thiệu** &rarr; **Cài đặt tin cậy chứng nhận (Certificate Trust Settings)**.
2. Đối chiếu SHA-256 Fingerprint của chứng chỉ với thông tin tại `/api/health`.
3. Chỉ bật công tắc tin cậy cho chứng chỉ Lab Root CA do chính bạn tự sinh trên VPS (tuyệt đối không bật tin cậy cho các chứng chỉ lạ không rõ nguồn gốc khóa riêng).

### Bước 5: Kiểm tra HTTPS với Domain Lab
1. Truy cập domain kiểm thử của Lab (`https://locketgold.vuthanhluan.bond/api/health`) từ Safari trên iPhone.
2. Xác nhận kết nối TLS thành công, không có lỗi chứng chỉ và trả về `"status": "ok"`.

### Bước 6: Kiểm tra Phản hồi Thuê bao Giả lập (Mock Entitlement) & Thu hồi Quyền
1. Gọi endpoint kiểm tra thuê bao với `device_token` vừa tạo:
   - Khi tài khoản ở trạng thái `ACTIVE`: API `/v1/subscribers/{account_id}` trả về `subscriber.entitlements.Gold` kèm đúng `expires_date` và header `X-Lab-Entitlement-Status: active`.
2. Trên Admin Dashboard, bấm nút **Revoke** trên dòng tài khoản đó.
3. Gọi lại endpoint `/v1/subscribers/{account_id}` từ thiết bị:
   - Xác nhận phản hồi trả về `subscriber.entitlements: {}` và header `X-Lab-Entitlement-Status: revoked` ngay lập tức.
4. Kiểm tra mục **3. Linked iPhone Test Devices & Lab Requests** trên Admin Dashboard để thấy cả 2 lượt gọi được ghi nhận đầy đủ trong `lab_requests`.

### Bước 7: Quan sát Trạng thái Thực tế trên Ứng dụng
1. Mở ứng dụng trên iPhone và quan sát hành vi thực tế, các truy vấn DNS xuất hiện trong NextDNS Logs và thông báo lỗi mạng (nếu có).
2. Ghi nhận kết quả vào hệ thống qua API `POST /admin/test-results` mà không suy diễn từ trạng thái mock JSON.
