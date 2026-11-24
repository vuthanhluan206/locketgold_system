# HƯỚNG DẪN CÀI ĐẶT, KIỂM THỬ VÀ GỠ BỎ CẤU HÌNH TRÊN IPHONE — `IPHONE_INSTALL_AND_REMOVE_GUIDE.md`

Tài liệu này hướng dẫn chi tiết từng bước cài đặt hồ sơ cấu hình (`.mobileconfig`) gồm **NextDNS (`a8b247`)** và **Chứng chỉ Root CA của Research Lab**, cách kiểm thử với **Lab Test Client**, cũng như quy trình **thu hồi và gỡ bỏ hoàn toàn (Clean Removal)** khỏi iPhone sau khi kết thúc phiên nghiên cứu.

---

## PHẦN 1: CÀI ĐẶT CẤU HÌNH TRÊN IPHONE

### Bước 1: Tải hồ sơ cấu hình qua trình duyệt Safari
1. Mở trình duyệt **Safari** trên iPhone (lưu ý: phải dùng Safari, không dùng trình duyệt nhúng trong Zalo/Messenger/Chrome vì iOS chỉ cho phép Safari nạp trực tiếp hồ sơ vào Cài đặt hệ thống).
2. Truy cập một trong các đường dẫn sau trên hệ thống của bạn:
   - **Cấu hình chuẩn (NextDNS `a8b247` + Lab Root CA):**
     `https://locketgold.vuthanhluan.bond/profile.mobileconfig`
   - **Cấu hình chỉ NextDNS (không cài Root CA):**
     `https://locketgold.vuthanhluan.bond/profile.mobileconfig?mode=dns_only`
   - **Cấu hình Split-DNS chỉ bắt các tên miền thử nghiệm của Lab (`SupplementalMatchDomains`):**
     `https://locketgold.vuthanhluan.bond/profile.mobileconfig?mode=scoped_lab&device_token=<MÃ_DEVICE_TOKEN_CỦA_BẠN>`
3. Khi hộp thoại *"Trang web này đang cố gắng tải về một hồ sơ cấu hình. Bạn có muốn cho phép không?"* xuất hiện, nhấn **Cho phép (Allow)** &rarr; nhấn **Đóng (Close)**.

### Bước 2: Cài đặt hồ sơ trong Cài đặt (Settings)
1. Mở ứng dụng **Cài đặt (Settings)** trên iPhone.
2. Nhấn vào mục **Đã tải về hồ sơ (Profile Downloaded)** hiển thị ngay dưới tên Apple ID của bạn (hoặc vào **Cài đặt chung (General)** &rarr; **Quản lý VPN & thiết bị (VPN & Device Management)**).
3. Chọn hồ sơ **Locket Gold DNS** &rarr; nhấn **Cài đặt (Install)** ở góc trên bên phải.
4. Nhập mật mã mở khóa màn hình iPhone của bạn.
5. Đọc thông tin chi tiết của 2 payload (`NextDNS` và `Root CA`) &rarr; nhấn **Cài đặt (Install)** &rarr; **Xong (Done)**.

### Bước 3: Bật Tin cậy Chứng chỉ Gốc (Chỉ thực hiện khi kiểm thử TLS trong Research Lab)
> [!IMPORTANT]
> Chỉ bật tin cậy cho chứng chỉ **LocketGold Research Lab Root CA** mà chính bạn đã tự khởi tạo trên VPS bằng lệnh `python -m scripts.generate_lab_ca` (đối chiếu đúng mã `SHA-256 Fingerprint` hiển thị trong mục PKI Status trên Admin Dashboard).

1. Mở **Cài đặt (Settings)** &rarr; **Cài đặt chung (General)** &rarr; **Giới thiệu (About)**.
2. Cuộn xuống cuối trang, chọn **Cài đặt tin cậy chứng nhận (Certificate Trust Settings)**.
3. Dưới mục *Bật tin cậy đầy đủ cho chứng nhận gốc (Enable full trust for root certificates)*, tìm đúng tên chứng chỉ **`LocketGold Research Lab Root CA`**.
4. Gạt công tắc sang màu xanh và nhấn **Tiếp tục (Continue)** để xác nhận.

### Bước 4: Kiểm tra Kết nối NextDNS và Lab Test Client
1. Mở Safari trên iPhone, truy cập `https://test.nextdns.io` để xác nhận `"status": "ok"`, `"protocol": "DOH"` và `"profile": "a8b247"`.
2. Mở Admin Dashboard (`https://locketgold.vuthanhluan.bond/admin`), chuyển tới mục **3. Interactive Lab Test Client (Simulated Subscriber Check)**, nhập `Account ID` để kiểm tra ngay các trạng thái `active`, `expired`, `revoked` và `none`, đồng thời quan sát nhật ký Request/Response đã được che dữ liệu nhạy cảm (`***REDACTED***`) ở bảng bên dưới.

---

## PHẦN 2: QUY TRÌNH GỠ BỎ HOÀN TOÀN CẤU HÌNH KHỎI IPHONE (CLEAN REMOVAL)

Khi hoàn tất phiên kiểm thử hoặc muốn đưa iPhone về trạng thái mạng mặc định ban đầu, thực hiện theo đúng thứ tự 3 bước sau:

### Bước 1: Tắt Full Trust của Root CA (Nếu đã bật)
1. Vào **Cài đặt (Settings)** &rarr; **Cài đặt chung (General)** &rarr; **Giới thiệu (About)** &rarr; **Cài đặt tin cậy chứng nhận (Certificate Trust Settings)**.
2. Gạt tắt công tắc của chứng chỉ **`LocketGold Research Lab Root CA`** về màu xám.

### Bước 2: Xóa Hồ sơ Cấu hình (`.mobileconfig`)
1. Vào **Cài đặt (Settings)** &rarr; **Cài đặt chung (General)** &rarr; **Quản lý VPN & thiết bị (VPN & Device Management)**.
2. Dưới mục **Hồ sơ cấu hình (Configuration Profiles)**, chạm vào **Locket Gold DNS**.
3. Nhấn **Xóa hồ sơ (Remove Profile)** (chữ màu đỏ).
4. Nhập mật mã mở khóa màn hình iPhone và nhấn **Xóa (Remove)**.
   - *Ngay khi xóa hồ sơ, iOS sẽ tự động gỡ bỏ cả cấu hình NextDNS DoH lẫn chứng chỉ Root CA đi kèm trong hồ sơ đó khỏi hệ thống.*

### Bước 3: Thu hồi Device Token trên Admin Dashboard và Làm mới DNS Cache
1. Trên Admin Dashboard (`/admin`), tại bảng **Linked iPhone Test Devices**, bấm nút **Revoke Device** cạnh thiết bị vừa gỡ để vô hiệu hóa vĩnh viễn `device_token`.
2. Trên iPhone, bật **Chế độ máy bay (Airplane Mode)** trong 5 giây rồi tắt đi để iOS `mDNSResponder` xóa sạch bộ nhớ đệm DNS (DNS Cache) và quay về sử dụng DNS mặc định của Wi-Fi / 4G.
