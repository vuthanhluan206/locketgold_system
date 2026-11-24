# NHỮNG GIỚI HẠN KỸ THUẬT ĐÃ XÁC MINH — `KNOWN_LIMITATIONS.md`

Tài liệu này ghi nhận trung thực các giới hạn kỹ thuật của giao thức iOS DNS-over-HTTPS, X.509 PKI và cơ chế xác minh thuê bao để không nhầm lẫn giữa môi trường mô phỏng (Research Lab) và hệ thống sản xuất của bên thứ ba:

1. **Phản hồi Mock JSON không thay đổi trạng thái trên Server chính thức của nhà phát triển:**
   - Endpoint `GET /v1/subscribers/{account_id}` trong dự án này chỉ trả về cấu trúc dữ liệu `CustomerInfo` dựa trên database `locket_manager` của Research Lab.
   - Nó không tạo giao dịch App Store (`StoreKit`), không sinh biên lai JWS của Apple và không thay đổi trạng thái tài khoản trên máy chủ backend chính thức của Locket Labs hay RevenueCat.

2. **Public Share Link (`https://locket.cam/<username>`) không chứa Firebase UID xác thực:**
   - Đường dẫn chia sẻ công khai chỉ chứa `username` (handle). Trong khi đó, định danh tài khoản nội bộ trên hệ thống Firebase/RevenueCat là chuỗi UID 28 ký tự alphanumeric.
   - Do đó, `Account Identity Service` (`app/services/identity_service.py`) luôn phân biệt rõ `verified_uid` (khi cung cấp đúng UID 28 ký tự) với `unverified_handle` (khi chỉ cung cấp link username), không tự suy đoán.

3. **Giới hạn của DNS-over-HTTPS (NextDNS):**
   - Bản thân NextDNS (`https://dns.nextdns.io/a8b247`) chỉ phân giải tên miền sang địa chỉ IP. NextDNS không phải là máy chủ HTTP Proxy, không thể chấm dứt TLS và không thể sửa đổi nội dung gói tin JSON.
   - Nếu cấu hình DNS Rewrite trên NextDNS chỉ ghi đè bản ghi `A` (IPv4) mà tên miền đích có bản ghi `AAAA` (IPv6) hoặc bản ghi `HTTPS` (Type 65), iOS sẽ ưu tiên kết nối qua IPv6 tới máy chủ thật.

4. **Hồ sơ `.mobileconfig` chưa ký CMS và thao tác Bật Full Trust thủ công:**
   - Tệp `.mobileconfig` do hệ thống sinh ra là XML Plist chuẩn (`application/x-apple-aspen-config`), chưa được ký bằng chứng chỉ Apple Developer/MDM CMS nên iOS sẽ hiển thị nhãn *"Not Signed / Chưa được ký"* khi cài đặt.
   - Ngay cả khi cài đặt payload `com.apple.security.root`, iOS không bao giờ tự động bật Full Trust cho chứng chỉ gốc trên thiết bị cá nhân không qua Supervised MDM.

5. **Trạng thái Kiểm thử Thiết bị Thực tế:**
   - Toàn bộ Unit Tests, Integration Tests, X.509 Certificate Validation Tests và Regression Tests đã được chạy và xác minh tự động (`VERIFIED`).
   - Các bước cài đặt trực tiếp trên thiết bị iPhone vật lý và kết nối tới MongoDB Atlas production cần được thực hiện bởi quản trị viên trên môi trường VPS thực tế (`NOT VERIFIED` trong môi trường local sandbox).
