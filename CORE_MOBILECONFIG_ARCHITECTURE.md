# KIẾN TRÚC CỐT LÕI HAI PAYLOAD CỦA `.mobileconfig` (`CORE_MOBILECONFIG_ARCHITECTURE.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Tài liệu gốc đối chiếu:** `cotloicualocketgold.txt` và `LocketGold_Clean_Unlocked.mobileconfig`
**Ngày cập nhật:** 2026-11-25

---

## 1. BẢO TOÀN KIẾN TRÚC HAI PAYLOAD CỐT LÕI

Trong cấu hình gốc `LocketGold_Clean_Unlocked.mobileconfig` (và mô tả trong `cotloicualocketgold.txt`), một hồ sơ cấu hình iOS (`.mobileconfig`) dành cho môi trường Research Lab gồm một container `PayloadType = Configuration` (`PayloadScope = System`) chứa đúng **2 payload thành phần** trong mảng `PayloadContent`:

| Thứ tự | `PayloadType` | Vai trò kỹ thuật trên iOS | Chế độ `dns_only` (Production) | Chế độ `lab_ca` / `scoped_lab` (Research Lab) |
| :---: | :--- | :--- | :---: | :---: |
| **1** | **`com.apple.dnsSettings.managed`** | Cấu hình hệ thống phân giải tên miền qua giao thức **DNS-over-HTTPS (`DNSProtocol = HTTPS`)** tới `ServerURL`, kèm tùy chọn `SupplementalMatchDomains` (Split-DNS). | **Có** (Payload duy nhất) | **Có** (Đi kèm `SupplementalMatchDomains` giới hạn trong các tên miền của Lab) |
| **2** | **`com.apple.security.root`** | Cài đặt chứng chỉ công khai X.509 Root CA ở định dạng nhị phân DER (`PayloadContent = <DER bytes>`) vào kho chứng chỉ của iOS. | **Không** (Tuyệt đối không nhúng CA trên Production) | **Có** (Nhúng chứng chỉ công khai của Lab Root CA đã kiểm định chữ ký và thời hạn) |

---

## 2. PHÂN TÍCH ĐỘC LẬP 6 MẮT XÍCH KỸ THUẬT (KHÔNG ĐÁNH ĐỒNG CÁC BƯỚC)

Một hệ thống kiểm thử mạng trên iOS bao gồm 6 mắt xích hoàn toàn độc lập. Việc tạo được file XML `.mobileconfig` chỉ là mắt xích đầu tiên và không tự động đồng nghĩa với các mắt xích sau:

1. **DNS-only Resolution (`com.apple.dnsSettings.managed` không có `SupplementalMatchDomains`)**:
   - Toàn bộ truy vấn DNS của hệ điều hành iOS được gửi qua kết nối HTTPS tới `ServerURL` (ví dụ: `https://dns.nextdns.io/a8b247`).
   - Nếu máy chủ DoH trả về địa chỉ IP thực của máy chủ đích trên Internet, lưu lượng HTTPS sau đó vẫn đi thẳng tới máy chủ gốc mà không qua bất kỳ proxy nào.
2. **Split DNS với `SupplementalMatchDomains`**:
   - Khi mảng `SupplementalMatchDomains` được khai báo, trình phân giải `mDNSResponder` của iOS chỉ gửi truy vấn DNS của các tên miền nằm trong danh sách này tới `ServerURL`, còn mọi tên miền khác vẫn dùng DNS mặc định của mạng Wi-Fi / 4G.
   - Trong tài liệu gốc `LocketGold_Clean_Unlocked.mobileconfig`, có 7 tên miền bên thứ ba được liệt kê (`api.revenuecat.com`, `revenuecat.com`, `firebaseremoteconfig.googleapis.com`, `firebaseremoteconfigrealtime.googleapis.com`, `firebaselogging.googleapis.com`, `adsbynimbus.com`, `locketlabs-locketcamera.adsbynimbus.com`).
   - **Ranh giới an toàn bắt buộc trong `locketgold_system`:** Chúng tôi giữ nguyên danh sách 7 tên miền này trong báo cáo phân tích học thuật, nhưng trong mã nguồn vận hành (`app/config.py`, `scripts/generate_lab_ca.py`), hệ thống **cấm tuyệt đối** việc đưa tên miền thanh toán/dịch vụ bên thứ ba vào `LAB_SCOPED_DOMAINS` hoặc chứng chỉ Leaf. Mọi bài kiểm thử chủ động chỉ sử dụng các tên miền thuộc quyền sở hữu của bạn (`mock.lab.vuthanhluan.bond`, `sub.lab.vuthanhluan.bond`, `locketgold.vuthanhluan.bond`).
3. **DNS Response có địa chỉ IP tùy chỉnh (Custom A / AAAA Record)**:
   - Máy chủ DoH của Lab (`/dns-query`) trả về bản ghi `A` trỏ tên miền thử nghiệm (`mock.lab.vuthanhluan.bond`) về địa chỉ IP của máy chủ Mock HTTPS Lab (`127.0.0.1` khi chạy `LAB_MODE=local`, hoặc IPv4 công khai của VPS `103.118.29.159` khi chạy `LAB_MODE=real_device` cho iPhone thật).
4. **HTTPS Proxy / Mock Server Routing**:
   - Sau khi nhận IP từ bước 3, ứng dụng hoặc client thử nghiệm trên iPhone mở kết nối TCP/TLS tới địa chỉ IP đó và gửi tên miền trong trường **TLS SNI (Server Name Indication)** cũng như header HTTP `Host`.
5. **TLS Certificate Validation**:
   - Hệ điều hành iOS kiểm tra chứng chỉ Leaf mà máy chủ HTTPS trả về:
     - Chữ ký số của Leaf phải được ký bởi một Root CA đã được cài đặt **và** được người dùng bật công tắc **Full Trust** trong *Certificate Trust Settings*.
     - Tên miền trong SNI phải khớp với trường `SubjectAlternativeName (SAN)` của chứng chỉ Leaf.
     - Thời hạn hiệu lực của chứng chỉ Leaf phải $\le 397$ ngày theo chuẩn Apple HT210176.
6. **Application-Layer Certificate Pinning & Server-Side Verification**:
   - Ngay cả khi hệ điều hành iOS chấp nhận chứng chỉ Root CA do người dùng bật Full Trust (bước 5), một ứng dụng chính thức có áp dụng **SSL/Certificate Pinning** ở tầng ứng dụng (ghim cứng khóa công khai SPKI của máy chủ thật) sẽ từ chối kết nối TLS tới máy chủ Mock.
   - Hơn nữa, phản hồi JSON mô phỏng từ Mock Lab không tạo ra bản ghi giao dịch trên máy chủ backend thực của nhà phát triển ứng dụng.
