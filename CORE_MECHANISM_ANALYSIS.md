# CORE MECHANISM ANALYSIS — KIỂM CHỨNG KỸ THUẬT `cotloicualocketgold.txt`

**Ngày phân tích:** 24/11/2026  
**Phương pháp:** Phân tích mật mã học X.509 thực nghiệm (.NET `X509Certificate2` / DER ASN.1 parsing), đối chiếu đặc tả Apple Configuration Profile (`com.apple.security.root`, `com.apple.dnsSettings.managed`), giao thức RFC 8484 (DoH), RFC 5280 (PKIX) và kiến trúc RevenueCat REST API v1.

---

## 1. PHÂN TÍCH CHỨNG CHỈ SỐ X.509 & PAYLOAD A (`com.apple.security.root`)

### 1.1. Trích xuất và kiểm nghiệm chứng chỉ thực tế từ các file trong Workspace

Chúng tôi đã trích xuất byte nhị phân (DER/PEM) của tất cả các chứng chỉ xuất hiện trong cả 4 gói mã nguồn và tính toán mã băm mật mã học trực tiếp. Phát hiện có **02 chứng chỉ Root CA hoàn toàn khác nhau** đang tồn tại trong dự án:

#### Chứng chỉ #1: `LocketProxy CA`
- **Vị trí xuất hiện:**
  - `LocketGold-Installer.zip -> LocketGoldCA.cer`
  - `LocketGold-Installer.zip -> LocketGold.mobileconfig` (dòng 40–53)
  - `LocketGold-Installer.zip -> LocketGold_Unlocked_XML.mobileconfig` (dòng 40–53)
  - `amlongtruc-source.rar -> LocketGoldCA.cer`
  - `amlongtruc-source.rar -> LocketGold_Clean_Unlocked.mobileconfig` (dòng 40–53)
  - `amlongtruc-source.rar -> LocketGold_dnslocket.mobileconfig` (dòng 40–53)
- **Thông số kỹ thuật X.509 thực tế (đã xác minh):**
  - **Subject:** `C=VN, O=Local Research, CN=LocketProxy CA`
  - **Issuer:** `C=VN, O=Local Research, CN=LocketProxy CA` (Self-signed)
  - **Serial Number:** `01` (`0x01`)
  - **Validity (UTC):**
    - `NotBefore`: `2026-09-26 04:44:42 UTC`
    - `NotAfter`: `2036-09-26 04:44:42 UTC`
  - **Public Key Algorithm:** `RSA (2048 bits)`
  - **Signature Algorithm:** `sha256WithRSAEncryption` (`1.2.840.113549.1.1.11`)
  - **SHA-1 Thumbprint:** `DAC4B786DBBA77A2C40EFBA07EB4C8E1A3CF1526`
  - **SHA-256 Fingerprint:** `16:2C:34:B4:EB:9C:15:42:4D:DE:28:4B:72:9F:A7:0D:35:0C:EB:91:E5:EC:ED:1A:AA:49:FD:E3:B5:85:AF:F1`
  - **X.509v3 Extensions:**
    - `Basic Constraints (2.5.29.19)`: `Critical = False`, `CA:TRUE`, `Path Length Constraint: None`
    - **Không có** `Key Usage (2.5.29.15)`
    - **Không có** `Subject Key Identifier (2.5.29.14)`
    - **Không có** `Subject Alternative Name (SAN)`

#### Chứng chỉ #2: `LocketGold Root CA`
- **Vị trí xuất hiện:**
  - `locket.gold.zip -> locket.gold/web/index.html` (nhúng cứng trong biến JS `mobileConfigXML`, dòng 592–594)
- **Thông số kỹ thuật X.509 thực tế (đã xác minh):**
  - **Subject:** `CN=LocketGold Root CA, O=LocketGold CA, C=US`
  - **Issuer:** `CN=LocketGold Root CA, O=LocketGold CA, C=US` (Self-signed)
  - **Serial Number:** `0AED8D0DDFCEFF03C6077449E345D33665551834`
  - **Validity (UTC):**
    - `NotBefore`: `2026-09-28 16:30:31 UTC`
    - `NotAfter`: `2036-09-25 16:30:31 UTC`
  - **Public Key Algorithm:** `RSA (4096 bits)`
  - **Signature Algorithm:** `sha256WithRSAEncryption` (`1.2.840.113549.1.1.11`)
  - **SHA-256 Fingerprint:** `8E:1E:A1:ED:39:A5:64:58:BE:06:2C:71:F6:07:18:25:3E:98:2C:50:E6:25:0F:85:7B:E1:8E:18:1E:0A:6D:26`
  - **X.509v3 Extensions:**
    - `Basic Constraints (2.5.29.19)`: `Critical = True`, `CA:TRUE`
    - `Key Usage (2.5.29.15)`: `Critical = True`, `Digital Signature, Certificate Signing, Off-line CRL Signing, CRL Signing (0x86)`
    - `Subject Key Identifier (2.5.29.14)`: `Critical = False`, `afe24f0b915a1756313b9f22592f0dbae736b36b`

### 1.2. Đánh giá kỹ thuật PKI / TLS / iOS Trust Store đối với Payload A

1. **Vấn đề thiếu Private Key của cả 2 Root CA trong toàn bộ 5 file:**
   - Trong toàn bộ 5 file được cung cấp, **chỉ có chứng chỉ công khai (Public Certificate `.cer` / `.der`)**, hoàn toàn **không có khóa riêng (`Private Key .key`)** của `LocketProxy CA` hay `LocketGold Root CA`.
   - **Hệ quả mật mã học:** Một máy chủ HTTPS (hoặc MITM Proxy) muốn thiết lập kết nối TLS cho một tên miền (như domain lab hay bất kỳ domain nào được DNS trỏ về IP của nó) bắt buộc phải trình ra một **Server Leaf Certificate** được ký bởi Private Key của Root CA, VÀ phải nắm giữ **Private Key của Leaf Certificate** đó để thực hiện bước `CertificateVerify` trong TLS 1.2 / TLS 1.3 Handshake.
   - Nếu người dùng cài chứng chỉ `LocketProxy CA` trong `.mobileconfig` có sẵn nhưng máy chủ VPS của bạn không nắm giữ Private Key của `LocketProxy CA` để ký chứng chỉ TLS cho máy chủ, thì mọi kết nối HTTPS trỏ về VPS của bạn sẽ thất bại ngay lập tức với lỗi `SSL_ERROR_BAD_CERT_DOMAIN` hoặc `ERR_CERT_AUTHORITY_INVALID` (vì Caddy trên VPS sẽ dùng chứng chỉ Let's Encrypt của `locketgold.vuthanhluan.bond`, không khớp với SNI của domain đích, hoặc tự sinh chứng chỉ Caddy Internal CA không được iPhone tin cậy).

2. **Phân biệt Root CA, Intermediate CA và Server (Leaf) Certificate trên iOS:**
   - **Root CA:** Chứng chỉ tự ký (`Subject == Issuer`), có `BasicConstraints: CA=TRUE` và `KeyUsage: keyCertSign`. Được cài đặt qua payload `com.apple.security.root` làm mỏ neo tin cậy (Trust Anchor).
   - **Intermediate CA:** Được ký bởi Root CA, có `CA=TRUE`, dùng để cấp phát chứng chỉ máy chủ nhằm cách ly khóa gốc.
   - **Server (Leaf) Certificate:** Được ký bởi Root CA hoặc Intermediate CA, có `BasicConstraints: CA=FALSE`, `ExtendedKeyUsage: serverAuth (1.3.6.1.5.5.7.3.1)`, và bắt buộc phải có `SubjectAlternativeName (SAN)` khớp với tên miền trong TLS SNI. Theo chính sách **Apple TLS Server Certificate Requirements (HT210176)**, chứng chỉ Leaf trên iOS bắt buộc phải có RSA $\ge$ 2048-bit (hoặc ECDSA P-256), SHA-256+, phải dùng trường `SAN` (iOS không còn chấp nhận chỉ dùng `CN`), và thời hạn hiệu lực của Leaf cert phát hành sau ngày 01/09/2020 **không được vượt quá 398 ngày** (13 tháng). (Lưu ý: Giới hạn 398 ngày áp dụng cho Server Leaf Certificate, không áp dụng cho Root CA).

3. **Sự khác biệt giữa Cài đặt Profile và Bật Full Trust trên iOS:**
   - Khi người dùng tải `.mobileconfig` qua Safari và bấm **Install** trong *Settings → Profile Downloaded*, chứng chỉ trong `com.apple.security.root` mới chỉ được đưa vào Keychain hệ thống nhưng **chưa được kích hoạt làm TLS Trust Anchor cho các kết nối mạng**.
   - Người dùng bắt buộc phải thực hiện thao tác thủ công: *Settings → General → About → Certificate Trust Settings (Cài đặt tin cậy chứng nhận)* và gạt công tắc dưới mục *Enable full trust for root certificates (Bật tin cậy đầy đủ cho chứng nhận gốc)*. Apple thiết kế bước này không thể tự động hóa đối với thiết bị không thuộc diện Supervised MDM để bảo vệ người dùng khỏi các cấu hình độc hại.

4. **Vì sao tin cậy Root CA KHÔNG tự chuyển lưu lượng qua Proxy:**
   - Root CA chỉ là một tập tin dữ liệu tĩnh nằm trong bộ nhớ kiểm tra chữ ký X.509 của hệ điều hành (`Security.framework`). Nó hoàn toàn **không chứa địa chỉ IP, không chứa cổng mạng, không cấu hình bảng định tuyến (routing table) và không thiết lập HTTP Proxy**. Nếu DNS vẫn trả về IP thật của máy chủ gốc, iPhone vẫn kết nối thẳng tới máy chủ gốc và xác minh bằng Root CA công cộng (như DigiCert, Let's Encrypt, Google Trust Services).

5. **Giới hạn của TLS và Certificate Pinning (SPKI Pinning):**
   - Ngay cả khi DNS đã chuyển hướng tên miền về một máy chủ Proxy và Root CA của Proxy đã được bật Full Trust trên iOS, nếu ứng dụng iOS triển khai **SSL/Certificate Pinning** (ví dụ kiểm tra mã băm SHA-256 của `SubjectPublicKeyInfo` trong delegate `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)` hoặc qua TrustKit / Alamofire `PinnedCertificatesTrustEvaluator`), ứng dụng sẽ đối chiếu khóa công khai của chứng chỉ nhận được với danh sách mã băm gắn cứng trong binary của ứng dụng. Nếu không khớp, ứng dụng tự hủy kết nối TLS bất chấp hệ điều hành iOS đánh giá chứng chỉ là hợp lệ.

---

## 2. PHÂN TÍCH PAYLOAD B (`com.apple.dnsSettings.managed` & DNS-OVER-HTTPS)

### 2.1. Cách iOS áp dụng Managed DNS Settings và `SupplementalMatchDomains`

Trong tài liệu `cotloicualocketgold.txt` và file `LocketGold_Unlocked_XML.mobileconfig`, Payload 2 có cấu trúc:

```xml
<key>DNSSettings</key>
<dict>
  <key>DNSProtocol</key>
  <string>HTTPS</string>
  <key>ServerURL</key>
  <string>https://dns.nodns.vn/dns-query</string>
  <key>SupplementalMatchDomains</key>
  <array>
    <string>api.revenuecat.com</string>
    <string>revenuecat.com</string>
    <string>firebaseremoteconfig.googleapis.com</string>
    <string>firebaseremoteconfigrealtime.googleapis.com</string>
    <string>firebaselogging.googleapis.com</string>
    <string>adsbynimbus.com</string>
    <string>locketlabs-locketcamera.adsbynimbus.com</string>
  </array>
</dict>
```

1. **Ý nghĩa chính xác của `SupplementalMatchDomains` (Split-DNS trên iOS 14+):**
   - Theo tài liệu *Apple Device Management — DNSSettings*:
     - Nếu `SupplementalMatchDomains` **không được khai báo** (hoặc chứa chuỗi rỗng `""`), iOS định tuyến **100% truy vấn DNS trên toàn thiết bị** tới `ServerURL` (đây là cách `app/profile.py` trong `locket.gold.zip` đang làm với `https://dns.nextdns.io/{nextdns_id}`).
     - Nếu `SupplementalMatchDomains` được khai báo một danh sách tên miền cụ thể, iOS tạo một quy tắc **Scoped / Split DNS** trong tiến trình hệ thống `mDNSResponder`: **Chỉ những tên miền nằm trong danh sách (và subdomain của chúng)** mới được gửi qua giao thức DoH (RFC 8484) tới `ServerURL`. Mọi tên miền khác (như Facebook, YouTube, ngân hàng, hay cả `api.locketcamera.com` nếu không nằm trong danh sách) vẫn sử dụng DNS mặc định của Wi-Fi / 4G.

2. **Sự khác biệt giữa DNS Filtering, DNS Rewrite và HTTPS Interception:**
   - **DNS Filtering (Chặn quảng cáo/tên miền):** Khi iPhone hỏi địa chỉ IP (`A` hoặc `AAAA` record) của `adsbynimbus.com`, máy chủ DoH trả về `0.0.0.0`, `::` hoặc `NXDOMAIN`. Kết nối mạng tới domain quảng cáo bị chặn ngay ở bước phân giải tên miền, không cần bất kỳ chứng chỉ Root CA hay Proxy nào.
   - **DNS Rewrite (Ghi đè bản ghi A/AAAA/CNAME):** Trong cấu hình NextDNS (ví dụ ID `a8b247`), tính năng *Settings → Rewrites* cho phép định nghĩa một tên miền trả về một địa chỉ IP tùy chỉnh (ví dụ IP VPS `103.118.29.159`). Khi đó, máy chủ DoH chỉ đóng vai trò trả lời: *"Tên miền X có địa chỉ IPv4 là `103.118.29.159`"*. **Bản thân NextDNS không hề giải mã HTTPS và không hề trả về bất kỳ chuỗi JSON nào.**
   - **HTTPS Interception / Termination:** Sau khi nhận được IP `103.118.29.159` từ bước DNS Rewrite, ứng dụng trên iPhone sẽ mở kết nối TCP tới cổng `443` của `103.118.29.159`, gửi gói `TLS ClientHello` với trường `SNI (Server Name Indication)` là tên miền gốc, và gửi HTTP Request bên trong đường hầm TLS đó. Nếu tại `103.118.29.159:443` không có máy chủ HTTPS nào chấp nhận SNI đó với chứng chỉ được ký bởi Root CA mà iPhone đã bật Full Trust, kết nối sẽ đứt gãy ngay ở tầng TLS Handshake.

3. **Vai trò của DNS Cache, IPv4/IPv6 (`AAAA`), và bản ghi `HTTPS`/`SVCB` (RFC 9460):**
   - **Vấn đề IPv6 (`AAAA`) & `HTTPS` Record Bypass (Lỗi rất phổ biến khi dùng NextDNS Rewrites):**
     - iOS ưu tiên kết nối IPv6 (Happy Eyeballs v2 - RFC 8305) và luôn gửi đồng thời 3 truy vấn DNS cho mỗi kết nối HTTPS: loại `A` (IPv4), loại `AAAA` (IPv6), và loại `HTTPS` (Type 65 - SVCB/ECH/ALPN hint).
     - Khi bạn thêm một bản ghi **DNS Rewrite** trên NextDNS trỏ một tên miền về địa chỉ IPv4 (`103.118.29.159`), NextDNS chỉ ghi đè bản ghi `A`. Nhưng đối với truy vấn `AAAA` và `HTTPS` (Type 65) của tên miền đó, nếu tên miền thật trên Internet có hỗ trợ IPv6 (ví dụ các dịch vụ chạy sau Cloudflare/AWS/Fastly) hoặc có bản ghi `HTTPS` chứa `ipv6hint` / `ipv4hint`, NextDNS vẫn có thể trả về địa chỉ IPv6 thật hoặc IP hint thật từ upstream!
     - Khi đó, iPhone có kết nối mạng 4G/5G hoặc Wi-Fi có IPv6 sẽ **kết nối thẳng qua IPv6 tới máy chủ thật** mà bỏ qua hoàn toàn địa chỉ IPv4 `103.118.29.159` trong bản ghi Rewrite! Đây chính là một trong những nguyên nhân kỹ thuật khiến bạn thấy truy vấn xuất hiện trong NextDNS Logs nhưng lưu lượng không hề đi vào VPS.

---

## 3. PHÂN TÍCH PAYLOAD C — GIẢ THUYẾT REVENUECAT & QUẢN LÝ ENTITLEMENT

### 3.1. Đối chiếu các cấu trúc JSON xuất hiện trong 3 nguồn code

Trong 5 file bạn cung cấp, có 3 hàm tạo JSON phản hồi thuê bao với cấu trúc khác nhau:

| Trường JSON / Thuộc tính | `locket.gold/app/models.py` (`subscriber_response`) | `locket_gold_mitm_server.js` (`buildLocketGoldSubscriberResponse`) | `LocketGold-Installer/server.js` (`buildLocketGoldPayload`) |
|---|---|---|---|
| Endpoint lắng nghe | `GET /v1/subscribers/{account_id}` và `/proxy/*` | `GET\|POST /v1/subscribers/*`, `POST /v1/receipts` | `GET\|POST /v1/subscribers/*`, `POST /v1/receipts` |
| `subscriber.entitlements` keys | Chỉ có `Gold` | `Gold`, `pro` | `Gold`, `gold`, `locket_gold`, `profile_badge` |
| `product_identifier` | `com.locket.gold.yearly` | `locket_1600_1y` | `locket_1600_1y`, `locket_gold_annual` |
| `expires_date` | Theo DB (nhưng lỗi fallback `2029-12-31` khi `account=None`) | Cứng `2099-12-31T23:59:59Z` | Cứng `2099-12-31T23:59:59Z` |
| `subscriber_attributes` | Không có | Không có | Có `$badge`, `profile_badge`, `gold_badge`, `gold_since`, `$gold_since`, `gold_member_since` |
| Header `X-RevenueCat-ETag` | Không có (thậm chí xóa `etag` ở bản vá) | Có `"locket_gold_spoof_v1"` | Không có |

### 3.2. Phân biệt Client-Side UI State và Backend-Verified Entitlement

1. **Cách hoạt động của SDK quản lý thuê bao (như RevenueCat `Purchases-iOS`):**
   - Khi ứng dụng khởi động hoặc làm mới trạng thái, SDK gọi `GET /v1/subscribers/<app_user_id>` để lấy đối tượng `CustomerInfo`.
   - Đối tượng `CustomerInfo` chứa:
     - `entitlements`: Ánh xạ tên quyền (ví dụ `"Gold"`) tới đối tượng thông tin quyền gồm `expires_date`, `purchase_date`, `product_identifier`. SDK dựa vào `expires_date > request_date` để xác định `entitlement.isActive == true`.
     - `subscriptions`: Ánh xạ `product_identifier` tới chi tiết gói đăng ký trên App Store (`store: "app_store"`, `ownership_type: "PURCHASED"`, `period_type: "normal"`).
   - **Cơ chế Cache trên thiết bị:** SDK lưu cache phản hồi `CustomerInfo` vào `UserDefaults` / bộ nhớ cục bộ của ứng dụng (thường có hiệu lực ít nhất 5 phút khi app đang chạy hoặc lâu hơn khi offline). Ngoài ra, nếu server trả về HTTP `304 Not Modified` dựa trên `X-RevenueCat-ETag`, SDK sẽ dùng lại bản cache cũ.

2. **Giới hạn giữa Quyền hiển thị ở Client (Client-side Feature Gate) và Quyền xác minh ở Backend (Server-side Verification):**
   - **Các tính năng chỉ kiểm tra ở Client UI:** Những tính năng mà ứng dụng chỉ kiểm tra `customerInfo.entitlements["Gold"]?.isActive == true` ngay trên giao diện iOS (ví dụ: ẩn quảng cáo client-side, mở khóa giao diện chọn icon ứng dụng cục bộ, bật nút quay video dài hơn trên UI).
   - **Các tính năng được Backend chính thức xác minh:** Khi người dùng thực hiện hành động ghi dữ liệu lên máy chủ backend chính thức (ví dụ gọi API của `api.locketcamera.com` hoặc Google Cloud Functions), máy chủ backend của nhà phát triển có dữ liệu đồng bộ trực tiếp từ **RevenueCat Webhooks / Server-to-Server API** hoặc **Apple App Store Server Notifications V2** (có chữ ký JWS của Apple). Một phản hồi JSON giả lập giữa client và mock server **không bao giờ thay đổi được cơ sở dữ liệu trên máy chủ của nhà phát triển ứng dụng**.

---

## 4. BÁO CÁO PHÂN LOẠI KẾT LUẬN KỸ THUẬT (VERIFICATION MATRIX)

Theo yêu cầu mục 3 & 4, toàn bộ các nhận định trong `cotloicualocketgold.txt` và mã nguồn hiện tại được phân loại nghiêm ngặt thành 3 nhóm dựa trên bằng chứng:

### Nhóm 1: VERIFIED (Đã chứng minh bằng mã nguồn và kiểm nghiệm mật mã học)

1. **[VERIFIED] Cấu trúc 2 Payload trong các file `.mobileconfig` mẫu:**
   - **Bằng chứng:** `LocketGold-Installer/LocketGold_Unlocked_XML.mobileconfig#L25-L85`, `amlongtruc-source/LocketGold_Clean_Unlocked.mobileconfig#L25-L85`.
   - **Chi tiết:** File cấu hình chứa đúng 2 payload là `com.apple.security.root` (cài chứng chỉ gốc) và `com.apple.dnsSettings.managed` (cấu hình DoH với `SupplementalMatchDomains` gồm 7 tên miền).
2. **[VERIFIED] Thông số mật mã học X.509 của chứng chỉ `LocketGoldCA.cer` khớp với `cotloicualocketgold.txt`:**
   - **Bằng chứng:** Kiểm nghiệm nhị phân `LocketGoldCA.cer` bằng `.NET X509Certificate2` & `SHA256`.
   - **Chi tiết:** Subject và Issuer đúng là `C=VN, O=Local Research, CN=LocketProxy CA`; thời hạn `2026-09-26 04:44:42Z` đến `2036-09-26 04:44:42Z`; SHA-256 Fingerprint khớp chính xác 100%: `16:2C:34:B4:EB:9C:15:42:4D:DE:28:4B:72:9F:A7:0D:35:0C:EB:91:E5:EC:ED:1A:AA:49:FD:E3:B5:85:AF:F1`.
3. **[VERIFIED] File `LocketGold.mobileconfig` trong `LocketGold-Installer.zip` KHÔNG PHẢI là hồ sơ đã ký CMS:**
   - **Bằng chứng:** `HUONG_DAN_CAI_DAT.md#L9` tuyên bố *"LocketGold.mobileconfig: Hồ sơ cấu hình iOS đã ký chuẩn"*, nhưng kết quả kiểm tra byte thực tế của `LocketGold.mobileconfig` (3,986 bytes, byte 0 là `<?xml version="1.0"...`) chứng minh nó là file XML thuần giống hệt `LocketGold_Unlocked_XML.mobileconfig`.
4. **[VERIFIED] Không có Private Key tương ứng với `LocketProxy CA` hay `LocketGold Root CA` trong bất kỳ file nào được cung cấp:**
   - **Bằng chứng:** Quét toàn bộ cây thư mục của cả 5 file. Chỉ tồn tại chứng chỉ công khai (`.cer` / `<data>` DER). Không thể dùng lại chứng chỉ `LocketProxy CA` của `dns.nodns.vn` cho máy chủ VPS riêng của bạn vì bạn không có khóa riêng để ký TLS Server Certificate.
5. **[VERIFIED] Hệ thống `locket.gold.zip` hiện tại đang bị lỗi logic nghiêm trọng: luôn trả về Gold active (hạn 2029) cho cả những tài khoản KHÔNG tồn tại trong MongoDB:**
   - **Bằng chứng:** `locket.gold/app/models.py#L48-L51` (`if expiry is None: expiry = datetime(2029, 12, 31, ...)`), `locket.gold/app/routers/subscribers.py#L14-L15`, và `locket.gold/app/locket_modifier.py#L240-L241`.
6. **[VERIFIED] Hệ thống `locket.gold.zip` hiện tại có thiết kế DNS và Proxy rời rạc, không kết nối được với nhau:**
   - **Bằng chứng:**
     - `web/index.html#L614` tải về profile trỏ tới NextDNS ID cứng `8f4cb9` và Root CA cứng `CN=LocketGold Root CA`.
     - `app/profile.py#L22` sinh profile trỏ tới `https://dns.nextdns.io/{settings.nextdns_id}` (`a8b247`).
     - `app/locket_modifier.py#L52-L70` lại sinh một profile khác dùng sai `PayloadType = com.apple.webClip.managed` chứa `AutoProxy`.
     - Không có bất kỳ cấu hình TLS Reverse Proxy (Caddy) hay DNS Rewrite hợp lệ nào kết nối luồng DNS từ thiết bị vào endpoint `/v1/subscribers/{account_id}` với chứng chỉ TLS tương ứng.

### Nhóm 2: PARTIALLY VERIFIED (Có bằng chứng hỗ trợ một phần nhưng cần điều kiện môi trường bên ngoài)

1. **[PARTIALLY VERIFIED] Cơ chế Split-DNS qua `SupplementalMatchDomains` kết hợp DNS Rewrite và HTTPS Mock Server:**
   - **Bằng chứng:** Về mặt kiến trúc mạng iOS (Apple `DNSSettings` specification), khi một tên miền nằm trong `SupplementalMatchDomains`, iOS gửi truy vấn DoH tới `ServerURL`. Nếu DoH resolver trả về IP của một máy chủ HTTPS mà máy chủ đó trình ra chứng chỉ Leaf hợp lệ (có SAN khớp với tên miền đó và được ký bởi Root CA đã bật Full Trust trên iOS), đồng thời ứng dụng client **không áp dụng SSL Pinning** trên tên miền đó, thì client sẽ nhận phản hồi JSON từ máy chủ HTTPS đó.
   - **Điểm chưa xác minh / Phụ thuộc:** Trong các file bạn cung cấp, máy chủ `https://dns.nodns.vn/dns-query` là máy chủ bên ngoài không nằm trong mã nguồn; còn với NextDNS (`a8b247`), mã nguồn chưa có cấu hình chặn IPv6/HTTPS record và chưa có chứng chỉ Leaf + Private Key trên VPS để hoàn tất TLS handshake.
2. **[PARTIALLY VERIFIED] Khả năng trích xuất Identifier / UID từ Username hoặc Link Locket:**
   - **Bằng chứng:** Trong `amlongtruc-source/src/components/LocketGoldFreePage.tsx#L27-L34`, code tách `username` từ link `https://locket.cam/<username>` và gọi API `/api/uplocket/lookup` để lấy `uid`, `name`, `avatar`. Trong `LocketGoldFreePage.tsx#L7`, các URL avatar mẫu (`https://cdn2.locketcamera.com/v0/b/locket-img/o/users%2F<FIREBASE_UID>%2Fpublic%2Fprofile_pic.webp`) cho thấy `uid` của Locket có định dạng **Firebase Auth UID (28 ký tự alphanumeric)**, hoàn toàn khác với `username` trên link `locket.cam/<username>`.
   - **Điểm chưa xác minh:** `amlongtruc-source/server.js#L151` chỉ gọi proxy sang `https://amlongtruc.net/api/uplocket/lookup` chứ không chứa mã nguồn phân giải gốc từ `locket.cam/<username>` ra Firebase UID. Do đó, hệ thống không được phép tự coi `username` trong link là `uid` nếu chưa qua bước xác minh.

### Nhóm 3: UNVERIFIED / INCORRECT (Không đúng về mặt kỹ thuật hoặc chưa có bằng chứng)

1. **[INCORRECT] Nhận định trong `cotloicualocketgold.txt` (dòng 9): *"Khi bật công tắc xanh cho chứng chỉ này, iPhone sẽ cho phép máy chủ LocketProxy CA giải mã và viết lại nội dung gói tin HTTPS mà ứng dụng không hề phát hiện"*:**
   - **Phản biện kỹ thuật:**
     - Thứ nhất, chứng chỉ Root CA trên iPhone chỉ cho phép `Security.framework` chấp nhận chữ ký trên chứng chỉ TLS của máy chủ khi thực hiện kết nối mới, chứ bản thân chứng chỉ không thể "giải mã" gói tin nếu không có lưu lượng đi qua máy chủ nắm giữ Private Key.
     - Thứ hai, chứng chỉ `LocketProxy CA` trong `cotloicualocketgold.txt` có `NotBefore = 26/09/2026`. Nếu đồng hồ hệ thống thực tế của iPhone đang ở thời điểm **trước ngày 26/09/2026**, iOS `Security.framework` sẽ đánh dấu chứng chỉ này là **Not Yet Valid (Chưa đến ngày có hiệu lực)** và từ chối toàn bộ kết nối TLS! (Chính `app/profile.py#L55-L56` cũng có đoạn kiểm tra `if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc: raise ValueError('The CA certificate is expired or not yet valid')`).
     - Thứ ba, chứng chỉ `LocketProxy CA` không có extension `KeyUsage` (`keyCertSign`), vi phạm RFC 5280 mục 4.2.1.3 đối với chứng chỉ CA chuẩn khi kiểm tra nghiêm ngặt.
2. **[INCORRECT] Nhận định rằng chỉ cần cài profile NextDNS + Root CA là FastAPI `/v1/subscribers/{account_id}` sẽ tự động cấp Gold theo UUID:**
   - **Phản biện kỹ thuật:**
     - Trong `locket.gold/app/routers/subscribers.py#L11`, endpoint `/v1/subscribers/{account_id}` đang gắn dependency `Depends(require_subscriber_access)`.
     - Hàm `require_subscriber_access` (`app/security.py#L20-L49`) yêu cầu header `Authorization: Bearer <token>` phải khớp với `SUBSCRIBER_API_TOKEN` của server hoặc `session` của Superadmin trong MongoDB!
     - Một ứng dụng client bên ngoài (hoặc kể cả client thử nghiệm) không bao giờ gửi `Authorization: Bearer <admin_session_token>` của bạn. Do đó, mọi request gửi tới `/v1/subscribers/{account_id}` trên FastAPI hiện tại đều bị chặn bởi **HTTP `401 Unauthorized`**!
3. **[UNVERIFIED] Giả định rằng một phản hồi JSON giả lập `/v1/subscribers/<uid>` đồng nghĩa với việc tài khoản Locket chính thức được mở khóa Gold trên hệ thống của Locket Labs:**
   - **Phản biện kỹ thuật:** Như đã phân tích tại mục 3.2, phản hồi JSON từ một mock server chỉ là dữ liệu mô phỏng giao thức client-server. Nó không tạo ra giao dịch trên App Store và không cấp quyền trên máy chủ backend chính thức của nhà phát triển ứng dụng. Trong Research Lab của chúng ta, mọi kết quả kiểm thử phải phân biệt rõ ràng giữa:
     - **Lab Mock Entitlement Status:** Trạng thái JSON do `Subscription Mock Service` trả về từ database `locket_manager`.
     - **Observed Client Behavior:** Hành vi thực tế quan sát được trên client thử nghiệm trong Lab.
