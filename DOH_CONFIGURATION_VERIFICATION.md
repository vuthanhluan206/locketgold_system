# BÁO CÁO XÁC MINH CẤU HÌNH DNS-OVER-HTTPS LINH HOẠT (`DOH_CONFIGURATION_VERIFICATION.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Các file triển khai:** [app/config.py](file:///e:/locketgold/app/config.py), [app/profile.py](file:///e:/locketgold/app/profile.py), [app/services/doh_service.py](file:///e:/locketgold/app/services/doh_service.py), [app/routers/subscribers.py](file:///e:/locketgold/app/routers/subscribers.py)
**Ngày cập nhật:** 2026-11-25

---

## 1. HAI CHẾ ĐỘ CẤU HÌNH DOH TRONG `app/profile.py` (`resolve_doh_server_url`)

Thay vì hardcode một URL duy nhất, hàm `resolve_doh_server_url(settings, device_label=...)` trong [app/profile.py](file:///e:/locketgold/app/profile.py) hỗ trợ hai chế độ rõ ràng:

| Chế độ | Biến môi trường kích hoạt | Cấu trúc `ServerURL` trong `.mobileconfig` | Phạm vi áp dụng |
| :--- | :--- | :--- | :--- |
| **Mode A — NextDNS** | `NEXTDNS_ID=a8b247` (và để trống `DOH_SERVER_URL=`) | `https://dns.nextdns.io/a8b247` (hoặc `https://dns.nextdns.io/a8b247/<device_id>` khi kèm `device_token`) | Chế độ mặc định cho Production và kiểm thử DoH qua hạ tầng NextDNS của bạn. |
| **Mode B — Custom DoH Lab** | `DOH_SERVER_URL=https://mock.lab.vuthanhluan.bond/dns-query` | `https://mock.lab.vuthanhluan.bond/dns-query` (hoặc `.../dns-query/<device_id>`) | Chế độ kiểm thử khép kín với endpoint RFC 8484 DoH tích hợp sẵn trong hệ thống Lab. |

### Các quy tắc bảo mật trên `DOH_SERVER_URL` (`validate_doh_url` trong `app/config.py`):
1. **Bắt buộc `https://`**: Mọi URL dùng `http://` hoặc scheme khác bị từ chối ngay khi khởi động (`ValidationError`).
2. **Không nhận URL tùy ý từ người dùng cuối**: Endpoint `/profile.mobileconfig` chỉ đọc cấu hình từ biến môi trường của server, không bao giờ nhận URL DoH từ query parameter của client.
3. **Cấm thông tin nhạy cảm & query string**: Từ chối mọi URL chứa `username:password@`, `?query` hoặc `#fragment`.
4. **Cấm endpoint bên thứ ba chưa xác minh**: Từ chối cứng `dns.nodns.vn`, `api.revenuecat.com`, `api.locketcamera.com`.

---

## 2. PHÂN TÁCH `LAB_MODE=local` VÀ `LAB_MODE=real_device` CHO IPHONE THẬT

Một lỗi phổ biến khi triển khai Lab là để máy chủ DNS trả về địa chỉ loopback `127.0.0.1` cho thiết bị iPhone nằm bên ngoài VPS. Nếu iPhone nhận được bản ghi `A = 127.0.0.1`, iPhone sẽ tự kết nối vào chính nó thay vì kết nối tới VPS.

Do đó, `app/config.py` kiểm soát chặt chẽ biến `LAB_MODE`:

1. **`LAB_MODE=local` (Mặc định cho Docker E2E & Localhost)**:
   - Cho phép `LAB_DNS_TARGET_IP=127.0.0.1`.
   - Chỉ dùng cho các bài kiểm thử chạy bên trong Docker hoặc trên cùng máy host.
2. **`LAB_MODE=real_device` (Bắt buộc khi kiểm thử với iPhone thật bên ngoài VPS)**:
   - Nếu `LAB_DNS_TARGET_IP` là `127.0.0.1`, `0.0.0.0` hoặc bất kỳ địa chỉ loopback nào, `Settings` sẽ **từ chối khởi động ngay lập tức** với lỗi `ValidationError`.
   - Nếu `DOH_SERVER_URL` chứa `localhost` hoặc `127.0.0.1`, `Settings` cũng từ chối khởi động.
   - Bắt buộc người vận hành đặt `LAB_DNS_TARGET_IP` là địa chỉ IPv4 thực sự có thể truy cập được của VPS (ví dụ: `103.118.29.159`) và tùy chọn `LAB_DNS_TARGET_IPV6` hợp lệ.

---

## 3. ENDPOINT RFC 8484 DOH TÍCH HỢP (`/dns-query`) — KHÔNG LÀM OPEN PROXY

Endpoint `GET /dns-query` và `POST /dns-query` trong [app/routers/subscribers.py](file:///e:/locketgold/app/routers/subscribers.py) và [app/services/doh_service.py](file:///e:/locketgold/app/services/doh_service.py) tuân thủ chuẩn RFC 8484 (`application/dns-message`) và JSON DNS format:
- **Chỉ phân giải các tên miền nằm trong `LAB_SCOPED_DOMAINS`** (`mock.lab.vuthanhluan.bond`, `sub.lab.vuthanhluan.bond`, `locketgold.vuthanhluan.bond`):
  - Truy vấn `A` (`qtype=1`): Trả về `RCODE = 0 (NOERROR)` kèm `LAB_DNS_TARGET_IP`.
  - Truy vấn `AAAA` (`qtype=28`): Nếu có cấu hình `LAB_DNS_TARGET_IPV6` thì trả về bản ghi `AAAA`; nếu không cấu hình IPv6 thì trả về `NOERROR_NODATA` (0 answers) để iOS chuyển sang dùng IPv4 một cách chuẩn xác.
- **Từ chối mọi tên miền bên ngoài (`RCODE = 5 / REFUSED`)**:
  - Mọi truy vấn tới tên miền không thuộc `LAB_SCOPED_DOMAINS` (ví dụ `api.revenuecat.com`, `google.com`, `apple.com`) đều nhận mã phản hồi `REFUSED`. Nhờ đó, máy chủ của bạn **không bao giờ trở thành một Open DNS Resolver / Open Proxy**.
