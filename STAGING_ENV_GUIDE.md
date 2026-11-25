# HƯỚNG DẪN CẤU HÌNH BIẾN MÔI TRƯỜNG STAGING & PROXY (`STAGING_ENV_GUIDE.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**File mẫu:** [.env.staging.example](file:///e:/locketgold/.env.staging.example)
**Ngày cập nhật:** 2026-11-25

---

## 1. BẢNG THAM CHIẾU CÁC BIẾN MÔI TRƯỜNG TRONG `.env.staging`

| Biến môi trường | Giá trị chuẩn trên Staging | Giải thích & Ràng buộc an toàn |
| :--- | :--- | :--- |
| `APP_ENV` | `staging` | **Bắt buộc.** Kích hoạt chốt chặn bảo vệ database production: nếu `MONGODB_DATABASE=locket_manager`, ứng dụng sẽ từ chối khởi động. |
| `MONGODB_URI` | `mongodb+srv://staging_user:***@.../locket_manager_staging` | URI kết nối tới MongoDB Atlas (khuyến nghị dùng tài khoản DB chỉ có quyền `readWrite` trên `locket_manager_staging`). |
| `MONGODB_DATABASE` | `locket_manager_staging` | **Bắt buộc khác `locket_manager`.** Tên database riêng biệt dành cho toàn bộ thao tác kiểm thử Staging. |
| `NEXTDNS_ID` | `a8b247` | Mã cấu hình NextDNS 6 ký tự hex (Mode A). |
| `DOH_SERVER_URL` | *(Để trống)* hoặc `https://mock.lab.vuthanhluan.bond/dns-query` | URL của máy chủ Custom DoH Lab (Mode B). Bắt buộc dùng `https://`, cấm chứa thông tin đăng nhập, query string hoặc domain bên thứ ba chưa xác minh (`dns.nodns.vn`). |
| `LAB_MODE` | `local` hoặc `real_device` | Đặt `local` khi kiểm thử trong Docker/localhost; đặt `real_device` khi kiểm thử với iPhone thật bên ngoài VPS (chặn `127.0.0.1` trong `LAB_DNS_TARGET_IP`). |
| `LAB_DNS_TARGET_IP` | `127.0.0.1` (`local`) hoặc `103.118.29.159` (`real_device`) | Địa chỉ IPv4 mà endpoint `/dns-query` trả về cho các tên miền nằm trong `LAB_SCOPED_DOMAINS`. |
| `ROOT_CA_PATH` | *(Để trống)* hoặc `/app/certs_public/lab_root_ca.pem` | Đường dẫn chứng chỉ công khai Root CA đã mount ở chế độ `:ro` trong container `api`. Để trống khi chỉ dùng DNS-only. |
| `REQUIRE_HTTPS` | `false` (Mode A Loopback) / `true` (Mode B qua Caddy) | Khi đặt `true`, chỉ chấp nhận request HTTPS hoặc request đi qua proxy nằm trong `TRUSTED_PROXY_CIDRS` có header `X-Forwarded-Proto: https` (trừ health/readiness probes trên loopback `127.0.0.1`). |
| `TRUSTED_PROXY_CIDRS` | `[]` (Mode A) hoặc `["172.18.0.5/32"]` (Mode B) | Danh sách CIDR của Reverse Proxy tin cậy đứng trước FastAPI. |
| `ENABLE_RESEARCH_PROXY` | `false` | Giữ `false` để khóa hoàn toàn route `/proxy/*` đối với dịch vụ bên thứ ba. |

---

## 2. CÁCH XÁC ĐỊNH ĐỊA CHỈ IP REVERSE PROXY THỰC TẾ TRONG DOCKER (`TRUSTED_PROXY_CIDRS`)

Thay vì mở rộng toàn bộ dải `172.16.0.0/12` khi không cần thiết:
- **Ở Chế độ A (Core Staging qua Loopback `127.0.0.1:18000` hoặc SSH Tunnel):**
  - Không có Caddy đứng trước cổng `18000`, nên đặt `REQUIRE_HTTPS=false` và `TRUSTED_PROXY_CIDRS=[]`. Mọi header `X-Forwarded-Proto` hoặc `CF-Connecting-IP` do client tự gửi đều bị bỏ qua hoàn toàn.
- **Ở Chế độ B (Khi bật container `locket_staging_lab_https` qua `--profile lab`):**
  - Bạn có thể lấy chính xác địa chỉ IP nội bộ `/32` của container Caddy trong mạng bridge `locket_staging_default` bằng lệnh:
    ```bash
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}/32{{end}}' locket_staging_lab_https
    ```
  - Sau đó điền đúng IP `/32` này (ví dụ `TRUSTED_PROXY_CIDRS=["172.19.0.3/32"]`) vào `.env.staging`.
