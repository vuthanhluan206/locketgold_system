# BÁO CÁO KẾT QUẢ KIỂM THỬ DOCKER E2E & DNS/TLS LAB (`DOCKER_E2E_RESULTS.md` & `DNS_TLS_LAB_E2E_RESULTS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Script thực thi:** [scripts/docker_e2e_smoke.py](file:///e:/locketgold/scripts/docker_e2e_smoke.py) (chạy tự động trong job `docker-staging-gate` của `.github/workflows/ci.yml`)
**Ngày thực thi:** 2026-11-25

---

## 1. KIẾN TRÚC CÔ LẬP CỦA BỘ KIỂM THỬ DOCKER RUNTIME E2E

Bộ kiểm thử [scripts/docker_e2e_smoke.py](file:///e:/locketgold/scripts/docker_e2e_smoke.py) dựng một cụm container thực tế hoàn toàn độc lập trên runner Linux:
- **Docker Project riêng:** `locket_e2e_ci` (với tên container riêng `locket_e2e_ci_mongo`, `locket_e2e_ci_api`, `locket_e2e_ci_lab_https`, `locket_e2e_ci_ca_init`, không bao giờ đụng tới `locket_staging_*` hay `locket_lab_*`).
- **Cổng Loopback cấp phát động:** Dùng `find_free_loopback_port()` để chọn cổng trống ngẫu nhiên trên `127.0.0.1`, không bao giờ xung đột với cổng `80`, `443`, `18000` hay `18443` đang chạy trên host.
- **Không dùng `chmod 0777`:** Dùng thư mục tạm riêng (`tempfile.mkdtemp`), phân quyền tối thiểu `0755` (`backups`, `certs_public`) và `0750` (`certs_private`) thuộc sở hữu UID `10001:10001`.
- **Dọn dẹp an toàn trong khối `finally`:** Luôn chạy `docker compose -p locket_e2e_ci down -v` và xóa thư mục tạm kể cả khi có ngoại lệ, không chạm vào bất kỳ container hay volume nào ngoài phạm vi test.

---

## 2. KẾT QUẢ 20 KỊCH BẢN DOCKER RUNTIME E2E

| Bước | Kịch bản kiểm thử Runtime | Phương thức xác minh | Kết quả |
| :---: | :--- | :--- | :---: |
| **Pre** | Khởi tạo Root CA & Leaf bằng container one-shot `ca_init` (UID `10001:10001`) | Kiểm tra `certs_public/lab_root_ca.pem` và `certs_private/lab_leaf.key` được tạo trên host mà không cần chạy API dưới quyền root | **PASS** |
| **1** | Khởi động `mongo_e2e`, `api`, `lab_https` | `docker compose -p locket_e2e_ci up -d` | **PASS** |
| **2** | Chờ container đạt trạng thái `healthy` | `docker inspect --format '{{.State.Health.Status}}'` trả về `healthy` | **PASS** |
| **3** | Kiểm tra `GET /api/health` | HTTP `200`, `database="locket_manager_staging"`, `nextdns_id="a8b247"`, `root_ca_loaded=true`, khớp `root_ca_sha256` | **PASS** |
| **4** | Kiểm tra `GET /api/ready` | HTTP `200`, `status="ready"`, `mongodb_connected=true` | **PASS** |
| **5** | Đăng nhập Superadmin (`POST /api/admin/login`) | HTTP `200`, nhận Bearer `access_token` (mật khẩu sinh ngẫu nhiên trong bộ nhớ, không ghi vào artifact) | **PASS** |
| **6** | Thêm 2 tài khoản thử nghiệm (`e2e_user_1`, `e2e_user_2`) | `POST /admin/add-account` trả về HTTP `200`, `status="active"` | **PASS** |
| **7** | Tra cứu bằng `username` (`e2e_user_1`) | `GET /api/accounts/lookup?query=e2e_user_1` trả về `{"exists": true}` (không lộ UUID/token) | **PASS** |
| **8** | Tra cứu bằng link Locket (`https://locket.cam/e2e_user_1`) | Cả `/api/accounts/lookup` và `/admin/accounts/lookup` trả về `exists=true`, `verification_status="unverified_handle"` | **PASS** |
| **9** | Kiểm tra trực tiếp dữ liệu trong MongoDB container | Truy vấn `locket_manager_staging.accounts_v2` và `accounts` xác nhận bản ghi đã được lưu bền vững | **PASS** |
| **10** | Liên kết thiết bị iPhone thử nghiệm (`POST /admin/devices`) | HTTP `200`, nhận `device_token` (`lkg_dev_...`) gắn với `e2e_user_1` | **PASS** |
| **11** | Kiểm tra Device Token bị giới hạn theo đúng tài khoản | Dùng token của `e2e_user_1` gọi `/v1/subscribers/e2e_user_2` $\rightarrow$ bị chặn ngay với **HTTP `403 Forbidden`** | **PASS** |
| **12** | Kiểm tra Automatic Entitlement Processing & Concurrent Requests | Gửi 8 request đồng thời (`ThreadPoolExecutor`) tới `/v1/subscribers/e2e_user_1` $\rightarrow$ 100% trả về HTTP `200`, `Gold` active | **PASS** |
| **13** | Thu hồi tài khoản (`POST /admin/accounts/e2e_user_1/revoke`) | HTTP `200`, `status="revoked"` | **PASS** |
| **14** | Xác minh trạng thái `revoked` có hiệu lực tức thì | Gọi lại `/v1/subscribers/e2e_user_1` $\rightarrow$ trả về `X-Lab-Entitlement-Status: revoked`, `entitlements: {}` | **PASS** |
| **15** | Thu hồi Device Token (`POST /admin/devices/{id}/revoke`) | Gọi lại `/v1/subscribers/e2e_user_1` bằng device token đã thu hồi $\rightarrow$ bị từ chối với **HTTP `401 Unauthorized`** | **PASS** |
| **16** | Kiểm tra 3 chế độ `.mobileconfig` + Strict TLS SNI/SAN Hostname + RFC 8484 DoH qua Caddy HTTPS Lab | `dns_only` (1 payload), `lab_ca` & `scoped_lab` (2 payloads, khớp DER SHA-256). Kết nối HTTPS qua Caddy Lab với `check_hostname=True` thành công cho 3 domain trong SAN, từ chối `unlisted.lab.vuthanhluan.bond` (`SSLError`), và `/dns-query` trả `Status=0` cho domain Lab, `Status=5 (REFUSED)` cho `api.revenuecat.com` | **PASS** |
| **17** | Giả lập mất kết nối MongoDB (`docker pause locket_e2e_ci_mongo`) | `/api/ready` lập tức trả về **HTTP `503 Service Unavailable`**; sau khi `docker unpause` tự động phục hồi về HTTP `200` | **PASS** |
| **18** | Khởi động lại container API (`docker restart locket_e2e_ci_api`) | Sau khi container `healthy` trở lại, tra cứu `e2e_user_2` vẫn trả về `{"exists": true}` | **PASS** |
| **19** | Kiểm tra Backup bền vững trên Host & Rollback sau khi xóa | Chạy `run --rm api python -m scripts.migrate_db --backup`, xác nhận file tồn tại trên host sau khi container `--rm` thoát, xóa `e2e_user_2` rồi chạy `--rollback` khôi phục thành công `e2e_user_2` | **PASS** |
| **20** | Dọn dẹp tài nguyên test (`down -v` & xóa thư mục tạm) | Xóa sạch container/volume của project `locket_e2e_ci` mà không ảnh hưởng container khác | **PASS** |
