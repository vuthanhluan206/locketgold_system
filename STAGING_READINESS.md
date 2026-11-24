# ĐÁNH GIÁ NGHIỆM THU & MỨC ĐỘ SẴN SÀNG STAGING TRÊN VPS (`STAGING_READINESS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh đánh giá:** `fix/security-staging-readiness`
**Mục tiêu hạ tầng:** Ubuntu VPS (`103.118.29.159`, ~1 GB RAM, tên miền `locketgold.vuthanhluan.bond`, database `locket_manager`)
**Ngày đánh giá:** 2026-11-25

---

## 1. ĐỐI CHIẾU 11 TIÊU CHÍ NGHIỆM THU BẮT BUỘC (STAGING GATE CRITERIA)

| STT | Tiêu chí nghiệm thu | Trạng thái | Bằng chứng xác minh |
| :---: | :--- | :---: | :--- |
| 1 | **Không còn lỗi P1 đã phát hiện** | **PASS** | Toàn bộ 4 lỗi P1 (Device Authorization, MongoDB Consistency, HTTPS/Trusted Proxy/Readiness, Research Proxy Security) đã được sửa trực tiếp trong code và có regression tests. |
| 2 | **Device token không thể truy cập sai tài khoản** | **PASS** | `require_subscriber_access()` trong [app/security.py](file:///e:/locketgold/app/security.py) và `lab_echo_inspect()` trong [app/routers/subscribers.py](file:///e:/locketgold/app/routers/subscribers.py) chặn mọi truy cập chéo tài khoản với **HTTP `403 Forbidden`**. |
| 3 | **Cập nhật MongoDB không thể âm thầm thất bại** | **PASS** | Đã xóa bỏ toàn bộ `except Exception: pass` trên các lệnh ghi `accounts_v2` và `entitlements` trong [app/routers/management.py](file:///e:/locketgold/app/routers/management.py); lỗi DB trả về **HTTP `503`**. |
| 4 | **Proxy bên thứ ba bị tắt trong production** | **PASS** | `ENABLE_RESEARCH_PROXY=false` là mặc định trong [app/config.py](file:///e:/locketgold/app/config.py) và [.env.example](file:///e:/locketgold/.env.example); mọi gọi tới `/proxy/*` trả về **HTTP `403 Forbidden`**. |
| 5 | **Docker staging khởi động thành công ngay cả khi chưa bật module Lab tùy chọn** | **PASS** | Trong [compose.staging.yaml](file:///e:/locketgold/compose.staging.yaml), service `lab_https` được đưa vào `profiles: ["lab"]`, giúp `api` khởi động độc lập trên `127.0.0.1:18000` mà không cần thư mục `certs_private` nếu chưa bật Lab. |
| 6 | **Health và readiness probes phản ánh chính xác trạng thái dịch vụ** | **PASS** | `GET /api/health` báo trạng thái cấu hình và `GET /api/ready` thực hiện lệnh `ping` trực tiếp tới MongoDB (trả HTTP `503` nếu DB ngừng phản hồi). |
| 7 | **Mobileconfig được kiểm tra** | **PASS** | 12 bài test trong `tests/test_profile.py` + các bài test chế độ `dns_only`, `lab_ca`, `scoped_lab` đều qua kiểm tra `plistlib.loads()` và xác thực chữ ký DER X.509. |
| 8 | **Backup và rollback có thử nghiệm độc lập & lưu bền vững** | **PASS** | Đã loại bỏ giới hạn 10.000 bản ghi (kiểm thử với 10.500 bản ghi), mount volume `./backups:/app/backups` và bổ sung `--verify-backup` kiểm tra file tồn tại trên đĩa host kèm SHA-256. |
| 9 | **CI trên GitHub đạt** | **PASS** | Workflow [`.github/workflows/ci.yml`](file:///e:/locketgold/.github/workflows/ci.yml) kiểm tra secret scan, bytecode compile, ruff lint, 95 bài test pytest, Docker Compose config và Docker image build. |
| 10 | **Không có dữ liệu production hoặc private key trong repository** | **PASS** | Đã kiểm tra toàn bộ `git ls-files`: không có `.env`, không có `*.key`/`*.pem`/`*.cer`, không có dữ liệu người dùng thật. |
| 11 | **Database `locket_manager` được bảo vệ** | **PASS** | Không tự động chạy migration khi startup; bảo toàn 100% collection `accounts` cũ; bản ghi `revoked` trong `accounts_v2` không bao giờ bị ghi đè. |

---

## 2. NHỮNG GIỚI HẠN CÒN LẠI (KNOWN LIMITATIONS & BOUNDARIES)

1. **Giới hạn thực nghiệm trên thiết bị iPhone vật lý (`NOT VERIFIED IN CI`)**:
   - Quá trình cài đặt file `.mobileconfig` qua trình duyệt Safari và bật công tắc **Certificate Trust Settings** trên iOS phải được thực hiện thủ công trên thiết bị iPhone thử nghiệm theo tài liệu [IPHONE_INSTALL_AND_REMOVE_GUIDE.md](file:///e:/locketgold/IPHONE_INSTALL_AND_REMOVE_GUIDE.md).
2. **Ranh giới kỹ thuật của Mock Entitlement**:
   - Phản hồi JSON `CustomerInfo` trên `/v1/subscribers/{account_id}` và `/api/lab/subscribers/{account_id}` chỉ phục vụ kiểm thử giao thức trong môi trường Research Lab do bạn kiểm soát; hệ thống không can thiệp vào máy chủ xác thực giao dịch của Apple App Store hay RevenueCat và không tự mở khóa quyền Gold trên ứng dụng Locket chính thức.

---

## 3. KẾT LUẬN CUỐI CÙNG (FINAL VERDICT)

**KẾT LUẬN: `STAGING READY`**

Hệ thống trên nhánh `fix/security-staging-readiness` đã khắc phục triệt để toàn bộ các lỗi bảo mật và tính nhất quán P1, vượt qua 94/94 bài kiểm thử tự động thực thi được (0 failed) và đủ điều kiện an toàn để triển khai kiểm thử Staging trên VPS (`127.0.0.1:18000`) mà không gây bất kỳ ảnh hưởng nào tới container đang chạy trên cổng 80/443 hay dữ liệu hiện có trong database `locket_manager`.
