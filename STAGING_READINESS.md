# ĐÁNH GIÁ NGHIỆM THU & MỨC ĐỘ SẴN SÀNG STAGING TRÊN VPS (`STAGING_READINESS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh đánh giá:** `fix/security-staging-readiness` (Pull Request #1)
**Mục tiêu hạ tầng:** Ubuntu VPS (`103.118.29.159`, ~1 GB RAM, tên miền `locketgold.vuthanhluan.bond`, database test `locket_manager_staging` / production `locket_manager`)
**Ngày đánh giá:** 2026-11-25

---

## 1. ĐỐI CHIẾU 11 TIÊU CHÍ NGHIỆM THU BẮT BUỘC (STAGING GATE CRITERIA)

| STT | Tiêu chí nghiệm thu | Trạng thái | Bằng chứng xác minh thực tế |
| :---: | :--- | :---: | :--- |
| 1 | **Không còn lỗi P1 & Final Blockers đã phát hiện** | **PASS** | Toàn bộ các lỗi P1 và 4 nhóm Blocker A/B/C/D (Secret Scanner, Canonical Expiry Precedence, Chống giả mạo `verified_uid` từ Admin input, HTTPS/Staging & Linux CI) đã được sửa và có regression tests. |
| 2 | **Device token không thể truy cập sai tài khoản** | **PASS** | `require_subscriber_access()` trong [app/security.py](file:///e:/locketgold/app/security.py) và `lab_echo_inspect()` trong [app/routers/subscribers.py](file:///e:/locketgold/app/routers/subscribers.py) chặn mọi truy cập chéo tài khoản với **HTTP `403 Forbidden`**. |
| 3 | **Cập nhật MongoDB không thể âm thầm thất bại & `accounts_v2` có quyền ưu tiên tuyệt đối** | **PASS** | Đã xóa bỏ toàn bộ `except Exception: pass` trên các lệnh ghi bắt buộc; `merge_canonical_and_legacy_account()` trong [app/services/entitlement_service.py](file:///e:/locketgold/app/services/entitlement_service.py) đảm bảo `expires_date` và `status` của `accounts_v2` không bao giờ bị bản ghi legacy ghi đè. |
| 4 | **Tra cứu tài khoản theo `locketgoldmanager` & Chống giả mạo `verified_uid`** | **PASS** | `GET /api/accounts/lookup` chỉ trả `{"exists": bool}`; `GET /admin/accounts/lookup` tra cứu MongoDB mà không gọi `amlongtruc-source`. `POST /admin/add-account` luôn đặt `_server_uid_proof=False` và phân loại chuỗi 28 ký tự do Admin nhập tay là `unverified_uid`. |
| 5 | **Proxy bên thứ ba bị tắt trong production** | **PASS** | `ENABLE_RESEARCH_PROXY=false` là mặc định trong [app/config.py](file:///e:/locketgold/app/config.py) và [.env.example](file:///e:/locketgold/.env.example); mọi gọi tới `/proxy/*` trả về **HTTP `403 Forbidden`**. |
| 6 | **Docker staging khởi động thành công ngay cả khi chưa bật module Lab tùy chọn** | **PASS** | Trong [compose.staging.yaml](file:///e:/locketgold/compose.staging.yaml), service `lab_https` được đưa vào `profiles: ["lab"]`, giúp `api` khởi động độc lập trên `127.0.0.1:18000` mà không xung đột cổng 80/443. |
| 7 | **Health và readiness probes phản ánh chính xác trạng thái dịch vụ** | **PASS** | `GET /api/health` và `GET /api/ready` (chủ động `ping` MongoDB, trả HTTP `503` nếu DB lỗi) hoạt động qua loopback HTTP ngay cả khi `REQUIRE_HTTPS=true`. |
| 8 | **Mobileconfig được kiểm tra** | **PASS** | 12 bài test trong `tests/test_profile.py` + các bài test chế độ `dns_only`, `lab_ca`, `scoped_lab` đều qua kiểm tra `plistlib.loads()` và xác thực chữ ký DER X.509. |
| 9 | **Backup và rollback có thử nghiệm độc lập & lưu bền vững** | **PASS** | Đã loại bỏ giới hạn 10.000 bản ghi (kiểm thử với 10.500 bản ghi), mount volume `./backups:/app/backups` và bổ sung `--verify-backup` kiểm tra file tồn tại trên đĩa host kèm SHA-256. |
| 10 | **CI trên GitHub Actions đạt 100% (`conclusion=success`)** | **PASS** | Đã xác minh trực tiếp trên GitHub Actions Run https://github.com/vuthanhluan206/locketgold_system/actions/runs/45471428165: cả 2 job (`Python Compile, Lint, Secret Scan & Pytest Suite` và `Docker Build, Compose Config & Staging Smoke Gate`) đều **SUCCESS**. |
| 11 | **Không có dữ liệu production hoặc private key trong repository & Database `locket_manager` được bảo vệ** | **PASS** | `python -m scripts.check_secrets` đạt 100%; `DEPLOY_STAGING.md` quy định bắt buộc dùng `MONGODB_DATABASE=locket_manager_staging` cho mọi bài kiểm thử có thao tác ghi dữ liệu trên Staging. |

---

## 2. NHỮNG GIỚI HẠN CÒN LẠI (KNOWN LIMITATIONS & BOUNDARIES)

1. **Giới hạn thực nghiệm trên thiết bị iPhone vật lý (`NOT VERIFIED IN CI`)**:
   - Quá trình cài đặt file `.mobileconfig` qua trình duyệt Safari và bật công tắc **Certificate Trust Settings** trên iOS phải được thực hiện thủ công trên thiết bị iPhone thử nghiệm theo tài liệu [IPHONE_INSTALL_AND_REMOVE_GUIDE.md](file:///e:/locketgold/IPHONE_INSTALL_AND_REMOVE_GUIDE.md).
2. **Ranh giới kỹ thuật của Mock Entitlement**:
   - Phản hồi JSON `CustomerInfo` trên `/v1/subscribers/{account_id}` và `/api/lab/subscribers/{account_id}` chỉ phục vụ kiểm thử giao thức trong môi trường Research Lab do bạn kiểm soát; hệ thống không can thiệp vào máy chủ xác thực giao dịch của Apple App Store hay RevenueCat và không tự mở khóa quyền Gold trên ứng dụng Locket chính thức.

---

## 3. KẾT LUẬN CUỐI CÙNG (FINAL VERDICT)

**KẾT LUẬN: `STAGING READY` (VERIFIED BY GITHUB ACTIONS CI)**

Toàn bộ các lỗi P1, các vấn đề đồng bộ tra cứu tài khoản và các blocker trên GitHub Actions CI đã được khắc phục hoàn toàn. Cả 2 job trên GitHub Actions (`test-and-verify` với 124/124 bài test runnable PASSED và `docker-staging-gate` với Docker Compose validation + Docker image build) đều đạt trạng thái **`success`**.
