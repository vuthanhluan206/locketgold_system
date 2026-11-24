# BÁO CÁO KHẮC PHỤC CÁC LỖI TRỌNG YẾU P1 & ĐỒNG BỘ HỆ THỐNG (`CRITICAL_FIX_REPORT.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh:** `fix/security-staging-readiness`
**Base Commit:** `650a14f74a4674d8d98a64f0aa4c7f6272201c4c`
**Ngày thực hiện:** 2026-11-25

---

## 1. TỔNG HỢP CÁC LỖI P1 & LỖI ĐỒNG BỘ ĐÃ ĐƯỢC SỬA TRỰC TIẾP TRONG MÃ NGUỒN

### 1.1. [P1-SEC-01] Ràng buộc quyền của Device Token với Tài khoản đích (Device Authorization)
- **Hiện trạng trước khi sửa:** Trong `app/security.py`, hàm `require_subscriber_access()` xác minh `lkg_dev_*` có tồn tại và đang `active` trong collection `devices`, nhưng chưa đối chiếu `device_doc['locket_id']` với `request.path_params['account_id']`. Hệ quả là Device Token cấp cho tài khoản A có thể đọc trạng thái thuê bao thử nghiệm của tài khoản B.
- **Giải pháp đã triển khai:**
  - Tại [app/security.py](file:///e:/locketgold/app/security.py#L43-L57): Khi `caller_kind == "device_token"`, hệ thống trích xuất `target_account_id = request.path_params.get("account_id")` và so sánh với `bound_account_id = device_doc.get("locket_id")`. Nếu khác nhau, lập tức từ chối với **HTTP `403 Forbidden`** (`"Device token is not authorized to access this account"`).
  - Tại [app/routers/subscribers.py](file:///e:/locketgold/app/routers/subscribers.py#L105-L115): Trong endpoint `POST /api/lab/inspect`, nếu request dùng `device_token` mà gửi body JSON chứa `locket_id` của tài khoản khác, lập tức trả về **HTTP `403 Forbidden`**.
  - Chính sách phân quyền 3 tầng rõ ràng:
    1. `device_token` (`lkg_dev_*`): Chỉ được truy cập đúng `locket_id` mà thiết bị đó được đăng ký; bị thu hồi (`status='revoked'`) trả về HTTP `401`.
    2. `service_token` (`SUBSCRIBER_API_TOKEN`): Dành riêng cho kết nối server-to-server tin cậy.
    3. `admin_session` (64-char token trong collection `sessions`): Dành cho Superadmin kiểm tra trên Dashboard.
- **Bài kiểm thử xác minh:** `tests/test_prompt7_security_and_staging.py::test_p1_device_authorization_cross_account_access_blocked` (PASSED).

---

### 1.2. [P1-DB-02] Tính nhất quán MongoDB & Loại bỏ `except Exception: pass` trên các thao tác ghi bắt buộc
- **Hiện trạng trước khi sửa:**
  1. Trong `app/routers/management.py`, các thao tác ghi vào `accounts_v2` và `entitlements` trong `upsert_account`, `revoke_account`, `activate_account`, `delete_account` được bọc trong `try ... except Exception: pass`, khiến API có thể trả về HTTP 200 ngay cả khi ghi vào `accounts_v2` thất bại.
  2. Trong `app/services/entitlement_service.py` và `app/routers/subscribers.py`, khi gộp bản ghi từ `accounts` (legacy) và `accounts_v2` (canonical), trường `expires_date` của bản ghi legacy hoặc bản ghi thiếu trường `status` có nguy cơ gây sai lệch nếu không ưu tiên trạng thái `revoked` của `accounts_v2`.
  3. `GET /admin/accounts` và `DELETE /admin/accounts/{account_id}` chỉ truy vấn collection `accounts` trước, nên có thể bỏ sót tài khoản chỉ tồn tại trong `accounts_v2`.
- **Giải pháp đã triển khai:**
  - Tại [app/services/entitlement_service.py](file:///e:/locketgold/app/services/entitlement_service.py): Xây dựng hàm `merge_canonical_and_legacy_account(doc_v2, doc_v1)` quy định `accounts_v2` là **Single Source of Truth (Canonical Store)**. Nếu `doc_v2` có `status == 'revoked'` hoặc `'pending'`, trạng thái đó là bất biến — bản ghi legacy `doc_v1` không bao giờ ghi đè được.
  - Tại [app/routers/management.py](file:///e:/locketgold/app/routers/management.py): Xóa bỏ toàn bộ các khối `except Exception: pass` quanh lệnh ghi `accounts_v2` và `entitlements`. Nếu bất kỳ bước ghi bắt buộc nào ném `PyMongoError`, exception handler toàn cục trả về **HTTP `503 Service Unavailable`** (không rò rỉ chi tiết DB nội bộ).
  - Cập nhật `list_accounts` và `delete_account` hợp nhất khóa `locket_id` từ cả `accounts_v2` và `accounts`.
- **Bài kiểm thử xác minh:** `tests/test_prompt7_security_and_staging.py::test_p1_mongodb_consistency_no_swallowed_errors_and_revoked_precedence` (PASSED).

---

### 1.3. [P1-NET-03] Xử lý `REQUIRE_HTTPS=true` sau Caddy Reverse Proxy & Readiness Probe kiểm tra MongoDB
- **Hiện trạng trước khi sửa:**
  1. Trong `app/middleware.py`, `https = scope['scheme'] == 'https'`. Khi Caddy chuyển tiếp request tới `api:8000` qua HTTP nội bộ kèm header `X-Forwarded-Proto: https`, Uvicorn mặc định nhìn thấy `scope['scheme'] == 'http'` nếu IP của container Caddy nằm trong mạng bridge Docker chưa được kiểm tra qua `TRUSTED_PROXY_CIDRS`, dẫn tới nguy cơ từ chối toàn bộ request với lỗi `400 HTTPS is required`.
  2. Healthcheck trong Docker cũng gọi `http://127.0.0.1:8000/api/health` qua plain HTTP nên sẽ bị chặn khi `REQUIRE_HTTPS=true`, và `/api/health` trước đây chỉ trả JSON tĩnh mà chưa ping MongoDB.
  3. Trong `compose.staging.yaml`, service `lab_https` luôn khởi động mặc định và đòi mount `./certs_private`, gây lỗi nếu người vận hành chưa chạy script sinh chứng chỉ Lab.
- **Giải pháp đã triển khai:**
  - Tại [app/middleware.py](file:///e:/locketgold/app/middleware.py): Bổ sung hàm `is_trusted_proxy_peer(scope)` và `effective_https(scope, headers)`. Hệ thống chỉ tin header `X-Forwarded-Proto: https` khi IP kết nối trực tiếp (`scope['client'][0]`) thuộc `TRUSTED_PROXY_CIDRS`. Client bên ngoài giả mạo `X-Forwarded-Proto: https` bị chặn ngay với HTTP `400`.
  - Cho phép các probe nội bộ trên loopback (`127.0.0.1`, `::1`) truy cập `/api/health` và `/api/ready` qua HTTP để Docker healthcheck luôn hoạt động khi `REQUIRE_HTTPS=true`.
  - Tại [app/routers/management.py](file:///e:/locketgold/app/routers/management.py#L110-L138): Bổ sung endpoint `GET /api/ready` thực hiện lệnh `ping` trực tiếp tới MongoDB và trả về HTTP `503` nếu mất kết nối DB.
  - Tại [compose.staging.yaml](file:///e:/locketgold/compose.staging.yaml): Gắn `profiles: ["lab"]` cho `lab_https` để `docker compose -p locket_staging -f compose.staging.yaml up -d` khởi động thành công ngay cả khi chưa tạo chứng chỉ Lab tùy chọn.
- **Bài kiểm thử xác minh:** `tests/test_prompt7_security_and_staging.py::test_p1_https_behind_trusted_caddy_and_readiness_probe` (PASSED).

---

### 1.4. [P1-SEC-04] Khóa an toàn Research Proxy (`/proxy/*`) trong Production
- **Hiện trạng trước khi sửa:** `app/locket_modifier.py` định nghĩa `UPSTREAM_TARGET = "https://api.locketcamera.com"` và mở route `/proxy/{path:path}` mặc định.
- **Giải pháp đã triển khai:**
  - Bổ sung cờ cấu hình `ENABLE_RESEARCH_PROXY=false` (mặc định tắt hoàn toàn) và `RESEARCH_PROXY_UPSTREAM=http://127.0.0.1:8081` trong [app/config.py](file:///e:/locketgold/app/config.py) và [.env.example](file:///e:/locketgold/.env.example).
  - Khi `ENABLE_RESEARCH_PROXY=false`, mọi request tới `/proxy/{path}` bị chặn ngay với **HTTP `403 Forbidden`**.
  - Ngay cả khi bật trong Lab, hệ thống kiểm tra `FORBIDDEN_THIRD_PARTY_HOSTS` để cấm tuyệt đối việc trỏ proxy tới các máy chủ thanh toán bên thứ ba (`api.revenuecat.com`, `buy.itunes.apple.com`, `sandbox.itunes.apple.com`).
- **Bài kiểm thử xác minh:** `tests/test_prompt7_security_and_staging.py::test_p1_research_proxy_disabled_in_production_and_blocks_third_party_payment_domains` (PASSED).

---

### 1.5. [FIX-05] Đồng bộ CLI `scripts/generate_lab_ca.py`, Bảo vệ Backup bền vững & Identity Verification
- **`scripts/generate_lab_ca.py`**: Hỗ trợ đầy đủ `--out-public` (chỉ lưu `.pem`, `.cer` công khai) và `--out-private` (lưu `.key` với quyền `0600` và bundle cho Caddy) khớp 100% với `DEPLOY_STAGING.md`, đồng thời vẫn giữ `--out-dir` tương thích ngược. Cấm sinh chứng chỉ Leaf cho tên miền của bên thứ ba.
- **`scripts/migrate_db.py` & `app/database.py`**: Loại bỏ giới hạn cắt cụt `length=10000` (dùng `_fetch_all_documents()` với `length=None`, đã test với 10.500 bản ghi), mount volume bền vững `./backups:/app/backups` trong Docker Compose, và bổ sung cờ `--verify-backup <file>` kiểm tra sự tồn tại của file trên đĩa host, kích thước $> 0$, số lượng bản ghi và mã băm `snapshot_sha256`.
- **`app/services/identity_service.py` & `app/models.py`**: Xóa bỏ trường boolean `trusted_proof` khỏi `LinkVerifyInput` (client gửi lên sẽ bị từ chối với HTTP `422 Unprocessable Entity`), bổ sung trường `verification_source` để ghi rõ nguồn xác minh.
