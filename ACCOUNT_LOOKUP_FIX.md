# BÁO CÁO TRIỂN KHAI CƠ CHẾ TRA CỨU TÀI KHOẢN & PHÂN GIẢI UUID (`ACCOUNT_LOOKUP_FIX.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh:** `fix/security-staging-readiness`
**Ngày cập nhật:** 2026-11-25

---

## 1. LUỒNG XỬ LÝ MỚI ĐÃ TRIỂN KHAI (5 BƯỚC CHUẨN HÓA)

Hệ thống đã được cập nhật để xử lý việc tra cứu tài khoản và liên kết UUID theo đúng 5 bước yêu cầu, kết hợp cơ chế đã được chứng minh trong `locketgoldmanager` với kiến trúc Canonical Store (`accounts_v2` + `accounts`) của `locketgold_system`:

### Bước 1 & Bước 2: Tiếp nhận và Kiểm tra Link / Username (`normalize_lookup_query`)
- Thực hiện tại [app/services/identity_service.py](file:///e:/locketgold/app/services/identity_service.py#L19-L55):
  - Hỗ trợ: `username`, `@username`, `https://locket.cam/<username>`, `locket.cam/<username>/`, `https://www.locket.cam/@<username>`, `https://locketcamera.com/<username>`, `https://locket.camera/<username>`.
  - Kiểm tra chặt chẽ `scheme in ('http', 'https')` và `netloc.lower() in ALLOWED_LOCKET_HOSTS`.
  - Giải mã URL (`unquote(link.path.strip('/'))`), loại bỏ tiền tố `@` và kiểm tra khớp toàn bộ chuỗi với `ACCOUNT_ID_PATTERN` (`^[A-Za-z0-9_$:@.\-]{1,128}$`).
  - Mọi URL giả mạo hostname (`https://locket.cam.evil.test/alice`, `https://example.com/alice`), đường dẫn nhiều cấp (`https://locket.cam/a/b`) hoặc ký tự độc hại (`%24%7Bbad%7D`) đều bị từ chối ngay với **HTTP `422 Unprocessable Entity`** mà không thực hiện bất kỳ truy vấn nào xuống MongoDB.

### Bước 3: Tìm kiếm trong MongoDB (`locket_manager`)
- Thực hiện tại [app/services/entitlement_service.py](file:///e:/locketgold/app/services/entitlement_service.py#L140-L176) (`find_canonical_account`) và [app/routers/management.py](file:///e:/locketgold/app/routers/management.py):
  - Tìm kiếm trên cả `accounts_v2` (theo `locket_id`, `username`, `firebase_uid` — đã đánh sparse index trong [app/database.py](file:///e:/locketgold/app/database.py)) và `accounts` (legacy).
  - Hợp nhất kết quả qua `merge_canonical_and_legacy_account(doc_v2, doc_v1)` (bảo đảm trạng thái `revoked` trong `accounts_v2` không bao giờ bị ghi đè).

### Bước 4: Đánh giá và Liên kết UUID Trung thực (`extract_verified_uid_metadata`)
- Thực hiện tại [app/services/entitlement_service.py](file:///e:/locketgold/app/services/entitlement_service.py#L58-L110):
  - **Có UID kèm bằng chứng xác minh hợp lệ**: Chỉ khi bản ghi chứa UID 28 ký tự hợp lệ (`^[A-Za-z0-9]{28}$`), có `verification_status == 'verified_uid'`, `verification_method in {'trusted_proof', 'direct_uid'}` và `verification_source` hợp lệ (khác `'regex_28char_format_only'` / `'format_inspection_only'`), hệ thống mới trả về `uid_verified=True` và `verification_status='verified_uid'`.
  - **Có chuỗi 28 ký tự nhưng chưa có bằng chứng xác minh độc lập**: Hệ thống tự động hạ cấp về `uid_verified=False`, `verification_status='unverified_uid'`, `verification_method='format_only_uid'`. Không bao giờ đánh dấu `verified_uid` chỉ dựa trên độ dài 28 ký tự.
  - **Bản ghi chỉ có username**: Trả về `firebase_uid=None`, `uid_verified=False`, `verification_status='unverified_handle'`.
  - **Không tìm thấy trong MongoDB**: Trả về `exists=False` cùng thông báo rõ ràng cho Admin.

### Bước 5: Lưu dữ liệu an toàn (`POST /admin/add-account`)
- Unique index trên `locket_id` trong cả `accounts` và `accounts_v2` ngăn tạo tài khoản trùng lặp.
- Lưu tách biệt `locket_id`, `username`, `firebase_uid`, `verification_status`, `verification_method`, `verification_source` để không bao giờ nhầm lẫn username với Firebase UID.
- Không tự động cấp quyền `Gold` khi chỉ gọi API tra cứu (`lookup` hoặc `verify-link`). Quyền thử nghiệm chỉ được cấp khi Admin chủ động lưu tài khoản với trạng thái `active` và thời hạn trong tương lai.

---

## 2. ĐẶC TẢ HAI ENDPOINT API TRA CỨU (PUBLIC & ADMIN)

### 2.1. Public Lookup API: `GET /api/accounts/lookup?query=...`
- **Mục đích:** Khôi phục đầy đủ tính năng tra cứu công khai từ `locketgoldmanager`.
- **Phản hồi (`PublicLookupOutput`):**
  ```json
  {
    "exists": true
  }
  ```
- **Bảo mật:** Chỉ trả về duy nhất trường boolean `exists`. Tuyệt đối không tiết lộ `firebase_uid`, `locket_id`, `expires_date`, `device_token` hay trạng thái nội bộ. Được bảo vệ bởi `SecurityMiddleware` (rate limit 120 req/phút/IP) và fail-closed với HTTP `503` khi MongoDB ngừng phản hồi.

### 2.2. Admin Detailed Lookup API: `GET /admin/accounts/lookup?query=...` (và `POST /admin/verify-link`)
- **Quyền truy cập:** Yêu cầu phiên Bearer của Superadmin (`Depends(require_admin)`, giới hạn 60 req/phút/IP).
- **Phản hồi (`AdminAccountLookupOutput`):**
  ```json
  {
    "exists": true,
    "normalized_query": "verified_member",
    "input_kind": "locket_link",
    "username": "verified_member",
    "internal_identifier": "4Vee1rBLoJN9TDjql9xPzDEuf5D2",
    "firebase_uid": "4Vee1rBLoJN9TDjql9xPzDEuf5D2",
    "uid_verified": true,
    "verification_status": "verified_uid",
    "verification_method": "trusted_proof",
    "verification_source": "verified_subscriber_traffic",
    "entitlement_status": "active",
    "expires_date": "2027-01-09T00:00:00Z",
    "updated_at": "2026-11-25T02:00:00Z",
    "message": "Đã tìm thấy tài khoản trong MongoDB (ID: 4Vee1rBLoJN9TDjql9xPzDEuf5D2) kèm Firebase UID đã xác minh..."
  }
  ```
- **Tích hợp Admin Dashboard ([web/index.html](file:///e:/locketgold/web/index.html#L856-L873)):**
  - Hộp công cụ **"1. Account Link & Identifier Verification"** trên trang `/admin` hiện gọi trực tiếp `GET /admin/accounts/lookup?query=...`, hiển thị rõ trạng thái `[FOUND IN MONGODB]` hoặc `[NOT IN MONGODB]`, trạng thái xác minh (`VERIFIED_UID`, `UNVERIFIED_UID`, `UNVERIFIED_HANDLE`) và tự động điền `internal_identifier` vào biểu mẫu tạo/gia hạn tài khoản.

---

## 3. BẰNG CHỨNG KIỂM THỬ TỰ ĐỘNG (`tests/test_account_lookup.py`)

Toàn bộ 12 yêu cầu kiểm thử bắt buộc đã được cài đặt trong [tests/test_account_lookup.py](file:///e:/locketgold/tests/test_account_lookup.py) (27 test cases tham số hóa) và chạy thực tế bằng `pytest`:
1. Tìm kiếm bằng `username` (`alice`): **PASSED**
2. Tìm kiếm bằng `@username` (`@alice`): **PASSED**
3. Tìm kiếm bằng link Locket (`https://locket.cam/alice`, `locket.cam/alice/`, `https://locketcamera.com/alice`): **PASSED**
4. Tìm kiếm tài khoản có trong MongoDB: **PASSED**
5. Tìm kiếm tài khoản không tồn tại: **PASSED**
6. Bản ghi có username nhưng không có UUID (`unverified_handle`): **PASSED**
7. Bản ghi có UUID và bằng chứng xác minh hợp lệ (`verified_uid`): **PASSED**
8. UUID sai hoặc chưa có nguồn xác minh độc lập (`unverified_uid`): **PASSED**
9. Link giả mạo hostname (`https://locket.cam.evil.test/alice`, `https://example.com/alice` $\rightarrow$ HTTP 422, không gọi DB): **PASSED**
10. MongoDB không khả dụng (`PyMongoError` $\rightarrow$ HTTP 503, không lộ thông tin nội bộ): **PASSED**
11. Không rò rỉ UUID/token qua API công khai `/api/accounts/lookup`: **PASSED**
12. Không phụ thuộc vào API của `amlongtruc-source`: **PASSED**
