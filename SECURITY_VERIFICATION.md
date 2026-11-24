# BÁO CÁO KIỂM ĐỊNH BẢO MẬT HỆ THỐNG (`SECURITY_VERIFICATION.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Nhánh kiểm định:** `fix/security-staging-readiness`
**Ngày kiểm định:** 2026-11-25

---

## 1. KIỂM ĐỊNH PHÂN QUYỀN & CHỐNG TRUY CẬP CHÉO TÀI KHOẢN (IDOR / BROKEN OBJECT LEVEL AUTHORIZATION)

| Tác nhân (Caller Kind) | Phương thức xác thực | Quyền hạn trên `/v1/subscribers/{account_id}` & `/api/lab/*` | Kết quả kiểm thử |
| :--- | :--- | :--- | :---: |
| **Anonymous (Không có token)** | Không có `Authorization: Bearer` | Bị từ chối hoàn toàn với **HTTP `401 Unauthorized`**. | **VERIFIED (PASS)** |
| **Enrolled Device (`device_token`: `lkg_dev_*`)** | SHA-256 hash đối chiếu trong collection `devices` (`status == 'active'`, `revoked_at == None`) | Chỉ được phép đọc dữ liệu khi `device_doc['locket_id'] == account_id`. Nếu truy cập `account_id` của người khác $\rightarrow$ **HTTP `403 Forbidden`**. Nếu thiết bị đã bị thu hồi $\rightarrow$ **HTTP `401 Unauthorized`**. | **VERIFIED (PASS)** |
| **Trusted Server (`service_token`: `SUBSCRIBER_API_TOKEN`)** | So sánh constant-time (`secrets.compare_digest`) với token 32–256 ký tự ASCII trong `.env` | Được phép tra cứu trạng thái thuê bao từ backend tin cậy. | **VERIFIED (PASS)** |
| **Superadmin (`admin_session`)** | 64-char token đối chiếu SHA-256 trong `sessions` (`expires_at > now`, khớp `auth_version` của `superadmin`) | Toàn quyền quản trị trên `/admin/*` và kiểm thử trên Interactive Lab Client. Giới hạn tốc độ 60 req/phút/IP. | **VERIFIED (PASS)** |

---

## 2. KIỂM ĐỊNH BẢO MẬT REVERSE PROXY, TRUSTED PROXY & HTTPS

1. **Chống giả mạo `X-Forwarded-Proto` và `CF-Connecting-IP` ([app/middleware.py](file:///e:/locketgold/app/middleware.py)):**
   - Hàm `is_trusted_proxy_peer(scope)` kiểm tra địa chỉ IP kết nối trực tiếp (`scope['client'][0]`) có nằm trong danh sách `TRUSTED_PROXY_CIDRS` hay không.
   - Nếu request đến từ một client không nằm trong `TRUSTED_PROXY_CIDRS`, các header `X-Forwarded-Proto: https` và `CF-Connecting-IP` bị **bỏ qua hoàn toàn**. Khi `REQUIRE_HTTPS=true`, kết nối HTTP thường từ client không tin cậy luôn bị từ chối với HTTP `400`.
   - Khi chạy sau Caddy trong mạng nội bộ Docker (đã khai báo CIDR mạng bridge nội bộ trong `TRUSTED_PROXY_CIDRS`), Caddy gắn `X-Forwarded-Proto: https` và FastAPI nhận diện chính xác kết nối HTTPS, trả kèm header `Strict-Transport-Security: max-age=31536000`.
2. **Khóa an toàn Research Proxy trong Production ([app/locket_modifier.py](file:///e:/locketgold/app/locket_modifier.py)):**
   - Mặc định `ENABLE_RESEARCH_PROXY=false`: mọi request tới `/proxy/{path}` trả về **HTTP `403 Forbidden`**.
   - Chặn chuyển tiếp thông tin xác thực nội bộ: nếu client gửi `SUBSCRIBER_API_TOKEN` hoặc token phiên Admin (`sessions`) vào `/proxy/*`, request bị chặn ngay với HTTP `401` để không bao giờ rò rỉ token nội bộ ra upstream.
   - Cấm tuyệt đối các tên miền thanh toán bên thứ ba (`api.revenuecat.com`, `buy.itunes.apple.com`, `sandbox.itunes.apple.com`) trong cả `RESEARCH_PROXY_UPSTREAM`, `LAB_SCOPED_DOMAINS` và `scripts/generate_lab_ca.py`.

---

## 3. KIỂM ĐỊNH BẢO MẬT CHỨNG CHỈ X.509, MOBILECONFIG & SECRETS

1. **Tách biệt Khoá riêng (Private Key) và Chứng chỉ công khai (Public Certificate):**
   - Công cụ [scripts/generate_lab_ca.py](file:///e:/locketgold/scripts/generate_lab_ca.py) ghi khoá riêng (`lab_root_ca.key`, `lab_leaf.key`) vào thư mục `--out-private` (`certs_private/`, quyền `0600`) và chỉ ghi chứng chỉ công khai (`lab_root_ca.pem`, `lab_root_ca.cer`) vào `--out-public` (`certs_public/`).
   - Hàm `load_validated_root_ca()` trong [app/profile.py](file:///e:/locketgold/app/profile.py) từ chối ngay lập tức nếu dữ liệu chứng chỉ chứa chuỗi `PRIVATE KEY`, chứa nhiều hơn 1 chứng chỉ (chain), hết hạn, hoặc không có `BasicConstraints(ca=True)` và `KeyUsage(key_cert_sign=True)`.
2. **Chống giả mạo xác minh định danh (`POST /admin/verify-link`):**
   - Model `LinkVerifyInput` bật `ConfigDict(extra='forbid')` và không nhận bất kỳ cờ boolean xác minh nào từ phía client. Mọi chuỗi 28 ký tự nhập vào khi không có provider xác thực độc lập phía server đều được gán trạng thái trung thực `unverified_uid` (`uid_verified=False`, `verification_source='regex_28char_format_only'`).
3. **Quét Secrets & Dữ liệu nhạy cảm trong Git Repository:**
   - Đã kiểm tra toàn bộ các file được theo dõi bởi Git (`git ls-files`): **0 file `.env` thật, 0 file `.key` / `.pem` / `.cer` / `.der` / `.p12`, 0 chuỗi `-----BEGIN PRIVATE KEY-----`, 0 dữ liệu người dùng thật từ production**.
