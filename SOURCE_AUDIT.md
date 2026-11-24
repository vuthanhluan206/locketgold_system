# SOURCE AUDIT REPORT — LOCKET GOLD RESEARCH SYSTEM

**Ngày kiểm toán:** 24/11/2026  
**Phạm vi kiểm toán:** Toàn bộ 5 tệp tin và gói mã nguồn trong workspace `e:\locketgold`

---

## 1. INVENTORY & ĐỐI CHIẾU TỆP TIN TRONG WORKSPACE

Tất cả 5 tệp tin người dùng yêu cầu đã được truy cập, giải nén và đọc toàn bộ nội dung thành công. Lưu ý tên file thực tế trên ổ đĩa `e:\locketgold` không có hậu tố `(2)`, `(3)`, `(4)` như cách trình duyệt đặt khi tải trùng, cụ thể:

| STT | Tên trong yêu cầu | Tên thực tế tại `e:\locketgold` | Kích thước (Bytes) | Trạng thái đọc & giải nén |
|---|---|---|---|---|
| 1 | `locket.gold.zip` | `e:\locketgold\locket.gold.zip` | 755,838 | **Đã giải nén & đọc 100%** (bao gồm cả `.git` và `SOURCE.md` bản vá mới hơn) |
| 2 | `LocketGold-Installer(2).zip` | `e:\locketgold\LocketGold-Installer.zip` | 12,959 | **Đã giải nén & đọc 100%** |
| 3 | `locket_gold_mitm_server(3).js` | `e:\locketgold\locket_gold_mitm_server.js` | 3,319 | **Đã đọc 100%** |
| 4 | `amlongtruc-source(4).rar` | `e:\locketgold\amlongtruc-source.rar` | 580,885 | **Đã giải nén & đọc 100%** |
| 5 | `cotloicualocketgold.txt` | `e:\locketgold\cotloicualocketgold.txt` | 2,569 | **Đã đọc 100%** |

> [!NOTE]
> Tệp `e:\locketgold\New Text Document.txt` xuất hiện trong trạng thái con trỏ IDE ban đầu đã không còn tồn tại trên đĩa tại thời điểm kiểm toán (`file does not exist`).

---

## 2. CẤU TRÚC THƯ MỤC CHI TIẾT SAU KHI GIẢI NÉN

### 2.1. Gói 1: `locket.gold.zip` (Hệ thống FastAPI & MongoDB hiện tại)

```text
locket.gold/
├── .dockerignore
├── .env.example
├── .gitignore
├── .python-version              # Chỉ định Python 3.12
├── .vercelignore
├── CODE-AUDIT.md                # Nhật ký rà soát code ngày 04/11/2026
├── compose.yaml                 # Chỉ có container mongo:8.0 local, KHÔNG có Caddy hay FastAPI service
├── DEPLOY-VERCEL.md             # Hướng dẫn deploy Vercel
├── Dockerfile                   # python:3.12-slim chạy uvicorn 1 worker
├── index.py                     # Entrypoint cho Vercel (from app.main import app)
├── pyproject.toml               # Khai báo dependencies & pytest config
├── README.md                    # Tài liệu vận hành hiện tại
├── requirements-dev.txt         # pytest, httpx, httpx2 (lỗi tên gói)
├── requirements.txt             # fastapi, uvicorn[standard], pymongo, pydantic-settings, cryptography
├── SECURITY-AUDIT.md            # Nhật ký vá bảo mật
├── SOURCE.md                    # Snapshot toàn bộ mã nguồn của một phiên bản ĐÃ VÁ (khác với file thực tế trên đĩa!)
├── vercel.json
├── app/
│   ├── __init__.py
│   ├── auth.py                  # POST /api/admin/login, GET /api/admin/me, POST /api/admin/logout
│   ├── bootstrap.py             # CLI tạo hash PBKDF2-SHA256 vào .env và đồng bộ superadmin lên MongoDB
│   ├── config.py                # Pydantic BaseSettings đọc biến môi trường
│   ├── database.py              # Lifespan kết nối AsyncMongoClient, tạo index, build profile cache
│   ├── locket_modifier.py       # Router /proxy/* (PAC, mobileconfig sai PayloadType, reverse proxy)
│   ├── main.py                  # Khởi tạo FastAPI, CORSMiddleware, SecurityMiddleware, exception handlers
│   ├── middleware.py            # RateLimiter theo RAM, giới hạn 8KiB body, CSP nonce, TrustedHostMiddleware
│   ├── models.py                # AccountInput, AccountOutput, hàm subscriber_response()
│   ├── passwords.py             # PBKDF2-HMAC-SHA256 (600,000 vòng)
│   ├── profile.py               # Hàm build_profile() tạo XML .mobileconfig (NextDNS + Root CA tùy chọn)
│   ├── security.py              # HTTPBearer: require_admin, require_subscriber_access
│   ├── turnstile.py             # Xác minh Cloudflare Turnstile siteverify
│   └── routers/
│       ├── __init__.py
│       ├── management.py        # GET /, GET /admin, GET /profile.mobileconfig, CRUD /admin/accounts
│       └── subscribers.py       # GET /v1/subscribers/{account_id}
├── tests/
│   ├── conftest.py
│   ├── test_admin_protection.py
│   ├── test_app.py
│   ├── test_auth_entrypoint.py
│   ├── test_icons.py
│   ├── test_mongodb_integration.py
│   ├── test_profile.py
│   └── test_proxy.py
└── web/
    ├── apple-touch-icon.png
    ├── favicon.ico
    └── index.html               # Single-file SPA chứa cả Public View (<!-- PUBLIC_START -->) và Admin View (<!-- ADMIN_START -->)
```

### 2.2. Gói 2: `LocketGold-Installer.zip`

```text
LocketGold-Installer/
├── Chay_Server.bat                        # Script Windows chạy node server.js
├── HUONG_DAN_CAI_DAT.md                   # Hướng dẫn cài mobileconfig và bật Certificate Trust
├── HUONG_DAN_CAI_DAT.txt                  # Bản sao văn bản của HUONG_DAN_CAI_DAT.md
├── LocketGold.mobileconfig                # File XML plist (3,986 bytes - thực chất là XML thuần, KHÔNG phải CMS signed)
├── LocketGold_Unlocked_XML.mobileconfig   # File XML plist giống hệt LocketGold.mobileconfig (3,986 bytes)
├── LocketGoldCA.cer                       # Chứng chỉ Root CA định dạng PEM (CN=LocketProxy CA, O=Local Research, C=VN)
├── package.json                           # ESM package ("type": "module")
└── server.js                              # HTTP server cổng 8080 phục vụ trang tải .mobileconfig và mock /v1/subscribers/*
```

### 2.3. Tệp 3: `locket_gold_mitm_server.js`

Một tệp Node.js độc lập (98 dòng) sử dụng `node:http`, lắng nghe trên cổng `MITM_PORT || 8080` (HTTP thuần, **không có TLS/HTTPS**), trả về JSON giả lập cho `/v1/subscribers/*` và `/v1/receipts`, hoặc HTTP `204` nếu header `Host` chứa `adsbynimbus.com`.

### 2.4. Gói 4: `amlongtruc-source.rar`

```text
amlongtruc-source/
├── .htaccess                              # Rewrite rule cho Apache/123HOST
├── index.html
├── LocketGold_Clean_Unlocked.mobileconfig # Giống hệt LocketGold_Unlocked_XML.mobileconfig (DoH dns.nodns.vn + LocketProxy CA)
├── LocketGold_dnslocket.mobileconfig      # Giống hệt LocketGold_Clean_Unlocked.mobileconfig
├── LocketGoldCA.cer                       # Giống hệt LocketGoldCA.cer trong bộ Installer
├── locket_gold_mitm_server.js             # Giống hệt File 3
├── package.json
├── README.md
├── server.js                              # Node.js backend phục vụ SPA, quản lý mã mời COC-*, proxy lookup tới amlongtruc.net
├── tsconfig.json
├── vite.config.ts
├── api/
│   ├── profile.php                        # Bản PHP tương đương với server.js
│   └── data/
│       ├── invites.json                   # Lưu mã mời COC-CON6EMEYG
│       ├── profile.json                   # Cấu hình trang Bio
│       └── uplocket_init.json             # Cấu hình bảng giá gói Gold và danh mục khung viền
├── dist/                                  # Bản build tĩnh của frontend React
└── src/
    ├── App.tsx
    ├── index.css
    ├── constants/shared.ts
    └── components/
        ├── LocketGoldFreePage.tsx         # Luồng nhập username -> gọi /api/uplocket/lookup -> nhập inviteCode -> tải mobileconfig
        ├── LocketGoldCustomPage.tsx       # Luồng đăng nhập Firebase Auth (Email/Pass hoặc Token) -> lấy UID -> đăng video/khung
        └── admin/AdminDashboard.tsx       # Quản trị mã mời COC-*, nhạc nền, QR, Netflix code
```

---

## 3. PHÂN TÍCH MÃ NGUỒN, LUỒNG DỮ LIỆU & PHÁT HIỆN MÂU THUẪN NGHIÊM TRỌNG

### 3.1. Sự bất đồng bộ giữa mã nguồn thực tế (`app/*`) và tài liệu (`SOURCE.md`, `tests/*`) trong `locket.gold.zip`

Một phát hiện cực kỳ quan trọng khi đối chiếu từng dòng lệnh trong `locket.gold.zip`: **Các file thực tế trong thư mục `app/` và `web/` là phiên bản CŨ/LỖI, trong khi `tests/` và `SOURCE.md` lại thuộc về một phiên bản ĐÃ VÁ.** Nếu chạy `pytest` ngay trên thư mục `locket.gold` được giải nén, **bộ kiểm thử sẽ thất bại hàng loạt** vì những lý do sau:

1. **Lỗi mặc định cấp quyền Gold cho tài khoản KHÔNG tồn tại (`app/models.py#L41-L51`):**
   - Trong `app/models.py` thực tế:
     ```python
     try:
         expiry = normalize_expiry(account['expires_date']) if account else None
     except (ValueError, TypeError, KeyError):
         expiry = None

     if expiry is None:
         expiry = datetime(2029, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
     ```
   - **Hệ quả:** Khi `account` là `None` (tài khoản không tồn tại trong MongoDB hoặc đã bị Admin xóa), `expiry` là `None` nhưng dòng 48–49 lại gán cứng `expiry = 2029-12-31`! Do đó `active = expiry > now` luôn bằng `True`. Bất kỳ ID nào không có trong DB hoặc vừa bị xóa khi gọi `GET /v1/subscribers/{account_id}` (`app/routers/subscribers.py#L11-L16`) đều được trả về quyền Gold hạn tới năm 2029.
   - Điều này mâu thuẫn trực tiếp với `tests/test_app.py#L143, L226, L261` (nơi test kỳ vọng `entitlements == {}` khi `account` là `None`).

2. **Lỗi trong `app/locket_modifier.py` thực tế so với `SOURCE.md`:**
   - **Kết nối MongoDB đồng bộ chặn Event Loop (`app/locket_modifier.py#L14-L25`):** Khởi tạo `pymongo.MongoClient` đồng bộ ngay lúc import module và gọi `db.accounts.find_one({"api_token": user_token})` đồng bộ bên trong hàm `async def dynamic_reverse_proxy` (`#L245`).
   - **Tra cứu sai khóa và mặc định `is_gold_active = True` (`app/locket_modifier.py#L240-L262`):** Đặt mặc định `is_gold_active = True`, `expiry_date = "2029-12-31T23:59:59Z"`. Sau đó tìm trong `db.accounts.find_one({"api_token": user_token})`. Nhưng Admin Dashboard (`app/routers/management.py#L81-L88`) chỉ lưu `{"locket_id": ..., "expires_date": ...}`, **không bao giờ lưu trường `api_token` hay `is_active`**. Vì vậy `account_record` luôn là `None`, và proxy luôn tiêm quyền Gold giả cho mọi request!
   - **Tạo dữ liệu giả `viewers` (`app/locket_modifier.py#L218-L226`):** Khi `db.viewers_history` không có dữ liệu, code tự động chèn người xem giả `"user_id": "vtl_cloud_id", "username": "vuthanhluan", "display_name": "Vũ Thành Luân"`.
   - **Sai `PayloadType` trong `/proxy/install` (`app/locket_modifier.py#L52-L70`):** Đặt `<key>AutoProxy</key>` bên trong `<string>com.apple.webClip.managed</string>`. Theo chuẩn Apple Configuration Profile Reference, `com.apple.webClip.managed` dùng để tạo icon shortcut trên màn hình chính (yêu cầu khóa `URL` và `Label`), hoàn toàn không hỗ trợ `AutoProxy`. Cấu hình này vô tác dụng trên iOS.
   - **Thiếu hằng số `MAX_PROXY_BODY` trong `app/middleware.py`:** File `tests/test_proxy.py#L13` import `from app.middleware import MAX_PROXY_BODY`, nhưng trong `app/middleware.py` thực tế chỉ có `MAX_BODY = 8192` (dòng 13), gây `ImportError` ngay khi chạy pytest.

3. **Mâu thuẫn trên trang chủ Public View (`web/index.html#L565-L664`):**
   - Trong `web/index.html` thực tế trên đĩa: Nút `#installBtn` dùng `<script nonce="__NONCE__">` tạo `Blob` từ chuỗi XML cứng `mobileConfigXML` chứa chứng chỉ `CN=LocketGold Root CA, O=LocketGold CA, C=US` và NextDNS ID cứng `https://dns.nextdns.io/8f4cb9` (`web/index.html#L614`) — hoàn toàn bỏ qua endpoint `/profile.mobileconfig` và bỏ qua biến môi trường `NEXTDNS_ID=a8b247` của server!
   - Hơn nữa, `tests/test_app.py#L102-L103` kiểm tra `assert '<script' not in public.text` và `assert 'href="/profile.mobileconfig"' in public.text`, nên test này chắc chắn fail trên file `web/index.html` hiện tại.

4. **Lỗi cấu hình CORS và OpenAPI (`app/main.py#L14-L30`):**
   - `app/main.py` thực tế bật `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` và không tắt `openapi_url=None`, khiến `tests/test_proxy.py#L87-L89` (`assert http.get('/openapi.json').status_code == 404` và kiểm tra không có `access-control-allow-origin`) bị lỗi.

5. **Lỗi dependency trong `requirements-dev.txt` (`locket.gold/requirements-dev.txt#L4`):**
   - Dòng 4 ghi `httpx2` — đây là một gói không tồn tại hoặc sai tên trên PyPI, gây lỗi khi chạy `pip install -r requirements-dev.txt`.

6. **Thiếu cấu hình Deployment thực tế cho VPS (`locket.gold/compose.yaml`):**
   - `compose.yaml` hiện chỉ khai báo duy nhất service `mongo:8.0` bind vào `127.0.0.1:27017`, hoàn toàn thiếu service `api` (FastAPI), thiếu reverse proxy `caddy`, thiếu `Caddyfile`, không có giới hạn bộ nhớ (`mem_limit`) cho VPS 1 GB RAM, và không có healthcheck.

---

## 4. PHÂN TÍCH VAI TRÒ TỪNG MODULE & LUỒNG DỮ LIỆU HIỆN TẠI

### 4.1. Luồng Quản trị & Xác thực (`app/auth.py`, `app/security.py`, `app/passwords.py`, `app/turnstile.py`)
- **Cơ chế hoạt động:**
  1. Khi ứng dụng khởi động (`app/database.py#L48-L50`), hàm `lifespan` thực hiện `db.admins.update_one({'_id': 'superadmin'}, {'$setOnInsert': admin_document(settings)}, upsert=True)`.
  2. Khi Admin đăng nhập tại `POST /api/admin/login` (`app/auth.py#L49-L69`), hệ thống kiểm tra giới hạn tốc độ trong collection `login_limits` (10 lần/IP/phút, 30 lần/toàn cục/phút), gọi Cloudflare Turnstile (`verify_turnstile`), sau đó băm mật khẩu với `PBKDF2-HMAC-SHA256` (600,000 vòng) trong worker thread (`asyncio.to_thread`).
  3. Nếu hợp lệ, sinh token ngẫu nhiên 48 bytes (`secrets.token_urlsafe(48)` -> chuỗi 64 ký tự), băm SHA-256 (`token_digest`) làm `_id` lưu vào collection `sessions` kèm `auth_version` và `expires_at`.
- **Đánh giá:** Module xác thực được thiết kế tốt, an toàn mật mã, chống timing attack (`secrets.compare_digest`), có cơ chế tự động vô hiệu hóa toàn bộ session cũ khi đổi mật khẩu thông qua `auth_version`.

### 4.2. Luồng Quản lý Tài khoản & Thuê bao (`app/routers/management.py`, `app/routers/subscribers.py`, `app/models.py`)
- **Cơ chế hoạt động:**
  1. Admin gọi `POST /admin/add-account` gửi `{"locket_id": "...", "expires_date": "..."}`.
  2. Dữ liệu chỉ có 2 trường `locket_id` và `expires_date` được upsert vào collection `db.accounts`.
  3. Không có trường `status` (`active`, `revoked`, `expired`, `pending`), không có lịch sử chỉnh sửa (audit log), không có cơ chế nhận diện từ link `locket.cam/...` hay xác minh UUID thật.
  4. Khi thu hồi quyền, Admin chỉ có lựa chọn xóa trắng bản ghi (`DELETE /admin/accounts/{account_id}`), dẫn đến mất dấu vết lịch sử kiểm thử.

### 4.3. Luồng Sinh Cấu hình iOS (`app/profile.py`)
- **Cơ chế hoạt động:**
  1. Hàm `build_profile(settings)` được gọi **1 lần duy nhất lúc khởi động FastAPI** (`app/database.py#L25`) và lưu bytes kết quả vào `app.state.profile`.
  2. Tạo payload `com.apple.dnsSettings.managed` với `ServerURL = https://dns.nextdns.io/{settings.nextdns_id}` (không có `SupplementalMatchDomains`, nghĩa là bắt toàn bộ truy vấn DNS của thiết bị đi qua NextDNS).
  3. Nếu có `ROOT_CA_PATH` hoặc `ROOT_CA_PEM`, kiểm tra tính hợp lệ của chứng chỉ X.509 (`BasicConstraints.ca == True`, tự ký `verify_directly_issued_by`, còn hạn, không chứa `PRIVATE KEY`) và nhúng DER bytes vào payload `com.apple.security.root`.
- **Hạn chế:**
  - Không hỗ trợ sinh profile động theo từng thiết bị/phiên kiểm thử hoặc tùy chọn `SupplementalMatchDomains` cho môi trường Lab.
  - Không lưu phiên bản profile (`profile_versions`) vào database để đối chiếu khi kiểm thử trên iPhone.

### 4.4. Luồng Tra cứu Tài khoản trong `amlongtruc-source.rar` (`src/components/LocketGoldFreePage.tsx`, `src/components/LocketGoldCustomPage.tsx`)
- Trong `LocketGoldFreePage.tsx#L27-L34`:
  - Hàm `tt(e)` cắt chuỗi `locket.cam/<username>` hoặc `@username` để lấy `username`.
  - Sau đó gửi `POST /api/uplocket/lookup` với `{"username": t}`.
  - Tuy nhiên, trong `amlongtruc-source/server.js#L149-L162` và `api/profile.php#L149-L173`, backend này **không có logic tự phân giải username sang UID** mà chỉ forward (`fetch` / `curl_init`) sang `https://amlongtruc.net/api/uplocket/lookup`!
- Trong `LocketGoldCustomPage.tsx#L31-L39`:
  - Người dùng nhập Email/Password hoặc Firebase Token và gọi `/api/locket/login` (hoặc `/api/locket_proxy.php?action=login`). Tuy nhiên, cả hai file `/api/locket/*` và `api/locket_proxy.php` **đều không tồn tại** trong gói `amlongtruc-source.rar` (đây là phần backend bị thiếu khi người tạo gói rar trích xuất từ web).

---

## 5. ĐỐI CHIẾU CÁC LỖI LỊCH SỬ (HISTORICAL BUGS) VỚI MÃ NGUỒN

Bảng dưới đây xác minh nguyên nhân gốc rễ (Root Cause) của 11 lỗi lịch sử dựa trên bằng chứng mã nguồn thực tế:

| STT | Lỗi lịch sử | Bằng chứng trong mã nguồn | Nguyên nhân gốc rễ (Root Cause) |
|---|---|---|---|
| 1 | Thiếu thư viện `httpx` | `requirements.txt#L1-L5`, `requirements-dev.txt#L3-L4` | `httpx` chỉ nằm trong `requirements-dev.txt` (kèm dòng lỗi `httpx2`), không có trong `requirements.txt` khi cần thực hiện async HTTP client request hoặc chạy test trong container. |
| 2 | `ALLOWED_HOSTS` sai định dạng JSON | `app/config.py#L20, L89-L104` | Trong Pydantic Settings v2, kiểu `list[str]` mặc định yêu cầu chuỗi JSON hợp lệ (`["host1","host2"]`) trước khi đi vào validator nếu không xử lý kiểu `str | list[str]`. Nếu người dùng nhập `ALLOWED_HOSTS=locketgold.vuthanhluan.bond` (không có ngoặc vuông JSON), Pydantic báo lỗi parse JSON trước khi chạy validator. |
| 3 | MongoDB SRV URI sai | `app/config.py#L82-L87`, `requirements.txt#L3` | Khi dùng `mongodb+srv://` (MongoDB Atlas), `pymongo` bắt buộc phải có thư viện `dnspython` để phân giải bản ghi SRV/TXT. Nếu môi trường cài đặt thiếu hoặc URI chứa ký tự đặc biệt chưa URL-encode, hoặc DNS container không phân giải được SRV record, ứng dụng crash ngay khi khởi tạo `AsyncMongoClient`. |
| 4 | MongoDB authentication & Network Access | `app/database.py#L28-L35` | `await client.admin.command('ping')` chạy ngay trong `lifespan` với timeout 5000ms. Nếu IP VPS (`103.118.29.159`) chưa được whitelist trên MongoDB Atlas Network Access hoặc sai user/pass, `lifespan` ném ngoại lệ làm Uvicorn dừng khởi động. |
| 5 | `KeyError: status` | `app/models.py#L18-L38`, `app/routers/management.py#L81-L94` | Schema `AccountInput` / `AccountOutput` chỉ lưu `locket_id` và `expires_date`, hoàn toàn không có trường `status`. Khi code frontend/backend cũ truy cập `account['status']` trực tiếp thay vì `.get('status')` hoặc tính toán qua Entitlement Service sẽ gây `KeyError: 'status'`. |
| 6 | Cấu trúc dữ liệu cũ không tương thích | `app/locket_modifier.py#L247-L258` vs `app/models.py#L20-L21` | Các bản code khác nhau dùng tên trường hỗn loạn trên cùng collection `accounts`: nơi dùng `expires_date` (datetime/string), nơi dùng `expires_at`, `gold_expires_at`, `is_active`, `api_token`, `uid`, `locket_id`. |
| 7 | Sai collection `accounts` và `accounts_v2` | `app/database.py#L37`, `app/locket_modifier.py#L245` | Hệ thống cũ đọc/ghi trực tiếp vào `db.accounts` mà không có lớp Repository/Migration hay phân tách `accounts` (legacy) với `accounts_v2` (schema chuẩn hóa). |
| 8 | Khởi động API thất bại khiến Caddy không chạy | `app/database.py#L21-L53`, `compose.yaml` | Khi FastAPI crash ở `lifespan` (do lỗi env, CA, hoặc MongoDB timeout), container API thoát. Nếu Caddy cấu hình `depends_on` cứng hoặc upstream không khả dụng, toàn bộ cổng 80/443 trả lỗi `502 Bad Gateway`. |
| 9 | Lỗi HTTPS và chứng chỉ | `app/profile.py#L42-L56`, `web/index.html#L593`, `LocketGoldCA.cer` | Có tới **2 chứng chỉ Root CA khác nhau** đang tồn tại lẫn lộn trong các file (`CN=LocketProxy CA` trong `LocketGoldCA.cer` và `CN=LocketGold Root CA` cứng trong `web/index.html`). Đặc biệt, `CN=LocketProxy CA` có `NotBefore = 2026-09-26` và thiếu `KeyUsage` extension! |
| 10 | NextDNS ghi Logs nhưng Locket không nhận entitlement | `app/profile.py#L20-L22`, `cotloicualocketgold.txt` | **Nguyên nhân cốt lõi về kiến trúc mạng:** NextDNS chỉ là máy chủ phân giải DNS (DoH). Khi iPhone cài profile NextDNS (`https://dns.nextdns.io/a8b247`), NextDNS ghi log truy vấn tên miền (ví dụ `api.revenuecat.com`). Nhưng nếu NextDNS trả về IP thật của RevenueCat, hoặc nếu NextDNS rewrite IP về VPS mà trên VPS **không có HTTPS server giữ Private Key tương ứng với Root CA đã tin cậy trên máy** (hoặc ứng dụng có Certificate Pinning), thì gói tin HTTPS không bao giờ lấy được JSON từ VPS. |
| 11 | Không thống nhất trạng thái active/revoked giữa Admin và API | `app/models.py#L48-L51`, `web/index.html#L885`, `app/locket_modifier.py#L240` | Admin UI (`web/index.html#L885`) tính trạng thái bằng `new Date(row.expires_date) > new Date() ? 'Gold' : 'Expired'`. Trong khi đó `app/models.py#L48-L50` lại gán mặc định `2029-12-31` khi không tìm thấy tài khoản, và `app/locket_modifier.py#L240` gán mặc định `is_gold_active = True`. |
