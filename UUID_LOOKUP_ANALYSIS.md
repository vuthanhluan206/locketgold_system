# PHÂN TÍCH CƠ CHẾ TRA CỨU TÀI KHOẢN & XỬ LÝ UUID TỪ `locketgoldmanager` (`UUID_LOOKUP_ANALYSIS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Repository tham khảo bắt buộc:** `https://github.com/vuthanhluan206/locketgoldmanager`
**Nhánh làm việc:** `fix/security-staging-readiness`
**Ngày phân tích:** 2026-11-25

---

## 1. PHÂN TÍCH TRỰC TIẾP 4 FILE THAM KHẢO TRONG `locketgoldmanager`

Chúng tôi đã đọc trực tiếp 4 file từ repository `locketgoldmanager`:
1. `app/routers/management.py`
2. `app/locket_modifier.py`
3. `tests/test_account_lookup.py`
4. `web/index.html`

### 1.1. Phân tích Endpoint `GET /api/accounts/lookup` trong `locketgoldmanager` (`app/routers/management.py`)

Nguyên văn cơ chế trong `locketgoldmanager`:
```python
@router.get('/api/accounts/lookup')
async def lookup_account(accounts: Accounts, query: str = Query(min_length=1, max_length=512)):
    account_id = query.strip()
    if '://' in account_id or '/' in account_id:
        try:
            link = urlsplit(account_id if '://' in account_id else 'https://' + account_id)
            if link.scheme not in ('http', 'https') or link.netloc.lower() not in (
                'locket.cam', 'www.locket.cam', 'locketcamera.com', 'www.locketcamera.com',
            ):
                raise ValueError
            account_id = unquote(link.path.strip('/'))
        except ValueError:
            raise HTTPException(422, 'Vui lòng nhập username hoặc link Locket hợp lệ.')
    account_id = account_id.removeprefix('@')
    if not re.fullmatch(r'[A-Za-z0-9_$:@.\-]{1,128}', account_id):
        raise HTTPException(422, 'Vui lòng nhập username hoặc link Locket hợp lệ.')
    account = await accounts.find_one({'locket_id': account_id}, {'_id': 1})
    return {'exists': account is not None}
```

**Đánh giá kỹ thuật:**
- **Chuẩn hóa đầu vào chặt chẽ**:
  - Tiếp nhận cả 3 dạng: username thuần (`alice`), handle có tiền tố `@` (`@alice`), hoặc link chia sẻ Locket (`https://locket.cam/alice`, `locket.cam/alice/`, `https://locket.cam/alice?share=1`, `https://locketcamera.com/alice`).
  - Dùng `urlsplit` kiểm tra `scheme` bắt buộc là `http` hoặc `https` và `netloc.lower()` phải khớp chính xác danh sách whitelist tên miền Locket. Mọi tên miền giả mạo (`https://locket.cam.evil.test/alice`, `https://example.com/alice`) hoặc đường dẫn nhiều tầng (`https://locket.cam/a/b`) đều bị chặn ở bước regex `r'[A-Za-z0-9_$:@.\-]{1,128}'` và trả về **HTTP `422`** mà **không chạm tới MongoDB**.
- **Bảo mật dữ liệu trên API công khai**:
  - Truy vấn MongoDB với projection tối thiểu `{'_id': 1}` và chỉ trả về duy nhất `{'exists': True/False}`.
  - Hoàn toàn không làm lộ Firebase UID, ngày hết hạn, trạng thái thiết bị hay token.
- **Không phụ thuộc `amlongtruc-source`**:
  - Không hề gọi API bên thứ ba `amlongtruc.net/api/uplocket/lookup`. Toàn bộ quá trình tra cứu diễn ra nội bộ với MongoDB (`locket_manager`).

---

### 1.2. Phân tích Hàm `_extract_locket_id()` trong `locketgoldmanager` (`app/locket_modifier.py`)

Nguyên văn hàm `_extract_locket_id` trong `locketgoldmanager`:
```python
def _extract_locket_id(path: str, data: dict, request_headers: dict) -> str:
    headers_lower = {k.lower(): v for k, v in request_headers.items()}
    for hk in ["x-app-user-id", "x-revenuecat-app-user-id", "x-locket-user-id"]:
        if hk in headers_lower and headers_lower[hk]:
            return headers_lower[hk]
    sub = data.get('subscriber')
    if isinstance(sub, dict) and isinstance(sub.get('original_app_user_id'), str) and sub['original_app_user_id']:
        return sub['original_app_user_id']
    parts = [p for p in path.split("/") if p]
    if "subscribers" in parts:
        idx = parts.index("subscribers")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ''
```

**Phân tích thứ tự trích xuất & đánh giá độ tin cậy của từng trường:**

| Thứ tự ưu tiên trong `_extract_locket_id` | Nguồn dữ liệu | Bản chất kỹ thuật thực tế | Có phải là Firebase UID đã xác minh (`verified_uid`) không? |
| :---: | :--- | :--- | :--- |
| **1** | Header HTTP: `x-app-user-id`, `x-revenuecat-app-user-id`, `x-locket-user-id` | Header do HTTP client tự đính kèm khi gửi request. | **KHÔNG.** Bất kỳ client nào cũng có thể tự đặt giá trị bất kỳ vào header HTTP. Đây chỉ là `unverified_claim` từ phía client, tuyệt đối không được tự động coi là Firebase UID đã xác minh nếu chưa đối chiếu với phiên/token hợp lệ. |
| **2** | Trường JSON response: `data["subscriber"]["original_app_user_id"]` | Mã định danh người dùng trong cấu trúc JSON `CustomerInfo` của subscriber API. | **CHỈ KHI ĐẾN TỪ NGUỒN ĐÃ XÁC THỰC.** Trong môi trường Lab hoặc từ bản ghi đã được xác minh trong database, đây là `account_id` / `original_app_user_id`. Nếu chỉ đọc từ một payload chưa xác thực hoặc chỉ kiểm tra độ dài 28 ký tự thì vẫn là `unverified_uid`. |
| **3** | Đường dẫn URL: `/v1/subscribers/<id>` (`parts[idx + 1]`) | Tham số path trên URL mà client yêu cầu tra cứu. | **KHÔNG.** Đây chỉ là `requested_account_id` (tài khoản mục tiêu mà client đang hỏi). Trong `locketgold_system`, chúng ta đã khóa chặt ở `app/security.py`: `device_token` chỉ được phép gọi URL có `<id>` trùng khớp với `locket_id` đã liên kết với thiết bị đó. |

---

## 2. KẾT LUẬN QUAN TRỌNG VỀ LINK CÔNG KHAI VÀ FIREBASE UID

1. **Bằng chứng từ `locketgoldmanager`**:
   - Repository `locketgoldmanager` **không** suy diễn hay giải mã Firebase UID từ một đường link chia sẻ công khai `https://locket.cam/<username>`.
   - Thay vào đó, `locketgoldmanager` trích xuất `<username>` (hoặc identifier) từ đường dẫn URL, chuẩn hóa (bỏ `@`, kiểm tra hostname và ký tự hợp lệ), rồi **tra cứu trực tiếp trong MongoDB (`locket_manager`)**.
2. **Loại bỏ hoàn toàn sự phụ thuộc vào `amlongtruc-source`**:
   - Trong gói `amlongtruc-source.rar`, trang frontend gọi một dịch vụ bên ngoài (`amlongtruc.net/api/uplocket/lookup`) để đổi username ra UID. Phụ thuộc vào dịch vụ bên thứ ba này vừa không kiểm soát được độ tin cậy, vừa tiềm ẩn rủi ro bảo mật và gián đoạn dịch vụ.
   - Do đó, trong `locketgold_system`, toàn bộ cơ chế tra cứu tài khoản và phân giải UUID được thực hiện **100% nội bộ trên MongoDB `locket_manager`** kết hợp với chính sách xác minh trung thực (**Zero-Guessing Policy**).
