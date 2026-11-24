# BÁO CÁO KẾT QUẢ KIỂM THỬ TỰ ĐỘNG TOÀN DIỆN (`TEST_RESULTS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_v2_fixed`)
**Thời gian thực thi:** 2026-11-25
**Môi trường thực thi:** Python 3.14.6 (`pytest-9.2.0`, `anyio-4.16.0`, `httpx-0.28.1`, `cryptography`, `pymongo`)

---

## 1. TỔNG QUAN KẾT QUẢ CHẠY PYTEST THỰC TẾ

Lệnh thực thi:
```powershell
& "C:\Users\fpt\AppData\Local\Python\bin\python.exe" -m pytest -v
```

| Chỉ số | Kết quả | Ghi chú |
| :--- | :---: | :--- |
| **Tổng số bài kiểm thử (Collected)** | **88** | Bao gồm 8 file test chuyên biệt trong `tests/` |
| **Số bài PASSED** | **87** | **100% các bài test không yêu cầu MongoDB daemon thật đều PASS** |
| **Số bài SKIPPED** | **1** | `tests/test_mongodb_integration.py` tự động skip an toàn vì không đặt `TEST_MONGODB_URI` trỏ tới daemon MongoDB thật trong môi trường sandbox |
| **Số bài FAILED / ERROR** | **0** | Không có bất kỳ lỗi hay cảnh báo deprecation nào (chạy trong 10.93s) |

---

## 2. CHI TIẾT CÁC NHÓM KIỂM THỬ ĐÃ XÁC MINH

### 2.1. Kiểm thử Sẵn sàng Sản xuất & 7 Nhóm Sửa lỗi Prompt 6 (`tests/test_prompt6_production_readiness.py`)
1. `test_issue1_legacy_env_vars_compatibility_and_conflict_detection`:
   - Xác minh `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`, `MONGO_URI` hoạt động tương thích hoàn toàn khi không có `SUPERADMIN_*`.
   - Xác minh khi đặt cả hai trùng khớp thì khởi động bình thường; khi đặt cả hai khác giá trị nhau thì bị chặn bởi `ValidationError` và tuyệt đối không lộ chuỗi hash mật khẩu trong thông báo lỗi hay `repr(settings)`.
2. `test_issue2_staging_compose_zero_port_conflict_with_production_caddy`:
   - Xác minh `compose.staging.yaml` chỉ bind `127.0.0.1:18000:8000` và `127.0.0.1:18443:8443`, không chứa `"80:80"` hay `"443:443"`.
3. `test_issue3_no_automatic_db_migration_on_fastapi_startup`:
   - Chạy thực tế context manager `lifespan(app)` với mock MongoDB client và xác nhận `accounts_v2.update_one.call_count == 0` và `accounts.find.call_count == 0` (không tự động ghi hay quét migration khi khởi động FastAPI).
4. `test_issue3_and_4_controlled_migration_and_safe_partial_vs_full_rollback`:
   - Xác minh `export_backup_to_dict()` sinh mã băm `snapshot_sha256` và `verify_snapshot_integrity()` phát hiện ngay khi dữ liệu snapshot bị sửa đổi.
   - Xác minh `run_controlled_migration(db, dry_run=True)` thống kê chính xác `total_legacy=5`, `inserted=1`, `skipped=1`, `conflict=1`, `invalid=2` mà không ghi vào DB.
   - Xác minh khi chạy `dry_run=False`, bản ghi xung đột (`conflict_user` đang có trạng thái `revoked` và hạn mới hơn trong `accounts_v2`) **không bị ghi đè** bởi dữ liệu cũ từ `accounts`.
   - Xác minh `restore_rollback_from_dict(..., mode='partial')` khôi phục bản ghi cũ mà không xóa bản ghi `post_migration_user` mới tạo.
   - Xác minh `restore_rollback_from_dict(..., mode='full', confirm_destructive=False)` từ chối xóa bản ghi mới nếu thiếu cờ xác nhận, và khôi phục chính xác 100% trạng thái cũ khi có `confirm_destructive=True`.
5. `test_issue5_mobileconfig_dns_only_vs_lab_ca_and_plist_validation`:
   - Xác minh `/profile.mobileconfig?mode=dns_only` chỉ sinh payload `com.apple.dnsSettings.managed` (`https://dns.nextdns.io/a8b247`), không đính kèm Root CA.
   - Xác minh `/profile.mobileconfig?mode=lab_ca` sinh đầy đủ 2 payload (`com.apple.dnsSettings.managed` + `com.apple.security.root`), parse ngược DER X.509 khớp đúng SHA-256 fingerprint của Lab Root CA.
6. `test_issue6_and_7_mongodb_fail_closed_and_srv_auth_error_resilience`:
   - Giả lập lỗi xác thực MongoDB (`OperationFailure('Authentication failed.')`) và xác minh `/v1/subscribers/test_user` trả về HTTP `503 Service Unavailable`, tuyệt đối không trả về quyền `Gold`.

### 2.2. Kiểm thử Hồi quy & Luồng E2E Research Lab (`tests/test_lab_regression.py` & `tests/test_phase4_full_audit.py`)
- `test_regression_allowed_hosts_accepts_comma_separated_and_json`: PASSED
- `test_regression_no_default_gold_for_nonexistent_or_revoked_accounts`: PASSED
- `test_regression_legacy_record_without_status_field_never_raises_keyerror`: PASSED
- `test_identity_service_zero_guessing_policy`: PASSED (Xác minh link `locket.cam/<username>` trả về `unverified_handle`; chuỗi 28 ký tự không có bằng chứng bên ngoài trả về `unverified_uid` / `format_only_uid`; chỉ khi có `trusted_proof=True` mới trả về `verified_uid`).
- `test_pki_lab_root_ca_and_leaf_generation`: PASSED (Kiểm tra BasicConstraints `CA:TRUE`, `keyCertSign`, SAN và giới hạn thời hạn chứng chỉ Leaf $\le 397$ ngày theo chuẩn Apple iOS TLS).
- `test_end_to_end_lab_flow_devices_revocation_and_scoped_profile`: PASSED (Luồng khép kín từ đăng nhập Admin $\rightarrow$ thêm tài khoản $\rightarrow$ cấp Device Token cho iPhone $\rightarrow$ chặn vượt quá `max_devices` $\rightarrow$ tải Scoped Mobileconfig $\rightarrow$ truy vấn entitlement `active` $\rightarrow$ thu hồi tài khoản tức thì `revoked` $\rightarrow$ kích hoạt lại $\rightarrow$ thu hồi thiết bị trả về HTTP `401`).
- `test_python_compile_and_static_checks`: PASSED (Biên dịch kiểm tra cú pháp toàn bộ các file `.py` trong `app/`, `scripts/`, `tests/`).

### 2.3. Kiểm thử Bảo mật, Rate Limit, Turnstile, Session & Giao diện (`tests/test_app.py`, `tests/test_admin_protection.py`, `tests/test_auth_entrypoint.py`, `tests/test_icons.py`)
- Toàn bộ **73 bài kiểm thử** bảo mật, CSP nonce, chống NoSQL injection, giới hạn kích thước request body, giới hạn tốc độ đăng nhập (rate limiting), xác thực Cloudflare Turnstile, kiểm tra mật khẩu PBKDF2-SHA256 và icon giao diện đều **PASSED 100%**.
