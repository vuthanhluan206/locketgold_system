# BÁO CÁO XÁC MINH HTTPS RESEARCH LAB & TLS HOSTNAME VERIFICATION (`HTTPS_LAB_VERIFICATION.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Các thành phần kiểm định:** [Caddyfile.lab](file:///e:/locketgold/Caddyfile.lab), [compose.staging.yaml](file:///e:/locketgold/compose.staging.yaml), [scripts/generate_lab_ca.py](file:///e:/locketgold/scripts/generate_lab_ca.py), [app/services/pki_service.py](file:///e:/locketgold/app/services/pki_service.py), [scripts/docker_e2e_smoke.py](file:///e:/locketgold/scripts/docker_e2e_smoke.py)
**Ngày kiểm định:** 2026-11-25

---

## 1. KIẾN TRÚC TÁCH BIỆT CORE STAGING (MODE A) VÀ HTTPS RESEARCH LAB (MODE B)

| Đặc tính | Mode A — Core Staging (`api`) | Mode B — HTTPS Research Lab (`lab_https` + `ca_init`) |
| :--- | :--- | :--- |
| **Cổng lắng nghe** | Loopback `127.0.0.1:18000 -> 8000` (HTTP nội bộ / SSH Tunnel) | Loopback `127.0.0.1:18443 -> 8443` (HTTPS TLS) & `127.0.0.1:18081 -> 8081` |
| **Xung đột cổng 80/443 Production** | **Không** (Hoàn toàn không chạm cổng 80/443) | **Không** (Chạy dưới Docker Compose profile `--profile lab`) |
| **Chứng chỉ TLS sử dụng** | Không yêu cầu chứng chỉ Lab CA khi chạy DNS-only | Leaf Certificate (`lab_leaf.pem` + `lab_leaf.key`) ký bởi `LocketGold Research Lab Root CA` |
| **Tên miền SAN được cấp phép** | `ALLOWED_HOSTS` | Chỉ các tên miền thuộc quyền sở hữu của bạn: `locketgold.vuthanhluan.bond`, `mock.lab.vuthanhluan.bond`, `sub.lab.vuthanhluan.bond` |
| **Chặn mạo danh bên thứ ba** | `FORBIDDEN_THIRD_PARTY_HOSTS` | `FORBIDDEN_THIRD_PARTY_SAN_DOMAINS` trong `scripts/generate_lab_ca.py` cấm tuyệt đối việc sinh chứng chỉ cho `api.revenuecat.com`, `buy.itunes.apple.com`, `api.locketcamera.com` |

---

## 2. XÁC MINH THỰC TẾ TLS SNI, SAN HOSTNAME & CERTIFICATE CHAIN (KHÔNG DÙNG `verify=False` / `-k`)

Trong [scripts/docker_e2e_smoke.py](file:///e:/locketgold/scripts/docker_e2e_smoke.py#L46-L115), chúng tôi đã loại bỏ hoàn toàn `ssl_ctx.check_hostname = False` và thay bằng cơ chế xác thực TLS đầy đủ (`https_req_with_strict_sni_and_hostname_verification`):

1. **Cơ chế kết nối có kiểm tra SNI & SAN Hostname (`_LabPinnedHTTPSConnection`)**:
   - Mở kết nối TCP tới `127.0.0.1:<https_port>` (tương đương cơ chế `--resolve mock.lab.vuthanhluan.bond:<port>:127.0.0.1` của `curl` hoặc bản ghi DNS `A` từ DoH Lab).
   - Khởi tạo `ssl.create_default_context(cafile=".../certs_public/lab_root_ca.pem")` với:
     - `ssl_ctx.check_hostname = True`
     - `ssl_ctx.verify_mode = ssl.CERT_REQUIRED`
   - Gọi `ssl_ctx.wrap_socket(raw_sock, server_hostname=self.host)` để gửi đúng trường **TLS SNI (`mock.lab.vuthanhluan.bond`)** lên Caddy và bắt buộc OpenSSL của Python kiểm tra khớp hostname với phần mở rộng `SubjectAlternativeName (SAN)` trên chứng chỉ Leaf mà Caddy trả về.
2. **Kiểm định chuỗi chứng chỉ (Chain & Lifetime Verification)**:
   - Sau khi bắt tay TLS thành công, hàm lấy chứng chỉ nhị phân DER thực tế từ socket (`conn.sock.getpeercert(binary_form=True)`) và chạy `verify_certificate_chain_and_hostname(ca_cert, peer_cert, hostname)` để xác nhận:
     - `leaf_cert.verify_directly_issued_by(root_ca)` thành công.
     - Thời hạn chứng chỉ Leaf $\le 398$ ngày (`leaf_lifetime_days = 366.0`).
     - `ExtendedKeyUsage` có `serverAuth` và `BasicConstraints(ca=False)`.
3. **Kiểm thử phủ định (Negative TLS Hostname Test)**:
   - Khi gọi tới cùng cổng HTTPS đó nhưng với một tên miền không nằm trong danh sách SAN (`https://unlisted.lab.vuthanhluan.bond/api/health`), kết nối TLS bị chặn ngay lập tức bởi `ssl.SSLCertVerificationError` (`Hostname mismatch`).
