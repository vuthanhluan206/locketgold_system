# BÁO CÁO ĐỐI CHIẾU CHỨNG CHỈ GỐC `LocketProxy CA` VÀ CHỨNG CHỈ LAB MỚI (`ROOT_CA_COMPARISON.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Ngày kiểm định:** 2026-11-25

---

## 1. KIỂM CHỨNG TRỰC TIẾP CHỨNG CHỈ THAM CHIẾU (`LocketGoldCA.cer` / `LocketGold_Clean_Unlocked.mobileconfig`)

Chúng tôi đã trích xuất trực tiếp khối dữ liệu nhị phân DER từ thẻ `<data>` của payload `com.apple.security.root` trong `LocketGold_Clean_Unlocked.mobileconfig` (và file `LocketGoldCA.cer`) bằng thư viện mật mã `cryptography.x509` và kiểm thử tự động trong `tests/test_mobileconfig_doh_core.py::test_check2_and_4_reference_locketproxy_ca_vs_generated_lab_ca`:

| Thuộc tính X.509 | Giá trị trích xuất từ DER thực tế (`LocketGoldCA.cer`) | Trạng thái kiểm chứng |
| :--- | :--- | :---: |
| **Subject** | `C=VN, O=Local Research, CN=LocketProxy CA` | **VERIFIED FROM DER** |
| **Issuer** | `C=VN, O=Local Research, CN=LocketProxy CA` | **VERIFIED FROM DER** |
| **Not Valid Before (UTC)** | `2026-09-26T04:44:42+00:00` | **VERIFIED FROM DER** |
| **Not Valid After (UTC)** | `2036-09-26T04:44:42+00:00` (10 năm) | **VERIFIED FROM DER** |
| **SHA-256 Fingerprint** | `16:2C:34:B4:EB:9C:15:42:4D:DE:28:4B:72:9F:A7:0D:35:0C:EB:91:E5:EC:ED:1A:AA:49:FD:E3:B5:85:AF:F1` | **VERIFIED (100% EXACT MATCH)** |
| **Public Key Algorithm** | RSA 2048-bit (`sha256WithRSAEncryption`) | **VERIFIED FROM DER** |
| **BasicConstraints** | `CA=True, path_length=None` (`critical=False`) | **VERIFIED FROM DER** |
| **KeyUsage Extension** | **Không có (`ExtensionNotFound`)** | **VERIFIED FROM DER** |
| **Chữ ký tự ký (Self-Signature)** | `cert.verify_directly_issued_by(cert)` thành công | **VERIFIED FROM DER** |
| **Khoá bí mật (Private Key `.key`)** | **Không tồn tại trong bất kỳ file nguồn nào** | **VERIFIED ABSENT** |

---

## 2. SO SÁNH VỚI CHỨNG CHỈ ROOT CA MỚI DO RESEARCH LAB TỰ SINH (`scripts/generate_lab_ca.py`)

Vì chứng chỉ `LocketProxy CA` gốc không đi kèm khoá bí mật (Private Key), về mặt mật mã học không ai có thể dùng chứng chỉ đó để ký chứng chỉ Leaf TLS cho máy chủ VPS của bạn. Do đó, hệ thống Research Lab sử dụng `scripts/generate_lab_ca.py` (`app/services/pki_service.py`) để sinh một cặp khóa Root CA và Leaf Certificate hoàn toàn mới thuộc quyền kiểm soát của riêng bạn:

| Tiêu chí so sánh | Chứng chỉ tham chiếu (`LocketProxy CA`) | Chứng chỉ mới do dự án sinh (`LocketGold Research Lab Root CA`) |
| :--- | :--- | :--- |
| **Subject / Issuer** | `C=VN, O=Local Research, CN=LocketProxy CA` | `C=VN, O=LocketGold Research Lab, CN=LocketGold Research Lab Root CA` |
| **SHA-256 Fingerprint** | Cố định: `16:2C:34:B4:...:AF:F1` | **Khác biệt hoàn toàn** (sinh ngẫu nhiên theo từng cặp khóa ECDSA P-256 mới; được tính động và trả về qua `/api/health` và `/admin/pki/status`) |
| **Thuật toán khóa** | RSA 2048-bit | ECDSA P-256 (`SECP256R1`) hiệu năng cao |
| **Thời điểm bắt đầu hiệu lực (`NotBefore`)** | `2026-09-26` (Nếu thiết bị có đồng hồ trước thời điểm này sẽ báo `NotYetValid`) | `now - 7 days` (Lùi 7 ngày so với thời điểm chạy lệnh sinh, luôn hợp lệ ngay lập tức) |
| **BasicConstraints** | `CA=True` (`critical=False`) | `CA=True, path_length=0` (`critical=True` chuẩn RFC 5280) |
| **KeyUsage** | Thiếu extension `KeyUsage` | `digital_signature=True, key_cert_sign=True, crl_sign=True` (`critical=True`) |
| **Quản lý Private Key** | Không có Private Key | Lưu riêng trong `certs_private/lab_root_ca.key` với quyền `0600` (UID `10001`), **không bao giờ** mount vào container FastAPI, không đưa vào `.mobileconfig` và không commit lên GitHub |
