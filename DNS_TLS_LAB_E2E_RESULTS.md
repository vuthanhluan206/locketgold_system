# BÁO CÁO KẾT QUẢ KIỂM THỬ KHÉP KÍN DNS-OVER-HTTPS + TLS LAB + AUTOMATIC PROCESSING (`DNS_TLS_LAB_E2E_RESULTS.md`)

**Dự án:** Locket Gold Research & Entitlement Lab (`locketgold_system`)
**Các file kiểm thử thực thi:** [tests/test_mobileconfig_doh_core.py](file:///e:/locketgold/tests/test_mobileconfig_doh_core.py), [tests/test_prompt10_final_iphone_readiness.py](file:///e:/locketgold/tests/test_prompt10_final_iphone_readiness.py), [scripts/docker_e2e_smoke.py](file:///e:/locketgold/scripts/docker_e2e_smoke.py)
**Ngày cập nhật:** 2026-11-25

---

## 1. KẾT QUẢ KIỂM THỬ 13 MẮT XÍCH CỐT LÕI CỦA KIẾN TRÚC HAI PAYLOAD (SECTION 7 ADDENDUM)

| STT | Mắt xích kỹ thuật cần kiểm chứng | Bài kiểm thử tự động thực thi | Kết quả |
| :---: | :--- | :--- | :---: |
| **1** | `.mobileconfig` chứa đúng 2 payload (`com.apple.dnsSettings.managed` + `com.apple.security.root`) khi ở chế độ `lab_ca` / `scoped_lab` | `test_check1_2_3_4_5_6_dual_payload_architecture_and_flexible_doh_modes` & `docker_e2e_smoke.py` (Scenario 16b) | **PASS** |
| **2** | Chế độ `dns_only` (`?mode=dns_only`) chỉ chứa 1 payload DNS, tuyệt đối không nhúng Root CA | `test_check1_2_3_4_5_6_dual_payload_architecture_and_flexible_doh_modes` & `docker_e2e_smoke.py` (Scenario 16a) | **PASS** |
| **3** | Chứng chỉ công khai Root CA hợp lệ (`BasicConstraints(ca=True)`, `KeyUsage(key_cert_sign=True)`, tự ký, trong hạn hiệu lực, không chứa private key) | `test_profile.py` (12 test cases) & `test_check2_and_4_reference_locketproxy_ca_vs_generated_lab_ca` | **PASS** |
| **4** | SHA-256 fingerprint được tính động từ khối nhị phân DER thực tế (cả trên chứng chỉ gốc `LocketProxy CA` `16:2C:34:B4...AF:F1` lẫn chứng chỉ Lab mới sinh) | `test_check2_and_4_reference_locketproxy_ca_vs_generated_lab_ca` | **PASS** |
| **5** | `ServerURL` của DoH đúng cấu hình ở cả Mode A (`https://dns.nextdns.io/a8b247`) và Mode B (`DOH_SERVER_URL=https://mock.lab.vuthanhluan.bond/dns-query`), từ chối HTTP thường và domain bên thứ ba chưa xác minh (`dns.nodns.vn`) | `test_check1_2_3_4_5_6_dual_payload_architecture_and_flexible_doh_modes` | **PASS** |
| **6** | `SupplementalMatchDomains` chỉ chứa các tên miền Lab được phép (`mock.lab.vuthanhluan.bond`, `sub.lab.vuthanhluan.bond`) và từ chối tên miền thanh toán bên thứ ba (`api.revenuecat.com`) | `test_p1_research_proxy_disabled_in_production_and_blocks_third_party_payment_domains` | **PASS** |
| **7** | Endpoint DoH của Lab (`/dns-query` GET wireformat, POST wireformat, JSON) trả về bản ghi `A`/`AAAA` hợp lệ cho tên miền Lab (hỗ trợ cả `LAB_MODE=local` và `LAB_MODE=real_device` với IP công khai `103.118.29.159`), và trả `REFUSED (rcode=5)` cho mọi tên miền ngoài Lab | `test_check7_8_9_10_11_12_13_doh_resolver_tls_chain_and_automatic_processing` & `test_p1_real_device_lab_mode_rejects_loopback_and_supports_public_ipv4_ipv6` | **PASS** |
| **8** | Máy chủ HTTPS Mock Lab (`Caddyfile.lab`) sử dụng chứng chỉ Leaf hợp lệ ($\le 397$ ngày, có `serverAuth` EKU, khớp SAN hostname) ký bởi Lab Root CA | `docker_e2e_smoke.py` (Scenario 16c với `check_hostname=True` và `ssl.CERT_REQUIRED`) | **PASS** |
| **9** | Client thử nghiệm kết nối thành công tới HTTPS Mock Lab qua TLS với kiểm tra SNI + SAN hostname nghiêm ngặt | `https_req_with_strict_sni_and_hostname_verification` trong `docker_e2e_smoke.py` | **PASS** |
| **10** | Backend tự động xác thực `device_token`, tra cứu MongoDB `locket_manager_staging` và trả về JSON `CustomerInfo` ngay lập tức (kể cả khi gửi 8 request đồng thời) mà không cần Admin thao tác tay | `docker_e2e_smoke.py` (Scenario 12 — `ThreadPoolExecutor(max_workers=8)`) | **PASS** |
| **11** | Tài khoản bị thu hồi (`revoked`) bị từ chối quyền `Gold` ngay lập tức (`entitlements: {}`, `X-Lab-Entitlement-Status: revoked`) | `docker_e2e_smoke.py` (Scenario 13 & 14) | **PASS** |
| **12** | Thiết bị không hợp lệ hoặc đã bị thu hồi bị từ chối ngay với HTTP `401`, và thiết bị truy cập chéo tài khoản khác bị chặn với HTTP `403` | `docker_e2e_smoke.py` (Scenario 11 & 15) | **PASS** |
| **13** | Báo cáo kết quả kiểm thử (`format_entitlement_report`) ghi chú rõ `GOLD ACTIVE (Simulated in Lab)`, không bao giờ đánh đồng phản hồi mô phỏng trong Lab với quyền thuê bao chính thức trên ứng dụng Locket | `test_check7_8_9_10_11_12_13_doh_resolver_tls_chain_and_automatic_processing` | **PASS** |
