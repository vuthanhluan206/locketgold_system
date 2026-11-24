# HƯỚNG DẪN TRIỂN KHAI VPS UBUNTU (~1 GB RAM) — `DEPLOY_VPS.md`

## Thông số Môi trường Mục tiêu
- **Domain:** `locketgold.vuthanhluan.bond`
- **VPS IPv4:** `103.118.29.159`
- **Database:** MongoDB Atlas (`locket_manager`)
- **NextDNS Configuration ID:** `a8b247` (`https://dns.nextdns.io/a8b247`)
- **Container Runtime:** Docker Compose + Caddy 2

---

## Bước 1: Cấu hình DNS và MongoDB Atlas Network Access

1. **Bản ghi DNS tên miền `vuthanhluan.bond`:**
   - Tạo bản ghi `A` cho `locketgold.vuthanhluan.bond` trỏ về `103.118.29.159` (Tắt proxy đám mây vàng Cloudflare nếu muốn Caddy tự xin chứng chỉ Let's Encrypt trực tiếp, hoặc bật chế độ Full Strict nếu dùng qua Cloudflare).
   - Tạo bản ghi `A` cho `mock.lab.vuthanhluan.bond` trỏ về `103.118.29.159` để phục vụ kiểm thử Lab.
2. **MongoDB Atlas Network Access:**
   - Trong giao diện MongoDB Atlas &rarr; **Network Access** &rarr; Thêm địa chỉ IP của VPS: `103.118.29.159/32`.

---

## Bước 2: Tối ưu Swap cho VPS Ubuntu 1 GB RAM

Trên VPS 1 GB RAM, tạo 1 GB Swap file để tránh OOM khi build Docker image:

```bash
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## Bước 3: Thiết lập `.env`, Khởi tạo Admin & Chứng chỉ Lab Root CA

```bash
git clone https://github.com/vuthanhluan206/locketgoldmanager.git /opt/locketgold
cd /opt/locketgold
cp .env.example .env
```

1. **Tạo tài khoản Superadmin an toàn (không lưu plaintext password):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   python -m app.bootstrap
   ```
2. **Tạo chứng chỉ Root CA riêng cho Research Lab (tùy chọn khi kiểm thử TLS Lab):**
   ```bash
   python -m scripts.generate_lab_ca --out-dir ./certs_private
   ```
3. **Cập nhật `.env`:**
   - Điền `MONGODB_URI="mongodb+srv://..."`
   - Điền `MONGODB_DATABASE="locket_manager"`
   - Điền `NEXTDNS_ID="a8b247"`
   - Điền `ALLOWED_HOSTS='["locketgold.vuthanhluan.bond","localhost","127.0.0.1"]'`
   - Điền `REQUIRE_HTTPS=true`
4. **Chạy kiểm tra Migration không mất dữ liệu cũ:**
   ```bash
   python -m scripts.migrate_db --dry-run
   python -m scripts.migrate_db --apply
   ```

---

## Bước 4: Khởi chạy Docker Compose & Kiểm tra Healthcheck

```bash
docker compose up -d --build
docker compose ps
curl -s https://locketgold.vuthanhluan.bond/api/health
```
