# DevSecOps Pipeline 

> **Đồ án môn An toàn Mạng** — Triển khai đường hầm tích hợp & kiểm thử an toàn tự động  
>   Nhóm: Thành Thắng Tâm &nbsp;|&nbsp; Năm: 2026

---

##  Mục lục

- [Tổng quan](#-tổng-quan)
- [Chức năng chính](#-chức-năng-chính)
- [Công nghệ sử dụng](#-công-nghệ-sử-dụng)
- [Kiến trúc pipeline](#-kiến-trúc-pipeline)
- [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
- [Cài đặt & Chạy thử local](#-cài-đặt--chạy-thử-local)
- [Cấu hình](#-cấu-hình)
- [Hướng dẫn sử dụng](#-hướng-dẫn-sử-dụng)
- [Kịch bản demo bảo mật](#-kịch-bản-demo-bảo-mật)
- [Hạn chế hiện tại](#-hạn-chế-hiện-tại)
- [Hướng phát triển](#-hướng-phát-triển)

---

## Tổng quan

Dự án này triển khai một **DevSecOps CI/CD Pipeline** hoàn chỉnh trên nền tảng **GitHub Actions**, tích hợp bốn lớp kiểm thử bảo mật tự động vào quy trình phát triển phần mềm.

### Vấn đề giải quyết

Trong quy trình phát triển phần mềm truyền thống, kiểm thử bảo mật thường được thực hiện **sau cùng** — khi sản phẩm gần hoàn thiện. Điều này dẫn đến:

- Phát hiện lỗ hổng **muộn**, chi phí sửa chữa cao.
- Lỗ hổng bảo mật có thể lọt vào môi trường production.
- Quy trình kiểm tra thủ công, dễ bỏ sót.

### Giải pháp

Pipeline này áp dụng triết lý **"Shift Left Security"** — đưa kiểm thử bảo mật vào **ngay từ đầu** của vòng đời phát triển:

```
Mỗi lần git push → Tự động quét bảo mật → Block deploy nếu có lỗ hổng nghiêm trọng
```

---

## Chức năng chính

| Chức năng | Mô tả | Công cụ |
|-----------|-------|---------|
| **Secret Scanning** | Phát hiện API Key, Password, Token bị hardcode trong source code và git history | GitLeaks |
| **SAST** | Phân tích tĩnh mã nguồn, tìm lỗi lập trình như SQL Injection, Command Injection, Weak Cryptography | Semgrep |
| **SCA** | Phát hiện lỗ hổng CVE trong các thư viện bên thứ ba | Trivy (filesystem) |
| **Container Security** | Build Docker image, kiểm tra ứng dụng chạy đúng, quét lỗ hổng trong image | Trivy (image) |
| **Quality Gate** | Tự động chặn deploy nếu phát hiện lỗ hổng mức HIGH hoặc CRITICAL | Logic tích hợp trong pipeline |
| **Email Notification** | Gửi email cảnh báo khi pipeline thất bại, gửi email xác nhận khi deploy thành công | Gmail SMTP |
| **Pipeline Summary** | Tổng hợp kết quả tất cả các bước bảo mật vào bảng tóm tắt trên GitHub Actions | GitHub Step Summary |

---

## Công nghệ sử dụng

### Ứng dụng mẫu
| Thành phần | Phiên bản | Mục đích |
|-----------|-----------|---------|
| Python | 3.11 | Ngôn ngữ lập trình |
| Flask | 3.1.3 | Web framework |
| Werkzeug | 3.1.9 | WSGI utility library |
| Gunicorn | 26.2.0 | Production WSGI server |

### CI/CD & Bảo mật
| Công cụ | Vai trò |
|---------|---------|
| GitHub Actions | Nền tảng CI/CD |
| GitLeaks `v2` | Secret Scanning |
| Semgrep | SAST — phân tích mã nguồn tĩnh |
| Trivy | SCA (filesystem) + Container Security (image) |
| dawidd6/action-send-mail `v24` | Gửi email thông báo qua Gmail SMTP |

### Hạ tầng
| Thành phần | Mô tả |
|-----------|-------|
| Docker | Đóng gói ứng dụng thành container |
| GitHub Container Registry (GHCR) | *(Chưa tích hợp — xem Hạn chế)* |

---

##  Kiến trúc Pipeline

```
git push lên branch
        │
        ▼
┌───────────────────────────────────────────────────────┐
│          STAGE 1+2 — SECURITY SCANNING (Song song)    │
│                                                       │
│  ┌─────────────────┐ ┌──────────────┐ ┌───────────┐  │
│  │ secret-scanning │ │  sast-scan   │ │  sca-scan │  │
│  │   (GitLeaks)    │ │  (Semgrep)   │ │  (Trivy)  │  │
│  └────────┬────────┘ └──────┬───────┘ └─────┬─────┘  │
└───────────┼─────────────────┼───────────────┼─────────┘
            │    Cả 3 phải PASS mới tiếp tục  │
            └──────────────────┬──────────────┘
                               ▼
┌──────────────────────────────────────────────────────┐
│         STAGE 3 — CONTAINER SECURITY                 │
│                                                      │
│  1. Build Docker image                               │
│  2. Kiểm tra app response /health                    │
│  3. Kiểm tra container chạy đúng user (appuser)      │
│  4. Trivy quét image (báo cáo JSON)                  │
│  5. Trivy gate — block nếu HIGH / CRITICAL           │
└──────────────────────────┬───────────────────────────┘
                           │ PASS
                           ▼
┌──────────────────────────────────────────────────────┐
│         STAGE 4 — DEPLOY (chỉ trên branch main)      │
│           Hiện tại là placeholder echo               │
└──────────────────────────┬───────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
┌─────────────────────┐    ┌────────────────────────┐
│  STAGE 5 — NOTIFY   │    │  STAGE 6/7 — EMAIL     │
│  Bảng tóm tắt kết   │    │  Failure email (FAIL)  │
│  quả trên Actions   │    │  Success email (PASS)  │
└─────────────────────┘    └────────────────────────┘
```

### Chính sách Quality Gate

Pipeline tự động **chặn deploy** nếu phát hiện bất kỳ lỗ hổng nào ở mức:
- `HIGH` — Nguy hiểm cao
- `CRITICAL` — Nghiêm trọng

---

## Cấu trúc thư mục

```
web_app_1.0/
│
├── .github/
│   └── workflows/
│       └── main.yml          # File pipeline CI/CD chính (7 stage)
│
├── docs/
│   └── template-temp.yml     # Template mẫu cấu trúc một job mới
│
├── app.py                    # Ứng dụng Flask (trang "Phiên bản 1.0" + /health)
├── Dockerfile                # Đóng gói ứng dụng, chạy với non-root user
├── requirements.txt          # Danh sách thư viện Python
├── .dockerignore             # Loại trừ file không cần thiết khi build image
└── README.md                 # Tài liệu dự án
```

### Vai trò các file quan trọng

| File | Vai trò |
|------|---------|
| `main.yml` | **Trái tim của dự án** — định nghĩa toàn bộ luồng CI/CD và các bước kiểm thử bảo mật |
| `app.py` | Ứng dụng web tối giản làm "đối tượng" để pipeline kiểm tra |
| `Dockerfile` | Build image với `python:3.11-slim`, chạy bằng gunicorn dưới user `appuser` (non-root) |
| `requirements.txt` | Khai báo thư viện — Trivy SCA sẽ quét file này để tìm CVE |
| `template-temp.yml` | Template tham khảo khi thêm job bảo mật mới vào pipeline |

---

## Cài đặt & Chạy thử local

### Yêu cầu

- Python **3.11+**
- pip
- Docker *(tùy chọn — để chạy bằng container)*

### Chạy trực tiếp bằng Python

```bash
# 1. Clone repository
git clone https://github.com/TuanThanh05/devsecops-pipeline.git
cd devsecops-pipeline

# 2. Tạo virtual environment (khuyến nghị)
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Cài đặt thư viện
pip install -r requirements.txt

# 4. Chạy ứng dụng
python app.py
```

Truy cập: [http://localhost:5000](http://localhost:5000)

### Chạy bằng Docker

```bash
# 1. Build image
docker build -t devsecops-app .

# 2. Chạy container
docker run -p 5000:5000 devsecops-app
```

Truy cập: [http://localhost:5000](http://localhost:5000)

---

## Cấu hình

### GitHub Secrets (bắt buộc để pipeline hoạt động đầy đủ)

Vào **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Mô tả | Bắt buộc |
|--------|-------|----------|
| `GITHUB_TOKEN` | Tự động được GitHub inject — không cần tạo thủ công | ✅ Tự động |
| `MAIL_USERNAME` | Địa chỉ Gmail dùng để gửi thông báo | ✅ Nếu muốn email |
| `MAIL_PASSWORD` | App Password của Gmail *(không phải mật khẩu đăng nhập)* | ✅ Nếu muốn email |
| `MAIL_TO` | Địa chỉ email nhận thông báo | ✅ Nếu muốn email |

> **Lưu ý:** Cần bật **2-Factor Authentication** trên Gmail và tạo **App Password** tại [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).

### Permissions trong `main.yml`

File `main.yml` đã khai báo sẵn các quyền cần thiết:

```yaml
permissions:
  contents: read          # Đọc source code
  security-events: write  # Upload kết quả SARIF lên GitHub Security tab
```

### Branches kích hoạt pipeline

Pipeline tự động chạy khi push lên các branch:

```yaml
branches: [ main, dev-project, tv1-deploy, tv2-deploy, tv3-deploy ]
```

---

## Hướng dẫn sử dụng

### Kích hoạt pipeline

```bash
# Thực hiện thay đổi code
git add .
git commit -m "mô tả thay đổi"
git push origin <branch-name>
```

Pipeline tự động khởi chạy sau khi GitHub nhận được push.

### Xem kết quả pipeline

```
GitHub repo → Tab "Actions" → Click vào run mới nhất
```

- 🟢 **Xanh** — Job PASS
- 🔴 **Đỏ** — Job FAIL (có lỗ hổng bảo mật)
- 🟡 **Vàng** — Đang chạy

### Xem kết quả bảo mật chi tiết

```
GitHub repo → Tab "Security" → "Code scanning alerts"
```

Kết quả từ Semgrep và Trivy được upload dưới dạng SARIF, hiển thị trực tiếp tại đây.

### Xem báo cáo container scan

```
GitHub Actions → Run cụ thể → Artifacts → "container-scan-report"
```

File `trivy-image.json` chứa toàn bộ kết quả quét Docker image.

### Xem bảng tóm tắt pipeline

```
GitHub Actions → Run cụ thể → Tab "Summary"
```

Hiển thị bảng kết quả tổng hợp:

| Gate | Tool | Result |
|------|------|--------|
| Secret Scan | Gitleaks | success / failure |
| SAST | Semgrep | success / failure |
| SCA | Trivy fs | success / failure |
| Container Scan | Trivy image | success / failure |
| Deploy | — | success / skipped |

### Kiểm tra endpoint

```bash
# Health check
curl http://localhost:5000/health
# Kết quả: {"status": "healthy", "version": "1.0"}

# Trang chính
curl http://localhost:5000/
```

## Hạn chế hiện tại

| Hạn chế | Mô tả |
|---------|-------|
| **Deploy là placeholder** | Stage 4 (`deploy-production`) chỉ thực thi lệnh `echo` — chưa deploy thật lên server nào |
| **Không dùng GHCR** | Docker image được build và quét trực tiếp trên máy ảo — không push lên registry |
| **Ứng dụng tối giản** | `app.py` chỉ phục vụ mục đích minh họa pipeline, không có business logic thực tế |
| **Không có database** | Ứng dụng không kết nối database |
| **Email cần cấu hình thủ công** | Phải tạo Gmail App Password và điền Secrets trên GitHub mới nhận được email thông báo |

---

## Hướng phát triển

- [ ] Tích hợp deploy thật lên cloud platform (Render, Railway, hoặc VPS)
- [ ] Push Docker image lên GitHub Container Registry (GHCR) để tái sử dụng giữa các job
- [ ] Thêm DAST (Dynamic Application Security Testing) với OWASP ZAP
- [ ] Tích hợp thông báo qua Slack / Telegram thay vì chỉ email
- [ ] Thêm badge trạng thái pipeline vào README
- [ ] Mở rộng ứng dụng mẫu để kiểm thử phong phú hơn

---

## Contributors

> Thông tin thành viên nhóm — 
- Bùi Huỳnh Tuấn Thành
- Phan Minh Thắng
- Trần Khánh Tâm
---

## License

Dự án được xây dựng phục vụ mục đích học tập trong khuôn khổ đồ án môn **An toàn Mạng**.
