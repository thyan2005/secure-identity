# BÁO CÁO BÀI LAB 01: SECURE IDENTITY, SESSION & AUTHORIZATION

## 1. THÔNG TIN SINH VIÊN
- **Họ và tên:** Nguyễn Hoàng Thy Ân
- **MSSV:** 23150371
- **Môn học:** An Toàn Thương Mại Điện Tử

---

## 2. KIẾN TRÚC & CÁC QUYẾT ĐỊNH BẢO MẬT (Security Decisions)

### 2.1. Xác thực 2 bước (TOTP RFC 6238) & Cửa sổ trôi thời gian
- **Bước 1:** Xác thực username/password băm bằng thuật toán `BCrypt`. Nếu thông tin chính xác, hệ thống cấp một phiên tạm thời trước MFA (`SID_before`) có hiệu lực trong vòng 5 phút để chuyển sang bước 2. Phiên tạm thời này hoàn toàn chưa được cấp bất kỳ quyền hạn nào trong hệ thống.
- **Bước 2:** Xác thực mã 6 số TOTP dựa trên thuật toán RFC 6238 với secret Base32. Hệ thống cho phép độ lệch đồng hồ (clock drift) tối đa $\pm 1$ step ($30s \times 3 = 90s$).

### 2.2. Chống tấn công Replay Attack bằng Redis Atomic SET NX
- Để ngăn chặn việc kẻ tấn công nghe lén và dùng lại mã OTP trong cửa sổ 90 giây còn hiệu lực, sau khi verify OTP thành công, hệ thống sử dụng lệnh nguyên tử:
  `redis.set(f"used_otp:{userId}:{totpCode}", timestamp, ex=120, nx=True)`
- **TTL = 120s:** Bao phủ toàn bộ cửa sổ chấp nhận của TOTP.
- **Cơ chế:** Nếu gửi lại cùng một mã OTP lần thứ hai, lệnh `SET NX` trả về `False` -> Server chặn đứng lập tức, trả về mã lỗi HTTP 400 kèm ghi nhận sự kiện bảo mật `REPLAY_DETECTED`.

### 2.3. Session Hardening & Chống Session Fixation
- **Rotate Session ID:** Ngay sau khi người dùng xác thực thành công MFA, phiên làm việc tạm trước đó (`SID_before`) bị hủy hoàn toàn trên Redis. Hệ thống sinh ra một `SID_after` hoàn toàn mới bằng bộ sinh số ngẫu nhiên an toàn mật mã (`secrets.token_hex(32)` với 256-bit entropy).
- **Thuộc tính Cookie:** Được gắn cờ `HttpOnly` (chống XSS đánh cắp phiên), `SameSite=Lax/Strict` (chống CSRF), và `Secure` khi triển khai trên giao thức HTTPS.
- **Quản lý Timeout kép:**
  - *Idle Timeout (15 phút):* Tự động vô hiệu hóa phiên nếu không phát sinh request nào trong 15 phút.
  - *Absolute Timeout (8 giờ):* Buộc phiên đăng nhập phải hết hạn sau 8 giờ kể từ lúc tạo, bất kể có đang hoạt động hay không.

### 2.4. Phân quyền RBAC & Tách quyền (Separation of Duties - SoD)
- **RBAC:** Kiểm tra phân quyền trực tiếp tại tầng API/Backend (không phụ thuộc vào việc ẩn/hiện nút trên UI):
  - Vai trò CSKH (`role="CSKH"`): Chỉ có quyền tạo yêu cầu hoàn tiền (`CREATE_REFUND`).
  - Vai trò Kế toán (`role="KeToan"`): Chỉ có thẩm quyền phê duyệt hoàn tiền (`APPROVE_REFUND`).
- **Separation of Duties (SoD):** Ngăn ngừa gian lận nội bộ bằng điều kiện logic: Người tạo yêu cầu hoàn tiền tuyệt đối không thể tự duyệt đơn của chính mình (`created_by != approver_id`). Nếu vi phạm, hệ thống từ chối với mã lỗi `403 Forbidden`.

### 2.5. Audit Log an toàn & Bảo vệ dữ liệu nhạy cảm
- Ghi nhật ký đầy đủ 9 trường truy vết điều tra theo chuẩn kiểm toán:
  `timestamp`, `actor_id`, `role`, `action`, `object_id`, `result`, `source_ip`, `correlation_id`, `session_id_hash`.
- **Masking:** Số tài khoản/thẻ ngân hàng (PAN) chỉ giữ lại 4 số cuối (ví dụ: `************9012`).
- **Data Protection:** Mật khẩu, TOTP secret, mã OTP thô và mã CVV tuyệt đối không được ghi ra file log hay lưu trữ trong Database.

### 2.6. Thu hồi phiên (Session Revocation)
- Khi gọi endpoint `/api/auth/logout`, Session ID tương ứng lập tức bị xóa khỏi Redis. Bất kỳ request nào sử dụng lại Session ID cũ đều bị chặn với mã `401 Unauthorized`.

---

## 3. DANH SÁCH TÀI KHOẢN MẪU DÙNG ĐỂ KIỂM THỬ

| Vai trò | Username | Password | TOTP Secret (Base32) | Quyền hạn |
| :--- | :--- | :--- | :--- | :--- |
| **CSKH** | `cskh01` | `Password@123` | `JBSWY3DPEHPK3PXP` | Chỉ tạo đơn hoàn tiền |
| **Kế toán** | `ketoan01` | `Password@123` | `JBSWY3DPEHPK3PXP` | Chỉ duyệt đơn hoàn tiền |

---

## 4. KẾT QUẢ KIỂM THỬ BẮT BUỘC (T1 -> T8)

Dự án đã tích hợp kịch bản kiểm thử tự động tại file `test_lab01.py`, vượt qua toàn bộ 8 bài test theo yêu cầu:

| Mã | Tên kịch bản | Thao tác kiểm thử | Tiêu chuẩn ĐẠT (PASS) | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| **T1** | TOTP hợp lệ | Password -> Nhập đúng OTP lần đầu | HTTP 200, MFA verified | **PASS** |
| **T2** | Replay OTP | Gửi lại mã OTP của T1 trong cùng chu kỳ | HTTP 400, event REPLAY_DETECTED | **PASS** |
| **T3** | OTP sai / hết hạn | Gửi mã OTP `000000` | HTTP 400, từ chối cấp quyền | **PASS** |
| **T4** | Session Fixation | So sánh SID trước và sau MFA; thử dùng SID cũ | `SID_before != SID_after`, SID cũ bị từ chối 401 | **PASS** |
| **T5** | RBAC bypass | Dùng session của CSKH gọi API approve refund | HTTP 403 Forbidden | **PASS** |
| **T6** | Luồng hợp lệ & SoD | CSKH tạo refund -> Kế toán duyệt refund | Cả 2 bước thành công HTTP 200 đúng vai trò | **PASS** |
| **T7** | Log Masking | Gửi dữ liệu có PAN và CVV | PAN bị che còn last-4; Không có CVV trong log | **PASS** |
| **T8** | Session Revocation | Đăng xuất -> Gọi lại API bằng cookie cũ | HTTP 401 Unauthorized | **PASS** |

---

## 5. HƯỚNG DẪN CÀI ĐẶT VÀ CHẠY DỰ ÁN

### Yêu cầu môi trường:
- Python 3.10 trở lên
- Docker Desktop (đang chạy)

### Các bước triển khai:

1. **Khởi động dịch vụ Redis:**
```bash
docker compose up -d
```

2. **Kích hoạt môi trường ảo và cài đặt thư viện:**
- Trên Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
- Trên Linux / macOS:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

3. **Khởi chạy Backend (FastAPI):**
```bash
uvicorn main:app --reload --port 8000
```
- Giao diện Web Portal: http://localhost:8000
- Tài liệu API (Swagger UI): http://localhost:8000/docs

4. **Chạy kịch bản kiểm thử tự động (Test Suite T1 -> T8):**
Mở một tab terminal mới trong VS Code và gõ:
```bash
python test_lab01.py
```

5. **Kiểm tra File Audit Log:**
Xem kết quả ghi nhận nhật ký kiểm toán thực tế tại file `audit.log`.

---

## 6. CẤU TRÚC THƯ MỤC NỘP BÀI

```text
lab01-secure-identity/
├── docker-compose.yml             # Cấu hình container Redis
├── requirements.txt               # Thư viện phụ thuộc
├── main.py                        # Mã nguồn ứng dụng & Security controls
├── test_lab01.py                  # Script kiểm thử tự động T1 -> T8
├── lab01_postman_collection.json  # File Import Postman / Apidog
├── audit.log                      # Bằng chứng Audit Log thực tế
├── README.md                      # Báo cáo & Hướng dẫn chạy
├── templates/
│   └── index.html                 # Giao diện Web Portal demo
└── evidence/                      # Ảnh chụp màn hình kết quả kiểm thử
    └── evidence_test_runner.png
```