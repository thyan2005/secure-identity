import json
import time
import pyotp
import requests

BASE_URL = "http://localhost:8000"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

def title(t_code, t_name):
    print("\n" + "=" * 70)
    print(f" [{t_code}] {t_name}")
    print("=" * 70)

def run_mandatory_tests():
    totp = pyotp.TOTP(TOTP_SECRET)
    s = requests.Session()

    # -------------------------------------------------------------
    # T1: TOTP hợp lệ (Slide 98)
    # -------------------------------------------------------------
    title("T1", "TOTP HỢP LỆ (LOGIN PASSWORD -> TOTP)")
    res_s1 = s.post(f"{BASE_URL}/api/auth/login-step1", json={"username": "cskh01", "password": "Password@123"})
    assert res_s1.status_code == 200
    sid_before = s.cookies.get("SESSIONID")
    print(f"[Evidence] Step 1 OK. SID_before = {sid_before}")

    valid_otp = totp.now()
    res_s2 = s.post(f"{BASE_URL}/api/auth/login-step2", json={"totp_code": valid_otp})
    assert res_s2.status_code == 200
    sid_after = s.cookies.get("SESSIONID")
    print(f"[Evidence] Step 2 OK. Response={res_s2.json()} | SID_after = {sid_after}")
    print("=> PASS T1: Đăng nhập 2 bước thành công, MFA verified.")

    # -------------------------------------------------------------
    # T2: Replay OTP (Slide 98)
    # -------------------------------------------------------------
    title("T2", "CHỐNG REPLAY ATTACK OTP (DÙNG LẠI CÙNG MÃ OTP)")
    # Thử bắt đầu một luồng đăng nhập mới nhưng gửi lại mã vừa dùng
    s_replay = requests.Session()
    s_replay.post(f"{BASE_URL}/api/auth/login-step1", json={"username": "cskh01", "password": "Password@123"})
    res_replay = s_replay.post(f"{BASE_URL}/api/auth/login-step2", json={"totp_code": valid_otp})
    
    print(f"[Evidence] Status: {res_replay.status_code} | Body: {res_replay.json()}")
    assert res_replay.status_code == 400
    assert "đã được sử dụng" in res_replay.json()["detail"]
    print("=> PASS T2: Atomic SET NX phát hiện mã cũ và chặn đứng (REPLAY_DETECTED).")

    # -------------------------------------------------------------
    # T3: OTP sai / hết hạn (Slide 98)
    # -------------------------------------------------------------
    title("T3", "TỪ CHỐI OTP SAI / HẾT HẠN")
    s_wrong = requests.Session()
    s_wrong.post(f"{BASE_URL}/api/auth/login-step1", json={"username": "cskh01", "password": "Password@123"})
    res_wrong = s_wrong.post(f"{BASE_URL}/api/auth/login-step2", json={"totp_code": "000000"})
    
    print(f"[Evidence] Status: {res_wrong.status_code} | Body: {res_wrong.json()}")
    assert res_wrong.status_code == 400
    assert "không chính xác" in res_wrong.json()["detail"]
    print("=> PASS T3: OTP sai bị từ chối; không cấp session đặc quyền.")

    # -------------------------------------------------------------
    # T4: Session Fixation (Slide 98)
    # -------------------------------------------------------------
    title("T4", "SESSION FIXATION (SO SÁNH SID TRƯỚC VÀ SAU MFA)")
    print(f"[Evidence] SID_before (Pre-auth): {sid_before}")
    print(f"[Evidence] SID_after (Post-auth): {sid_after}")
    assert sid_before != sid_after, "Lỗi: Session ID không được xoay!"
    
    # Thử gửi request bằng SID cũ xem có gọi được API không
    hacker_session = requests.Session()
    hacker_session.cookies.set("SESSIONID", sid_before)
    res_hacker = hacker_session.post(f"{BASE_URL}/api/refund/create", json={
        "amount": 100, "reason": "hack", "pan": "12345678"
    })
    print(f"[Evidence] Dùng SID cũ gọi API: Status = {res_hacker.status_code}")
    assert res_hacker.status_code == 401
    print("=> PASS T4: SID_before != SID_after. Session cũ bị vô hiệu hóa hoàn toàn.")

    # -------------------------------------------------------------
    # T5: RBAC Bypass (Slide 98)
    # -------------------------------------------------------------
    title("T5", "RBAC BYPASS (CSKH CỐ DUYỆT HOÀN TIỀN)")
    # Giả lập ID đơn hoàn tiền bất kỳ
    res_bypass = s.post(f"{BASE_URL}/api/refund/REF_TEST123/approve")
    print(f"[Evidence] CSKH gọi API approve: Status = {res_bypass.status_code} | Body = {res_bypass.json()}")
    assert res_bypass.status_code == 403
    print("=> PASS T5: Backend chặn ngay lập tức (403 Forbidden).")

    # -------------------------------------------------------------
    # T6: Luồng hợp lệ & Tách quyền SoD (Slide 98)
    # -------------------------------------------------------------
    title("T6", "LUỒNG HỢP LỆ (CSKH TẠO ĐƠN -> KẾ TOÁN DUYỆT)")
    # 1. CSKH tạo refund
    res_create = s.post(f"{BASE_URL}/api/refund/create", json={
        "amount": 1200000.0,
        "reason": "Sản phẩm nứt vỡ",
        "pan": "9704123456789012",
        "cvv": "999"  # Sẽ kiểm tra xem CVV có bị log ở T7 không
    })
    assert res_create.status_code == 200
    refund_id = res_create.json()["refund"]["id"]
    print(f"[Evidence] CSKH tạo đơn thành công: ID = {refund_id}")

    # 2. Đăng nhập tài khoản Kế toán
    s_kt = requests.Session()
    s_kt.post(f"{BASE_URL}/api/auth/login-step1", json={"username": "ketoan01", "password": "Password@123"})
    # Lấy OTP cho Kế toán (cùng secret)
    kt_otp = totp.now()
    # Nếu mã này bị trùng do cùng time-step với bước trên, đợi time-step kế tiếp
    if kt_otp == valid_otp:
        print("Đang đợi time-step 30s mới cho Kế toán...")
        time.sleep(30)
        kt_otp = totp.now()

    res_kt_auth = s_kt.post(f"{BASE_URL}/api/auth/login-step2", json={"totp_code": kt_otp})
    assert res_kt_auth.status_code == 200

    # 3. Kế toán duyệt đơn
    res_approve = s_kt.post(f"{BASE_URL}/api/refund/{refund_id}/approve")
    print(f"[Evidence] Kế toán duyệt: Status = {res_approve.status_code} | Body = {res_approve.json()}")
    assert res_approve.status_code == 200
    print("=> PASS T6: CSKH tạo và Kế toán duyệt thành công đúng thẩm quyền.")

    # -------------------------------------------------------------
    # T7: Log Masking (Slide 98)
    # -------------------------------------------------------------
    # -------------------------------------------------------------
    # T7: Log Masking (Slide 98)
    # -------------------------------------------------------------
    title("T7", "LOG MASKING (KIỂM TRA DỮ LIỆU NHẠY CẢM TRONG LOG)")
    with open("audit.log", "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    # Tìm chính xác dòng log ứng với đơn hoàn tiền vừa tạo
    refund_log_line = ""
    for line in log_lines:
        if refund_id in line:
            refund_log_line = line
            break

    assert refund_log_line != "", f"Không tìm thấy log của đơn {refund_id} trong audit.log!"
    print(f"[Evidence Audit Log dòng thực tế]:\n{refund_log_line.strip()}")

    # 1. Kiểm tra PAN: Không được có số thẻ đầy đủ "9704123456789012"
    assert "9704123456789012" not in refund_log_line, "Lỗi bảo mật: Full PAN bị lộ trong log đơn hàng!"
    # 2. Kiểm tra Masked PAN: Phải có dạng masked "************9012"
    assert "************9012" in refund_log_line, "Lỗi: Không tìm thấy masked PAN trong log!"
    # 3. Kiểm tra CVV: Tuyệt đối không lưu trường CVV hay giá trị CVV (999) trong dòng log này
    assert "999" not in refund_log_line, "Lỗi bảo mật: CVV bị ghi vào log đơn hàng!"
    assert "cvv" not in refund_log_line.lower(), "Lỗi bảo mật: Tên trường CVV xuất hiện trong log!"
    # 4. Kiểm tra Secret: Không được chứa TOTP secret
    assert TOTP_SECRET not in refund_log_line, "Lỗi: TOTP secret bị lộ trong log!"

    print("=> PASS T7: Đã kiểm chứng log thực tế: Full PAN và CVV không hề bị rò rỉ.")

    # -------------------------------------------------------------
    # T8: Session Revocation (Slide 98)
    # -------------------------------------------------------------
    title("T8", "SESSION REVOCATION (THU HỒI PHIÊN KHI LOGOUT)")
    res_logout = s_kt.post(f"{BASE_URL}/api/auth/logout")
    assert res_logout.status_code == 200
    print(f"[Evidence] Logout thành công.")

    # Thử gọi lại API bằng session vừa logout
    res_after_revoke = s_kt.post(f"{BASE_URL}/api/refund/{refund_id}/approve")
    print(f"[Evidence] Gọi lại API sau khi Logout: Status = {res_after_revoke.status_code}")
    assert res_after_revoke.status_code == 401
    print("=> PASS T8: Session đã bị thu hồi khỏi Redis, request nhận 401.")

if __name__ == "__main__":
    run_mandatory_tests()