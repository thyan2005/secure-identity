import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

import bcrypt
import pyotp
import redis
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

# =========================================================================
# 1. CẤU HÌNH AUDIT LOG ĐỦ 9 TRƯỜNG BẮT BUỘC (Slide 97 - Mục 5)
# =========================================================================
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(message)s"
)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("[AUDIT] %(message)s"))
logging.getLogger().addHandler(console)

def hash_sid(sid: Optional[str]) -> str:
    """Tạo session_id_hash để điều tra mà không làm lộ Session ID gốc."""
    if not sid:
        return "NONE"
    return hashlib.sha256(sid.encode()).hexdigest()[:16]

def write_audit(
    request: Request,
    action: str,
    actor_id: str,
    role: str,
    object_id: str,
    result: str,  # SUCCESS, DENIED, BLOCKED, FAILED
    details: str = ""
):
    ip = request.client.host if request.client else "unknown"
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    sid = request.cookies.get("SESSIONID")
    sid_hash = hash_sid(sid)
    timestamp = datetime.now(timezone.utc).isoformat()

    log_entry = {
        "timestamp": timestamp,
        "actor_id": actor_id,
        "role": role,
        "action": action,
        "object_id": object_id,
        "result": result,
        "source_ip": ip,
        "correlation_id": correlation_id,
        "session_id_hash": sid_hash,
        "details": details
    }
    logging.info(json.dumps(log_entry, ensure_ascii=False))

def mask_pan(pan: str) -> str:
    """Chỉ giữ last-4 của PAN (Số thẻ/tài khoản)."""
    clean_pan = pan.strip()
    if len(clean_pan) <= 4:
        return "****"
    return "*" * (len(clean_pan) - 4) + clean_pan[-4:]

# =========================================================================
# 2. KHỞI TẠO FASTAPI & REDIS
# =========================================================================
app = FastAPI(title="LAB 01: Secure Identity & Session", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

# Middleware gắn Correlation ID cho mỗi request
@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    request.state.correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = request.state.correlation_id
    return response

# Dữ liệu mẫu (Không lưu password thô hay TOTP secret ở log)
USERS_DB = {
    "cskh01": {
        "id": "usr_cskh_01",
        "username": "cskh01",
        "password_hash": bcrypt.hashpw(b"Password@123", bcrypt.gensalt()).decode(),
        "role": "CSKH",
        "totp_secret": "JBSWY3DPEHPK3PXP",  # RFC 6238 Base32 Secret
    },
    "ketoan01": {
        "id": "usr_ketoan_01",
        "username": "ketoan01",
        "password_hash": bcrypt.hashpw(b"Password@123", bcrypt.gensalt()).decode(),
        "role": "KeToan",
        "totp_secret": "JBSWY3DPEHPK3PXP",
    }
}
REFUNDS_DB = {}

# =========================================================================
# 3. QUẢN LÝ SESSION: IDLE TIMEOUT (15m) & ABSOLUTE TIMEOUT (8h)
# =========================================================================
IDLE_TIMEOUT_SECONDS = 15 * 60        # 15 phút
ABSOLUTE_TIMEOUT_SECONDS = 8 * 3600   # 8 giờ

def get_current_session(request: Request) -> dict:
    sid = request.cookies.get("SESSIONID")
    if not sid:
        write_audit(request, "AUTHENTICATE", "ANONYMOUS", "NONE", "SESSION", "DENIED", "Missing SESSIONID cookie")
        raise HTTPException(status_code=401, detail="Thiếu cookie phiên làm việc (SESSIONID).")

    session_raw = redis_client.get(f"session:{sid}")
    if not session_raw:
        write_audit(request, "AUTHENTICATE", "ANONYMOUS", "NONE", "SESSION", "DENIED", "Invalid or revoked session")
        raise HTTPException(status_code=401, detail="Phiên làm việc không tồn tại hoặc đã bị thu hồi.")

    session = json.loads(session_raw)
    now_ts = datetime.now(timezone.utc).timestamp()

    # Kiểm tra Absolute Timeout (8 giờ)
    if now_ts - session["created_at_ts"] > ABSOLUTE_TIMEOUT_SECONDS:
        redis_client.delete(f"session:{sid}")
        write_audit(request, "SESSION_EXPIRED", session["user_id"], session["role"], sid, "EXPIRED", "Absolute timeout exceeded (8h)")
        raise HTTPException(status_code=401, detail="Phiên làm việc đã quá 8 giờ (Absolute Timeout). Vui lòng đăng nhập lại.")

    # Kiểm tra Idle Timeout (15 phút)
    if now_ts - session["last_active_ts"] > IDLE_TIMEOUT_SECONDS:
        redis_client.delete(f"session:{sid}")
        write_audit(request, "SESSION_EXPIRED", session["user_id"], session["role"], sid, "EXPIRED", "Idle timeout exceeded (15m)")
        raise HTTPException(status_code=401, detail="Phiên làm việc hết hạn do không hoạt động quá 15 phút (Idle Timeout).")

    # Cập nhật thời gian hoạt động mới nhất (trượt Idle timeout)
    session["last_active_ts"] = now_ts
    redis_client.setex(f"session:{sid}", IDLE_TIMEOUT_SECONDS, json.dumps(session))
    return session

# =========================================================================
# 4. SCHEMAS
# =========================================================================
class LoginStep1Dto(BaseModel):
    username: str
    password: str

class LoginStep2Dto(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$")

class RefundCreateDto(BaseModel):
    amount: float = Field(..., gt=0)
    reason: str
    pan: str = Field(..., min_length=6, description="Số thẻ / tài khoản (PAN)")
    cvv: Optional[str] = Field(None, min_length=3, max_length=4, description="CVV - Tuyệt đối không log")

# =========================================================================
# 5. ENDPOINTS
# =========================================================================

@app.post("/api/auth/login-step1", summary="Bước 1: Password & Cấp Session tạm trước MFA (T4)")
def login_step1(body: LoginStep1Dto, request: Request, response: Response):
    user = USERS_DB.get(body.username)
    if not user or not bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        write_audit(request, "LOGIN_STEP_1", body.username, "NONE", "CREDENTIALS", "FAILED", "Invalid username or password")
        raise HTTPException(status_code=401, detail="Sai tài khoản hoặc mật khẩu")

    # Cấp SID_before (Pre-auth session)
    pre_auth_sid = "pre_" + secrets.token_hex(24)
    pre_payload = {"user_id": user["id"], "stage": "MFA_PENDING"}
    redis_client.setex(f"pre_session:{pre_auth_sid}", 300, json.dumps(pre_payload))  # Sống 5 phút

    # Gán Cookie tạm SID_before
    is_secure = (request.url.scheme == "https")
    response.set_cookie(key="SESSIONID", value=pre_auth_sid, httponly=True, secure=is_secure, samesite="lax", max_age=300)

    write_audit(request, "LOGIN_STEP_1", user["id"], user["role"], "PASSWORD", "SUCCESS", f"Step 1 OK. Issued SID_before={pre_auth_sid[:10]}***")
    return {"status": "AWAITING_MFA", "message": "Xác thực mật khẩu thành công. Vui lòng gửi mã TOTP bước 2."}

@app.post("/api/auth/login-step2", summary="Bước 2: Verify TOTP, Atomic SET NX Anti-Replay & Rotate Session")
def login_step2(body: LoginStep2Dto, request: Request, response: Response):
    old_sid = request.cookies.get("SESSIONID")
    if not old_sid or not old_sid.startswith("pre_"):
        write_audit(request, "LOGIN_STEP_2", "ANONYMOUS", "NONE", "SESSION", "FAILED", "Missing or invalid pre-auth session")
        raise HTTPException(status_code=400, detail="Phiên xác thực trước MFA không tồn tại hoặc đã hết hạn.")

    pre_raw = redis_client.get(f"pre_session:{old_sid}")
    if not pre_raw:
        write_audit(request, "LOGIN_STEP_2", "ANONYMOUS", "NONE", "SESSION", "FAILED", "Pre-session expired")
        raise HTTPException(status_code=400, detail="Phiên xác thực trước MFA đã hết hạn.")

    pre_data = json.loads(pre_raw)
    user = next((u for u in USERS_DB.values() if u["id"] == pre_data["user_id"]), None)

    # 1. Chống Replay bằng Atomic SET NX + TTL 120s (Slide 97 - Mục 2)
    # TTL 120s bao trùm toàn bộ cửa sổ clock drift ±1 step (30s x 3 = 90s)
    totp_obj = pyotp.TOTP(user["totp_secret"])
    current_time_step = int(datetime.now(timezone.utc).timestamp() // 30)
    replay_key = f"used_otp:{user['id']}:{body.totp_code}"

    # Lệnh atomic SET NX (chỉ lưu nếu chưa tồn tại)
    acquired = redis_client.set(replay_key, current_time_step, ex=120, nx=True)
    if not acquired:
        # Đã tồn tại mã này trong Redis -> REPLAY_DETECTED
        write_audit(request, "REPLAY_DETECTED", user["id"], user["role"], "TOTP", "BLOCKED", f"Replay OTP detected: {body.totp_code}")
        raise HTTPException(status_code=400, detail="Mã OTP này đã được sử dụng. Vui lòng đợi mã mới trên thiết bị!")

    # 2. Verify TOTP RFC 6238 với clock drift tối đa ±1 step (valid_window=1)
    if not totp_obj.verify(body.totp_code, valid_window=1):
        # Nếu sai mã, xóa lock replay để người dùng không bị kẹt nếu bấm lại
        redis_client.delete(replay_key)
        write_audit(request, "LOGIN_STEP_2", user["id"], user["role"], "TOTP", "FAILED", "Invalid or expired OTP code")
        raise HTTPException(status_code=400, detail="Mã OTP không chính xác hoặc đã ngoài cửa sổ thời gian cho phép.")

    # 3. Session Hardening & Rotation: HỦY SID cũ, SINH SID mới (Slide 97 - Mục 3)
    redis_client.delete(f"pre_session:{old_sid}")  # Thu hồi SID_before

    new_sid = "sess_" + secrets.token_hex(32)
    now_ts = datetime.now(timezone.utc).timestamp()
    session_payload = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at_ts": now_ts,
        "last_active_ts": now_ts
    }
    # Lưu phiên mới vào Redis
    redis_client.setex(f"session:{new_sid}", IDLE_TIMEOUT_SECONDS, json.dumps(session_payload))

    # Gán Cookie phiên chính thức (HttpOnly, Secure, SameSite)
    is_secure = (request.url.scheme == "https")
    response.set_cookie(
        key="SESSIONID",
        value=new_sid,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=ABSOLUTE_TIMEOUT_SECONDS
    )

    write_audit(request, "LOGIN_STEP_2", user["id"], user["role"], "SESSION", "SUCCESS", f"MFA verified. Rotated SID from {old_sid[:8]}*** to {new_sid[:8]}***")
    return {"status": "SUCCESS", "message": "Đăng nhập thành công", "role": user["role"]}

@app.post("/api/refund/create", summary="Tạo yêu cầu hoàn tiền (Chỉ CSKH)")
def create_refund(body: RefundCreateDto, request: Request):
    session = get_current_session(request)

    # RBAC: Chỉ CSKH mới được tạo đơn
    if session["role"] != "CSKH":
        write_audit(request, "CREATE_REFUND", session["user_id"], session["role"], "REFUND", "DENIED", "Unauthorized role for refund creation")
        raise HTTPException(status_code=403, detail="Chỉ bộ phận CSKH mới được phép tạo yêu cầu hoàn tiền.")

    refund_id = f"REF_{secrets.token_hex(4).upper()}"
    masked = mask_pan(body.pan)

    # TUYỆT ĐỐI KHÔNG LƯU HOẶC LOG CVV
    refund_record = {
        "id": refund_id,
        "amount": body.amount,
        "reason": body.reason,
        "masked_pan": masked,
        "created_by": session["user_id"],
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    REFUNDS_DB[refund_id] = refund_record

    # Audit Log: Có masked PAN, hoàn toàn KHÔNG có CVV
    write_audit(
        request, "CREATE_REFUND", session["user_id"], session["role"], refund_id, "SUCCESS",
        f"Amount={body.amount} | MaskedPAN={masked}"
    )
    return {"message": "Tạo yêu cầu hoàn tiền thành công", "refund": refund_record}

@app.post("/api/refund/{refund_id}/approve", summary="Duyệt hoàn tiền (Chỉ Kế toán, Separation of Duties)")
def approve_refund(refund_id: str, request: Request):
    session = get_current_session(request)

    # RBAC: Chỉ Kế toán mới được duyệt
    if session["role"] != "KeToan":
        write_audit(request, "APPROVE_REFUND", session["user_id"], session["role"], refund_id, "DENIED", "CSKH cannot approve refund")
        raise HTTPException(status_code=403, detail="Chỉ bộ phận Kế toán mới có quyền duyệt hoàn tiền.")

    refund = REFUNDS_DB.get(refund_id)
    if not refund:
        raise HTTPException(status_code=404, detail="Không tìm thấy đơn hoàn tiền.")

    # Separation of Duties (SoD): Không cho tự duyệt đơn do chính mình tạo
    if refund["created_by"] == session["user_id"]:
        write_audit(request, "APPROVE_REFUND", session["user_id"], session["role"], refund_id, "DENIED", "SoD violation: self-approval blocked")
        raise HTTPException(status_code=403, detail="Vi phạm Separation of Duties: Không thể tự duyệt đơn do mình tạo!")

    refund["status"] = "APPROVED"
    refund["approved_by"] = session["user_id"]
    refund["approved_at"] = datetime.now(timezone.utc).isoformat()

    write_audit(request, "APPROVE_REFUND", session["user_id"], session["role"], refund_id, "SUCCESS", "Refund approved successfully")
    return {"message": "Duyệt hoàn tiền thành công", "refund": refund}

@app.post("/api/auth/logout", summary="Thu hồi phiên (Revocation)")
def logout(request: Request, response: Response):
    sid = request.cookies.get("SESSIONID")
    if sid:
        redis_client.delete(f"session:{sid}")
        is_secure = (request.url.scheme == "https")
        response.delete_cookie(key="SESSIONID", httponly=True, secure=is_secure, samesite="lax")
        write_audit(request, "LOGOUT", "UNKNOWN", "NONE", sid, "SUCCESS", f"Revoked session {hash_sid(sid)}")

    return {"message": "Đăng xuất và hủy phiên thành công."}

# Route phục vụ giao diện Web demo
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    try:
        with open("templates/index.html", "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h3>Hệ thống Lab 01 đang chạy. Truy cập <a href='/docs'>/docs</a> để xem API.</h3>"