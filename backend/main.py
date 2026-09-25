import os
import uuid
import json
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form, BackgroundTasks, WebSocket
from fastapi.responses import Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

# Your custom modules
import models, database, security, crypto_engine, email_service, scanner_engine
from database import engine, get_db
from chat_manager import manager

# Create uploads folder
os.makedirs("uploads", exist_ok=True)

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="PrivacyOS Enterprise Suite API")

# --- ENTERPRISE SECURITY HEADERS (DAY 6) ---
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Server"] = "PrivacyOS-Ghost-Engine/1.0"
    return response

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- REQUEST SCHEMAS ---
class UserCreate(BaseModel):
    full_name: str
    username: str
    email: EmailStr
    phone_number: str = None
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class LoginStep1(BaseModel):
    email: EmailStr
    password: str

class LoginStep2(BaseModel):
    email: EmailStr
    otp: str


# --- API ROUTES ---

@app.get("/api/health")
def health_check():
    return {"message": "PrivacyOS Enterprise Suite Backend is running!"}

# ==========================================
# 🔑 AUTHENTICATION & IDENTITY (WITH MFA OTP)
# ==========================================
@app.post("/api/register")
def register_user(user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(
        (models.User.email == user.email) | (models.User.username == user.username)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email or Username already registered")
    
    hashed_pw = security.get_password_hash(user.password)
    new_user = models.User(
        full_name=user.full_name, username=user.username, email=user.email,
        phone_number=user.phone_number, hashed_password=hashed_pw, is_active=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    otp_code = security.generate_otp()
    background_tasks.add_task(security.send_real_email_otp, user.email, otp_code)
    return {"message": "Registration successful. Check your email for the OTP.", "email": new_user.email}

@app.post("/api/verify-otp")
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    db.commit()
    return {"message": "Account activated successfully!"}

@app.post("/api/login/initiate")
def login_initiate(data: LoginStep1, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user or not security.verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Please verify your initial registration OTP first")
        
    otp_code = security.generate_otp()
    background_tasks.add_task(security.send_real_email_otp, user.email, otp_code)
    
    app.state.login_otps = getattr(app.state, "login_otps", {})
    app.state.login_otps[user.email] = otp_code
    
    return {"message": "Credentials verified. Check your email for your login OTP.", "email": user.email}

@app.post("/api/login/verify")
def login_verify(data: LoginStep2, db: Session = Depends(get_db)):
    stored_otps = getattr(app.state, "login_otps", {})
    expected_otp = stored_otps.get(data.email)
    
    if not expected_otp or expected_otp != data.otp:
        raise HTTPException(status_code=401, detail="Invalid or expired login OTP.")
        
    del stored_otps[data.email]
    
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    access_token = security.create_access_token(data={"sub": user.email, "id": user.id})
    return {
        "message": "Login successful", "access_token": access_token,
        "token_type": "bearer", "user_id": user.id, "username": user.username
    }

# ==========================================
# 🛡️ TERMINAL A: ENCRYPT & PROTECT
# ==========================================
@app.post("/api/protect")
async def protect_data(
    background_tasks: BackgroundTasks,                  
    sender_email: str = Form(...),                      
    recipient_email: str = Form(...),
    security_tier: str = Form(...),
    transfer_mode: str = Form(...),
    lock_type: str = Form(...),         
    lock_password: str = Form(...),     
    max_views: int = Form(1),
    max_downloads: int = Form(1),
    secret_file: UploadFile = File(...),
    carrier_file: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    if security_tier == "level3":
        transfer_mode = "hidden"
        max_views = 1
    elif security_tier == "level1":
        max_views = 999

    secret_bytes = await secret_file.read()
    encrypted_payload = crypto_engine.encrypt_file_data(secret_bytes, lock_password)
    file_id = str(uuid.uuid4())
    
    if transfer_mode == 'hidden':
        if not carrier_file:
            raise HTTPException(status_code=400, detail="Carrier image required for Level 3 Ghost Mode / Hidden transfer")
        temp_carrier_path = f"uploads/temp_{file_id}_{carrier_file.filename}"
        with open(temp_carrier_path, "wb") as f:
            f.write(await carrier_file.read())
        final_output_path = f"uploads/{file_id}_stego.png"
        try:
            crypto_engine.hide_data_in_image(temp_carrier_path, encrypted_payload, final_output_path, watermark=sender_email)
        except ValueError as e:
            os.remove(temp_carrier_path)
            raise HTTPException(status_code=400, detail=str(e))
        os.remove(temp_carrier_path)
    else:
        final_output_path = f"uploads/{file_id}.enc"
        with open(final_output_path, "wb") as f:
            f.write(encrypted_payload)
            
    new_file = models.ProtectedFile(
        id=file_id, sender_id=1, recipient_email=recipient_email,
        file_name=secret_file.filename, security_level=security_tier,
        transfer_mode=transfer_mode, encrypted_payload_path=final_output_path
    )
    db.add(new_file)
    db.flush()
    
    new_policy = models.AccessPolicy(file_id=file_id, max_views=max_views, max_downloads=max_downloads)
    db.add(new_policy)
    db.commit()
    
    background_tasks.add_task(
        email_service.send_dispatch_email,
        sender_email=sender_email, 
        recipient_email=recipient_email,
        file_id=file_id, 
        lock_type=lock_type
    )
    return {"message": "File successfully encrypted and stored.", "file_id": file_id, "transfer_mode": transfer_mode}

# ==========================================
# 🔓 TERMINAL B: EXTRACT & DECRYPT
# ==========================================
@app.post("/api/extract/{file_id}")
def extract_file(
    file_id: str, 
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    file_record = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    policy = db.query(models.AccessPolicy).filter(models.AccessPolicy.file_id == file_id).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
        
    if file_record.is_revoked:
        raise HTTPException(status_code=403, detail="PAYLOAD DESTROYED: Revoked by sender.")
        
    file_age = datetime.utcnow() - file_record.created_at
    if file_age > timedelta(minutes=60):
        file_record.is_revoked = True
        if file_record.encrypted_payload_path and os.path.exists(file_record.encrypted_payload_path):
            os.remove(file_record.encrypted_payload_path)
        db.commit()
        raise HTTPException(status_code=403, detail="TIME BOMB DETONATED: 60-minute limit exceeded.")

    failed_attempts = db.query(models.AuditLog).filter(
        models.AuditLog.event_type == "DECRYPTION_FAILED",
        models.AuditLog.details.contains(file_id)
    ).count()

    if failed_attempts >= 3:
        raise HTTPException(status_code=403, detail="HACKER TRIPWIRE: Payload shredded.")

    if password == "MAYDAY":
        log = models.AuditLog(user_id=1, event_type="SILENT_ALARM", details=f"🚨 DURESS CODE USED on {file_id}.")
        db.add(log)
        db.commit()
        decoy_text = "CONFIDENTIAL MEMO:\nPlease ensure all office supply orders are approved by HR."
        return Response(content=decoy_text.encode('utf-8'), media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="decrypted_{file_record.file_name}.txt"'
        })
        
    try:
        if file_record.transfer_mode == 'hidden':
            encrypted_payload = crypto_engine.extract_data_from_image(file_record.encrypted_payload_path)
        else:
            with open(file_record.encrypted_payload_path, "rb") as f:
                encrypted_payload = f.read()
                
        decrypted_bytes = crypto_engine.decrypt_file_data(encrypted_payload, password)
        
        if policy:
            policy.current_downloads += 1
            if policy.max_views == 1:
                file_record.is_revoked = True
                if file_record.encrypted_payload_path and os.path.exists(file_record.encrypted_payload_path):
                    os.remove(file_record.encrypted_payload_path)
                db.add(models.AuditLog(user_id=1, event_type="PAYLOAD_BURNED", details=f"Burned {file_id}."))
        
        db.add(models.AuditLog(user_id=1, event_type="FILE_DECRYPTED", details=f"Extracted {file_id}."))
        db.commit()
        return Response(content=decrypted_bytes, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="decrypted_{file_record.file_name}"'
        })
    except ValueError:
        strikes_left = 2 - failed_attempts
        db.add(models.AuditLog(user_id=1, event_type="DECRYPTION_FAILED", details=f"File {file_id}: Invalid key. Strikes left: {strikes_left}"))
        if strikes_left <= 0:
            file_record.is_revoked = True
            db.add(models.AuditLog(user_id=1, event_type="TRIPWIRE_ACTIVATED", details=f"Shredded {file_id}."))
            db.commit()
            raise HTTPException(status_code=403, detail="Hacker Tripwire Activated. Payload Destroyed.")
        db.commit()
        raise HTTPException(status_code=400, detail=f"Invalid Password. Attempts remaining: {strikes_left}")

# ==========================================
# 💬 STAND-ALONE SIGNAL CHAT WEBSOCKET
# ==========================================
@app.websocket("/ws/chat/{agent_email}")
async def websocket_chat_endpoint(websocket: WebSocket, agent_email: str, db: Session = Depends(get_db)):
    await manager.connect(agent_email, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            packet = json.loads(data)
            recipient_email = packet.get("recipient_email")
            encrypted_content = packet.get("encrypted_content")
            is_burned = packet.get("is_burned", False)
            
            new_msg = models.ChatMessage(
                sender_email=agent_email, recipient_email=recipient_email,
                encrypted_message=encrypted_content, is_burned=is_burned
            )
            db.add(new_msg)
            db.commit()
            
            outgoing_packet = {
                "sender_email": agent_email, "encrypted_content": encrypted_content,
                "is_burned": is_burned, "timestamp": str(new_msg.created_at)
            }
            await manager.send_personal_message(outgoing_packet, recipient_email)
            await websocket.send_json({"status": "DELIVERED", "timestamp": outgoing_packet["timestamp"]})
    except Exception:
        manager.disconnect(agent_email)

# ==========================================
# 👥 AGENT FRIEND DIRECTORY
# ==========================================
@app.get("/api/agents/search")
def search_agents(search_query: str, db: Session = Depends(get_db)):
    users = db.query(models.User).filter(
        (models.User.username.contains(search_query)) | (models.User.email.contains(search_query))
    ).all()
    return [{"username": u.username, "email": u.email} for u in users]

@app.post("/api/friends/add")
def add_friend(
    user_id: int = Form(...),
    friend_email: str = Form(...),
    friend_username: str = Form(...),
    db: Session = Depends(get_db)
):
    existing = db.query(models.FriendContact).filter(
        models.FriendContact.user_id == user_id,
        models.FriendContact.friend_email == friend_email
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Agent is already in your contact roster.")
        
    new_contact = models.FriendContact(
        user_id=user_id,
        friend_email=friend_email,
        friend_username=friend_username,
        status="active"
    )
    db.add(new_contact)
    db.commit()
    return {"message": "Agent successfully added to secure contacts."}

@app.get("/api/friends/list/{user_id}")
def get_friends(user_id: int, db: Session = Depends(get_db)):
    contacts = db.query(models.FriendContact).filter(models.FriendContact.user_id == user_id).all()
    return [{"friend_username": c.friend_username, "friend_email": c.friend_email} for c in contacts]

# ==========================================
# 🔐 ZERO-KNOWLEDGE PASSWORD VAULT
# ==========================================
@app.post("/api/vault/credentials/save")
def save_credential_blob(
    user_id: int = Form(...),
    title: str = Form(...),
    encrypted_blob: str = Form(...),
    db: Session = Depends(get_db)
):
    item = models.PasswordVaultItem(
        user_id=user_id,
        title=title,
        encrypted_blob=encrypted_blob
    )
    db.add(item)
    db.commit()
    return {"message": "Credential encrypted and stored securely."}

@app.get("/api/vault/credentials/list/{user_id}")
def get_credential_blobs(user_id: int, db: Session = Depends(get_db)):
    items = db.query(models.PasswordVaultItem).filter(models.PasswordVaultItem.user_id == user_id).all()
    return [{"id": i.id, "title": i.title, "encrypted_blob": i.encrypted_blob, "created_at": i.created_at} for i in items]

@app.delete("/api/vault/credentials/delete/{item_id}")
def delete_credential_blob(item_id: int, db: Session = Depends(get_db)):
    item = db.query(models.PasswordVaultItem).filter(models.PasswordVaultItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(item)
    db.commit()
    return {"message": "Credential purged."}

# ==========================================
# 🔍 CODE SECURITY SCANNER
# ==========================================
@app.post("/api/scanner/analyze")
async def analyze_code(
    user_id: int = Form(1),
    file_name: str = Form("source_code.py"),
    code_text: str = Form(...),
    db: Session = Depends(get_db)
):
    scan_results = scanner_engine.scan_source_code(code_text)
    
    new_report = models.CodeScanReport(
        user_id=user_id,
        file_name=file_name,
        security_grade=scan_results["grade"],
        vulnerabilities_summary=json.dumps(scan_results["findings"])
    )
    db.add(new_report)
    db.commit()
    
    return {
        "message": "Code scan completed successfully.",
        "grade": scan_results["grade"],
        "total_vulnerabilities": scan_results["total_vulnerabilities"],
        "findings": scan_results["findings"]
    }

# ==========================================
# 📊 AUDIT LOGS, VAULT & FORENSICS
# ==========================================
@app.get("/api/audit")
def get_audit_logs(db: Session = Depends(get_db)):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(50).all()

@app.delete("/api/audit/wipe")
def wipe_audit_logs(db: Session = Depends(get_db)):
    db.query(models.AuditLog).delete()
    db.commit()
    return {"message": "SYSTEM LOGS WIPED."}

@app.get("/api/vault/outbox/{user_id}")
def get_outbox(user_id: int, db: Session = Depends(get_db)):
    sent = db.query(models.ProtectedFile).filter(models.ProtectedFile.sender_id == user_id).all()
    return [{"id": f.id, "recipient": f.recipient_email, "transfer_mode": f.transfer_mode, "is_revoked": f.is_revoked} for f in sent]

@app.get("/api/vault/inbox/{user_email}")
def get_inbox(user_email: str, db: Session = Depends(get_db)):
    received = db.query(models.ProtectedFile).filter(models.ProtectedFile.recipient_email == user_email).all()
    return [{"id": f.id, "file_name": f.file_name, "sender_id": f.sender_id, "is_revoked": f.is_revoked} for f in received]

@app.post("/api/vault/revoke/{file_id}")
def trigger_kill_switch(file_id: str, db: Session = Depends(get_db)):
    f = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    f.is_revoked = True
    db.commit()
    return {"message": "REVOKED"}

@app.delete("/api/vault/delete/{file_id}")
def delete_payload(file_id: str, db: Session = Depends(get_db)):
    f = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    if f.encrypted_payload_path and os.path.exists(f.encrypted_payload_path):
        os.remove(f.encrypted_payload_path)
    db.query(models.AccessPolicy).filter(models.AccessPolicy.file_id == file_id).delete()
    db.delete(f)
    db.commit()
    return {"message": "PURGED"}

@app.post("/api/forensics/scan")
async def scan_leaked_image(leak_file: UploadFile = File(...)):
    temp_path = f"uploads/temp_leak_{uuid.uuid4()}.png"
    with open(temp_path, "wb") as f:
        f.write(await leak_file.read())
    try:
        watermark = crypto_engine.scan_image_for_watermark(temp_path)
        os.remove(temp_path)
        if not watermark: return {"status": "CLEAN"}
        return {"status": "MOLE_IDENTIFIED", "source_agent": watermark}
    except Exception:
        if os.path.exists(temp_path): os.remove(temp_path)
        raise HTTPException(status_code=400, detail="Invalid image")


# ==========================================
# 🌐 SERVE FRONTEND UI DIRECTLY FROM BACKEND
# ==========================================
@app.get("/")
def serve_login_page():
    return FileResponse("frontend/index.html")

@app.get("/dashboard.html")
def serve_dashboard_page():
    return FileResponse("frontend/dashboard.html")
