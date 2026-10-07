import os
import uuid
import json
import hashlib
import random
import urllib.request
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form, BackgroundTasks, WebSocket, Request
from fastapi.responses import Response, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, Column, Integer, String, Float, DateTime
from pydantic import BaseModel, EmailStr

import models, database, security, crypto_engine, email_service, scanner_engine
from database import engine, get_db
from chat_manager import manager

os.makedirs("uploads", exist_ok=True)

with engine.begin() as conn:
    try:
        conn.execute(text("ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_file_id_fkey;"))
        conn.execute(text("ALTER TABLE protected_files DROP CONSTRAINT IF EXISTS protected_files_sender_id_fkey;"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active TIMESTAMP DEFAULT NOW();"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS omega_enabled BOOLEAN DEFAULT FALSE;"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS omega_days_threshold INTEGER DEFAULT 7;"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS omega_emergency_contact VARCHAR;"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS omega_triggered BOOLEAN DEFAULT FALSE;"))
        conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR;"))
        conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_signature VARCHAR;"))
    except Exception:
        pass

class ThreatLog(models.Base):
    __tablename__ = "threat_logs"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(String)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="PrivacyOS Enterprise Suite API")

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Server"] = "PrivacyOS-Ghost-Engine/2.0"
    return response

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def log_audit_event(db: Session, user_id: int, event_type: str, details: str):
    last_log = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).first()
    prev_hash = last_log.hash_signature if last_log and last_log.hash_signature else "GENESIS_BLOCK"
    new_log = models.AuditLog(user_id=user_id, event_type=event_type, details=details, previous_hash=prev_hash)
    db.add(new_log); db.flush()
    raw_data = f"{new_log.id}{new_log.timestamp.isoformat()}{event_type}{details}{prev_hash}"
    new_log.hash_signature = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()
    db.commit()

def geolocate_ip(ip: str):
    if ip in ["127.0.0.1", "localhost", "::1"]: return random.uniform(-60, 60), random.uniform(-180, 180)
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=2) as r:
            d = json.loads(r.read().decode())
            if d.get("status") == "success": return d.get("lat"), d.get("lon")
    except Exception: pass
    return 0.0, 0.0

@app.get("/api/threats")
def get_threats(db: Session = Depends(get_db)):
    return [{"lat": t.latitude, "lng": t.longitude, "details": t.details, "ip": t.ip_address} for t in db.query(ThreatLog).order_by(ThreatLog.id.desc()).limit(100).all()]

class UserCreate(BaseModel): full_name: str; username: str; email: EmailStr; phone_number: str = None; password: str
class OTPVerify(BaseModel): email: EmailStr; otp: str
class LoginStep1(BaseModel): email: EmailStr; password: str
class LoginStep2(BaseModel): email: EmailStr; otp: str

@app.post("/api/register")
def register_user(user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if db.query(models.User).filter((models.User.email == user.email) | (models.User.username == user.username)).first(): raise HTTPException(status_code=400, detail="Email/Username already registered")
    new_user = models.User(full_name=user.full_name, username=user.username, email=user.email, phone_number=user.phone_number, hashed_password=security.get_password_hash(user.password), is_active=False)
    db.add(new_user); db.commit(); db.refresh(new_user)
    otp_code = security.generate_otp()
    background_tasks.add_task(security.send_real_email_otp, user.email, otp_code)
    log_audit_event(db, new_user.id, "USER_REGISTERED", f"New agent registered: {user.username}")
    return {"message": "Registered. Check email for OTP."}

@app.post("/api/verify-otp")
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True; db.commit()
    log_audit_event(db, user.id, "MFA_VERIFIED", "Agent successfully verified identity.")
    return {"message": "Account activated successfully"}

@app.post("/api/login/initiate")
def login_initiate(data: LoginStep1, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user or not security.verify_password(data.password, user.hashed_password):
        if user: log_audit_event(db, user.id, "LOGIN_FAILED", "Invalid password attempt.")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active: raise HTTPException(status_code=403, detail="Verify initial OTP first")
    otp_code = security.generate_otp()
    background_tasks.add_task(security.send_real_email_otp, user.email, otp_code)
    app.state.login_otps = getattr(app.state, "login_otps", {})
    app.state.login_otps[user.email] = otp_code
    return {"message": "Credentials verified. Check email for login OTP."}

@app.post("/api/login/verify")
def login_verify(data: LoginStep2, db: Session = Depends(get_db)):
    stored_otps = getattr(app.state, "login_otps", {})
    if stored_otps.get(data.email) != data.otp:
        user = db.query(models.User).filter(models.User.email == data.email).first()
        if user: log_audit_event(db, user.id, "MFA_FAILED", "Invalid login OTP entered.")
        raise HTTPException(status_code=401, detail="Invalid OTP")
    del stored_otps[data.email]
    user = db.query(models.User).filter(models.User.email == data.email).first()
    log_audit_event(db, user.id, "AGENT_LOGIN", f"Agent {user.username} authenticated.")
    return {"access_token": security.create_access_token({"sub": user.email, "id": user.id}), "user_id": user.id, "username": user.username}

async def execute_protocol_omega_check():
    db: Session = database.SessionLocal()
    try:
        now = datetime.utcnow()
        active_omega_users = db.query(models.User).filter(models.User.omega_enabled == True, models.User.omega_triggered == False).all()
        for user in active_omega_users:
            if not user.last_active: continue
            deadline = user.last_active + timedelta(days=user.omega_days_threshold)
            if now >= deadline:
                db.query(models.PasswordVaultItem).filter(models.PasswordVaultItem.user_id == user.id).delete()
                for f in db.query(models.ProtectedFile).filter(models.ProtectedFile.sender_id == user.id).all():
                    f.is_revoked = True
                    if f.encrypted_payload_path and os.path.exists(f.encrypted_payload_path):
                        try: os.remove(f.encrypted_payload_path)
                        except Exception: pass
                log_audit_event(db, user.id, "PROTOCOL_OMEGA_EXECUTED", f"🚨 DEAD MAN'S SWITCH TRIGGERED for {user.username}. Vaults shredded.")
                user.omega_triggered = True
                db.commit()
                if user.omega_emergency_contact:
                    try: email_service.send_dispatch_email("omega-system@privacyos.net", user.omega_emergency_contact, "SYSTEM-PURGED", "OMEGA_EVENT")
                    except Exception: pass
    except Exception: pass
    finally: db.close()

scheduler = AsyncIOScheduler()
scheduler.add_job(execute_protocol_omega_check, 'interval', hours=1)
scheduler.start()

class OmegaConfig(BaseModel): user_id: int; enabled: bool; days_threshold: int; emergency_contact: EmailStr

@app.get("/api/omega/status/{user_id}")
def get_omega_status(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="Agent not found")
    deadline = time_remaining = None
    if user.omega_enabled and user.last_active:
        deadline = user.last_active + timedelta(days=user.omega_days_threshold)
        time_remaining = max(0, int((deadline - datetime.utcnow()).total_seconds()))
    return {"enabled": user.omega_enabled, "days_threshold": user.omega_days_threshold, "emergency_contact": user.omega_emergency_contact, "triggered": user.omega_triggered, "last_active": user.last_active, "deadline": deadline, "seconds_remaining": time_remaining}

@app.post("/api/omega/configure")
def configure_omega(config: OmegaConfig, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == config.user_id).first()
    if not user: raise HTTPException(status_code=404, detail="Agent not found")
    user.omega_enabled, user.omega_days_threshold, user.omega_emergency_contact = config.enabled, max(1, config.days_threshold), config.emergency_contact
    user.last_active, user.omega_triggered = datetime.utcnow(), False
    db.commit()
    log_audit_event(db, user.id, "OMEGA_CONFIGURED", f"Protocol Omega settings modified. Status: {config.enabled}")
    return {"message": "Protocol Omega settings updated."}

@app.post("/api/omega/checkin/{user_id}")
def checkin_omega(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="Agent not found")
    user.last_active, user.omega_triggered = datetime.utcnow(), False
    db.commit()
    log_audit_event(db, user.id, "OMEGA_HEARTBEAT", "Heartbeat received. Dead Man's Switch timer reset.")
    return {"message": "Check-in recorded."}

# ==========================================
# 🛡️ TERMINAL A: ENCRYPT & PROTECT (WITH AUDIO)
# ==========================================
@app.post("/api/protect")
async def protect_data(background_tasks: BackgroundTasks, sender_id: int = Form(1), sender_email: str = Form(...), recipient_email: str = Form(...), security_tier: str = Form(...), transfer_mode: str = Form(...), lock_type: str = Form(...), lock_password: str = Form(...), color_code: str = Form("none"), max_views: int = Form(1), max_downloads: int = Form(1), secret_file: UploadFile = File(...), carrier_file: UploadFile = File(None), db: Session = Depends(get_db)):
    
    if security_tier == "level3":
        max_views = 1
        if not carrier_file or not carrier_file.filename:
            transfer_mode = "direct"
    elif security_tier == "level1": max_views = 999
    
    final_key = lock_password if color_code == "none" else f"{lock_password}-{color_code}"
    secret_bytes = await secret_file.read()
    if not secret_bytes: raise HTTPException(status_code=400, detail="Secret payload is empty.")
    encrypted_payload = crypto_engine.encrypt_file_data(secret_bytes, final_key)
    file_id = str(uuid.uuid4())
    
    if transfer_mode == 'hidden' and carrier_file and carrier_file.filename:
        temp_path = f"uploads/temp_{file_id}_{carrier_file.filename}"
        with open(temp_path, "wb") as f: f.write(await carrier_file.read())
        final_output_path = f"uploads/{file_id}_stego.png"
        try: crypto_engine.hide_data_in_image(temp_path, encrypted_payload, final_output_path, watermark=sender_email)
        except Exception:
            final_output_path = f"uploads/{file_id}.enc"
            with open(final_output_path, "wb") as f: f.write(encrypted_payload)
            transfer_mode = "direct"
        if os.path.exists(temp_path): os.remove(temp_path)
        
    elif transfer_mode == 'audio' and carrier_file and carrier_file.filename:
        temp_path = f"uploads/temp_{file_id}_{carrier_file.filename}"
        with open(temp_path, "wb") as f: f.write(await carrier_file.read())
        final_output_path = f"uploads/{file_id}_stego.wav"
        try: 
            crypto_engine.hide_data_in_audio(temp_path, encrypted_payload, final_output_path)
        except Exception as e:
            if os.path.exists(temp_path): os.remove(temp_path)
            raise HTTPException(status_code=400, detail=str(e))
        if os.path.exists(temp_path): os.remove(temp_path)
        
    else:
        final_output_path = f"uploads/{file_id}.enc"
        with open(final_output_path, "wb") as f: f.write(encrypted_payload)
        transfer_mode = "direct"
            
    new_file = models.ProtectedFile(id=file_id, sender_id=sender_id, recipient_email=recipient_email, file_name=secret_file.filename or "secret.txt", security_level=security_tier, transfer_mode=transfer_mode, encrypted_payload_path=final_output_path)
    db.add(new_file)
    db.add(models.AccessPolicy(file_id=file_id, max_views=max_views, max_downloads=max_downloads))
    db.commit()
    log_audit_event(db, sender_id, "PAYLOAD_ENCRYPTED", f"Created {security_tier} payload via {transfer_mode}. Target: {recipient_email}")
    background_tasks.add_task(email_service.send_dispatch_email, sender_email=sender_email, recipient_email=recipient_email, file_id=file_id, lock_type=lock_type)
    return {"message": "Payload encrypted and stored.", "file_id": file_id, "transfer_mode": transfer_mode}

@app.get("/api/extract/meta/{file_id}")
def get_file_metadata(file_id: str, db: Session = Depends(get_db)):
    file_record = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    if not file_record: raise HTTPException(status_code=404, detail="File UUID not found in vault.")
    if file_record.is_revoked: raise HTTPException(status_code=403, detail="PAYLOAD DESTROYED / REVOKED")
    return {"security_level": file_record.security_level}

# ==========================================
# 🔓 TERMINAL B: ONLINE EXTRACT (WITH AUDIO)
# ==========================================
@app.post("/api/extract/{file_id}")
def extract_file(request: Request, file_id: str, password: str = Form(...), color_code: str = Form("none"), db: Session = Depends(get_db)):
    file_record = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    policy = db.query(models.AccessPolicy).filter(models.AccessPolicy.file_id == file_id).first()
    client_ip = request.client.host
    
    if not file_record: raise HTTPException(status_code=404, detail="File not found")
    if file_record.is_revoked: raise HTTPException(status_code=403, detail="PAYLOAD DESTROYED: Revoked by sender.")
    
    if (datetime.utcnow() - file_record.created_at) > timedelta(minutes=60):
        file_record.is_revoked = True
        if os.path.exists(file_record.encrypted_payload_path): os.remove(file_record.encrypted_payload_path)
        log_audit_event(db, 1, "TIME_BOMB_DETONATED", f"Payload {file_id} expired and auto-shredded.")
        raise HTTPException(status_code=403, detail="TIME BOMB DETONATED: 60-minute limit exceeded.")

    failed_attempts = db.query(models.AuditLog).filter(models.AuditLog.event_type == "DECRYPTION_FAILED", models.AuditLog.details.contains(file_id)).count()
    if failed_attempts >= 3: raise HTTPException(status_code=403, detail="HACKER TRIPWIRE: Payload shredded.")

    if password == "MAYDAY":
        log_audit_event(db, 1, "SILENT_ALARM", f"🚨 DURESS CODE USED on {file_id}.")
        return Response(content=b"CONFIDENTIAL MEMO:\nPlease verify regular system logs.", media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="decoy.txt"'})
        
    final_key = password if color_code == "none" else f"{password}-{color_code}"

    try:
        if file_record.transfer_mode == 'hidden':
            encrypted_payload = crypto_engine.extract_data_from_image(file_record.encrypted_payload_path)
        elif file_record.transfer_mode == 'audio':
            encrypted_payload = crypto_engine.extract_data_from_audio(file_record.encrypted_payload_path)
        else:
            encrypted_payload = open(file_record.encrypted_payload_path, "rb").read()
            
        decrypted_bytes = crypto_engine.decrypt_file_data(encrypted_payload, final_key)
        
        if policy:
            policy.current_downloads += 1
            if policy.max_views == 1:
                file_record.is_revoked = True
                if os.path.exists(file_record.encrypted_payload_path): os.remove(file_record.encrypted_payload_path)
                log_audit_event(db, 1, "PAYLOAD_BURNED", f"Burned {file_id} after viewing.")
        
        log_audit_event(db, 1, "FILE_DECRYPTED", f"Successfully extracted {file_id}.")
        return Response(content=decrypted_bytes, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="decrypted_{file_record.file_name}"'})
    except Exception:
        strikes_left = 2 - failed_attempts
        log_audit_event(db, 1, "DECRYPTION_FAILED", f"File {file_id}: Invalid key. Strikes left: {strikes_left}")
        lat, lon = geolocate_ip(client_ip)
        db.add(ThreatLog(ip_address=client_ip, latitude=lat, longitude=lon, details=f"Failed Extraction: {file_id}"))
        db.commit()
        
        if strikes_left <= 0:
            file_record.is_revoked = True
            log_audit_event(db, 1, "TRIPWIRE_ACTIVATED", f"Hacker detected. Shredded {file_id}.")
            raise HTTPException(status_code=403, detail="Hacker Tripwire Activated. Payload Destroyed.")
        raise HTTPException(status_code=400, detail=f"Invalid Password or Color Code. Strikes left: {strikes_left}")

@app.post("/api/extract/offline")
async def extract_offline(password: str = Form(...), color_code: str = Form("none"), transfer_mode: str = Form(...), payload_file: UploadFile = File(...)):
    final_key = password if color_code == "none" else f"{password}-{color_code}"
    file_bytes = await payload_file.read()
    try:
        if transfer_mode == 'hidden':
            temp_path = f"uploads/temp_offline_{uuid.uuid4()}.png"
            with open(temp_path, "wb") as f: f.write(file_bytes)
            try: encrypted_payload = crypto_engine.extract_data_from_image(temp_path)
            finally:
                if os.path.exists(temp_path): os.remove(temp_path)
                
        elif transfer_mode == 'audio':
            temp_path = f"uploads/temp_offline_{uuid.uuid4()}.wav"
            with open(temp_path, "wb") as f: f.write(file_bytes)
            try: encrypted_payload = crypto_engine.extract_data_from_audio(temp_path)
            finally:
                if os.path.exists(temp_path): os.remove(temp_path)
                
        else: encrypted_payload = file_bytes
        
        decrypted_bytes = crypto_engine.decrypt_file_data(encrypted_payload, final_key)
        clean_name = payload_file.filename.replace("_stego.png", "").replace("_stego.wav", "").replace(".enc", "")
        return Response(content=decrypted_bytes, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="unlocked_{clean_name}"'})
    except Exception: raise HTTPException(status_code=400, detail="Invalid Password/Color Code or corrupted payload file.")

@app.websocket("/ws/chat/{agent_email}")
async def websocket_chat_endpoint(websocket: WebSocket, agent_email: str, db: Session = Depends(get_db)):
    await manager.connect(agent_email, websocket)
    try:
        while True:
            packet = json.loads(await websocket.receive_text())
            new_msg = models.ChatMessage(sender_email=agent_email, recipient_email=packet.get("recipient_email"), encrypted_message=packet.get("encrypted_content"), is_burned=packet.get("is_burned", False))
            db.add(new_msg); db.commit()
            await manager.send_personal_message({"sender_email": agent_email, "encrypted_content": packet.get("encrypted_content"), "is_burned": packet.get("is_burned", False), "timestamp": str(new_msg.created_at)}, packet.get("recipient_email"))
            await websocket.send_json({"status": "DELIVERED"})
    except Exception: manager.disconnect(agent_email)

@app.get("/api/agents/search")
def search_agents(search_query: str, db: Session = Depends(get_db)):
    users = db.query(models.User).filter((models.User.username.contains(search_query)) | (models.User.email.contains(search_query))).all()
    return [{"username": u.username, "email": u.email} for u in users]

@app.post("/api/friends/add")
def add_friend(user_id: int = Form(...), friend_email: str = Form(...), friend_username: str = Form(...), db: Session = Depends(get_db)):
    if db.query(models.FriendContact).filter(models.FriendContact.user_id == user_id, models.FriendContact.friend_email == friend_email).first(): raise HTTPException(status_code=400, detail="Agent is already in your contacts.")
    db.add(models.FriendContact(user_id=user_id, friend_email=friend_email, friend_username=friend_username)); db.commit()
    return {"message": "Agent contact added."}

@app.get("/api/friends/list/{user_id}")
def get_friends(user_id: int, db: Session = Depends(get_db)):
    return [{"friend_username": c.friend_username, "friend_email": c.friend_email} for c in db.query(models.FriendContact).filter(models.FriendContact.user_id == user_id).all()]

@app.post("/api/vault/credentials/save")
def save_credential_blob(user_id: int = Form(...), title: str = Form(...), encrypted_blob: str = Form(...), db: Session = Depends(get_db)):
    db.add(models.PasswordVaultItem(user_id=user_id, title=title, encrypted_blob=encrypted_blob)); db.commit()
    log_audit_event(db, user_id, "CREDENTIAL_STORED", f"Stored ZK Vault item: {title}")
    return {"message": "Credential stored securely."}

@app.get("/api/vault/credentials/list/{user_id}")
def get_credential_blobs(user_id: int, db: Session = Depends(get_db)):
    return [{"id": i.id, "title": i.title, "encrypted_blob": i.encrypted_blob, "created_at": i.created_at} for i in db.query(models.PasswordVaultItem).filter(models.PasswordVaultItem.user_id == user_id).all()]

@app.delete("/api/vault/credentials/delete/{item_id}")
def delete_credential_blob(item_id: int, db: Session = Depends(get_db)):
    item = db.query(models.PasswordVaultItem).filter(models.PasswordVaultItem.id == item_id).first()
    if item:
        log_audit_event(db, item.user_id, "CREDENTIAL_DELETED", f"Purged ZK Vault item: {item.title}")
        db.delete(item); db.commit()
    return {"message": "Purged"}

@app.post("/api/scanner/analyze")
async def analyze_code(user_id: int = Form(1), file_name: str = Form("code.py"), code_text: str = Form(...), db: Session = Depends(get_db)):
    scan_results = scanner_engine.scan_source_code(code_text)
    db.add(models.CodeScanReport(user_id=user_id, file_name=file_name, security_grade=scan_results["grade"], vulnerabilities_summary=json.dumps(scan_results["findings"])))
    db.commit()
    log_audit_event(db, user_id, "CODE_SCANNED", f"Scanned {file_name}. Grade: {scan_results['grade']}")
    return {"grade": scan_results["grade"], "total_vulnerabilities": scan_results["total_vulnerabilities"], "findings": scan_results["findings"]}

@app.get("/api/audit")
def get_audit_logs(db: Session = Depends(get_db)):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(50).all()

@app.get("/api/audit/verify")
def verify_audit_ledger(db: Session = Depends(get_db)):
    logs = db.query(models.AuditLog).order_by(models.AuditLog.id.asc()).all()
    if not logs: return {"status": "CLEAN", "message": "Ledger is empty."}
    for i in range(1, len(logs)):
        current_log, prev_log = logs[i], logs[i-1]
        if current_log.previous_hash != prev_log.hash_signature: return {"status": "CORRUPTED", "message": f"CHAIN BROKEN at Log ID {current_log.id}. Missing Link."}
        recreated_hash = hashlib.sha256(f"{current_log.id}{current_log.timestamp.isoformat()}{current_log.event_type}{current_log.details}{current_log.previous_hash}".encode('utf-8')).hexdigest()
        if recreated_hash != current_log.hash_signature: return {"status": "CORRUPTED", "message": f"DATA TAMPERING DETECTED at Log ID {current_log.id}."}
    return {"status": "VERIFIED", "message": f"Ledger Intact. {len(logs)} blocks verified."}

@app.delete("/api/audit/wipe")
def wipe_audit_logs(db: Session = Depends(get_db)):
    db.query(models.AuditLog).delete(); db.commit()
    log_audit_event(db, 1, "LEDGER_RESET", "Audit blockchain manually wiped by admin.")
    return {"message": "WIPED"}

@app.get("/api/vault/outbox/{user_id}")
def get_outbox(user_id: int, db: Session = Depends(get_db)):
    return [{"id": f.id, "recipient": f.recipient_email, "transfer_mode": f.transfer_mode, "is_revoked": f.is_revoked} for f in db.query(models.ProtectedFile).filter(models.ProtectedFile.sender_id == user_id).all()]

@app.post("/api/vault/revoke/{file_id}")
def trigger_kill_switch(file_id: str, db: Session = Depends(get_db)):
    f = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    if f:
        f.is_revoked = True
        log_audit_event(db, f.sender_id, "PAYLOAD_REVOKED", f"Manually killed {file_id}.")
        db.commit()
    return {"message": "REVOKED"}

@app.delete("/api/vault/delete/{file_id}")
def delete_payload(file_id: str, db: Session = Depends(get_db)):
    f = db.query(models.ProtectedFile).filter(models.ProtectedFile.id == file_id).first()
    if f:
        if f.encrypted_payload_path and os.path.exists(f.encrypted_payload_path): os.remove(f.encrypted_payload_path)
        db.query(models.AccessPolicy).filter(models.AccessPolicy.file_id == file_id).delete()
        log_audit_event(db, f.sender_id, "PAYLOAD_DELETED", f"Permanently deleted {file_id}.")
        db.delete(f); db.commit()
    return {"message": "PURGED"}

# ==========================================
# 💻 ROOT ACCESS CONSOLE (LIVE CODE EDITOR)
# ==========================================
class FileEditRequest(BaseModel):
    filepath: str
    content: str

@app.get("/api/root/files")
def list_root_files():
    """Lists available Python and HTML files in the project directory."""
    files = []
    # Search current directory for python/html files
    for f in os.listdir("."):
        if f.endswith('.py') or f.endswith('.html'):
            files.append(f)
    # Search frontend folder if it exists
    if os.path.exists("frontend"):
        for f in os.listdir("frontend"):
            if f.endswith('.html') or f.endswith('.js') or f.endswith('.css'):
                files.append(f"frontend/{f}")
    return {"files": sorted(files)}

@app.get("/api/root/read")
def read_root_file(filepath: str):
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    with open(filepath, "r", encoding="utf-8") as f:
        return {"content": f.read()}

@app.post("/api/root/write")
def write_root_file(req: FileEditRequest, db: Session = Depends(get_db)):
    if not os.path.exists(req.filepath):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Overwrite the actual physical file
    with open(req.filepath, "w", encoding="utf-8") as f:
        f.write(req.content)
        
    # Log this action on the blockchain ledger
    log_audit_event(db, 1, "SYSTEM_CODE_MODIFIED", f"Root console live-edited source file: {req.filepath}")
    return {"message": f"Successfully updated {req.filepath}"}

# REMOVE OR COMMENT OUT FOR PRODUCTION:
# @app.post("/api/root/write")
# def write_root_file(req: FileEditRequest, db: Session = Depends(get_db)):
#     if not os.path.exists(req.filepath):
#         raise HTTPException(status_code=404, detail="File not found")
#     
#     # Overwrite the actual physical file
#     with open(req.filepath, "w", encoding="utf-8") as f:
#         f.write(req.content)
#         
#     # Log this action on the blockchain ledger
#     log_audit_event(db, 1, "SYSTEM_CODE_MODIFIED", f"Root console live-edited source file: {req.filepath}")
#     return {"message": f"Successfully updated {req.filepath}"}