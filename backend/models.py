from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone_number = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # === PROTOCOL OMEGA (DEAD MAN'S SWITCH) ===
    last_active = Column(DateTime, default=datetime.utcnow)
    omega_enabled = Column(Boolean, default=False)
    omega_days_threshold = Column(Integer, default=7)          # Days without check-in before wipe
    omega_emergency_contact = Column(String, nullable=True)     # Email alerted when wiped
    omega_triggered = Column(Boolean, default=False)            # Prevents duplicate wipe runs

class ProtectedFile(Base):
    __tablename__ = "protected_files"
    
    id = Column(String, primary_key=True, index=True) # UUID
    sender_id = Column(Integer, nullable=False)
    recipient_email = Column(String, nullable=False)
    file_name = Column(String, nullable=False)
    security_level = Column(String, nullable=False) # level1, level2, level3
    transfer_mode = Column(String, nullable=False)   # direct, hidden
    encrypted_payload_path = Column(String, nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class AccessPolicy(Base):
    __tablename__ = "access_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String, unique=True, index=True, nullable=False)
    max_views = Column(Integer, default=1)
    current_views = Column(Integer, default=0)
    max_downloads = Column(Integer, default=1)
    current_downloads = Column(Integer, default=0)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    event_type = Column(String, nullable=False)
    details = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # === IMMUTABLE LEDGER FIELDS ===
    previous_hash = Column(String, nullable=True)
    hash_signature = Column(String, nullable=True)

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_email = Column(String, nullable=False)
    recipient_email = Column(String, nullable=False)
    encrypted_message = Column(Text, nullable=False)
    is_burned = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class FriendContact(Base):
    __tablename__ = "friend_contacts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    friend_email = Column(String, nullable=False)
    friend_username = Column(String, nullable=False)
    status = Column(String, default="active")

class PasswordVaultItem(Base):
    __tablename__ = "password_vault_items"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    title = Column(String, nullable=False)
    encrypted_blob = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class CodeScanReport(Base):
    __tablename__ = "code_scan_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    file_name = Column(String, nullable=False)
    security_grade = Column(String, nullable=False)
    vulnerabilities_summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)