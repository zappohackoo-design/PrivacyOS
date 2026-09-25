from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

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

    # Relationships
    sent_files = relationship("ProtectedFile", foreign_keys="ProtectedFile.sender_id", back_populates="sender")
    password_vaults = relationship("PasswordVaultItem", back_populates="user", cascade="all, delete-orphan")
    code_scans = relationship("CodeScanReport", back_populates="user", cascade="all, delete-orphan")


class ProtectedFile(Base):
    __tablename__ = "protected_files"

    id = Column(String, primary_key=True, index=True) # UUID
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_email = Column(String, nullable=False)
    file_name = Column(String, nullable=False)
    security_level = Column(String, default="standard")
    transfer_mode = Column(String, default="direct") # 'direct' or 'hidden' (steganography)
    encrypted_payload_path = Column(String, nullable=False)
    is_revoked = Column(Boolean, default=False) # Kill switch / Time-bomb status
    created_at = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_files")
    policy = relationship("AccessPolicy", back_populates="file", uselist=False, cascade="all, delete-orphan")


class AccessPolicy(Base):
    __tablename__ = "access_policies"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String, ForeignKey("protected_files.id"), nullable=False)
    max_views = Column(Integer, default=1) # Burn-After-Reading threshold
    current_downloads = Column(Integer, default=0)

    file = relationship("ProtectedFile", back_populates="policy")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    event_type = Column(String, nullable=False) # e.g., FILE_DECRYPTED, TRIPWIRE_ACTIVATED, SILENT_ALARM
    details = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


# ==========================================
# 🆕 NEW TABLES FOR MASTER SUITE (STEP 2)
# ==========================================

class FriendContact(Base):
    __tablename__ = "friend_contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    friend_email = Column(String, nullable=False)
    friend_username = Column(String, nullable=False)
    status = Column(String, default="active") # active, pending, blocked
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_email = Column(String, nullable=False)
    recipient_email = Column(String, nullable=False)
    encrypted_message = Column(Text, nullable=False) # Client-side AES-GCM ciphertext
    is_burned = Column(Boolean, default=False)      # Disappearing messages / Burn-after-reading
    created_at = Column(DateTime, default=datetime.utcnow)


class PasswordVaultItem(Base):
    __tablename__ = "password_vault_items"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    encrypted_blob = Column(Text, nullable=False) # Client-side encrypted credential payload
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="password_vaults")


class CodeScanReport(Base):
    __tablename__ = "code_scan_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    file_name = Column(String, nullable=False)
    security_grade = Column(String, nullable=False) # A, B, C, D, F
    vulnerabilities_summary = Column(Text, nullable=False) # JSON summary of findings
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="code_scans")