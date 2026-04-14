# /app/main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import psycopg2
import hmac
import hashlib
import json
from datetime import datetime, timedelta
from uuid import uuid4
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()

# ============ DATABASE CONFIG ============
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/nfcs_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ============ DATABASE MODELS ============
class NoticeTemplate(Base):
    __tablename__ = "notice_templates"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    company_id = Column(String, nullable=False)
    version = Column(String, default="1.0")
    language = Column(String, default="en")
    title = Column(String)
    description = Column(String)
    data_categories = Column(JSON)  # List of data types collected
    purposes = Column(JSON)  # List of purposes
    retention_period = Column(String)
    user_rights = Column(JSON)  # Access, correction, deletion, etc.
    contact_info = Column(JSON)  # Privacy officer contact
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ConsentRecord(Base):
    __tablename__ = "consent_records"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String, nullable=False)
    company_id = Column(String, nullable=False)
    notice_version = Column(String)
    notice_language = Column(String)
    notice_timestamp = Column(DateTime)
    consent_data = Column(JSON)  # {core: bool, analytics: bool, marketing: bool}
    consent_timestamp = Column(DateTime)
    device_id_hash = Column(String)
    ip_hash = Column(String)
    signature = Column(String)  # HMAC-SHA256 signature
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    company_id = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    action = Column(String)  # "notice_displayed", "consent_given", "consent_withdrawn"
    timestamp = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSON)
    signature = Column(String)

Base.metadata.create_all(bind=engine)

# ============ PYDANTIC MODELS ============
class NoticeTemplateCreate(BaseModel):
    title: str
    description: str
    data_categories: list
    purposes: list
    retention_period: str
    user_rights: list
    contact_info: dict

class ConsentPayload(BaseModel):
    user_id: str
    notice_version: str
    language: str
    notice_timestamp: str
    consent: dict  # {core: bool, analytics: bool, marketing: bool}
    consent_timestamp: str
    device_id_hash: str
    ip_hash: str

# ============ HMAC UTILITIES ============
def generate_hmac_signature(data: dict, secret_key: str) -> str:
    """Generate HMAC-SHA256 signature for tamper detection"""
    payload = json.dumps(data, sort_keys=True)
    signature = hmac.new(
        secret_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature

def verify_hmac_signature(data: dict, signature: str, secret_key: str) -> bool:
    """Verify HMAC signature"""
    expected_signature = generate_hmac_signature(data, secret_key)
    return hmac.compare_digest(expected_signature, signature)

# ============ FASTAPI APP ============
app = FastAPI(
    title="NFCS Core API",
    description="Notice First Consent System - Insurance Compliance Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============ API ENDPOINTS ============

@app.post("/api/v1/notice/create")
def create_notice_template(
    company_id: str,
    notice: NoticeTemplateCreate,
    db: Session = Depends(get_db)
):
    """Create a new notice template for insurance company"""
    new_notice = NoticeTemplate(
        company_id=company_id,
        title=notice.title,
        description=notice.description,
        data_categories=notice.data_categories,
        purposes=notice.purposes,
        retention_period=notice.retention_period,
        user_rights=notice.user_rights,
        contact_info=notice.contact_info
    )
    db.add(new_notice)
    db.commit()
    db.refresh(new_notice)
    
    return {
        "status": "success",
        "notice_id": new_notice.id,
        "version": new_notice.version,
        "created_at": new_notice.created_at
    }

@app.get("/api/v1/notice/{company_id}/{version}/{language}")
def get_notice_template(
    company_id: str,
    version: str,
    language: str,
    db: Session = Depends(get_db)
):
    """Retrieve notice template for SDK display"""
    notice = db.query(NoticeTemplate).filter(
        NoticeTemplate.company_id == company_id,
        NoticeTemplate.version == version,
        NoticeTemplate.language == language
    ).first()
    
    if not notice:
        raise HTTPException(status_code=404, detail="Notice not found")
    
    return {
        "notice_id": notice.id,
        "title": notice.title,
        "description": notice.description,
        "data_categories": notice.data_categories,
        "purposes": notice.purposes,
        "retention_period": notice.retention_period,
        "user_rights": notice.user_rights,
        "contact_info": notice.contact_info,
        "version": notice.version,
        "language": notice.language
    }

@app.post("/api/v1/consent/submit")
def submit_consent(
    company_id: str,
    payload: ConsentPayload,
    db: Session = Depends(get_db),
    api_key: str = None
):
    """
    Receive and store consent record
    Flow: Notice → Proceed → Consent → Audit Record
    """
    
    # Validate required fields
    if not all([payload.user_id, payload.notice_version, payload.consent]):
        raise HTTPException(status_code=400, detail="Missing required fields")
    
    # Validate consent structure
    if not isinstance(payload.consent, dict):
        raise HTTPException(status_code=400, detail="Invalid consent format")
    
    # Core consent must be true (mandatory)
    if not payload.consent.get("core"):
        raise HTTPException(status_code=400, detail="Core consent is mandatory")
    
    # Create audit record
    audit_data = {
        "user_id": payload.user_id,
        "notice_version": payload.notice_version,
        "notice_timestamp": payload.notice_timestamp,
        "consent": payload.consent,
        "consent_timestamp": payload.consent_timestamp,
        "language": payload.language
    }
    
    # Generate HMAC signature
    secret_key = os.getenv("HMAC_SECRET_KEY", "default-secret-key-change-in-prod")
    signature = generate_hmac_signature(audit_data, secret_key)
    
    # Store consent record
    consent_record = ConsentRecord(
        user_id=payload.user_id,
        company_id=company_id,
        notice_version=payload.notice_version,
        notice_language=payload.language,
        notice_timestamp=datetime.fromisoformat(payload.notice_timestamp),
        consent_data=payload.consent,
        consent_timestamp=datetime.fromisoformat(payload.consent_timestamp),
        device_id_hash=payload.device_id_hash,
        ip_hash=payload.ip_hash,
        signature=signature
    )
    
    db.add(consent_record)
    
    # Create audit log
    audit_log = AuditLog(
        company_id=company_id,
        user_id=payload.user_id,
        action="consent_given",
        metadata=audit_data,
        signature=signature
    )
    
    db.add(audit_log)
    db.commit()
    
    return {
        "status": "success",
        "consent_id": consent_record.id,
        "signature": signature,
        "timestamp": consent_record.created_at
    }

@app.get("/api/v1/consent/{user_id}/{company_id}")
def get_consent_status(
    user_id: str,
    company_id: str,
    db: Session = Depends(get_db)
):
    """Check if user has valid consent"""
    consent = db.query(ConsentRecord).filter(
        ConsentRecord.user_id == user_id,
        ConsentRecord.company_id == company_id,
        ConsentRecord.is_active == True
    ).order_by(ConsentRecord.created_at.desc()).first()
    
    if not consent:
        return {"has_consent": False, "consent_id": None}
    
    return {
        "has_consent": True,
        "consent_id": consent.id,
        "consent_data": consent.consent_data,
        "consent_timestamp": consent.consent_timestamp,
        "signature": consent.signature
    }

@app.post("/api/v1/consent/withdraw")
def withdraw_consent(
    user_id: str,
    company_id: str,
    purpose: str,
    db: Session = Depends(get_db)
):
    """Withdraw consent for specific purpose"""
    
    # Get latest consent record
    consent = db.query(ConsentRecord).filter(
        ConsentRecord.user_id == user_id,
        ConsentRecord.company_id == company_id,
        ConsentRecord.is_active == True
    ).order_by(ConsentRecord.created_at.desc()).first()
    
    if not consent:
        raise HTTPException(status_code=404, detail="No active consent found")
    
    # Create new record with withdrawn purpose
    new_consent_data = consent.consent_data.copy()
    new_consent_data[purpose] = False
    
    # Create audit data
    audit_data = {
        "user_id": user_id,
        "action": "consent_withdrawn",
        "purpose": purpose,
        "previous_consent_id": consent.id,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    secret_key = os.getenv("HMAC_SECRET_KEY", "default-secret-key-change-in-prod")
    signature = generate_hmac_signature(audit_data, secret_key)
    
    # Create new consent record (append-only)
    new_consent_record = ConsentRecord(
        user_id=user_id,
        company_id=company_id,
        notice_version=consent.notice_version,
        notice_language=consent.notice_language,
        notice_timestamp=consent.notice_timestamp,
        consent_data=new_consent_data,
        consent_timestamp=datetime.utcnow(),
        device_id_hash=consent.device_id_hash,
        ip_hash=consent.ip_hash,
        signature=signature
    )
    
    db.add(new_consent_record)
    
    # Log withdrawal
    audit_log = AuditLog(
        company_id=company_id,
        user_id=user_id,
        action="consent_withdrawn",
        metadata=audit_data,
        signature=signature
    )
    
    db.add(audit_log)
    db.commit()
    
    return {
        "status": "success",
        "message": f"Consent withdrawn for {purpose}",
        "new_consent_id": new_consent_record.id
    }

@app.get("/api/v1/audit/logs/{company_id}")
def get_audit_logs(
    company_id: str,
    user_id: str = None,
    action: str = None,
    days: int = 30,
    db: Session = Depends(get_db)
):
    """Retrieve audit logs for compliance reporting"""
    query = db.query(AuditLog).filter(AuditLog.company_id == company_id)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    # Filter by date range
    start_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(AuditLog.timestamp >= start_date)
    
    logs = query.order_by(AuditLog.timestamp.desc()).all()
    
    return {
        "count": len(logs),
        "logs": [
            {
                "audit_id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "timestamp": log.timestamp,
                "signature": log.signature
            }
            for log in logs
        ]
    }

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "NFCS Core API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
