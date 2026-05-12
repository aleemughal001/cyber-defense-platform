from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Numeric
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from db import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=True)
    src_ip = Column(String(64), nullable=True)
    dest_ip = Column(String(64), nullable=True)
    signature = Column(Text, nullable=True)
    severity = Column(Integer, nullable=True)
    raw = Column(JSONB, nullable=False)

class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    src_ip = Column(String(64), nullable=False)
    risk_score = Column(Numeric(5, 4), nullable=False)
    predicted_attack = Column(Boolean, nullable=False)
    features = Column(JSONB, nullable=False)

class Response(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    src_ip = Column(String(64), nullable=False)
    action_taken = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    policy_result = Column(JSONB, nullable=False)
