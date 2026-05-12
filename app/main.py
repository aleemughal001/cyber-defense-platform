import threading
import os
import requests
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import text

from db import SessionLocal
from watcher import tail_file

from models import Alert, Prediction, Response
from responder import take_response
from predictor import predict_risk
from emerging_tech.iot_simulator import generate_iot_event
from emerging_tech.ml_guard import detect_adversarial_features
from blockchain_audit_layer import append_audit_record

app = FastAPI(title="Autonomous Cyber Defense Platform")

# Serve frontend static files
app.mount("/static", StaticFiles(directory="static"), name="static")

EVE_FILE = os.getenv("SURICATA_EVE_FILE", "/data/eve.json")
OPA_URL = "http://opa:8181/v1/data/cyberdefense"


@app.get("/")
def dashboard():
    return FileResponse("static/index.html")


def query_opa_policy(payload: dict) -> dict:
    try:
        response = requests.post(
            OPA_URL,
            json={"input": payload},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        return data.get("result", {})
    except Exception as e:
        return {
            "allow_block": False,
            "defense_mode": "observe",
            "error": str(e)
        }


class IoTEvent(BaseModel):
    timestamp: str
    device_id: str
    src_ip: str
    event_type: str
    severity: int
    firmware_outdated: int = 0
    adversarial_detected: int = 0


class PolicyTestInput(BaseModel):
    signature: str = ""
    risk_score: float = 0.0
    src_ip: str = "192.168.1.50"
    is_edge_device: int = 0
    firmware_outdated: int = 0
    adversarial_detected: int = 0


def insert_alert(db, src_ip: str, signature: str, severity: int):
    row = Alert(
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        signature=signature,
        severity=severity
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def insert_prediction(db, src_ip: str, risk_score: float, predicted_attack: bool, features: dict):
    row = Prediction(
        created_at=datetime.utcnow(),
        src_ip=src_ip,
        risk_score=risk_score,
        predicted_attack=predicted_attack,
        features=features
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def insert_response(db, src_ip: str, action_taken: str, reason: str):
    row = Response(
        created_at=datetime.utcnow(),
        src_ip=src_ip,
        action_taken=action_taken,
        reason=reason
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/stats")
def stats():
    db = SessionLocal()
    try:
        return {
            "alerts": db.query(Alert).count(),
            "predictions": db.query(Prediction).count(),
            "responses": db.query(Response).count()
        }
    finally:
        db.close()


@app.get("/recent-alerts")
def recent_alerts():
    db = SessionLocal()
    try:
        rows = db.query(Alert).order_by(Alert.id.desc()).limit(10).all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "src_ip": r.src_ip,
                "signature": r.signature,
                "severity": r.severity
            }
            for r in rows
        ]
    finally:
        db.close()


@app.get("/recent-predictions")
def recent_predictions():
    db = SessionLocal()
    try:
        rows = db.query(Prediction).order_by(Prediction.id.desc()).limit(10).all()
        return [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat(),
                "src_ip": r.src_ip,
                "risk_score": r.risk_score,
                "predicted_attack": r.predicted_attack,
                "features": r.features
            }
            for r in rows
        ]
    finally:
        db.close()


@app.get("/recent-responses")
def recent_responses():
    db = SessionLocal()
    try:
        rows = db.query(Response).order_by(Response.id.desc()).limit(10).all()
        return [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat(),
                "src_ip": r.src_ip,
                "action_taken": r.action_taken,
                "reason": r.reason
            }
            for r in rows
        ]
    finally:
        db.close()


@app.post("/test-policy")
def test_policy(payload: PolicyTestInput):
    policy_input = {
        "signature": payload.signature,
        "risk_score": payload.risk_score,
        "src_ip": payload.src_ip,
        "is_edge_device": payload.is_edge_device,
        "firmware_outdated": payload.firmware_outdated,
        "adversarial_detected": payload.adversarial_detected
    }

    policy_result = query_opa_policy(policy_input)

    return {
        "input": policy_input,
        "policy_result": policy_result
    }


@app.post("/simulate-iot-threat")
def simulate_iot_threat():
    db = SessionLocal()

    try:
        simulated = generate_iot_event()

        src_ip = simulated.get("src_ip", "192.168.100.118")
        threat_type = simulated.get("threat_type", "normal")
        severity = 5 if threat_type != "normal" else 2
        signature = f"IOT_{threat_type}"

        alert_row = insert_alert(
            db,
            src_ip,
            signature,
            severity
        )

        ml_features = {
            "device_type": simulated.get("device_type", "unknown"),
            "unexpected_protocol": simulated.get("unexpected_protocol", 0),
            "telemetry_spike": simulated.get("telemetry_spike", 0),
            "recent_alert_count": 1,
            "command_injection": simulated.get("command_injection", 0)
        }

        ml_result = detect_adversarial_features(ml_features)

        risk_score, predicted_attack, features = predict_risk(
            severity=severity,
            signature=signature,
            recent_alert_count=1,
            src_ip=src_ip
        )

        prediction_row = insert_prediction(
            db,
            src_ip,
            risk_score,
            predicted_attack,
            features
        )

        policy_input = {
            "signature": signature,
            "risk_score": risk_score,
            "is_edge_device": simulated.get("is_edge_device", 1),
            "firmware_outdated": simulated.get("firmware_outdated", 0),
            "adversarial_detected": ml_result.get("adversarial_detected", 0)
        }

        policy_result = query_opa_policy(policy_input)
        decision = policy_result.get("defense_mode", "observe")

        alert_context = {
            "src_ip": src_ip,
            "device_id": simulated.get("device_id", "unknown"),
            "signature": signature,
            "risk_score": risk_score
        }

        response_data = take_response(
            decision,
            alert_context
        )

        action_taken = response_data.get("action", decision)

        response_row = insert_response(
            db,
            src_ip,
            action_taken,
            f"OPA mode: {decision}"
        )

        append_audit_record(
            event_type="simulated_iot_threat",
            payload={
                "src_ip": src_ip,
                "signature": signature,
                "risk_score": risk_score,
                "action_taken": action_taken,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

        return {
            "message": "Simulated IoT threat processed and stored",
            "simulated_event": simulated,
            "ml_result": ml_result,
            "alert_id": alert_row.id,
            "prediction_id": prediction_row.id,
            "response_id": response_row.id,
            "risk_score": risk_score,
            "predicted_attack": predicted_attack,
            "policy_result": policy_result,
            "action_taken": action_taken
        }

    except Exception as e:
        db.rollback()
        return {"error": str(e)}

    finally:
        db.close()


@app.post("/self-heal/{service_name}")
def self_heal(service_name: str):
    allowed_services = {"suricata", "opa", "orchestrator"}

    if service_name not in allowed_services:
        return {
            "status": "error",
            "message": f"Unsupported service: {service_name}",
            "allowed_services": list(allowed_services)
        }

    return {
        "status": "success",
        "service": service_name,
        "action": "restart_simulated",
        "message": f"Self-healing initiated for {service_name}",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/test-db")
def test_db():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"database": "connected"}
    finally:
        db.close()


def start_watcher():
    if os.path.exists(EVE_FILE):
        thread = threading.Thread(
            target=tail_file,
            args=(EVE_FILE,),
            daemon=True
        )
        thread.start()


start_watcher()
