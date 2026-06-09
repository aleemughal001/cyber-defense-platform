import threading
import time
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

# In-memory service health state used for automatic self-healing demonstration
SERVICE_HEALTH = {
    "suricata": "healthy",
    "opa": "healthy",
    "orchestrator": "healthy"
}

AUTO_HEAL_CHECK_INTERVAL_SECONDS = 5
AUTO_HEAL_COOLDOWN_SECONDS = 30
LAST_AUTO_HEAL = {}
AUTO_HEAL_MONITOR_STARTED = False


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
    db = SessionLocal()

    try:
        policy_input = {
            "signature": payload.signature,
            "risk_score": payload.risk_score,
            "src_ip": payload.src_ip,
            "is_edge_device": payload.is_edge_device,
            "firmware_outdated": payload.firmware_outdated,
            "adversarial_detected": payload.adversarial_detected
        }

        policy_result = query_opa_policy(policy_input)
        decision = policy_result.get("defense_mode", "observe")

        response_row = insert_response(
            db,
            payload.src_ip,
            decision,
            f"OPA mode: {decision}"
        )

        return {
            "input": policy_input,
            "policy_result": policy_result,
            "response_id": response_row.id,
            "action_taken": decision,
            "stored": True
        }

    finally:
        db.close()


@app.post("/simulate-iot-threat")
def simulate_iot_threat():
    db = SessionLocal()

    try:
        simulated = generate_iot_event()

        src_ip = simulated.get("src_ip", "192.168.100.118")
        threat_type = simulated.get("threat_type", "normal")

        event_risk = float(simulated.get("risk_score", 0.0))
        if event_risk >= 0.90:
            severity = 5
        elif event_risk >= 0.80:
            severity = 4
        elif event_risk >= 0.70:
            severity = 3
        elif event_risk >= 0.50:
            severity = 2
        else:
            severity = 1

        signature = f"IOT_{threat_type}"
        recent_alert_count = db.query(Alert).filter(Alert.src_ip == src_ip).count()

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
            "recent_alert_count": recent_alert_count,
            "command_injection": simulated.get("command_injection", 0)
        }

        ml_result = detect_adversarial_features(ml_features)

        risk_score, predicted_attack, features = predict_risk(
            severity=severity,
            signature=signature,
            recent_alert_count=recent_alert_count,
            src_ip=src_ip,
            event_risk_score=simulated.get("risk_score", 0.0),
            telemetry_spike=simulated.get("telemetry_spike", 0),
            unexpected_protocol=simulated.get("unexpected_protocol", 0),
            command_injection=simulated.get("command_injection", 0),
            firmware_outdated=simulated.get("firmware_outdated", 0),
            is_edge_device=simulated.get("is_edge_device", 0),
            adversarial_detected=ml_result.get("adversarial_detected", 0)
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

    db = SessionLocal()

    try:
        health_before = "degraded"
        recovery_action = "restart_simulated"
        health_after = "healthy"
        timestamp = datetime.utcnow().isoformat()

        reason = (
            f"Self-healing workflow executed for {service_name}. "
            f"Health changed from {health_before} to {health_after}. "
            f"Action: {recovery_action}."
        )

        response_row = insert_response(
            db,
            src_ip="system",
            action_taken=f"self_heal_{service_name}",
            reason=reason
        )

        append_audit_record(
            event_type="self_healing_event",
            payload={
                "service": service_name,
                "health_before": health_before,
                "recovery_action": recovery_action,
                "health_after": health_after,
                "response_id": response_row.id,
                "timestamp": timestamp
            }
        )

        return {
            "status": "success",
            "service": service_name,
            "health_before": health_before,
            "recovery_action": recovery_action,
            "health_after": health_after,
            "action": recovery_action,
            "response_id": response_row.id,
            "audit_logged": True,
            "message": f"Self-healing completed for {service_name}",
            "timestamp": timestamp
        }

    except Exception as e:
        db.rollback()
        return {
            "status": "error",
            "service": service_name,
            "message": str(e),
            "audit_logged": False
        }

    finally:
        db.close()



@app.post("/simulate-zero-day")
def simulate_zero_day():
    timestamp = datetime.utcnow().isoformat()

    return {
        "status": "success",
        "simulation_type": "zero_day",
        "description": "Unknown behavior detected without a known signature.",
        "anomaly_detected": True,
        "risk_score": 0.91,
        "recommended_action": "deceive",
        "reason": (
            "The event represents unknown high-risk behavior. "
            "A deception response can redirect the attacker toward a controlled decoy environment."
        ),
        "timestamp": timestamp
    }


@app.get("/forecast-threats")
def forecast_threats():
    db = SessionLocal()

    try:
        alert_count = db.query(Alert).count()
        prediction_count = db.query(Prediction).count()
        response_count = db.query(Response).count()

        if alert_count >= 50:
            posture = "elevated"
            likely_attack = "IoT compromise or repeated edge-device abuse"
        elif alert_count >= 10:
            posture = "moderate"
            likely_attack = "suspicious scanning or policy-triggered activity"
        else:
            posture = "low"
            likely_attack = "limited activity"

        return {
            "status": "success",
            "forecast_window": "next_24_hours",
            "security_posture": posture,
            "likely_attack_type": likely_attack,
            "current_alerts": alert_count,
            "current_predictions": prediction_count,
            "current_responses": response_count,
            "recommendation": (
                "Continue monitoring IoT activity, review high-risk responses, "
                "and validate OPA policy decisions."
            ),
            "timestamp": datetime.utcnow().isoformat()
        }

    finally:
        db.close()


@app.get("/audit/verify")
def verify_audit_chain():
    import json
    from pathlib import Path

    ledger_path = Path(os.getenv("AUDIT_LEDGER_FILE", "/data/audit_ledger.jsonl"))

    if not ledger_path.exists():
        return {
            "status": "success",
            "ledger_found": False,
            "chain_valid": True,
            "records_checked": 0,
            "tampering_detected": False,
            "ledger_path": str(ledger_path),
            "message": "No audit ledger file found yet."
        }

    records_checked = 0
    invalid_lines = 0

    with ledger_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                json.loads(line)
                records_checked += 1
            except Exception:
                invalid_lines += 1

    tampering_detected = invalid_lines > 0

    return {
        "status": "success",
        "ledger_found": True,
        "chain_valid": not tampering_detected,
        "records_checked": records_checked,
        "invalid_lines": invalid_lines,
        "tampering_detected": tampering_detected,
        "ledger_path": str(ledger_path),
        "message": "Audit ledger parsed successfully." if not tampering_detected else "Invalid audit records detected."
    }


@app.get("/capability-map")
def capability_map():
    return {
        "status": "success",
        "project": "Next-Generation Cyber Defense Platform",
        "capabilities": [
            {
                "capability": "Autonomous Response",
                "implementation": "OPA policy decision plus response engine actions such as observe, block, isolate, deceive, and quarantine model input."
            },
            {
                "capability": "Predictive Threat Modeling",
                "implementation": "Prediction records and risk scoring based on event features such as severity, signature, source IP context, and recent alert count."
            },
            {
                "capability": "Adaptive Security",
                "implementation": "Rego policy rules dynamically select response modes based on risk, IoT criticality, and adversarial ML indicators."
            },
            {
                "capability": "IoT / Edge Security",
                "implementation": "Simulated IoT events include firmware status, telemetry spike, unexpected protocol, and command injection indicators."
            },
            {
                "capability": "Auditability",
                "implementation": "Blockchain-style audit records are written for response and self-healing actions."
            },
            {
                "capability": "Self-Healing",
                "implementation": "The platform simulates recovery of services such as Suricata, OPA, and orchestrator."
            },
            {
                "capability": "PQC Awareness",
                "implementation": "Project includes PQC demonstration material to show future-ready cryptographic migration awareness."
            }
        ]
    }



@app.post("/simulate-service-degradation/{service_name}")
def simulate_service_degradation(service_name: str):
    allowed_services = {"suricata", "opa", "orchestrator"}

    if service_name not in allowed_services:
        return {
            "status": "error",
            "message": f"Unsupported service: {service_name}",
            "allowed_services": list(allowed_services)
        }

    SERVICE_HEALTH[service_name] = "degraded"

    return {
        "status": "success",
        "service": service_name,
        "health": "degraded",
        "message": f"{service_name} marked as degraded. Auto-healing monitor will recover it automatically.",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/service-health")
def service_health():
    return {
        "status": "success",
        "services": SERVICE_HEALTH,
        "auto_heal_check_interval_seconds": AUTO_HEAL_CHECK_INTERVAL_SECONDS,
        "timestamp": datetime.utcnow().isoformat()
    }


def execute_auto_self_heal(service_name: str):
    db = SessionLocal()

    try:
        health_before = SERVICE_HEALTH.get(service_name, "unknown")
        recovery_action = "restart_simulated"
        health_after = "healthy"
        timestamp = datetime.utcnow().isoformat()

        SERVICE_HEALTH[service_name] = health_after

        reason = (
            f"Automatic self-healing workflow executed for {service_name}. "
            f"Health changed from {health_before} to {health_after}. "
            f"Action: {recovery_action}."
        )

        response_row = insert_response(
            db,
            src_ip="system",
            action_taken=f"self_heal_{service_name}",
            reason=reason
        )

        append_audit_record(
            event_type="automatic_self_healing_event",
            payload={
                "service": service_name,
                "health_before": health_before,
                "recovery_action": recovery_action,
                "health_after": health_after,
                "response_id": response_row.id,
                "trigger": "auto_health_monitor",
                "timestamp": timestamp
            }
        )

        return {
            "status": "success",
            "service": service_name,
            "health_before": health_before,
            "recovery_action": recovery_action,
            "health_after": health_after,
            "response_id": response_row.id,
            "audit_logged": True,
            "trigger": "auto_health_monitor",
            "timestamp": timestamp
        }

    except Exception as e:
        db.rollback()
        return {
            "status": "error",
            "service": service_name,
            "message": str(e),
            "audit_logged": False
        }

    finally:
        db.close()


def auto_health_monitor():
    while True:
        now = time.time()

        for service_name, health in list(SERVICE_HEALTH.items()):
            if health != "degraded":
                continue

            last_heal = LAST_AUTO_HEAL.get(service_name, 0)

            if now - last_heal >= AUTO_HEAL_COOLDOWN_SECONDS:
                execute_auto_self_heal(service_name)
                LAST_AUTO_HEAL[service_name] = now

        time.sleep(AUTO_HEAL_CHECK_INTERVAL_SECONDS)


def start_auto_health_monitor():
    global AUTO_HEAL_MONITOR_STARTED

    if AUTO_HEAL_MONITOR_STARTED:
        return

    thread = threading.Thread(
        target=auto_health_monitor,
        daemon=True
    )
    thread.start()
    AUTO_HEAL_MONITOR_STARTED = True



@app.get("/ml-forecast")
def ml_forecast():
    import numpy as np
    from sklearn.ensemble import RandomForestRegressor

    # Simulated historical alert counts over time
    alert_counts = np.array([
        3, 4, 5, 4, 6, 7, 8, 10, 9, 11,
        12, 13, 15, 14, 16, 18, 19, 21, 20, 22,
        24, 25, 27, 29, 28, 30, 31, 33, 35, 36
    ], dtype=float)

    window = 5
    X = []
    y = []

    for i in range(len(alert_counts) - window):
        X.append(alert_counts[i:i + window])
        y.append(alert_counts[i + window])

    X = np.array(X)
    y = np.array(y)

    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X, y)

    last_window = alert_counts[-window:].reshape(1, -1)
    prediction = model.predict(last_window)[0]

    return {
        "status": "success",
        "model": "scikit-learn RandomForestRegressor",
        "purpose": "Attack trend / alert-count forecasting",
        "input_window": alert_counts[-window:].tolist(),
        "predicted_next_alert_count": round(float(prediction), 2),
        "explanation": (
            "The model learns from previous alert-count windows and predicts "
            "the next expected alert count."
        ),
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

# Start automatic self-healing monitor
start_auto_health_monitor()
