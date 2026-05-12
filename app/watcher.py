import json
import os
import time
from datetime import datetime
import requests
from sqlalchemy import text
from db import SessionLocal
from models import Alert, Prediction, Response
from predictor import predict_risk
from responder import block_ip

OPA_URL = "http://localhost:8181/v1/data/cyberdefense"
EVE_FILE = os.getenv("SURICATA_EVE_FILE", "/data/eve.json")

def query_recent_alert_count(session, src_ip: str) -> int:
    q = text("""
        SELECT COUNT(*) FROM alerts
        WHERE src_ip = :src_ip
          AND timestamp >= NOW() - INTERVAL '15 minutes'
    """)
    result = session.execute(q, {"src_ip": src_ip}).scalar()
    return int(result or 0)

def ask_opa(src_ip: str, signature: str, risk_score: float):
    payload = {
        "input": {
            "src_ip": src_ip,
            "signature": signature,
            "risk_score": risk_score
        }
    }
    r = requests.post(OPA_URL, json=payload, timeout=10)
    r.raise_for_status()
    return r.json().get("result", {})

def process_event(event: dict):
    if event.get("event_type") != "alert":
        return

    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")
    signature = alert.get("signature", "unknown")
    severity = int(alert.get("severity", 1))
    ts_raw = event.get("timestamp")

    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else None
    except Exception:
        ts = None

    db = SessionLocal()

    try:
        db_alert = Alert(
            timestamp=ts,
            src_ip=src_ip,
            dest_ip=dest_ip,
            signature=signature,
            severity=severity,
            raw=event
        )
        db.add(db_alert)
        db.commit()

        recent_count = query_recent_alert_count(db, src_ip)
        risk_score, predicted_attack, features = predict_risk(
            severity, signature, recent_count, src_ip
        )

        db_pred = Prediction(
            src_ip=src_ip,
            risk_score=risk_score,
            predicted_attack=predicted_attack,
            features=features
        )
        db.add(db_pred)
        db.commit()

        policy_result = ask_opa(src_ip, signature, risk_score)
        mode = policy_result.get("defense_mode", "observe")

        if mode == "deceive":
            db_resp = Response(
                src_ip=src_ip,
                action_taken="redirect_to_honeypot",
                reason="High-confidence threat flagged for deception workflow",
                policy_result=policy_result
            )
            db.add(db_resp)
            db.commit()

        elif policy_result.get("allow_block", False):
            result = block_ip(src_ip)
            db_resp = Response(
                src_ip=src_ip,
                action_taken="block_ip",
                reason=result,
                policy_result=policy_result
            )
            db.add(db_resp)
            db.commit()

        else:
            db_resp = Response(
                src_ip=src_ip,
                action_taken="observe_only",
                reason="Policy did not authorize block",
                policy_result=policy_result
            )
            db.add(db_resp)
            db.commit()

    finally:
        db.close()

def tail_file(filepath: str):
    while not os.path.exists(filepath):
        print(f"[watcher] waiting for {filepath}")
        time.sleep(2)

    with open(filepath, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line.strip())
                process_event(event)
            except Exception as e:
                print(f"[watcher] error: {e}")
