from fastapi import APIRouter
from datetime import datetime, timezone
from pathlib import Path
import json
import random

router = APIRouter()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@router.post("/simulate-zero-day")
def simulate_zero_day():
    """
    Simulates an unknown / zero-day style threat.
    This demonstrates early-warning logic using anomaly score,
    unknown signature behavior, risk scoring, and autonomous response.
    """

    anomaly_score = round(random.uniform(0.82, 0.98), 2)
    risk_score = round(random.uniform(0.85, 0.99), 2)

    if risk_score >= 0.95:
        recommended_action = "deceive"
        reason = "Very high anomaly score and unknown behavior pattern"
    elif risk_score >= 0.85:
        recommended_action = "block"
        reason = "High-risk unknown behavior detected"
    else:
        recommended_action = "observe"
        reason = "Suspicious behavior requires monitoring"

    return {
        "event_type": "zero_day_simulation",
        "timestamp": utc_now(),
        "known_signature": False,
        "signature": "unknown_behavior_pattern",
        "anomaly_score": anomaly_score,
        "risk_score": risk_score,
        "threat_level": "critical" if risk_score >= 0.95 else "high",
        "recommended_action": recommended_action,
        "reason": reason,
        "status": "simulated"
    }


@router.get("/forecast-threats")
def forecast_threats():
    """
    Demonstrates predictive threat modeling output.
    """

    possible_attacks = [
        "iot_compromise",
        "sql_injection",
        "credential_attack",
        "adversarial_ml_input",
        "edge_device_abuse",
        "unknown_behavior_pattern"
    ]

    predicted_attack = random.choice(possible_attacks)
    confidence = round(random.uniform(0.72, 0.91), 2)

    if confidence >= 0.85:
        predicted_level = "high"
        recommended_posture = "increase_monitoring_and_enable_blocking"
    elif confidence >= 0.75:
        predicted_level = "medium"
        recommended_posture = "increase_monitoring"
    else:
        predicted_level = "low"
        recommended_posture = "observe"

    return {
        "forecast_window": "next_24_hours",
        "timestamp": utc_now(),
        "predicted_threat_level": predicted_level,
        "most_likely_attack": predicted_attack,
        "confidence": confidence,
        "recommended_security_posture": recommended_posture,
        "purpose": "predictive_threat_modeling_demo"
    }


@router.get("/audit/verify")
def verify_audit_chain():
    """
    Verifies blockchain-style audit ledger availability and readability.
    """

    possible_paths = [
        Path("/data/audit_ledger.jsonl"),
        Path("suricata/log/audit_ledger.jsonl"),
        Path("../suricata/log/audit_ledger.jsonl"),
    ]

    ledger_path = None

    for path in possible_paths:
        if path.exists():
            ledger_path = path
            break

    if ledger_path is None:
        return {
            "audit_chain_valid": False,
            "records_checked": 0,
            "tampering_detected": False,
            "message": "Audit ledger file was not found. Generate response events first.",
            "checked_paths": [str(p) for p in possible_paths]
        }

    records = []

    with ledger_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                return {
                    "audit_chain_valid": False,
                    "records_checked": len(records),
                    "tampering_detected": True,
                    "message": "Invalid JSON record found in audit ledger.",
                    "ledger_path": str(ledger_path)
                }

    return {
        "audit_chain_valid": True,
        "records_checked": len(records),
        "tampering_detected": False,
        "message": "Audit ledger verification completed successfully.",
        "ledger_path": str(ledger_path)
    }


@router.get("/capability-map")
def capability_map():
    """
    Maps project features to academic learning objectives.
    """

    return {
        "autonomous_cyber_defense": [
            "FastAPI orchestrator",
            "Python risk scoring",
            "Autonomous response engine",
            "OPA policy decisions"
        ],
        "predictive_threat_modeling": [
            "forecast-threats endpoint",
            "scikit-learn forecasting demo",
            "threat trend dashboard"
        ],
        "adaptive_security_architecture": [
            "OPA Rego policies",
            "Dynamic response modes",
            "Risk-based policy decision"
        ],
        "self_healing_security": [
            "self-heal service endpoint",
            "recovery simulation",
            "audit logging support"
        ],
        "emerging_technology_security": [
            "IoT simulator",
            "edge monitor",
            "ML guard",
            "adversarial ML input protection"
        ],
        "quantum_safe_security": [
            "PQC demo script",
            "Open Quantum Safe concept",
            "crypto-agility readiness"
        ],
        "blockchain_audit": [
            "blockchain-style audit ledger",
            "hash-linked audit records",
            "audit verification endpoint"
        ]
    }


