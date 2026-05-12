from blockchain_audit_layer import append_audit_record


def block_ip(src_ip: str):
    print(f"[ACTION] Blocking traffic source {src_ip}")

    response = {
        "action": "block",
        "status": "executed",
        "src_ip": src_ip
    }

    try:
        append_audit_record(
            event_type="autonomous_response",
            payload=response
        )
    except Exception as e:
        print(f"[blockchain-audit] failed to log block response: {e}")

    return response


def take_response(action: str, alert: dict):
    if action == "isolate":
        print(f"[ACTION] Isolating IoT/edge device {alert.get('device_id', 'unknown')}")

        response = {
            "action": "isolate",
            "status": "executed",
            "device_id": alert.get("device_id", "unknown"),
            "src_ip": alert.get("src_ip", "unknown"),
            "signature": alert.get("signature", "unknown"),
            "risk_score": alert.get("risk_score")
        }

    elif action == "quarantine_model_input":
        print(f"[ACTION] Quarantining suspicious ML input from {alert.get('device_id', 'unknown')}")

        response = {
            "action": "quarantine_model_input",
            "status": "executed",
            "device_id": alert.get("device_id", "unknown"),
            "src_ip": alert.get("src_ip", "unknown"),
            "signature": alert.get("signature", "unknown"),
            "risk_score": alert.get("risk_score")
        }

    elif action == "deceive":
        print(f"[ACTION] Redirecting {alert.get('src_ip', 'unknown')} to deception environment")

        response = {
            "action": "deceive",
            "status": "executed",
            "src_ip": alert.get("src_ip", "unknown"),
            "device_id": alert.get("device_id", "unknown"),
            "signature": alert.get("signature", "unknown"),
            "risk_score": alert.get("risk_score")
        }

    elif action == "block":
        src_ip = alert.get("src_ip", "unknown")
        return block_ip(src_ip)

    else:
        print(f"[ACTION] Observing source {alert.get('src_ip', 'unknown')}")

        response = {
            "action": "observe",
            "status": "executed",
            "src_ip": alert.get("src_ip", "unknown"),
            "device_id": alert.get("device_id", "unknown"),
            "signature": alert.get("signature", "unknown"),
            "risk_score": alert.get("risk_score")
        }

    try:
        append_audit_record(
            event_type="autonomous_response",
            payload=response
        )
    except Exception as e:
        print(f"[blockchain-audit] failed to log response: {e}")

    return response
