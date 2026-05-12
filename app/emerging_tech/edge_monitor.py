def normalize_iot_event(event: dict) -> dict:
    """
    Convert IoT/edge event into platform-compatible alert format
    """
    return {
        "src_ip": f"iot-{event['device_id']}",
        "signature": f"IOT {event['threat_type']}",
        "severity": 5 if event["risk_score"] >= 0.8 else 3,
        "is_external_ip": 0,
        "signature_sqlmap": 0,
        "recent_alert_count": 1,
        "risk_score": event["risk_score"],
        "device_id": event["device_id"],
        "device_type": event["device_type"],
        "location": event["location"],
        "network_zone": event["network_zone"],
        "is_edge_device": event["is_edge_device"],
        "firmware_outdated": event["firmware_outdated"],
        "unexpected_protocol": event["unexpected_protocol"],
        "telemetry_spike": event["telemetry_spike"],
        "command_injection": event["command_injection"]
    }


if __name__ == "__main__":
    sample = {
        "device_id": "cam-001",
        "device_type": "smart_camera",
        "location": "edge-branch-1",
        "network_zone": "iot",
        "threat_type": "firmware_tampering",
        "risk_score": 0.88,
        "is_edge_device": 1,
        "firmware_outdated": 1,
        "unexpected_protocol": 0,
        "telemetry_spike": 0,
        "command_injection": 0
    }

    print(normalize_iot_event(sample))
