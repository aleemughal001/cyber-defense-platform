import json
import random
from datetime import datetime
import requests

ORCHESTRATOR_URL = "http://localhost:8000/iot-event"

devices = [
    {
        "device_id": "cam-001",
        "device_type": "smart_camera",
        "firmware_version": "1.0.2",
        "location": "warehouse-edge-1",
        "network_zone": "iot",
        "expected_protocol": "rtsp"
    },
    {
        "device_id": "thermo-002",
        "device_type": "smart_thermostat",
        "firmware_version": "2.1.0",
        "location": "branch-edge-3",
        "network_zone": "iot",
        "expected_protocol": "mqtt"
    },
    {
        "device_id": "badge-003",
        "device_type": "access_control_panel",
        "firmware_version": "3.0.1",
        "location": "hq-edge-2",
        "network_zone": "iot",
        "expected_protocol": "https"
    }
]

threat_types = [
    "normal",
    "botnet_beaconing",
    "firmware_tampering",
    "unauthorized_access_attempt",
    "command_injection_attempt"
]

def generate_iot_event():
    device = random.choice(devices)
    threat = random.choice(threat_types)

    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "device_id": device["device_id"],
        "device_type": device["device_type"],
        "firmware_version": device["firmware_version"],
        "location": device["location"],
        "network_zone": device["network_zone"],
        "expected_protocol": device["expected_protocol"],
        "threat_type": threat,
        "risk_score": round(random.uniform(0.10, 0.98), 2),
        "is_edge_device": 1,
        "firmware_outdated": random.choice([0, 1]),
        "unexpected_protocol": random.choice([0, 1]),
        "telemetry_spike": random.choice([0, 1]),
        "command_injection": 1 if threat == "command_injection_attempt" else 0
    }

    if threat == "normal":
        event["risk_score"] = round(random.uniform(0.05, 0.30), 2)
        event["unexpected_protocol"] = 0
        event["telemetry_spike"] = 0
        event["command_injection"] = 0

    if threat == "firmware_tampering":
        event["firmware_outdated"] = 1
        event["risk_score"] = round(random.uniform(0.70, 0.95), 2)

    if threat == "botnet_beaconing":
        event["telemetry_spike"] = 1
        event["risk_score"] = round(random.uniform(0.75, 0.97), 2)

    if threat == "unauthorized_access_attempt":
        event["unexpected_protocol"] = 1
        event["risk_score"] = round(random.uniform(0.65, 0.93), 2)

    if threat == "command_injection_attempt":
        event["command_injection"] = 1
        event["risk_score"] = round(random.uniform(0.85, 0.99), 2)

    return event

def send_event(event):
    try:
        response = requests.post(ORCHESTRATOR_URL, json=event, timeout=5)
        print("\n--- Orchestrator Response ---")
        print("Status Code:", response.status_code)
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print("Failed to send event:", str(e))

if __name__ == "__main__":
    event = generate_iot_event()
    print("\n--- Generated IoT Event ---")
    print(json.dumps(event, indent=2))
    send_event(event)
