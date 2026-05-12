def detect_adversarial_features(features: dict) -> dict:
    """
    Detect suspicious or manipulated telemetry
    """
    flags = []

    if features.get("telemetry_spike", 0) == 1 and features.get("recent_alert_count", 0) == 0:
        flags.append("possible_input_manipulation")

    if features.get("unexpected_protocol", 0) == 1 and features.get("device_type") == "temperature_sensor":
        flags.append("protocol_anomaly_on_sensor")

    if features.get("command_injection", 0) == 1:
        flags.append("high_confidence_adversarial_signal")

    return {
        "adversarial_detected": 1 if flags else 0,
        "adversarial_flags": flags
    }


if __name__ == "__main__":
    sample = {
        "device_type": "temperature_sensor",
        "unexpected_protocol": 1,
        "telemetry_spike": 0,
        "recent_alert_count": 1,
        "command_injection": 0
    }

    print(detect_adversarial_features(sample))
