import ipaddress


def is_external_ip(src_ip: str) -> int:
    """
    Returns 1 if the source IP is public/external, otherwise 0.
    Private/internal IPs such as 192.168.x.x return 0.
    """
    try:
        ip = ipaddress.ip_address(src_ip)
        return 0 if ip.is_private else 1
    except Exception:
        return 0


def extract_features(
    severity: int,
    signature: str,
    recent_alert_count: int,
    src_ip: str,
    event_risk_score: float = 0.0,
    telemetry_spike: int = 0,
    unexpected_protocol: int = 0,
    command_injection: int = 0,
    firmware_outdated: int = 0,
    is_edge_device: int = 0,
    adversarial_detected: int = 0,
):
    signature_lower = (signature or "").lower()

    return {
        "severity": severity,
        "is_external_ip": is_external_ip(src_ip),
        "signature_sqlmap": 1 if "sqlmap" in signature_lower else 0,
        "signature_iot": 1 if "iot" in signature_lower else 0,
        "signature_command_injection": 1 if "command_injection" in signature_lower else 0,
        "recent_alert_count": recent_alert_count,
        "event_risk_score": round(float(event_risk_score), 2),
        "telemetry_spike": int(telemetry_spike),
        "unexpected_protocol": int(unexpected_protocol),
        "command_injection": int(command_injection),
        "firmware_outdated": int(firmware_outdated),
        "is_edge_device": int(is_edge_device),
        "adversarial_detected": int(adversarial_detected),
    }


def predict_risk(
    severity: int,
    signature: str,
    recent_alert_count: int,
    src_ip: str,
    event_risk_score: float = 0.0,
    telemetry_spike: int = 0,
    unexpected_protocol: int = 0,
    command_injection: int = 0,
    firmware_outdated: int = 0,
    is_edge_device: int = 0,
    adversarial_detected: int = 0,
):
    """
    Explainable proof-of-concept risk scoring model.
    This is not a black-box model. It calculates risk using event context,
    IoT indicators, adversarial indicators, and recent alert activity.
    """

    features = extract_features(
        severity=severity,
        signature=signature,
        recent_alert_count=recent_alert_count,
        src_ip=src_ip,
        event_risk_score=event_risk_score,
        telemetry_spike=telemetry_spike,
        unexpected_protocol=unexpected_protocol,
        command_injection=command_injection,
        firmware_outdated=firmware_outdated,
        is_edge_device=is_edge_device,
        adversarial_detected=adversarial_detected,
    )

    # Base risk from severity
    risk = 0.10 + (severity * 0.08)

    # Include simulator/model risk if available
    risk += float(event_risk_score) * 0.20

    # Contextual risk indicators
    if features["is_external_ip"]:
        risk += 0.10
    if features["signature_sqlmap"]:
        risk += 0.15
    if features["signature_iot"]:
        risk += 0.05
    if features["signature_command_injection"]:
        risk += 0.12
    if telemetry_spike:
        risk += 0.08
    if unexpected_protocol:
        risk += 0.08
    if command_injection:
        risk += 0.12
    if firmware_outdated:
        risk += 0.08
    if is_edge_device:
        risk += 0.05
    if adversarial_detected:
        risk += 0.15

    # Repeated activity raises risk gradually
    risk += min(recent_alert_count, 10) * 0.02

    risk_score = round(min(risk, 0.99), 2)
    predicted_attack = risk_score >= 0.70

    return risk_score, predicted_attack, features
