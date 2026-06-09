import ipaddress
import math


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
    It calculates risk using event context, IoT indicators,
    adversarial indicators, and recent alert activity.
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

    # Balanced base risk from alert severity
    risk = 0.08 + (severity * 0.07)

    # Include simulator event risk without letting it dominate completely
    risk += float(event_risk_score) * 0.18

    # Contextual indicators
    if features["is_external_ip"]:
        risk += 0.08
    if features["signature_sqlmap"]:
        risk += 0.10
    if features["signature_iot"]:
        risk += 0.03
    if features["signature_command_injection"]:
        risk += 0.08
    if telemetry_spike:
        risk += 0.04
    if unexpected_protocol:
        risk += 0.05
    if command_injection:
        risk += 0.08
    if firmware_outdated:
        risk += 0.05
    if is_edge_device:
        risk += 0.03
    if adversarial_detected:
        risk += 0.10

    # Repeated activity increases risk, but slowly.
    # log1p prevents high alert counts from pushing every event to 0.99.
    risk += min(math.log1p(recent_alert_count) * 0.035, 0.15)

    risk_score = round(min(risk, 0.95), 2)
    predicted_attack = risk_score >= 0.70

    return risk_score, predicted_attack, features
