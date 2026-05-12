import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Features:
# [severity, signature_sqlmap, recent_alert_count, is_external_ip]
X = np.array([
    [1, 0, 1, 0],
    [2, 0, 2, 0],
    [3, 0, 4, 1],
    [5, 1, 8, 1],
    [4, 1, 6, 1],
    [5, 1, 10, 1],
    [2, 0, 1, 1],
    [4, 0, 5, 1],
    [5, 1, 12, 1],
    [1, 0, 1, 1],
], dtype=float)

y = np.array([0, 0, 0, 1, 1, 1, 0, 1, 1, 0])

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

def is_external_ip(ip: str) -> int:
    private_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "192.168.", "127."
    )
    return 0 if ip.startswith(private_prefixes) else 1

def extract_features(severity: int, signature: str, recent_alert_count: int, src_ip: str):
    signature_sqlmap = 1 if "sqlmap" in signature.lower() else 0
    return np.array([[
        severity,
        signature_sqlmap,
        recent_alert_count,
        is_external_ip(src_ip)
    ]], dtype=float)

def predict_risk(severity: int, signature: str, recent_alert_count: int, src_ip: str):
    feats = extract_features(severity, signature, recent_alert_count, src_ip)
    risk = float(model.predict_proba(feats)[0][1])
    predicted_attack = bool(risk >= 0.70)

    return risk, predicted_attack, {
        "severity": severity,
        "signature_sqlmap": int(feats[0][1]),
        "recent_alert_count": recent_alert_count,
        "is_external_ip": int(feats[0][3]),
    }
