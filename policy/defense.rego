package cyberdefense

default allow_block = false
default defense_mode = "observe"

high_risk if {
    input.risk_score >= 0.70
}

very_high_risk if {
    input.risk_score >= 0.90
}

suspicious_signature if {
    contains(lower(input.signature), "sqlmap")
}

suspicious_signature if {
    contains(lower(input.signature), "injection")
}

iot_critical if {
    input.is_edge_device == 1
    input.firmware_outdated == 1
}

adversarial_ml if {
    input.adversarial_detected == 1
}

allow_block if {
    high_risk
}

allow_block if {
    iot_critical
}

defense_mode := "quarantine_model_input" if {
    adversarial_ml
}

defense_mode := "isolate" if {
    not adversarial_ml
    iot_critical
}

defense_mode := "deceive" if {
    not adversarial_ml
    not iot_critical
    very_high_risk
}

defense_mode := "block" if {
    not adversarial_ml
    not iot_critical
    not very_high_risk
    high_risk
}
