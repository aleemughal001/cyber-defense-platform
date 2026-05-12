CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    src_ip VARCHAR(64),
    dest_ip VARCHAR(64),
    signature TEXT,
    severity INT,
    raw JSONB
);

CREATE TABLE IF NOT EXISTS predictions (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT NOW(),
    src_ip VARCHAR(64),
    risk_score NUMERIC(5,4),
    predicted_attack BOOLEAN,
    features JSONB
);

CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT NOW(),
    src_ip VARCHAR(64),
    action_taken VARCHAR(64),
    reason TEXT,
    policy_result JSONB
);
