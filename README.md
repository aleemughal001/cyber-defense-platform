# Autonomous Cyber Defense Platform

This project is a proof-of-concept autonomous cyber defense platform designed for EduQual Level 6 assessment. It demonstrates threat detection, predictive risk scoring, adaptive policy decisions, autonomous response, self-healing simulation, post-quantum cryptography awareness, and audit logging.

## Main Components

- **FastAPI Orchestrator**: Main backend service that receives events, evaluates risk, communicates with OPA, stores results, and exposes API endpoints.
- **Suricata IDS**: Represents the intrusion detection layer.
- **OPA/Rego Policy Engine**: Applies adaptive security policies and selects response actions.
- **PostgreSQL**: Stores alerts, predictions, and responses.
- **Redis**: Supports fast state/cache handling.
- **Blockchain Audit Simulation**: Demonstrates tamper-evident audit logging.
- **PQC Demo**: Demonstrates post-quantum cryptography awareness using Open Quantum Safe concepts.
- **Dashboard**: Displays alerts, predictions, responses, and threat activity.

## Project Structure

```text
app/          FastAPI application, ML/risk logic, response engine, dashboard
db/init/      PostgreSQL schema initialization
policy/       OPA/Rego adaptive defense policy
pqc/          Post-quantum cryptography demo script
scripts/      Test traffic/demo scripts
suricata/     Suricata configuration and local rules
