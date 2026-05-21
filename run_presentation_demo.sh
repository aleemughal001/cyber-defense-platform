#!/bin/bash

BASE_URL="http://localhost:8000"

echo "======================================"
echo " AUTONOMOUS CYBER DEFENSE DEMO"
echo "======================================"

echo ""
echo "[1] Health Check"
curl -s $BASE_URL/health
echo ""

echo ""
echo "[2] Current Platform Stats"
curl -s $BASE_URL/stats
echo ""

echo ""
echo "[3] Simulating IoT Threat"
curl -s -X POST $BASE_URL/simulate-iot-threat
echo ""

echo ""
echo "[4] Simulating Zero-Day Style Threat"
curl -s -X POST $BASE_URL/simulate-zero-day
echo ""

echo ""
echo "[5] Predictive Threat Forecast"
curl -s $BASE_URL/forecast-threats
echo ""

echo ""
echo "[6] Testing Adaptive OPA Policy"
curl -s -X POST $BASE_URL/test-policy \
-H "Content-Type: application/json" \
-d '{
  "signature": "sqlmap injection attempt",
  "risk_score": 0.91,
  "src_ip": "192.168.1.50",
  "is_edge_device": 0,
  "firmware_outdated": 0,
  "adversarial_detected": 0
}'
echo ""

echo ""
echo "[7] Self-Healing Simulation"
curl -s -X POST $BASE_URL/self-heal/suricata
echo ""

echo ""
echo "[8] Audit Ledger Verification"
curl -s $BASE_URL/audit/verify
echo ""

echo ""
echo "[9] Capability Mapping"
curl -s $BASE_URL/capability-map
echo ""

echo ""
echo "======================================"
echo " DEMO COMPLETED"
echo "======================================"
