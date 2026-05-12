#!/usr/bin/env bash
set -e

echo "=============================="
echo "STEP 1: Starting platform"
echo "=============================="
docker compose up -d --build
sleep 5

echo
echo "=============================="
echo "STEP 2: Health and stats"
echo "=============================="
curl http://localhost:8000/health
echo
curl http://localhost:8000/stats
echo

echo
echo "=============================="
echo "STEP 3: Generate suspicious traffic"
echo "=============================="
chmod +x scripts/send-test-traffic.sh
./scripts/send-test-traffic.sh
sleep 5

echo
echo "=============================="
echo "STEP 4: Show recent alerts"
echo "=============================="
curl http://localhost:8000/recent-alerts
echo

echo
echo "=============================="
echo "STEP 5: Show recent predictions"
echo "=============================="
curl http://localhost:8000/recent-predictions
echo

echo
echo "=============================="
echo "STEP 6: Show adaptive policy decision"
echo "=============================="
curl -s -X POST http://localhost:8181/v1/data/cyberdefense \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "src_ip": "8.8.8.8",
      "signature": "LOCAL Suspicious User-Agent sqlmap",
      "risk_score": 0.95
    }
  }'
echo

echo
echo "=============================="
echo "STEP 7: Show autonomous responses"
echo "=============================="
curl http://localhost:8000/recent-responses
echo

echo
echo "=============================="
echo "STEP 8: Run scikit-learn forecast demo"
echo "=============================="
docker exec -it orchestrator python sklearn_forecast_demo.py

echo
echo "=============================="
echo "STEP 9: Run PQC / TLS demo"
echo "=============================="
chmod +x pqc/run-pqc-demo.sh
./pqc/run-pqc-demo.sh

echo
echo "=============================="
echo "STEP 10: Simulating IoT / Edge Threat"
echo "=============================="
curl -X POST http://localhost:8000/simulate-iot-threat
echo

echo "=============================="
echo "STEP 11: Platform Stats"
echo "=============================="
curl http://localhost:8000/stats
echo

echo "=============================="
echo "STEP 12: Recent Alerts"
echo "=============================="
curl http://localhost:8000/recent-alerts
echo

echo "=============================="
echo "STEP 13: Recent Responses"
echo "=============================="
curl http://localhost:8000/recent-responses
echo
