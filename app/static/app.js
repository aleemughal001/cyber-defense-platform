let threatChart = null;
let trendChart = null;
const AUTO_REFRESH_MS = 10000;

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    ...options
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${response.statusText} - ${text}`);
  }

  return response.json();
}

async function fetchFromCandidates(candidates) {
  let lastError = null;

  for (const candidate of candidates) {
    try {
      return await fetchJson(candidate.url, candidate.options || {});
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("All endpoint attempts failed.");
}

function formatValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getSeverityBadge(severity) {
  const sev = Number(severity);

  if (sev >= 4) return `<span class="badge badge-critical">Critical</span>`;
  if (sev === 3) return `<span class="badge badge-high">High</span>`;
  if (sev === 2) return `<span class="badge badge-medium">Medium</span>`;
  return `<span class="badge badge-low">Low</span>`;
}

function getRiskBadge(score) {
  const risk = Number(score);

  if (risk >= 0.9) return `<span class="badge badge-critical">Extreme</span>`;
  if (risk >= 0.7) return `<span class="badge badge-high">High</span>`;
  if (risk >= 0.4) return `<span class="badge badge-medium">Medium</span>`;
  return `<span class="badge badge-low">Low</span>`;
}

function getActionBadge(action) {
  const value = String(action || "").toLowerCase();

  if (value.includes("block")) {
    return `<span class="badge badge-critical">${escapeHtml(action)}</span>`;
  }
  if (value.includes("deceive")) {
    return `<span class="badge badge-high">${escapeHtml(action)}</span>`;
  }
  if (value.includes("observe")) {
    return `<span class="badge badge-medium">${escapeHtml(action || "observe")}</span>`;
  }
  return `<span class="badge badge-low">${escapeHtml(action || "unknown")}</span>`;
}

function renderCell(col, value) {
  if (col === "severity") {
    return `${escapeHtml(formatValue(value))}<br>${getSeverityBadge(value)}`;
  }

  if (col === "risk_score") {
    return `${escapeHtml(formatValue(value))}<br>${getRiskBadge(value)}`;
  }

  if (col === "action" || col === "action_taken" || col === "defense_mode") {
    return getActionBadge(value);
  }

  if (typeof value === "object" && value !== null) {
    return `<pre class="mini-json">${escapeHtml(JSON.stringify(value, null, 2))}</pre>`;
  }

  return escapeHtml(formatValue(value));
}

function renderTable(data, containerId, preferredColumns = []) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!Array.isArray(data) || data.length === 0) {
    container.innerHTML = `<p>No data available.</p>`;
    return;
  }

  const discoveredColumns = Object.keys(data[0] || {});
  const orderedColumns = [
    ...preferredColumns.filter((col) => discoveredColumns.includes(col)),
    ...discoveredColumns.filter((col) => !preferredColumns.includes(col))
  ];

  const thead = `
    <thead>
      <tr>
        ${orderedColumns.map((col) => `<th>${escapeHtml(col)}</th>`).join("")}
      </tr>
    </thead>
  `;

  const tbody = `
    <tbody>
      ${data.map((row) => `
        <tr>
          ${orderedColumns.map((col) => `<td>${renderCell(col, row[col])}</td>`).join("")}
        </tr>
      `).join("")}
    </tbody>
  `;

  container.innerHTML = `<table>${thead}${tbody}</table>`;
}

function updateLastRefreshTime() {
  const el = document.getElementById("last-refresh-time");
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString();
}

function updateSocStatus(stats = {}) {
  const textEl = document.getElementById("live-status-text");
  const dotEl = document.getElementById("live-status-dot");

  if (!textEl || !dotEl) return;

  const alerts = Number(stats.alerts || 0);
  const predictions = Number(stats.predictions || 0);
  const responses = Number(stats.responses || 0);

  dotEl.className = "status-dot";

  if (alerts >= 10 || responses >= 10) {
    textEl.textContent = "SOC Status: High Threat Activity";
    dotEl.classList.add("status-critical");
    return;
  }

  if (alerts >= 5 || predictions >= 5) {
    textEl.textContent = "SOC Status: Elevated Monitoring";
    dotEl.classList.add("status-warning");
    return;
  }

  textEl.textContent = "SOC Status: Monitoring";
  dotEl.classList.add("status-normal");
}

function countBy(items, keyFn) {
  const counts = {};
  for (const item of items) {
    const key = keyFn(item);
    if (!key) continue;
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function findTopKey(counts) {
  let topKey = "--";
  let topValue = -1;

  for (const [key, value] of Object.entries(counts)) {
    if (value > topValue) {
      topKey = key;
      topValue = value;
    }
  }

  return topKey;
}

async function updateIncidentSummary() {
  try {
    const alerts = await fetchJson(`/recent-alerts?_=${Date.now()}`);
    const responses = await fetchJson(`/recent-responses?_=${Date.now()}`);

    const threatLevelEl = document.getElementById("threat-level");
    const incidentsEl = document.getElementById("active-incidents");
    const blockedEl = document.getElementById("blocked-events");
    const tickerEl = document.getElementById("threat-ticker");

    const alertCount = Array.isArray(alerts) ? alerts.length : 0;
    const blockedCount = Array.isArray(responses)
      ? responses.filter((r) =>
          String(r.action_taken || r.action || "").toLowerCase().includes("block")
        ).length
      : 0;

    if (incidentsEl) incidentsEl.textContent = alertCount;
    if (blockedEl) blockedEl.textContent = blockedCount;

    if (threatLevelEl) {
    threatLevelEl.classList.remove("threat-low", "threat-medium", "threat-high");

    if (alertCount >= 10) {
      threatLevelEl.textContent = "HIGH";
      threatLevelEl.classList.add("threat-high");
   } else if (alertCount >= 5) {
     threatLevelEl.textContent = "MEDIUM";
     threatLevelEl.classList.add("threat-medium");
   } else {
     threatLevelEl.textContent = "LOW";
     threatLevelEl.classList.add("threat-low");
  }
}
    if (tickerEl) {
      if (Array.isArray(alerts) && alerts.length > 0) {
        const latest = alerts[0];
        tickerEl.textContent = `Latest Threat: ${latest.signature || "Unknown signature"} | Source IP: ${latest.src_ip || "unknown"} | Severity: ${latest.severity || "n/a"}`;
      } else {
        tickerEl.textContent = "Monitoring network activity...";
      }
    }
  } catch (error) {
    console.error("Error updating incident summary:", error);
  }
}

async function updateAnalystSummary() {
  try {
    const [alerts, predictions, responses] = await Promise.all([
      fetchJson(`/recent-alerts?_=${Date.now()}`),
      fetchJson(`/recent-predictions?_=${Date.now()}`),
      fetchJson(`/recent-responses?_=${Date.now()}`)
    ]);

    const topSrcIpEl = document.getElementById("top-src-ip");
    const topSignatureEl = document.getElementById("top-signature");
    const highestRiskEl = document.getElementById("highest-risk");
    const latestResponseEl = document.getElementById("latest-response");

    const srcCounts = countBy(Array.isArray(alerts) ? alerts : [], (item) => item.src_ip);
    const sigCounts = countBy(Array.isArray(alerts) ? alerts : [], (item) => item.signature);

    const topSrcIp = findTopKey(srcCounts);
    const topSignature = findTopKey(sigCounts);

    let highestRisk = 0;
    if (Array.isArray(predictions)) {
      for (const item of predictions) {
        const risk = Number(item.risk_score || 0);
        if (risk > highestRisk) highestRisk = risk;
      }
    }

    let latestResponse = "--";
    if (Array.isArray(responses) && responses.length > 0) {
      latestResponse =
        responses[0].action_taken ||
        responses[0].action ||
        responses[0].defense_mode ||
        "--";
    }

    if (topSrcIpEl) topSrcIpEl.textContent = topSrcIp;
    if (topSignatureEl) topSignatureEl.textContent = topSignature;
    if (highestRiskEl) highestRiskEl.textContent = highestRisk.toFixed(2);
    if (latestResponseEl) latestResponseEl.textContent = latestResponse;
  } catch (error) {
    console.error("Error updating analyst summary:", error);
  }
}

async function loadOverview() {
  try {
    const healthData = await fetchJson(`/health?_=${Date.now()}`);
    const statsData = await fetchJson(`/stats?_=${Date.now()}`);

    const healthEl = document.getElementById("health-status");
    const alertsEl = document.getElementById("alerts-count");
    const predictionsEl = document.getElementById("predictions-count");
    const responsesEl = document.getElementById("responses-count");

    if (healthEl) healthEl.textContent = healthData.status || "unknown";
    if (alertsEl) alertsEl.textContent = statsData.alerts ?? 0;
    if (predictionsEl) predictionsEl.textContent = statsData.predictions ?? 0;
    if (responsesEl) responsesEl.textContent = statsData.responses ?? 0;

    updateSocStatus(statsData);
  } catch (error) {
    console.error("Error loading overview:", error);
    const healthEl = document.getElementById("health-status");
    if (healthEl) healthEl.textContent = "error";
  }
}

async function loadAlerts() {
  try {
    const alerts = await fetchJson(`/recent-alerts?_=${Date.now()}`);
    renderTable(
      alerts,
      "alerts-table-container",
      ["id", "created_at", "timestamp", "src_ip", "dest_ip", "severity", "signature"]
    );
  } catch (error) {
    console.error("Error loading alerts:", error);
    const container = document.getElementById("alerts-table-container");
    if (container) container.innerHTML = `<p>Failed to load alerts.</p>`;
  }
}

async function loadPredictions() {
  try {
    const predictions = await fetchJson(`/recent-predictions?_=${Date.now()}`);
    renderTable(
      predictions,
      "predictions-table-container",
      ["id", "created_at", "src_ip", "risk_score", "predicted_attack", "features"]
    );
  } catch (error) {
    console.error("Error loading predictions:", error);
    const container = document.getElementById("predictions-table-container");
    if (container) container.innerHTML = `<p>Failed to load predictions.</p>`;
  }
}

async function loadResponses() {
  try {
    const responses = await fetchJson(`/recent-responses?_=${Date.now()}`);
    renderTable(
      responses,
      "responses-table-container",
      ["id", "created_at", "src_ip", "action", "action_taken", "defense_mode", "reason"]
    );
  } catch (error) {
    console.error("Error loading responses:", error);
    const container = document.getElementById("responses-table-container");
    if (container) container.innerHTML = `<p>Failed to load responses.</p>`;
  }
}

async function loadThreatChart() {
  try {
    const alerts = await fetchJson(`/recent-alerts?_=${Date.now()}`);

    const recentAlerts = Array.isArray(alerts) ? alerts.slice(0, 10).reverse() : [];

    const labels = recentAlerts.map((item, index) => {
      const time = item.created_at || item.timestamp || `Alert ${index + 1}`;
      return String(time).slice(11, 19);
    });

    const values = recentAlerts.map((item) =>
      Number(item.risk_score || item.severity || 0)
    );

    const canvas = document.getElementById("threatChart");
    if (!canvas || typeof Chart === "undefined") return;

    const ctx = canvas.getContext("2d");

    if (threatChart) {
      threatChart.destroy();
      threatChart = null;
    }

    threatChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: "Live Threat Activity",
            data: values,
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: {
            labels: { color: "#e5e7eb" }
          }
        },
        scales: {
          x: {
            ticks: { color: "#e5e7eb" },
            grid: { color: "rgba(255,255,255,0.08)" }
          },
          y: {
            beginAtZero: true,
            suggestedMax: 5,
            ticks: { color: "#e5e7eb" },
            grid: { color: "rgba(255,255,255,0.08)" }
          }
        }
      }
    });

    console.log("Threat chart updated with live alerts:", values);
  } catch (error) {
    console.error("Error loading threat chart:", error);
  }
}

async function loadTrendChart() {
  try {
    const [alerts, predictions] = await Promise.all([
      fetchJson(`/recent-alerts?_=${Date.now()}`),
      fetchJson(`/recent-predictions?_=${Date.now()}`)
    ]);

    const reversedAlerts = Array.isArray(alerts) ? alerts.slice().reverse() : [];
    const reversedPredictions = Array.isArray(predictions) ? predictions.slice().reverse() : [];

    const labels = reversedAlerts.length > 0
      ? reversedAlerts.map((item, index) => {
          const rawTime = item.created_at || item.timestamp || `Event ${index + 1}`;
          return String(rawTime).slice(11, 19) || `Event ${index + 1}`;
        })
      : reversedPredictions.map((_, index) => `Point ${index + 1}`);

    const alertSeverityValues = reversedAlerts.map((item) => Number(item.severity || 0));
    const predictionRiskValues = reversedPredictions.map((item) =>
      Number((Number(item.risk_score || 0) * 4).toFixed(2))
    );

    const alignedPredictionValues = labels.map((_, index) =>
      predictionRiskValues[index] !== undefined ? predictionRiskValues[index] : null
    );

    const canvas = document.getElementById("trendChart");
    if (!canvas || typeof Chart === "undefined") return;

    const ctx = canvas.getContext("2d");

    if (trendChart) {
      trendChart.destroy();
      trendChart = null;
    }

    trendChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Alert Severity Trend",
            data: alertSeverityValues,
            tension: 0.35,
            fill: false
          },
          {
            label: "Predicted Risk Trend (scaled)",
            data: alignedPredictionValues,
            tension: 0.35,
            fill: false
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: "#e5e7eb" }
          }
        },
        scales: {
          x: {
            ticks: { color: "#e5e7eb" },
            grid: { color: "rgba(255,255,255,0.08)" }
          },
          y: {
            beginAtZero: true,
            ticks: { color: "#e5e7eb" },
            grid: { color: "rgba(255,255,255,0.08)" }
          }
        }
      }
    });
  } catch (error) {
    console.error("Error loading trend chart:", error);
  }
}

async function simulateIoTThreat() {
  const resultEl = document.getElementById("iot-result");
  if (resultEl) resultEl.textContent = "Running simulation...";

  try {
    const data = await fetchFromCandidates([
      {
        url: "/simulate-iot-threat",
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" }
        }
      },
      {
        url: "/simulate-iot",
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" }
        }
      }
    ]);

    if (resultEl) resultEl.textContent = JSON.stringify(data, null, 2);
    await refreshDashboard();
  } catch (error) {
    console.error("Error simulating IoT threat:", error);
    if (resultEl) resultEl.textContent = `Simulation failed: ${error.message}`;
  }
}

async function selfHeal(service) {
  const resultEl = document.getElementById("self-heal-result");
  if (resultEl) resultEl.textContent = `Attempting self-heal for ${service}...`;

  try {
    const data = await fetchFromCandidates([
      {
        url: `/self-heal/${encodeURIComponent(service)}`,
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" }
        }
      },
      {
        url: "/self-heal",
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ service })
        }
      }
    ]);

    if (resultEl) resultEl.textContent = JSON.stringify(data, null, 2);
    await refreshDashboard();
  } catch (error) {
    console.error("Error during self-heal:", error);
    if (resultEl) resultEl.textContent = `Self-heal failed: ${error.message}`;
  }
}

async function testPolicy() {
  const signatureEl = document.getElementById("policy-signature");
  const riskEl = document.getElementById("policy-risk");
  const resultEl = document.getElementById("policy-result");

  const signature = signatureEl ? signatureEl.value.trim() : "";
  const riskScore = riskEl && riskEl.value !== "" ? Number(riskEl.value) : 0;

  const payload = {
    signature,
    risk_score: riskScore,
    src_ip: "192.168.1.50"
  };

  if (resultEl) resultEl.textContent = "Testing policy...";

  try {
    const data = await fetchFromCandidates([
      {
        url: "/test-policy",
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }
      },
      {
        url: "/policy-test",
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }
      },
      {
        url: "/policy/evaluate",
        options: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }
      }
    ]);

    if (resultEl) resultEl.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    console.error("Error testing policy:", error);
    if (resultEl) resultEl.textContent = `Policy test failed: ${error.message}`;
  }
}

async function refreshDashboard() {
  await Promise.allSettled([
    loadOverview(),
    loadAlerts(),
    loadPredictions(),
    loadResponses(),
    loadThreatChart(),
    loadTrendChart(),
    updateIncidentSummary(),
    updateAnalystSummary()
  ]);

  updateLastRefreshTime();
}

document.addEventListener("DOMContentLoaded", () => {
  refreshDashboard();
  setInterval(refreshDashboard, AUTO_REFRESH_MS);
});

async function runZeroDaySimulation() {
  const output = document.getElementById("zeroDayOutput");
  output.textContent = "Running zero-day simulation...";

  try {
    const response = await fetch("/simulate-zero-day", {
      method: "POST",
      cache: "no-store"
    });
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error running zero-day simulation: " + error;
  }
}

async function loadThreatForecast() {
  const output = document.getElementById("forecastOutput");
  output.textContent = "Loading threat forecast...";

  try {
    const response = await fetch("/forecast-threats", {
      cache: "no-store"
    });
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error loading threat forecast: " + error;
  }
}

async function verifyAuditChain() {
  const output = document.getElementById("auditOutput");
  output.textContent = "Verifying audit chain...";

  try {
    const response = await fetch("/audit/verify", {
      cache: "no-store"
    });
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error verifying audit chain: " + error;
  }
}

async function runSelfHealing() {
  const output = document.getElementById("selfHealOutput");
  output.textContent = "Running self-healing workflow...";

  try {
    const response = await fetch("/self-heal/suricata", {
      method: "POST",
      cache: "no-store"
    });
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error running self-healing: " + error;
  }
}

async function loadCapabilityMap() {
  const output = document.getElementById("capabilityOutput");
  output.textContent = "Loading capability map...";

  try {
    const response = await fetch("/capability-map", {
      cache: "no-store"
    });
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error loading capability map: " + error;
  }
}

window.runZeroDaySimulation = runZeroDaySimulation;
window.loadThreatForecast = loadThreatForecast;
window.verifyAuditChain = verifyAuditChain;
window.runSelfHealing = runSelfHealing;
window.loadCapabilityMap = loadCapabilityMap;

async function runMlForecast() {
  const output = document.getElementById("mlForecastOutput");
  if (!output) return;

  output.textContent = "Running ML forecast...";

  try {
    const response = await fetch("/ml-forecast");
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error running ML forecast: " + error;
  }
}

async function runMlForecast() {
  const output = document.getElementById("mlForecastOutput");
  if (!output) return;

  output.textContent = "Running ML forecast...";

  try {
    const response = await fetch("/ml-forecast");
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Error running ML forecast: " + error;
  }
}
