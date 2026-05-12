import numpy as np
from sklearn.ensemble import RandomForestRegressor

# Simulated historical alert counts over time
alert_counts = np.array([
    3, 4, 5, 4, 6, 7, 8, 10, 9, 11,
    12, 13, 15, 14, 16, 18, 19, 21, 20, 22,
    24, 25, 27, 29, 28, 30, 31, 33, 35, 36
], dtype=float)

WINDOW = 5

X = []
y = []

for i in range(len(alert_counts) - WINDOW):
    X.append(alert_counts[i:i+WINDOW])
    y.append(alert_counts[i+WINDOW])

X = np.array(X)
y = np.array(y)

model = RandomForestRegressor(n_estimators=100, random_state=42)
model.fit(X, y)

last_window = alert_counts[-WINDOW:].reshape(1, -1)
prediction = model.predict(last_window)[0]

print("=== Scikit-learn Forecast Demo ===")
print(f"Last observed alert counts: {alert_counts[-WINDOW:].tolist()}")
print(f"Predicted next alert count: {prediction:.2f}")
