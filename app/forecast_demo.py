import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor

df = pd.DataFrame({
    "count_t-3": [2, 3, 4, 7, 8, 5, 3, 9],
    "count_t-2": [3, 4, 7, 8, 5, 3, 9, 10],
    "count_t-1": [4, 7, 8, 5, 3, 9, 10, 12],
    "next_count": [7, 8, 5, 3, 9, 10, 12, 14]
})

X = df[["count_t-3", "count_t-2", "count_t-1"]]
y = df["next_count"]

model = RandomForestRegressor(n_estimators=100, random_state=42)
model.fit(X, y)

sample = pd.DataFrame([{
    "count_t-3": 8,
    "count_t-2": 10,
    "count_t-1": 12
}])
forecast = model.predict(sample)[0]

print(f"Predicted next 5-minute alert count: {forecast:.2f}")
