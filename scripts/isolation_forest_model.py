import pandas as pd
from sklearn.ensemble import IsolationForest

# Load dataset
df = pd.read_csv("data/cicids2017_cleaned.csv")

# Separate features
X = df.drop("Attack Type", axis=1)

print("Training Isolation Forest...")

model = IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42
)

model.fit(X)

print("Isolation Forest Training Complete")

# Predict anomalies
predictions = model.predict(X)

# -1 = anomaly, 1 = normal
df["Anomaly"] = predictions

print("\nAnomaly Detection Results:")
print(df["Anomaly"].value_counts())
