import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest

# Load dataset
df = pd.read_csv("data/cicids2017_cleaned.csv")

X = df.drop("Attack Type", axis=1)
y = df["Attack Type"]

encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42
)

# Train Random Forest
rf_model = RandomForestClassifier(n_estimators=100, n_jobs=-1)
rf_model.fit(X_train, y_train)

# Train Isolation Forest
iso_model = IsolationForest(contamination=0.02)
iso_model.fit(X)

# Save models
joblib.dump(rf_model, "models/random_forest.pkl")
joblib.dump(iso_model, "models/isolation_forest.pkl")
joblib.dump(encoder, "models/label_encoder.pkl")

print("Models saved successfully")