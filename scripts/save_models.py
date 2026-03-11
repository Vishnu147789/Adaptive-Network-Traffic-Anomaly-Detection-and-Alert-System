from __future__ import annotations

import json

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from runtime_features import (
    DATA_PATH,
    FEATURE_METADATA_PATH,
    LABEL_COLUMN,
    MODELS_DIR,
    RUNTIME_FEATURE_COLUMNS,
)


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(DATA_PATH)
    required_columns = RUNTIME_FEATURE_COLUMNS + [LABEL_COLUMN]
    missing = [column for column in required_columns if column not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    model_df = df[required_columns].dropna()
    X = model_df[RUNTIME_FEATURE_COLUMNS]
    y = model_df[LABEL_COLUMN]

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    rf_model = RandomForestClassifier(
        n_estimators=150,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
    )
    rf_model.fit(X_train, y_train)

    iso_model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
    )
    iso_model.fit(X_train)

    joblib.dump(rf_model, MODELS_DIR / "random_forest.pkl")
    joblib.dump(iso_model, MODELS_DIR / "isolation_forest.pkl")
    joblib.dump(encoder, MODELS_DIR / "label_encoder.pkl")

    FEATURE_METADATA_PATH.write_text(json.dumps(RUNTIME_FEATURE_COLUMNS, indent=2))

    accuracy = rf_model.score(X_test, y_test)
    print("Models saved successfully")
    print(f"Feature subset size: {len(RUNTIME_FEATURE_COLUMNS)}")
    print(f"Random Forest validation accuracy: {accuracy:.4f}")
    print(f"Classes: {list(encoder.classes_)}")


if __name__ == "__main__":
    main()
