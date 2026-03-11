from __future__ import annotations

from pathlib import Path


DATA_PATH = Path("data/cicids2017_cleaned.csv")
MODELS_DIR = Path("models")
ALERTS_PATH = Path("alerts.csv")
BLOCKLIST_PATH = MODELS_DIR / "blocked_ips.json"
FEATURE_METADATA_PATH = MODELS_DIR / "feature_columns.json"

# Runtime-friendly feature subset that we can estimate from packet/flow data and
# also train from the CICIDS-style dataset.
RUNTIME_FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "Idle Mean",
    "Idle Max",
    "Idle Min",
]

LABEL_COLUMN = "Attack Type"
DEFAULT_INTERFACE = "Wi-Fi"
DEFAULT_ALERT_THRESHOLD = 0.45
