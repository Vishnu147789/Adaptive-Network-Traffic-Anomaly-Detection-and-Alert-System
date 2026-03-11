import pyshark
import pandas as pd
import joblib
from datetime import datetime
import random

print("Loading models...")

rf_model = joblib.load("models/random_forest.pkl")
iso_model = joblib.load("models/isolation_forest.pkl")
encoder = joblib.load("models/label_encoder.pkl")

print("Models loaded successfully")

capture = pyshark.LiveCapture(interface="Wi-Fi")

print("Starting Real-Time IDS Monitoring...")

while True:

    for packet in capture.sniff_continuously(packet_count=1):

        try:

            packet_length = int(packet.length)

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            features = pd.DataFrame([[packet_length]*52])

            anomaly = iso_model.predict(features)[0]

            anomaly_score = float(iso_model.decision_function(features)[0])

            attack = rf_model.predict(features)[0]
            attack_name = encoder.inverse_transform([attack])[0]

            if anomaly == -1:
                anomaly_status = "YES"
                print("⚠️ Anomaly Detected")
            else:
                anomaly_status = "NO"

            log = {
                "time": datetime.now(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "packet_length": packet_length,
                "traffic_type": attack_name,
                "anomaly": anomaly_status,
                "anomaly_score": anomaly_score
            }

            df = pd.DataFrame([log])

            df.to_csv("alerts.csv", mode="a", header=False, index=False)

            print(log)

        except:
            pass