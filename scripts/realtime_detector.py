from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev
from typing import Iterable

import joblib
import pandas as pd

from defense_mitigation import MitigationEngine
from runtime_features import ALERTS_PATH, DEFAULT_INTERFACE, FEATURE_METADATA_PATH, MODELS_DIR, RUNTIME_FEATURE_COLUMNS
from traffic_simulator import ATTACK_TYPES, PacketEvent, TrafficSimulator

MIN_PACKETS_FOR_DECISION = 3
BASELINE_FLOW_WINDOW_SECONDS = 1.0
CRITICAL_ATTACK_LABELS = {ATTACK_TYPES["http"], ATTACK_TYPES["syn"], ATTACK_TYPES["udp"], ATTACK_TYPES["icmp"]}
LIVE_BENIGN_BURST_PROTOCOLS = {"QUIC", "TLS", "DNS", "MDNS", "SSDP", "DATA"}
LIVE_BENIGN_PORTS = {53, 80, 137, 1900, 443, 5353}


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    protocol: str
    destination_port: int
    first_seen: datetime
    last_seen: datetime
    packet_lengths: list[int] = field(default_factory=list)
    inter_arrivals: list[float] = field(default_factory=list)

    def add(self, event: PacketEvent) -> None:
        gap = (event.timestamp - self.last_seen).total_seconds()
        if gap > 0:
            self.inter_arrivals.append(gap)
        self.last_seen = event.timestamp
        self.packet_lengths.append(event.packet_length)

    @property
    def packet_count(self) -> int:
        return len(self.packet_lengths)

    def to_feature_row(self) -> dict[str, float]:
        observed_duration = max((self.last_seen - self.first_seen).total_seconds(), 0.0)
        effective_duration = max(observed_duration, BASELINE_FLOW_WINDOW_SECONDS)
        packets = len(self.packet_lengths)
        total_length = sum(self.packet_lengths)
        packet_mean = total_length / packets
        packet_std = pstdev(self.packet_lengths) if packets > 1 else 0.0
        idle_mean = mean(self.inter_arrivals) if self.inter_arrivals else effective_duration
        idle_max = max(self.inter_arrivals) if self.inter_arrivals else effective_duration
        idle_min = min(self.inter_arrivals) if self.inter_arrivals else effective_duration

        return {
            "Destination Port": float(self.destination_port),
            "Flow Duration": effective_duration,
            "Total Fwd Packets": float(packets),
            "Total Length of Fwd Packets": float(total_length),
            "Fwd Packet Length Max": float(max(self.packet_lengths)),
            "Fwd Packet Length Min": float(min(self.packet_lengths)),
            "Fwd Packet Length Mean": float(packet_mean),
            "Fwd Packet Length Std": float(packet_std),
            "Flow Bytes/s": float(total_length / effective_duration),
            "Flow Packets/s": float(packets / effective_duration),
            "Min Packet Length": float(min(self.packet_lengths)),
            "Max Packet Length": float(max(self.packet_lengths)),
            "Packet Length Mean": float(packet_mean),
            "Packet Length Std": float(packet_std),
            "Packet Length Variance": float(packet_std**2),
            "Average Packet Size": float(packet_mean),
            "Idle Mean": float(idle_mean),
            "Idle Max": float(idle_max),
            "Idle Min": float(idle_min),
        }


def load_feature_columns() -> list[str]:
    if FEATURE_METADATA_PATH.exists():
        try:
            columns = json.loads(FEATURE_METADATA_PATH.read_text())
            if isinstance(columns, list) and columns:
                return columns
        except json.JSONDecodeError:
            pass
    return RUNTIME_FEATURE_COLUMNS


def ensure_alerts_header(path: Path, reset: bool = False) -> None:
    if reset and path.exists():
        path.unlink()
    if path.exists() and path.stat().st_size > 0:
        return
    header = pd.DataFrame(
        columns=[
            "time",
            "src_ip",
            "dst_ip",
            "protocol",
            "destination_port",
            "packet_length",
            "packets_per_second",
            "bytes_per_second",
            "traffic_type",
            "anomaly",
            "anomaly_score",
            "network_status",
            "mitigation_action",
            "decision_reason",
            "source_mode",
            "flow_packets",
        ]
    )
    header.to_csv(path, index=False)


def decide_status(
    anomaly: int,
    traffic_type: str,
    packets_per_second: float,
    flow_packets: int,
    mode: str,
    protocol: str,
    destination_port: int,
    anomaly_score: float,
) -> tuple[str, str]:
    suspicious_label = traffic_type != ATTACK_TYPES["normal"]
    critical_attack = traffic_type in CRITICAL_ATTACK_LABELS
    live_benign_flow = (
        mode == "live"
        and protocol in LIVE_BENIGN_BURST_PROTOCOLS
        and destination_port in LIVE_BENIGN_PORTS
    )
    if flow_packets < MIN_PACKETS_FOR_DECISION:
        return "NORMAL", "Collecting enough packets to score this flow"
    if critical_attack and packets_per_second >= 3:
        return "CRITICAL", "Attack-classified flow exceeded escalation threshold"
    if live_benign_flow and not suspicious_label and anomaly == -1:
        if flow_packets < 8 and packets_per_second < 8 and anomaly_score > -0.08:
            return "NORMAL", "Short encrypted burst matched expected live traffic"
    if anomaly == -1 and (suspicious_label or packets_per_second >= 20):
        return "CRITICAL", "Anomalous burst traffic matched attack indicators"
    if live_benign_flow and not suspicious_label:
        if anomaly == -1 and packets_per_second >= 12 and anomaly_score <= -0.08:
            return "WARNING", "Sustained encrypted burst exceeded live baseline"
        return "NORMAL", "Traffic is within the live baseline"
    if anomaly == -1 or suspicious_label or packets_per_second >= 12:
        return "WARNING", "Traffic pattern exceeded baseline thresholds"
    return "NORMAL", "Traffic is within the learned baseline"


def load_models() -> tuple[object | None, object | None, object | None]:
    try:
        rf_model = joblib.load(MODELS_DIR / "random_forest.pkl")
        iso_model = joblib.load(MODELS_DIR / "isolation_forest.pkl")
        encoder = joblib.load(MODELS_DIR / "label_encoder.pkl")
        return rf_model, iso_model, encoder
    except FileNotFoundError:
        return None, None, None


def detect_with_models(
    feature_frame: pd.DataFrame,
    flow_packets: int,
    attack_hint: str,
    rf_model: object | None,
    iso_model: object | None,
    encoder: object | None,
    mode: str,
    protocol: str,
    destination_port: int,
) -> tuple[int, float, str]:
    if flow_packets < MIN_PACKETS_FOR_DECISION:
        return 1, 0.0, ATTACK_TYPES["normal"]

    if rf_model is None or iso_model is None or encoder is None:
        packets_per_second = float(feature_frame.iloc[0].get("Flow Packets/s", 0.0))
        if attack_hint != ATTACK_TYPES["normal"] or packets_per_second >= 20:
            return -1, -0.6, attack_hint
        if packets_per_second >= 12:
            return -1, -0.2, "Suspicious Traffic"
        return 1, 0.3, ATTACK_TYPES["normal"]

    anomaly = int(iso_model.predict(feature_frame)[0])
    anomaly_score = float(iso_model.decision_function(feature_frame)[0])
    attack_index = int(rf_model.predict(feature_frame)[0])
    traffic_type = encoder.inverse_transform([attack_index])[0]
    live_benign_flow = (
        mode == "live"
        and protocol in LIVE_BENIGN_BURST_PROTOCOLS
        and destination_port in LIVE_BENIGN_PORTS
    )

    if attack_hint != ATTACK_TYPES["normal"]:
        if traffic_type == ATTACK_TYPES["normal"]:
            traffic_type = attack_hint
        if anomaly != -1 and attack_hint in CRITICAL_ATTACK_LABELS:
            anomaly = -1
            anomaly_score = min(anomaly_score, -0.05)
    elif traffic_type != ATTACK_TYPES["normal"] and anomaly != -1:
        traffic_type = ATTACK_TYPES["normal"]
    elif live_benign_flow and traffic_type == ATTACK_TYPES["normal"] and anomaly == -1:
        packets_per_second = float(feature_frame.iloc[0].get("Flow Packets/s", 0.0))
        if flow_packets < 8 and packets_per_second < 8 and anomaly_score > -0.08:
            anomaly = 1
            anomaly_score = abs(anomaly_score)

    return anomaly, anomaly_score, traffic_type


def packet_event_from_live_packet(packet) -> PacketEvent | None:
    if not hasattr(packet, "ip"):
        return None
    protocol = getattr(packet, "highest_layer", "UNKNOWN")
    try:
        destination_port = int(getattr(packet, "tcp", getattr(packet, "udp", object())).dstport)
    except Exception:
        destination_port = 0

    return PacketEvent(
        timestamp=datetime.now(),
        src_ip=getattr(packet.ip, "src", "unknown"),
        dst_ip=getattr(packet.ip, "dst", "unknown"),
        protocol=protocol,
        destination_port=destination_port,
        packet_length=int(getattr(packet, "length", 0)),
        attack_type=ATTACK_TYPES["normal"],
    )


def iter_live_packets(interface: str) -> Iterable[PacketEvent]:
    import pyshark

    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        event = packet_event_from_live_packet(packet)
        if event is not None:
            yield event


def iter_simulated_packets() -> Iterable[PacketEvent]:
    simulator = TrafficSimulator()
    yield from simulator.mixed_stream()


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-time network anomaly detector")
    parser.add_argument("--mode", choices=["simulate", "live"], default="simulate")
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--reset-alerts", action="store_true")
    args = parser.parse_args()

    feature_columns = load_feature_columns()
    rf_model, iso_model, encoder = load_models()
    mitigation = MitigationEngine()
    ensure_alerts_header(ALERTS_PATH, reset=args.reset_alerts)

    flow_states: dict[tuple[str, str, int, str], FlowState] = {}
    events = iter_simulated_packets() if args.mode == "simulate" else iter_live_packets(args.interface)

    print(f"Starting detector in {args.mode} mode")

    for index, event in enumerate(events, start=1):
        if index > args.limit:
            break
        if mitigation.is_blocked(event.src_ip):
            continue

        key = (event.src_ip, event.dst_ip, event.destination_port, event.protocol)
        if key not in flow_states:
            flow_states[key] = FlowState(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                protocol=event.protocol,
                destination_port=event.destination_port,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                packet_lengths=[event.packet_length],
            )
        else:
            flow_states[key].add(event)

        flow_state = flow_states[key]
        feature_row = flow_state.to_feature_row()
        feature_frame = pd.DataFrame([[feature_row[column] for column in feature_columns]], columns=feature_columns)
        anomaly, anomaly_score, traffic_type = detect_with_models(
            feature_frame,
            flow_state.packet_count,
            event.attack_type,
            rf_model,
            iso_model,
            encoder,
            args.mode,
            event.protocol,
            event.destination_port,
        )
        packets_per_second = feature_row["Flow Packets/s"]
        bytes_per_second = feature_row["Flow Bytes/s"]
        network_status, decision_reason = decide_status(
            anomaly,
            traffic_type,
            packets_per_second,
            flow_state.packet_count,
            args.mode,
            event.protocol,
            event.destination_port,
            anomaly_score,
        )

        mitigation_action = "NONE"
        if network_status == "CRITICAL" and mitigation.block_ip(event.src_ip):
            mitigation_action = "BLOCKED_SOURCE_IP"

        anomaly_label = "YES" if anomaly == -1 else "NO"
        alert_row = {
            "time": event.timestamp.isoformat(sep=" ", timespec="milliseconds"),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "protocol": event.protocol,
            "destination_port": event.destination_port,
            "packet_length": event.packet_length,
            "packets_per_second": round(packets_per_second, 3),
            "bytes_per_second": round(bytes_per_second, 3),
            "traffic_type": traffic_type,
            "anomaly": anomaly_label,
            "anomaly_score": round(anomaly_score, 6),
            "network_status": network_status,
            "mitigation_action": mitigation_action,
            "decision_reason": decision_reason,
            "source_mode": args.mode,
            "flow_packets": flow_state.packet_count,
        }

        pd.DataFrame([alert_row]).to_csv(ALERTS_PATH, mode="a", header=False, index=False)
        print(alert_row)


if __name__ == "__main__":
    main()
