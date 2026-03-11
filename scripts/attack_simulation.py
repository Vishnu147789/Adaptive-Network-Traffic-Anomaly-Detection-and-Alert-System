from __future__ import annotations

import argparse

import pandas as pd

from traffic_simulator import TrafficSimulator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate simulated attack traffic for demos")
    parser.add_argument("--attack", choices=["http", "syn", "udp", "icmp", "mixed"], default="mixed")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--output", default="data/simulated_attack_traffic.csv")
    args = parser.parse_args()

    simulator = TrafficSimulator()
    if args.attack == "mixed":
        events = list(simulator.mixed_stream())
    else:
        events = list(simulator.attack_traffic(args.attack, args.count))

    rows = [
        {
            "time": event.timestamp.isoformat(sep=" ", timespec="milliseconds"),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "protocol": event.protocol,
            "destination_port": event.destination_port,
            "packet_length": event.packet_length,
            "attack_type": event.attack_type,
        }
        for event in events
    ]

    pd.DataFrame(rows).to_csv(args.output, index=False)
    print(f"Saved {len(rows)} simulated events to {args.output}")


if __name__ == "__main__":
    main()
