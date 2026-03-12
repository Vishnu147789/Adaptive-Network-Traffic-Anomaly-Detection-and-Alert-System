from __future__ import annotations

import argparse
import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterator

from traffic_simulator import ATTACK_TYPES, PacketEvent, TrafficSimulator


@dataclass
class AttackScenario:
    """Configuration for an attack scenario."""
    name: str
    attack_type: str
    duration_seconds: float
    packets_per_second: float
    source_pool_size: int = 8
    randomize_ports: bool = False
    intensity_ramp: bool = False


class RealtimeAttackGenerator:
    """Generates realistic network attack traffic in real-time for live testing."""

    # Pre-defined attack scenarios
    SCENARIOS = {
        "http_flood": AttackScenario(
            name="HTTP Flood",
            attack_type="http",
            duration_seconds=10.0,
            packets_per_second=50.0,
            source_pool_size=8,
        ),
        "syn_flood": AttackScenario(
            name="TCP SYN Flood",
            attack_type="syn",
            duration_seconds=8.0,
            packets_per_second=100.0,
            source_pool_size=12,
        ),
        "udp_flood": AttackScenario(
            name="UDP Flood",
            attack_type="udp",
            duration_seconds=12.0,
            packets_per_second=75.0,
            source_pool_size=10,
        ),
        "icmp_flood": AttackScenario(
            name="ICMP Flood",
            attack_type="icmp",
            duration_seconds=6.0,
            packets_per_second=60.0,
            source_pool_size=6,
        ),
        "distributed_attack": AttackScenario(
            name="Distributed Multi-Vector Attack",
            attack_type="mixed",
            duration_seconds=15.0,
            packets_per_second=120.0,
            source_pool_size=15,
        ),
        "slowloris": AttackScenario(
            name="Slowloris (Slow HTTP)",
            attack_type="http",
            duration_seconds=20.0,
            packets_per_second=5.0,
            source_pool_size=20,
            randomize_ports=True,
        ),
        "port_scan": AttackScenario(
            name="Sequential Port Scan",
            attack_type="syn",
            duration_seconds=15.0,
            packets_per_second=30.0,
            source_pool_size=1,
            randomize_ports=True,
        ),
        "low_intensity": AttackScenario(
            name="Low-Intensity Sustained Attack",
            attack_type="udp",
            duration_seconds=30.0,
            packets_per_second=10.0,
            source_pool_size=5,
        ),
        "burst_attack": AttackScenario(
            name="Burst Attack Pattern",
            attack_type="http",
            duration_seconds=12.0,
            packets_per_second=80.0,
            source_pool_size=8,
            intensity_ramp=True,
        ),
    }

    def __init__(self, target_ip: str = "192.168.1.10"):
        self.target_ip = target_ip
        self.simulator = TrafficSimulator(target_ip=target_ip)
        self._stop_event = threading.Event()
        self._current_scenario: AttackScenario | None = None
        self._base_timestamp = datetime.now()

    def generate_attack_stream(
        self, scenario: AttackScenario, callback: Callable[[PacketEvent], None] | None = None
    ) -> Iterator[PacketEvent]:
        """Generate attack traffic for the specified scenario in real-time."""
        start_time = datetime.now()
        packets_generated = 0
        packets_to_generate = int(scenario.packets_per_second * scenario.duration_seconds)

        print(f"\n🚨 Starting Attack: {scenario.name}")
        print(f"   Type: {scenario.attack_type}")
        print(f"   Duration: {scenario.duration_seconds}s")
        print(f"   Target Rate: {scenario.packets_per_second} pps")
        print(f"   Estimated Packets: {packets_to_generate}")
        print("-" * 60)

        if scenario.attack_type == "mixed":
            yield from self._generate_mixed_attack(scenario, callback)
        else:
            yield from self._generate_single_attack(scenario, callback)

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n✅ Attack Complete: {packets_generated} packets in {elapsed:.2f}s")

    def _generate_single_attack(
        self, scenario: AttackScenario, callback: Callable[[PacketEvent], None] | None = None
    ) -> Iterator[PacketEvent]:
        """Generate a single-type attack."""
        start_time = datetime.now()
        packets_sent = 0
        packet_interval = 1.0 / scenario.packets_per_second

        # Get attack configuration
        if scenario.attack_type == "http":
            protocol, port, packet_length_base = "TCP", 80, 1450
        elif scenario.attack_type == "syn":
            protocol, port, packet_length_base = "TCP", 443, 72
        elif scenario.attack_type == "udp":
            protocol, port, packet_length_base = "UDP", 53, 1320
        else:  # icmp
            protocol, port, packet_length_base = "ICMP", 0, 1180

        source_ips = self._generate_source_pool(
            scenario.attack_type, scenario.source_pool_size
        )

        while not self._stop_event.is_set():
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > scenario.duration_seconds:
                break

            # Calculate intensity if ramping
            if scenario.intensity_ramp:
                intensity_factor = min(1.0, elapsed / scenario.duration_seconds)
            else:
                intensity_factor = 1.0

            # Apply intensity to packet interval
            current_interval = packet_interval / max(intensity_factor, 0.1)

            src_ip = random.choice(source_ips)

            # Randomize ports if configured
            if scenario.randomize_ports:
                port = random.randint(1024, 65535)

            packet_length = int(
                packet_length_base + random.randint(-40, 40)
            )

            event = PacketEvent(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=self.target_ip,
                protocol=protocol,
                destination_port=port,
                packet_length=max(60, packet_length),
                attack_type=ATTACK_TYPES[scenario.attack_type],
            )

            if callback:
                callback(event)

            yield event
            packets_sent += 1

            # Real-time pacing
            time.sleep(current_interval)

            if packets_sent % 50 == 0:
                print(f"   [{packets_sent} packets sent] {elapsed:.1f}s elapsed")

    def _generate_mixed_attack(
        self, scenario: AttackScenario, callback: Callable[[PacketEvent], None] | None = None
    ) -> Iterator[PacketEvent]:
        """Generate a mixed multi-vector attack."""
        start_time = datetime.now()
        attack_types = ["http", "syn", "udp", "icmp"]
        packets_per_type = int(
            (scenario.packets_per_second * scenario.duration_seconds) / len(attack_types)
        )
        packets_sent = 0

        while not self._stop_event.is_set():
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > scenario.duration_seconds:
                break

            for attack_type in attack_types:
                if self._stop_event.is_set():
                    break

                # Generate packets for this attack type
                for event in self.simulator.attack_traffic(attack_type, packets_per_type):
                    if callback:
                        callback(event)
                    yield event
                    packets_sent += 1

                    if packets_sent % 100 == 0:
                        print(
                            f"   [{packets_sent} packets sent] {elapsed:.1f}s elapsed - "
                            f"Current: {attack_type}"
                        )

    def _generate_source_pool(self, attack_type: str, pool_size: int) -> list[str]:
        """Generate a pool of source IP addresses for the attack."""
        return [f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}" 
                for _ in range(pool_size)]

    def get_scenario(self, scenario_name: str) -> AttackScenario | None:
        """Get a predefined attack scenario by name."""
        return self.SCENARIOS.get(scenario_name)

    def list_scenarios(self) -> dict[str, str]:
        """List all available attack scenarios."""
        return {name: scenario.name for name, scenario in self.SCENARIOS.items()}

    def custom_attack(
        self,
        attack_type: str,
        duration_seconds: float,
        packets_per_second: float,
        callback: Callable[[PacketEvent], None] | None = None,
    ) -> Iterator[PacketEvent]:
        """Generate a custom attack with specified parameters."""
        scenario = AttackScenario(
            name=f"Custom {attack_type.upper()} Attack",
            attack_type=attack_type,
            duration_seconds=duration_seconds,
            packets_per_second=packets_per_second,
        )
        yield from self.generate_attack_stream(scenario, callback)

    def stop(self) -> None:
        """Stop the attack generation."""
        self._stop_event.set()


def print_attack_summary(event: PacketEvent) -> None:
    """Print a summary of the packet event."""
    timestamp = event.timestamp.strftime("%H:%M:%S.%f")[:-3]
    print(
        f"{timestamp} | {event.src_ip:15} → {event.dst_ip:15} | "
        f"{event.protocol:6} | Port: {event.destination_port:5} | "
        f"Length: {event.packet_length:5} | Type: {event.attack_type}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-time Network Attack Generator for Anomaly Detection Testing"
    )
    parser.add_argument(
        "--scenario",
        choices=list(RealtimeAttackGenerator.SCENARIOS.keys()),
        help="Predefined attack scenario to run",
    )
    parser.add_argument(
        "--attack",
        choices=["http", "syn", "udp", "icmp"],
        help="Custom attack type (use with --duration and --rate)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Attack duration in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=50.0,
        help="Packets per second (default: 50.0)",
    )
    parser.add_argument(
        "--target",
        default="192.168.1.10",
        help="Target IP address (default: 192.168.1.10)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available scenarios and exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed packet information",
    )
    args = parser.parse_args()

    generator = RealtimeAttackGenerator(target_ip=args.target)

    if args.list:
        print("\n📋 Available Attack Scenarios:")
        print("-" * 50)
        for key, name in generator.list_scenarios().items():
            scenario = generator.get_scenario(key)
            print(f"  {key:20} | {name}")
            print(f"  {'':20} | Duration: {scenario.duration_seconds}s, Rate: {scenario.packets_per_second} pps")
        return

    callback = print_attack_summary if args.verbose else None

    if args.scenario:
        scenario = generator.get_scenario(args.scenario)
        if scenario:
            for event in generator.generate_attack_stream(scenario, callback):
                pass
    elif args.attack:
        for event in generator.custom_attack(
            args.attack, args.duration, args.rate, callback
        ):
            pass
    else:
        # Default: run HTTP flood
        print("No scenario or attack type specified. Running default HTTP flood...")
        scenario = generator.get_scenario("http_flood")
        for event in generator.generate_attack_stream(scenario, callback):
            pass


if __name__ == "__main__":
    main()