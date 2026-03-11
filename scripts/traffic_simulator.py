from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator

ATTACK_TYPES = {
    "normal": "Normal Traffic",
    "http": "HTTP Flood",
    "syn": "TCP SYN Flood",
    "udp": "UDP Flood",
    "icmp": "ICMP Flood",
}


@dataclass
class PacketEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    destination_port: int
    packet_length: int
    attack_type: str = ATTACK_TYPES["normal"]


class TrafficSimulator:
    def __init__(self, target_ip: str = "192.168.1.10") -> None:
        self.target_ip = target_ip
        self._rng = random.Random(42)
        self._current_time = datetime.now()
        self._normal_sources = [f"192.168.1.{host}" for host in range(20, 60)]
        self._attack_sources = {
            "http": [f"10.0.0.{host}" for host in range(10, 18)],
            "syn": [f"10.0.1.{host}" for host in range(10, 18)],
            "udp": [f"10.0.2.{host}" for host in range(10, 18)],
            "icmp": [f"10.0.3.{host}" for host in range(10, 18)],
        }

    def _next_time(self, burst: bool = False) -> datetime:
        delta_ms = self._rng.randint(6, 20) if burst else self._rng.randint(80, 260)
        self._current_time += timedelta(milliseconds=delta_ms)
        return self._current_time

    def _event(
        self,
        src_ip: str,
        protocol: str,
        port: int,
        packet_length: int,
        attack_type: str,
        burst: bool,
    ) -> PacketEvent:
        return PacketEvent(
            timestamp=self._next_time(burst=burst),
            src_ip=src_ip,
            dst_ip=self.target_ip,
            protocol=protocol,
            destination_port=port,
            packet_length=max(60, packet_length),
            attack_type=attack_type,
        )

    def normal_traffic(self, count: int = 200) -> Iterator[PacketEvent]:
        profiles = [("TCP", 443, 420), ("TCP", 80, 380), ("UDP", 53, 180)]
        for _ in range(count):
            src_ip = self._rng.choice(self._normal_sources)
            protocol, port, center = self._rng.choice(profiles)
            yield self._event(
                src_ip=src_ip,
                protocol=protocol,
                port=port,
                packet_length=center + self._rng.randint(-90, 90),
                attack_type=ATTACK_TYPES["normal"],
                burst=False,
            )

    def attack_traffic(self, attack_name: str, count: int = 300) -> Iterator[PacketEvent]:
        if attack_name == "http":
            profile = ("TCP", 80, 1450, ATTACK_TYPES["http"])
        elif attack_name == "syn":
            profile = ("TCP", 443, 72, ATTACK_TYPES["syn"])
        elif attack_name == "udp":
            profile = ("UDP", 53, 1320, ATTACK_TYPES["udp"])
        else:
            profile = ("ICMP", 0, 1180, ATTACK_TYPES["icmp"])

        protocol, port, packet_length, label = profile
        sources = self._attack_sources[attack_name]
        for _ in range(count):
            src_ip = self._rng.choice(sources)
            yield self._event(
                src_ip=src_ip,
                protocol=protocol,
                port=port,
                packet_length=packet_length + self._rng.randint(-40, 40),
                attack_type=label,
                burst=True,
            )

    def mixed_stream(self) -> Iterator[PacketEvent]:
        yield from self.normal_traffic(180)
        yield from self.attack_traffic("http", 220)
        yield from self.normal_traffic(120)
        yield from self.attack_traffic("syn", 220)
        yield from self.attack_traffic("udp", 180)
        yield from self.normal_traffic(140)
        yield from self.attack_traffic("icmp", 180)
