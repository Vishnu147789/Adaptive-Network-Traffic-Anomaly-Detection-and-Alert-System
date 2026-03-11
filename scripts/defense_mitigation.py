from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from runtime_features import BLOCKLIST_PATH


class MitigationEngine:
    def __init__(self, path: Path = BLOCKLIST_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.blocked_ips = self._load()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            return set(json.loads(self.path.read_text()))
        except json.JSONDecodeError:
            return set()

    def _save(self) -> None:
        self.path.write_text(json.dumps(sorted(self.blocked_ips), indent=2))

    def block_ip(self, ip_address: str) -> bool:
        if not ip_address or ip_address in self.blocked_ips:
            return False
        self.blocked_ips.add(ip_address)
        self._save()
        return True

    def unblock_ip(self, ip_address: str) -> bool:
        if ip_address not in self.blocked_ips:
            return False
        self.blocked_ips.remove(ip_address)
        self._save()
        return True

    def is_blocked(self, ip_address: str) -> bool:
        return ip_address in self.blocked_ips

    def extend(self, ip_addresses: Iterable[str]) -> None:
        changed = False
        for ip_address in ip_addresses:
            if ip_address and ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                changed = True
        if changed:
            self._save()
