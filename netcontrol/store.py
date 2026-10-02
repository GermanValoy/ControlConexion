"""Persistencia simple en JSON: mensajes por equipo y horarios de bloqueo."""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional

CONFIG_PATH = os.environ.get(
    "CONTROL_CONFIG",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json"),
)


@dataclass
class Schedule:
    id: str
    name: str
    mac: str
    ip: str = ""                     # última IP conocida (se refresca al escanear)
    days: list[int] = field(default_factory=list)  # 0=Lun ... 6=Dom
    start: str = "22:00"             # HH:MM
    end: str = "06:00"              # HH:MM (puede cruzar medianoche)
    message: str = ""
    enabled: bool = True


class Store:
    def __init__(self, path: str = CONFIG_PATH):
        self.path = path
        self._lock = threading.Lock()
        self.device_messages: dict[str, str] = {}   # mac -> mensaje
        self.schedules: list[Schedule] = []
        self.load()

    # ---- persistencia ----
    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.device_messages = dict(data.get("device_messages", {}))
            self.schedules = [Schedule(**s) for s in data.get("schedules", [])]
        except Exception:
            # Config corrupta: empezar limpio sin romper el arranque.
            self.device_messages, self.schedules = {}, []

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "device_messages": self.device_messages,
                "schedules": [asdict(s) for s in self.schedules],
            }, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    # ---- mensajes por equipo ----
    def get_message(self, mac: str) -> str:
        with self._lock:
            return self.device_messages.get(mac.lower(), "")

    def set_message(self, mac: str, message: str):
        with self._lock:
            mac = mac.lower()
            if message.strip():
                self.device_messages[mac] = message.strip()
            else:
                self.device_messages.pop(mac, None)
            self.save()

    # ---- horarios ----
    def list_schedules(self) -> list[Schedule]:
        with self._lock:
            return list(self.schedules)

    def add_schedule(self, name, mac, ip, days, start, end, message="", enabled=True) -> Schedule:
        sch = Schedule(
            id=uuid.uuid4().hex[:8], name=name or "Horario",
            mac=mac.lower(), ip=ip, days=sorted(set(int(d) for d in days)),
            start=start, end=end, message=message.strip(), enabled=bool(enabled),
        )
        with self._lock:
            self.schedules.append(sch)
            self.save()
        return sch

    def toggle_schedule(self, sid: str, enabled: bool) -> bool:
        with self._lock:
            for s in self.schedules:
                if s.id == sid:
                    s.enabled = bool(enabled)
                    self.save()
                    return True
        return False

    def delete_schedule(self, sid: str) -> bool:
        with self._lock:
            n = len(self.schedules)
            self.schedules = [s for s in self.schedules if s.id != sid]
            if len(self.schedules) != n:
                self.save()
                return True
        return False

    def update_schedule_ip(self, mac: str, ip: str):
        """Refresca la última IP conocida de los horarios de una MAC."""
        changed = False
        with self._lock:
            for s in self.schedules:
                if s.mac == mac.lower() and s.ip != ip:
                    s.ip = ip
                    changed = True
            if changed:
                self.save()
