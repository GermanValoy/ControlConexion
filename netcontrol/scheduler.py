"""Aplica los horarios de bloqueo en segundo plano.

Separa la lógica pura (`schedule_active`, `due_macs`) para poder probarla
sin hilos ni reloj real.
"""
from __future__ import annotations

import threading
from datetime import datetime, time
from typing import Callable, Optional

from .store import Schedule, Store

TICK_SECONDS = 20


def _parse_hhmm(s: str) -> time:
    h, m = s.split(":")
    return time(int(h), int(m))


def schedule_active(sch: Schedule, now: datetime) -> bool:
    """¿Este horario está activo en el instante `now`?

    Soporta ventanas que cruzan la medianoche (ej. 22:00–06:00).
    El día se evalúa según el día en que INICIA la ventana.
    """
    if not sch.enabled or not sch.days:
        return False
    start = _parse_hhmm(sch.start)
    end = _parse_hhmm(sch.end)
    cur = now.time()
    today = now.weekday()           # 0=Lun ... 6=Dom
    yesterday = (today - 1) % 7

    if start < end:
        # Ventana en el mismo día.
        return today in sch.days and start <= cur < end
    if start > end:
        # Ventana nocturna que cruza medianoche.
        if today in sch.days and cur >= start:
            return True              # tramo de hoy después de 'start'
        if yesterday in sch.days and cur < end:
            return True              # tramo de madrugada del día anterior
        return False
    return False                     # start == end => sin duración


def due_macs(schedules: list[Schedule], now: datetime) -> dict[str, Schedule]:
    """MAC -> horario que la debe bloquear ahora (el primero que aplique)."""
    out: dict[str, Schedule] = {}
    for s in schedules:
        if schedule_active(s, now) and s.mac not in out:
            out[s.mac] = s
    return out


class Scheduler:
    def __init__(self, store: Store, blocker,
                 resolve_ip: Callable[[str], Optional[str]]):
        """
        resolve_ip(mac) -> IP actual del equipo (de el último escaneo), o None.
        blocker: instancia de Blocker.
        """
        self.store = store
        self.blocker = blocker
        self.resolve_ip = resolve_ip
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def tick(self, now: Optional[datetime] = None):
        """Un ciclo de aplicación. Expuesto para pruebas."""
        now = now or datetime.now()
        want = due_macs(self.store.list_schedules(), now)

        # 1) Bloquear lo que debe estar bloqueado por horario.
        for mac, sch in want.items():
            ip = self.resolve_ip(mac) or sch.ip
            if not ip:
                continue
            if not self.blocker.is_blocked(ip):
                msg = sch.message or self.store.get_message(mac)
                self.blocker.block(ip, mac, message=msg, source="schedule")

        # 2) Liberar lo que ya no corresponde (solo lo bloqueado por horario).
        for ip in self.blocker.blocked_ips():
            entry = self.blocker.entry(ip)
            if entry and entry.get("source") == "schedule":
                if entry.get("mac", "").lower() not in want:
                    self.blocker.unblock(ip, require_source="schedule")

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                pass
            self._stop.wait(TICK_SECONDS)
