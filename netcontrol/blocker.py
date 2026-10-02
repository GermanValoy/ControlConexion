"""Motor de bloqueo por ARP spoofing, dirigido a equipos concretos.

Cómo funciona el bloqueo
------------------------
Para cortar la salida a internet de UN equipo, se envenena su caché ARP
diciéndole que el gateway está en la MAC de ESTA máquina.

- Sin mensaje: no se reenvía su tráfico -> queda sin internet.
- Con mensaje (solo Linux): el portal cautivo redirige su navegador a una
  página con el mensaje personalizado (ver portal.py).

Al desbloquear o salir se restaura la caché ARP con las MAC correctas.

Uso previsto: tu propia red doméstica (control parental).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

from scapy.all import ARP, Ether, sendp

from . import netutils
from .portal import Portal

POISON_INTERVAL = 2.0   # segundos entre reenvíos del engaño
RESTORE_ROUNDS = 5      # paquetes de restauración al desbloquear


class Blocker:
    def __init__(self, info: netutils.NetInfo):
        self.info = info
        self.dry_run = os.environ.get("DRY_RUN") == "1"
        # ip -> {"mac","message","source"}
        self._targets: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.portal = Portal(info.own_ip, info.iface)

    # ---- API pública -------------------------------------------------
    def start(self):
        if self.dry_run:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def block(self, ip: str, mac: str, message: str = "",
              source: str = "manual") -> bool:
        if ip == self.info.gateway_ip or ip == self.info.own_ip:
            return False  # nunca bloquear el gateway ni a uno mismo
        with self._lock:
            existing = self._targets.get(ip)
            if existing:
                # No degradar un bloqueo manual a horario; sí refrescar mensaje.
                if not (existing["source"] == "manual" and source == "schedule"):
                    existing["source"] = source
                existing["message"] = message or existing.get("message", "")
                existing["mac"] = mac
            else:
                self._targets[ip] = {"mac": mac, "message": message or "",
                                     "source": source}
            snapshot = dict(self._targets)
        if not self.dry_run:
            self._poison_once(ip, mac)
            self.portal.reconcile(snapshot)
        return True

    def unblock(self, ip: str, require_source: Optional[str] = None) -> bool:
        with self._lock:
            entry = self._targets.get(ip)
            if entry is None:
                return False
            if require_source and entry["source"] != require_source:
                return False  # p.ej. el horario no libera un bloqueo manual
            mac = entry["mac"]
            del self._targets[ip]
            snapshot = dict(self._targets)
        if not self.dry_run:
            self._restore(ip, mac)
            self.portal.reconcile(snapshot)
        return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._targets

    def entry(self, ip: str) -> Optional[dict]:
        with self._lock:
            e = self._targets.get(ip)
            return dict(e) if e else None

    def blocked_ips(self) -> list[str]:
        with self._lock:
            return list(self._targets.keys())

    def shutdown(self):
        """Detiene el motor y restaura TODOS los equipos (importante)."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        with self._lock:
            targets = dict(self._targets)
            self._targets.clear()
        if not self.dry_run:
            for ip, e in targets.items():
                self._restore(ip, e["mac"])
            self.portal.shutdown()

    # ---- Internos ----------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                targets = [(ip, e["mac"]) for ip, e in self._targets.items()]
            for ip, mac in targets:
                self._poison_once(ip, mac)
            self._stop.wait(POISON_INTERVAL)

    def _send(self, dst_mac: str, pkt):
        # Envío a nivel de enlace (L2) por la interfaz correcta: más fiable en
        # Windows (Npcap) que el envío L3 para paquetes ARP.
        sendp(Ether(dst=dst_mac) / pkt, iface=self.info.iface, verbose=False)

    def _poison_once(self, ip: str, mac: str):
        self._send(mac, ARP(op=2, pdst=ip, hwdst=mac,
                            psrc=self.info.gateway_ip, hwsrc=self.info.own_mac))
        if self.info.gateway_mac:
            self._send(self.info.gateway_mac,
                       ARP(op=2, pdst=self.info.gateway_ip,
                           hwdst=self.info.gateway_mac,
                           psrc=ip, hwsrc=self.info.own_mac))

    def _restore(self, ip: str, mac: str):
        if not self.info.gateway_mac:
            return
        for _ in range(RESTORE_ROUNDS):
            self._send("ff:ff:ff:ff:ff:ff",
                       ARP(op=2, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff",
                           psrc=self.info.gateway_ip, hwsrc=self.info.gateway_mac))
            self._send("ff:ff:ff:ff:ff:ff",
                       ARP(op=2, pdst=self.info.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                           psrc=ip, hwsrc=mac))
            time.sleep(0.2)
