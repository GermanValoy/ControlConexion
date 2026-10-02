"""Descubrimiento de equipos en la LAN mediante ARP."""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Optional

from scapy.all import ARP, Ether, srp

from . import netutils


@dataclass
class Device:
    ip: str
    mac: str
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    is_gateway: bool = False
    is_self: bool = False


def _simulated_devices() -> list[Device]:
    """Lista de ejemplo para el modo DRY_RUN / pruebas sin red real."""
    return [
        Device("192.168.1.1", "aa:bb:cc:00:00:01", "Router ISP", "gateway", is_gateway=True),
        Device("192.168.1.10", "aa:bb:cc:00:00:10", "Intel Corp", "mi-pc", is_self=True),
        Device("192.168.1.21", "aa:bb:cc:00:00:21", "Apple, Inc.", "iphone-ana"),
        Device("192.168.1.22", "aa:bb:cc:00:00:22", "Samsung", "tablet-luis"),
        Device("192.168.1.23", "aa:bb:cc:00:00:23", "Sony", "playstation"),
    ]


def scan(info: netutils.NetInfo, timeout: float = 3.0,
         resolve_names: bool = True) -> list[Device]:
    """Escanea la red y devuelve los equipos encontrados.

    Con la variable de entorno DRY_RUN=1 devuelve una lista simulada,
    útil para probar la interfaz sin tocar la red.
    """
    if os.environ.get("DRY_RUN") == "1":
        return _simulated_devices()

    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=info.cidr),
        timeout=timeout,
        verbose=False,
    )
    devices: list[Device] = []
    seen: set[str] = set()
    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        if ip in seen:
            continue
        seen.add(ip)
        dev = Device(
            ip=ip,
            mac=mac,
            vendor=netutils.vendor_for_mac(mac),
            hostname=netutils.resolve_hostname(ip) if resolve_names else None,
            is_gateway=(ip == info.gateway_ip),
            is_self=(ip == info.own_ip),
        )
        devices.append(dev)

    # Asegura que nuestro propio equipo aparezca aunque no responda al ARP.
    if info.own_ip not in seen:
        devices.append(Device(
            ip=info.own_ip, mac=info.own_mac, vendor="(este equipo)",
            hostname="este-equipo", is_self=True,
        ))

    devices.sort(key=lambda d: tuple(int(p) for p in d.ip.split(".")))
    return devices


def to_dict(dev: Device) -> dict:
    return asdict(dev)
