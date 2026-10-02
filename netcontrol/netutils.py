"""Utilidades de red: detección de gateway, interfaz, IP/MAC propias y resolución de MAC.

Multiplataforma (Linux / macOS) gracias a scapy.conf.route.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional

from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp


@dataclass
class NetInfo:
    iface: str
    own_ip: str
    own_mac: str
    gateway_ip: str
    gateway_mac: Optional[str]
    cidr: str


def detect_gateway() -> tuple[str, str, str]:
    """Devuelve (iface, own_ip, gateway_ip) usando la tabla de rutas de scapy.

    Funciona en Linux y macOS sin depender del binario `ip`.
    """
    iface, own_ip, gateway_ip = conf.route.route("0.0.0.0")
    if not gateway_ip or gateway_ip == "0.0.0.0":
        raise RuntimeError(
            "No se pudo detectar el gateway. ¿Estás conectado a la red?"
        )
    return iface, own_ip, gateway_ip


def guess_cidr(own_ip: str, prefix: int = 24) -> str:
    """Red en formato CIDR a partir de la IP propia (por defecto /24)."""
    net = ipaddress.ip_network(f"{own_ip}/{prefix}", strict=False)
    return str(net)


def get_mac(ip: str, timeout: float = 2.0, retry: int = 2,
            iface: Optional[str] = None) -> Optional[str]:
    """Resuelve la MAC de una IP mediante una petición ARP."""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout,
            retry=retry,
            iface=iface,
            verbose=False,
        )
        for _, rcv in ans:
            return rcv[Ether].src
    except PermissionError:
        raise
    except Exception:
        return None
    return None


def _valid_ip(ip: Optional[str]) -> bool:
    return bool(ip) and ip not in ("0.0.0.0", "127.0.0.1")


def collect(prefix: int = 24) -> NetInfo:
    """Reúne toda la información de red necesaria para operar."""
    import os
    iface, route_ip, gateway_ip = detect_gateway()
    # Permite forzar la interfaz manualmente si la detección automática falla
    # (común en Windows con VPN/VirtualBox/WSL): CONTROL_IFACE="Wi-Fi"
    forced = os.environ.get("CONTROL_IFACE")
    if forced:
        iface = forced
    try:
        own_mac = get_if_hwaddr(iface)
    except Exception:
        own_mac = get_if_hwaddr(conf.iface)
    # La IP de la ruta hacia el gateway es la más fiable; solo la sustituimos
    # por la de la interfaz si esta es válida (en Windows a veces da 0.0.0.0).
    own_ip = route_ip
    try:
        a = get_if_addr(iface)
        if _valid_ip(a):
            own_ip = a
    except Exception:
        pass
    gateway_mac = get_mac(gateway_ip, iface=iface)
    return NetInfo(
        iface=iface,
        own_ip=own_ip,
        own_mac=own_mac,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        cidr=guess_cidr(own_ip, prefix),
    )


def resolve_hostname(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Intento best-effort de resolver el nombre del equipo."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def vendor_for_mac(mac: str) -> Optional[str]:
    """Fabricante a partir de la MAC usando la base OUI de scapy (si existe)."""
    try:
        manuf = conf.manufdb._get_manuf(mac)
        if manuf and manuf.lower() != mac.lower():
            return manuf
    except Exception:
        pass
    return None
