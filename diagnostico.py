#!/usr/bin/env python3
"""Diagnóstico de ControlConexion.

Muestra las tarjetas de red, qué interfaz se está detectando y cuántos equipos
se ven en cada una. Úsalo si "solo ves tu ordenador".

Windows:  doble clic en diagnostico_windows.bat  (o, como admin:  python diagnostico.py)
Linux/Mac:  sudo python3 diagnostico.py
"""
from __future__ import annotations

import os

from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp

from netcontrol import netutils


def listar_interfaces():
    print("\n== TARJETAS DE RED DETECTADAS ==")
    try:
        from scapy.arch import get_if_list
        names = get_if_list()
    except Exception:
        names = []
    try:
        # En Windows, conf.ifaces tiene nombres descriptivos.
        for i in conf.ifaces.values():
            ip = ""
            try:
                ip = get_if_addr(i.name)
            except Exception:
                pass
            print(f"  - {i.description or i.name}")
            print(f"      nombre scapy: {i.name}")
            if ip and ip != "0.0.0.0":
                print(f"      IP: {ip}")
    except Exception:
        for n in names:
            print(f"  - {n}")


def escanear(iface, cidr):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                     timeout=3, iface=iface, verbose=False)
        return [(r.psrc, r.hwsrc) for _, r in ans]
    except Exception as e:
        print(f"      (error escaneando {iface}: {e})")
        return []


def main():
    print("=" * 56)
    print(" DIAGNÓSTICO ControlConexion")
    print("=" * 56)

    listar_interfaces()

    print("\n== DETECCIÓN AUTOMÁTICA ==")
    try:
        info = netutils.collect()
    except Exception as e:
        print(f"  ERROR detectando la red: {e}")
        print("  ¿Estás conectado a internet? ¿Instalaste Npcap (Windows)?")
        return
    print(f"  Interfaz : {info.iface}")
    print(f"  Tu IP    : {info.own_ip}")
    print(f"  Tu MAC   : {info.own_mac}")
    print(f"  Gateway  : {info.gateway_ip}  MAC={info.gateway_mac or '??'}")
    print(f"  Red      : {info.cidr}")
    if info.own_ip in ("0.0.0.0", "127.0.0.1"):
        print("  ⚠️ Tu IP no es válida: la interfaz detectada es incorrecta.")

    print("\n== ESCANEO con la interfaz detectada ==")
    equipos = escanear(info.iface, info.cidr)
    print(f"  Equipos encontrados: {len(equipos)}")
    for ip, mac in sorted(equipos):
        print(f"    {ip:16s} {mac}")

    if len(equipos) <= 1:
        print("\n  ⚠️ Solo se ve 1 equipo (tu PC). Probemos CADA interfaz:")
        try:
            for i in conf.ifaces.values():
                ip = ""
                try:
                    ip = get_if_addr(i.name)
                except Exception:
                    pass
                if not ip or ip in ("0.0.0.0", "127.0.0.1"):
                    continue
                cidr = netutils.guess_cidr(ip)
                found = escanear(i.name, cidr)
                marca = "  <-- ESTA parece la correcta" if len(found) > 1 else ""
                print(f"    [{i.description or i.name}] {ip} -> {len(found)} equipos{marca}")
                if len(found) > 1:
                    print(f"       Para forzarla, arranca con:")
                    print(f"       CONTROL_IFACE=\"{i.name}\"")
        except Exception as e:
            print(f"    (no se pudo recorrer interfaces: {e})")

    print("\nListo. Copia TODO este texto si necesitas ayuda.")


if __name__ == "__main__":
    main()
