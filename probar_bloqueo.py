#!/usr/bin/env python3
"""Prueba de bloqueo de UN equipo, con mensajes claros.

Uso:
    py probar_bloqueo.py 192.168.100.5      (la IP del equipo a probar)

Bloquea ese equipo durante 60 segundos y luego lo restaura. Mientras corre,
revisa en ESE equipo si pierde internet (abre una web o YouTube).

Sirve para aislar el problema fuera del panel web.
"""
from __future__ import annotations

import sys
import time

from netcontrol import netutils
from netcontrol.blocker import Blocker, disable_ip_forwarding


def comprobar_forwarding():
    """Avisa si el reenvío de IP está activo (hace que el bloqueo NO funcione)."""
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
        val, _ = winreg.QueryValueEx(k, "IPEnableRouter")
        if val == 1:
            print("  ⚠️ IPEnableRouter=1 (reenvío GLOBAL activo).")
            print("     Esto hace que el bloqueo NO funcione. Apágalo así:")
            print("     - Desactiva 'Compartir conexión a internet' (ICS), o")
            print("     - En PowerShell admin:  Set-NetIPInterface -Forwarding Disabled")
    except FileNotFoundError:
        pass
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        print("Uso: py probar_bloqueo.py <IP-del-equipo>")
        print("Ej:  py probar_bloqueo.py 192.168.100.5")
        return 1

    target = sys.argv[1]
    print("=" * 56)
    print(" PRUEBA DE BLOQUEO -", target)
    print("=" * 56)

    comprobar_forwarding()
    print("  Desactivando reenvío de IP (necesario para que corte)...")
    disable_ip_forwarding()

    try:
        info = netutils.collect()
    except Exception as e:
        print(f"ERROR detectando la red: {e}")
        return 1

    print(f"  Tu IP    : {info.own_ip}  ({info.iface})")
    print(f"  Gateway  : {info.gateway_ip}  MAC={info.gateway_mac or '??'}")
    if not info.gateway_mac:
        print("  ⚠️ No se pudo obtener la MAC del gateway: el bloqueo no funcionará.")
        print("     ¿Estás conectado por CABLE a este módem?")
        return 1

    if target in (info.own_ip, info.gateway_ip):
        print("  ⚠️ No se puede bloquear tu propia PC ni el router. Elige otra IP.")
        return 1

    mac = netutils.get_mac(target, iface=info.iface)
    if not mac:
        print(f"  ⚠️ No respondió el equipo {target}. ¿Está encendido y en la red?")
        return 1
    print(f"  Objetivo : {target}  MAC={mac}")

    blk = Blocker(info)
    blk.start()
    blk.block(target, mac)

    print()
    print("  >>> BLOQUEANDO durante 60 segundos.")
    print("  >>> Ve a ESE equipo y abre una web o YouTube: debería quedarse SIN internet.")
    print()
    try:
        for i in range(60):
            print(f"      enviando paquetes de bloqueo...  {i + 1}/60", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print("\n\n  >>> Restaurando la conexión del equipo...")
    blk.unblock(target)
    blk.shutdown()
    time.sleep(1)
    print("  Listo. El equipo debería recuperar internet en unos segundos.")
    print()
    print("  ¿Perdió internet durante la prueba?  SÍ = funciona.  NO = cuéntame.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
