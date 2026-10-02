#!/usr/bin/env python3
"""ControlConexion - punto de entrada.

Uso:
    sudo CONTROL_PIN=1234 python3 control.py            # red real
    DRY_RUN=1 CONTROL_PIN=1234 python3 control.py        # modo prueba (sin tocar la red)

Luego abre desde tu celular:  http://<IP-de-esta-maquina>:8080

IMPORTANTE: úsalo solo en tu propia red doméstica.
"""
from __future__ import annotations

import atexit
import os
import sys

from netcontrol.webapp import create_app


def main():
    host = os.environ.get("CONTROL_HOST", "0.0.0.0")
    port = int(os.environ.get("CONTROL_PORT", "8080"))

    app = create_app()
    blocker = app.config["BLOCKER"]
    info = app.config["NETINFO"]

    # Al salir: restaurar la conexión de TODOS los equipos bloqueados.
    atexit.register(blocker.shutdown)

    banner(info, blocker.dry_run, port)
    try:
        app.run(host=host, port=port, threaded=True)
    except KeyboardInterrupt:
        pass
    finally:
        blocker.shutdown()


def banner(info, dry_run, port):
    print("=" * 56)
    print(" ControlConexion - control parental de red local")
    print("=" * 56)
    print(f" Interfaz : {info.iface}")
    print(f" Tu IP    : {info.own_ip}")
    print(f" Gateway  : {info.gateway_ip} ({info.gateway_mac or '??'})")
    print(f" Red      : {info.cidr}")
    print(f" Modo     : {'SIMULACIÓN (no toca la red)' if dry_run else 'REAL'}")
    print(f" Panel    : http://{info.own_ip}:{port}  (ábrelo en tu celular)")
    if not os.environ.get("CONTROL_PIN"):
        print(" AVISO    : sin PIN. Define CONTROL_PIN para proteger el panel.")
    print("=" * 56)


if __name__ == "__main__":
    sys.exit(main())
