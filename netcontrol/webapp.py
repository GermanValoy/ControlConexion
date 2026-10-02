"""Panel web (Flask) para monitorear y controlar la red desde el celular."""
from __future__ import annotations

import os
import secrets
import threading
from functools import wraps

from flask import (Flask, jsonify, redirect, render_template, request,
                   session, url_for)

from . import netutils, scanner
from .blocker import Blocker

# Estado global protegido por lock.
_state_lock = threading.Lock()
_devices: list[scanner.Device] = []


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )
    app.secret_key = os.environ.get("CONTROL_SECRET", secrets.token_hex(16))

    pin = os.environ.get("CONTROL_PIN", "")  # vacío = sin PIN (no recomendado)
    if os.environ.get("DRY_RUN") == "1":
        info = netutils.NetInfo(
            iface="sim0", own_ip="192.168.1.10", own_mac="aa:bb:cc:00:00:10",
            gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:00:00:01",
            cidr="192.168.1.0/24",
        )
    else:
        info = netutils.collect()
    blocker = Blocker(info)
    blocker.start()

    # Escaneo inicial.
    _refresh_devices(info, blocker)

    # ---- auth ----
    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if pin and not session.get("auth"):
                if request.path.startswith("/api/"):
                    return jsonify(error="no autorizado"), 401
                return redirect(url_for("login"))
            return f(*a, **kw)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not pin:
            return redirect(url_for("index"))
        if request.method == "POST":
            if secrets.compare_digest(request.form.get("pin", ""), pin):
                session["auth"] = True
                return redirect(url_for("index"))
            return render_template("login.html", error="PIN incorrecto"), 401
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- vistas ----
    @app.route("/")
    @login_required
    def index():
        return render_template("index.html", info=info, dry_run=blocker.dry_run)

    @app.route("/api/devices")
    @login_required
    def api_devices():
        with _state_lock:
            data = []
            for d in _devices:
                item = scanner.to_dict(d)
                item["blocked"] = blocker.is_blocked(d.ip)
                item["controllable"] = not (d.is_gateway or d.is_self)
                data.append(item)
        return jsonify(
            devices=data,
            gateway=info.gateway_ip,
            own_ip=info.own_ip,
            dry_run=blocker.dry_run,
        )

    @app.route("/api/scan", methods=["POST"])
    @login_required
    def api_scan():
        _refresh_devices(info, blocker)
        return jsonify(ok=True, count=len(_devices))

    @app.route("/api/block", methods=["POST"])
    @login_required
    def api_block():
        ip = (request.json or {}).get("ip", "")
        mac = (request.json or {}).get("mac", "")
        if not ip or not mac:
            return jsonify(error="ip y mac requeridos"), 400
        ok = blocker.block(ip, mac)
        if not ok:
            return jsonify(error="no se puede bloquear este equipo"), 400
        return jsonify(ok=True, ip=ip, blocked=True)

    @app.route("/api/unblock", methods=["POST"])
    @login_required
    def api_unblock():
        ip = (request.json or {}).get("ip", "")
        if not ip:
            return jsonify(error="ip requerida"), 400
        blocker.unblock(ip)
        return jsonify(ok=True, ip=ip, blocked=False)

    app.config["BLOCKER"] = blocker
    app.config["NETINFO"] = info
    return app


def _refresh_devices(info: netutils.NetInfo, blocker: Blocker):
    global _devices
    found = scanner.scan(info)
    with _state_lock:
        _devices = found
