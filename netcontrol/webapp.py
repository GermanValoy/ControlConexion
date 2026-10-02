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
from .portal import Portal
from .scheduler import Scheduler
from .store import Store

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

    store = Store()
    blocker = Blocker(info)
    blocker.start()

    scheduler = Scheduler(store, blocker, resolve_ip=_ip_for_mac)
    scheduler.start()

    _refresh_devices(info, store)

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
        return render_template("index.html", info=info, dry_run=blocker.dry_run,
                               portal_ok=Portal.available())

    @app.route("/api/devices")
    @login_required
    def api_devices():
        with _state_lock:
            data = []
            for d in _devices:
                item = scanner.to_dict(d)
                item["blocked"] = blocker.is_blocked(d.ip)
                e = blocker.entry(d.ip)
                item["block_source"] = e["source"] if e else None
                item["controllable"] = not (d.is_gateway or d.is_self)
                item["message"] = store.get_message(d.mac)
                data.append(item)
        return jsonify(
            devices=data, gateway=info.gateway_ip, own_ip=info.own_ip,
            dry_run=blocker.dry_run, portal_ok=Portal.available(),
        )

    @app.route("/api/scan", methods=["POST"])
    @login_required
    def api_scan():
        _refresh_devices(info, store)
        return jsonify(ok=True, count=len(_devices))

    @app.route("/api/block", methods=["POST"])
    @login_required
    def api_block():
        body = request.json or {}
        ip, mac = body.get("ip", ""), body.get("mac", "")
        if not ip or not mac:
            return jsonify(error="ip y mac requeridos"), 400
        message = store.get_message(mac)
        if not blocker.block(ip, mac, message=message, source="manual"):
            return jsonify(error="no se puede bloquear este equipo"), 400
        return jsonify(ok=True, ip=ip, blocked=True)

    @app.route("/api/unblock", methods=["POST"])
    @login_required
    def api_unblock():
        ip = (request.json or {}).get("ip", "")
        if not ip:
            return jsonify(error="ip requerida"), 400
        blocker.unblock(ip)  # desbloqueo manual: libera cualquier origen
        return jsonify(ok=True, ip=ip, blocked=False)

    @app.route("/api/message", methods=["POST"])
    @login_required
    def api_message():
        body = request.json or {}
        mac, message = body.get("mac", ""), body.get("message", "")
        if not mac:
            return jsonify(error="mac requerida"), 400
        store.set_message(mac, message)
        # Si está bloqueado ahora, refresca el mensaje en caliente.
        for ip in blocker.blocked_ips():
            e = blocker.entry(ip)
            if e and e["mac"].lower() == mac.lower():
                blocker.block(ip, mac, message=store.get_message(mac),
                              source=e["source"])
        return jsonify(ok=True, mac=mac, message=store.get_message(mac))

    # ---- horarios ----
    @app.route("/api/schedules", methods=["GET"])
    @login_required
    def api_schedules():
        from dataclasses import asdict
        return jsonify(schedules=[asdict(s) for s in store.list_schedules()])

    @app.route("/api/schedules", methods=["POST"])
    @login_required
    def api_schedule_create():
        b = request.json or {}
        if not b.get("mac"):
            return jsonify(error="mac requerida"), 400
        sch = store.add_schedule(
            name=b.get("name", ""), mac=b["mac"], ip=b.get("ip", ""),
            days=b.get("days", []), start=b.get("start", "22:00"),
            end=b.get("end", "06:00"), message=b.get("message", ""),
            enabled=b.get("enabled", True),
        )
        scheduler.tick()
        from dataclasses import asdict
        return jsonify(ok=True, schedule=asdict(sch))

    @app.route("/api/schedules/toggle", methods=["POST"])
    @login_required
    def api_schedule_toggle():
        b = request.json or {}
        ok = store.toggle_schedule(b.get("id", ""), b.get("enabled", True))
        scheduler.tick()
        return jsonify(ok=ok)

    @app.route("/api/schedules/delete", methods=["POST"])
    @login_required
    def api_schedule_delete():
        ok = store.delete_schedule((request.json or {}).get("id", ""))
        scheduler.tick()
        return jsonify(ok=ok)

    app.config.update(BLOCKER=blocker, NETINFO=info, SCHEDULER=scheduler, STORE=store)
    return app


def _ip_for_mac(mac: str):
    with _state_lock:
        for d in _devices:
            if d.mac.lower() == mac.lower():
                return d.ip
    return None


def _refresh_devices(info: netutils.NetInfo, store: Store):
    global _devices
    found = scanner.scan(info)
    with _state_lock:
        _devices = found
    for d in found:  # mantener actualizada la última IP de cada horario
        store.update_schedule_ip(d.mac, d.ip)
