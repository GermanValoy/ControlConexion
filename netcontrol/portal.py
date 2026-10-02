"""Portal cautivo: muestra un mensaje personalizado en el equipo bloqueado.

Mecanismo (solo Linux, requiere root):
  - El equipo ya cree que somos el router (ARP spoofing del Blocker).
  - Activamos reenvío IP y, con iptables, redirigimos SU tráfico:
      * DNS (53)  -> nuestro mini-servidor DNS (responde todo con nuestra IP)
      * HTTP (80) -> nuestro mini-servidor web (muestra tu mensaje)
      * el resto  -> descartado
  - Resultado: al abrir el navegador (o al saltar el aviso de "iniciar sesión
    en la red"), tu hijo ve tu mensaje. Las webs HTTPS simplemente no cargan.

En Windows/macOS no se aplica el portal: el bloqueo funciona igual (corte
total), pero sin la página de mensaje. Ver README.
"""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

HTTP_PORT = 8081
DNS_PORT = 5353
NAT_CHAIN = "CONEXION_NAT"
FWD_CHAIN = "CONEXION_FWD"

# mensajes compartidos: ip_del_equipo -> texto
_messages: dict[str, str] = {}
_messages_lock = threading.Lock()


def set_messages(mapping: dict[str, str]):
    with _messages_lock:
        _messages.clear()
        _messages.update(mapping)


def _message_for(ip: str) -> str:
    with _messages_lock:
        return _messages.get(ip, "Conexión en pausa por el control parental.")


def _page(message: str) -> bytes:
    safe = (message.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mensaje</title><style>
:root{{color-scheme:dark}}body{{margin:0;min-height:100vh;display:flex;
align-items:center;justify-content:center;font-family:system-ui,sans-serif;
background:#0f172a;color:#e2e8f0;padding:24px;text-align:center}}
.box{{max-width:460px;background:#1e293b;padding:32px;border-radius:20px;
box-shadow:0 10px 40px rgba(0,0,0,.4)}}
.emoji{{font-size:3rem;margin-bottom:8px}}
h1{{font-size:1.15rem;color:#93c5fd;margin:.2rem 0 1rem}}
p{{font-size:1.25rem;line-height:1.5;white-space:pre-wrap;margin:0}}
.foot{{margin-top:22px;font-size:.8rem;color:#64748b}}
</style></head><body><div class="box">
<div class="emoji">📵</div>
<h1>Internet en pausa</h1>
<p>{safe}</p>
<div class="foot">— Mensaje de tus padres · ControlConexion</div>
</div></body></html>"""
    return html.encode("utf-8")


class _MsgHandler(BaseHTTPRequestHandler):
    def _serve(self):
        msg = _message_for(self.client_address[0])
        body = _page(msg)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def log_message(self, *a):
        pass  # silencio


def _dns_response(data: bytes, answer_ip: str) -> Optional[bytes]:
    """Responde cualquier consulta A con `answer_ip`. Minimalista pero válido."""
    if len(data) < 12:
        return None
    tid = data[:2]
    flags = b"\x81\x80"              # respuesta estándar, sin error
    qd = data[4:6]
    # localizar fin de la pregunta
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    i += 1          # byte nulo
    qtype_qclass = data[i:i + 4]
    question = data[12:i + 4]
    an_count = b"\x00\x01"
    header = tid + flags + qd + an_count + b"\x00\x00" + b"\x00\x00"
    # answer: puntero al nombre (0xc00c), tipo A, clase IN, TTL 30, len 4, IP
    answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + struct.pack(">I", 30)
              + b"\x00\x04" + socket.inet_aton(answer_ip))
    return header + question + answer


class _DNSServer(threading.Thread):
    def __init__(self, answer_ip: str, port: int = DNS_PORT):
        super().__init__(daemon=True)
        self.answer_ip = answer_ip
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._run = True

    def run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.port))
        self._sock.settimeout(1.0)
        while self._run:
            try:
                data, addr = self._sock.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                break
            resp = _dns_response(data, self.answer_ip)
            if resp:
                try:
                    self._sock.sendto(resp, addr)
                except OSError:
                    pass

    def stop(self):
        self._run = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def _ipt(args: list[str]) -> bool:
    try:
        subprocess.run(["iptables", *args], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _ipt_ok(args: list[str]) -> bool:
    return subprocess.run(["iptables", *args],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


class Portal:
    """Gestiona servidores de mensaje/DNS y las reglas iptables (Linux)."""

    def __init__(self, own_ip: str):
        self.own_ip = own_ip
        self.dry_run = os.environ.get("DRY_RUN") == "1"
        self._http: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._dns: Optional[_DNSServer] = None
        self._active = False

    @staticmethod
    def available() -> bool:
        """El portal con mensaje solo está soportado en Linux con iptables."""
        if os.environ.get("DRY_RUN") == "1":
            return False
        if sys.platform != "linux":
            return False
        try:
            subprocess.run(["iptables", "-V"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    # ---- servidores ----
    def _ensure_servers(self):
        if self._http is None:
            self._http = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), _MsgHandler)
            self._http_thread = threading.Thread(
                target=self._http.serve_forever, daemon=True)
            self._http_thread.start()
        if self._dns is None:
            self._dns = _DNSServer(self.own_ip)
            self._dns.start()

    def _stop_servers(self):
        if self._http:
            try:
                self._http.shutdown()
            except Exception:
                pass
            self._http = None
        if self._dns:
            self._dns.stop()
            self._dns = None

    # ---- iptables ----
    def _set_forward(self, on: bool):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1" if on else "0")
        except Exception:
            pass

    def _build_chains(self):
        # crea/limpia nuestras cadenas y las enlaza una sola vez
        _ipt(["-t", "nat", "-N", NAT_CHAIN])
        _ipt(["-t", "nat", "-F", NAT_CHAIN])
        if not _ipt_ok(["-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN]):
            _ipt(["-t", "nat", "-I", "PREROUTING", "-j", NAT_CHAIN])
        _ipt(["-N", FWD_CHAIN])
        _ipt(["-F", FWD_CHAIN])
        if not _ipt_ok(["-C", "FORWARD", "-j", FWD_CHAIN]):
            _ipt(["-I", "FORWARD", "-j", FWD_CHAIN])

    def _teardown_chains(self):
        _ipt(["-t", "nat", "-D", "PREROUTING", "-j", NAT_CHAIN])
        _ipt(["-t", "nat", "-F", NAT_CHAIN])
        _ipt(["-t", "nat", "-X", NAT_CHAIN])
        _ipt(["-D", "FORWARD", "-j", FWD_CHAIN])
        _ipt(["-F", FWD_CHAIN])
        _ipt(["-X", FWD_CHAIN])

    def reconcile(self, targets: dict[str, dict]):
        """targets: ip -> {mac, message(str|'' ), source}. Reconstruye todo.

        - equipos con mensaje: redirige 80/53 al portal y descarta el resto.
        - equipos sin mensaje: descarta todo su tráfico reenviado.
        """
        if self.dry_run or not self.available():
            return
        any_portal = any(t.get("message") for t in targets.values())

        if not targets:
            if self._active:
                self._teardown_chains()
                self._set_forward(False)
                self._stop_servers()
                self._active = False
            return

        if any_portal:
            self._ensure_servers()
        self._set_forward(True)
        self._build_chains()
        self._active = True

        msg_map = {}
        for ip, t in targets.items():
            if t.get("message"):
                msg_map[ip] = t["message"]
                _ipt(["-t", "nat", "-A", NAT_CHAIN, "-s", ip, "-p", "udp",
                      "--dport", "53", "-j", "DNAT",
                      "--to-destination", f"{self.own_ip}:{DNS_PORT}"])
                _ipt(["-t", "nat", "-A", NAT_CHAIN, "-s", ip, "-p", "tcp",
                      "--dport", "80", "-j", "DNAT",
                      "--to-destination", f"{self.own_ip}:{HTTP_PORT}"])
            # todo lo demás reenviado desde este equipo: descartar
            _ipt(["-A", FWD_CHAIN, "-s", ip, "-j", "DROP"])
        set_messages(msg_map)

    def shutdown(self):
        if self.dry_run:
            return
        if self._active:
            self._teardown_chains()
            self._set_forward(False)
        self._stop_servers()
        self._active = False
