"""Portal cautivo multiplataforma: muestra un mensaje en el equipo bloqueado.

Mecanismo (Windows / macOS / Linux, requiere privilegios de administrador):
  - El equipo ya cree que somos el router (ARP spoofing del Blocker) y NO
    reenviamos su tráfico, así que queda sin internet.
  - Además, con Scapy escuchamos sus consultas DNS y le respondemos que
    CUALQUIER dominio apunta a NUESTRA IP (DNS spoofing).
  - Cuando su navegador abre una página (o salta el aviso de "iniciar sesión
    en la red"), llega a nuestro mini-servidor web, que muestra tu mensaje.

No necesita iptables ni drivers extra además de Npcap (en Windows). Las webs
HTTPS no mostrarán el mensaje (el navegador dirá que no hay conexión); el
mensaje aparece claro en el aviso de red del celular y en cualquier web http://.
"""
from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from scapy.all import DNS, DNSRR, IP, UDP, Ether, sendp, sniff

# Puerto del servidor de mensaje. Debe ser 80 porque el navegador del equipo
# bloqueado abrirá http://<dominio> (puerto 80 por defecto), que vía DNS
# spoofing resuelve a nuestra IP.
HTTP_PORT = int(os.environ.get("CONTROL_PORTAL_PORT", "80"))

_messages: dict[str, str] = {}      # ip_del_equipo -> texto
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
        body = _page(_message_for(self.client_address[0]))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = _serve

    def log_message(self, *a):
        pass


def build_dns_reply(pkt, answer_ip: str):
    """Construye una respuesta DNS que apunta cualquier dominio a `answer_ip`.

    Función pura (sin red) para poder probarla. Devuelve el paquete a enviar
    o None si el paquete no es una consulta DNS válida.
    """
    if not pkt.haslayer(DNS) or pkt.haslayer(Ether) is False:
        return None
    dns = pkt[DNS]
    if dns.qr != 0 or dns.qd is None:
        return None
    qname = dns.qd.qname
    eth = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)   # de nosotros al equipo
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
    rep = DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
              an=DNSRR(rrname=qname, type="A", ttl=30, rdata=answer_ip))
    return eth / ip / udp / rep


class _Sniffer(threading.Thread):
    """Escucha consultas DNS de los equipos objetivo y las responde falsas."""

    def __init__(self, own_ip: str, iface: Optional[str],
                 active: Callable[[], set[str]]):
        super().__init__(daemon=True)
        self.own_ip = own_ip
        self.iface = iface
        self.active = active
        self._stop = False

    def _cb(self, pkt):
        try:
            if DNS not in pkt or IP not in pkt:
                return
            if pkt[IP].src in self.active():
                reply = build_dns_reply(pkt, self.own_ip)
                if reply is not None:
                    sendp(reply, iface=self.iface, verbose=False)
        except Exception:
            pass

    def run(self):
        try:
            sniff(filter="udp port 53", prn=self._cb, store=0,
                  iface=self.iface, stop_filter=lambda p: self._stop)
        except Exception:
            pass

    def stop(self):
        self._stop = True


class Portal:
    """Servidor de mensaje (HTTP) + spoofing de DNS para los equipos objetivo."""

    def __init__(self, own_ip: str, iface: Optional[str] = None):
        self.own_ip = own_ip
        self.iface = iface
        self.dry_run = os.environ.get("DRY_RUN") == "1"
        self._http: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._sniffer: Optional[_Sniffer] = None
        self._active_ips: set[str] = set()
        self._lock = threading.Lock()
        self.last_error: str = ""

    @staticmethod
    def available() -> bool:
        """El mensaje funciona en cualquier SO con privilegios (no en simulación)."""
        return os.environ.get("DRY_RUN") != "1"

    def _active(self) -> set[str]:
        with self._lock:
            return set(self._active_ips)

    def _ensure_running(self):
        if self._http is None:
            try:
                self._http = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), _MsgHandler)
                self._http_thread = threading.Thread(
                    target=self._http.serve_forever, daemon=True)
                self._http_thread.start()
            except Exception as e:
                self.last_error = (
                    f"No se pudo abrir el puerto {HTTP_PORT} para el mensaje "
                    f"({e}). El bloqueo funciona igual, sin página de mensaje.")
                self._http = None
        if self._sniffer is None:
            self._sniffer = _Sniffer(self.own_ip, self.iface, self._active)
            self._sniffer.start()

    def _stop_running(self):
        if self._http:
            try:
                self._http.shutdown()
            except Exception:
                pass
            self._http = None
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None

    def reconcile(self, targets: dict[str, dict]):
        """targets: ip -> {mac, message, source}. Activa el mensaje donde haya."""
        if self.dry_run:
            return
        msg_map = {ip: t["message"] for ip, t in targets.items() if t.get("message")}
        with self._lock:
            self._active_ips = set(msg_map.keys())
        set_messages(msg_map)
        if msg_map:
            self._ensure_running()
        else:
            self._stop_running()

    def shutdown(self):
        with self._lock:
            self._active_ips = set()
        set_messages({})
        self._stop_running()
