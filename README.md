# ControlConexion 📡

Control parental para **tu propia red doméstica**: monitorea todos los equipos
y bloquea/habilita la conexión de los dispositivos de tus hijos desde una
interfaz web que abres también **desde el celular**.

Pensado para el caso en que **no tienes acceso admin al módem ni router propio**:
el bloqueo se hace por **ARP spoofing** dirigido a los equipos que tú elijas
(la misma técnica de apps tipo *NetCut*).

> ⚠️ **Uso legítimo:** esto es para TU red y TUS dispositivos. Usarlo en redes
> ajenas es ilegal. La técnica ARP es "ruidosa" y puede afectar la estabilidad
> de la red; es la única opción cuando no controlas el gateway.

---

## ¿Qué herramientas usa?

| Herramienta | Para qué |
|---|---|
| **Python 3** | Lenguaje base |
| **Scapy** | Escanear la red (ARP) y enviar los paquetes de bloqueo/restauración |
| **Flask** | Servir el panel web al que entras desde el celular |
| HTML/CSS/JS (sin dependencias) | La interfaz, responsiva para móvil |

## ¿Qué permisos necesita?

1. **Privilegios de red (root/administrador)** en la máquina donde corre, porque
   enviar paquetes ARP crudos requiere `sudo` (Linux/macOS) o ejecutar como
   administrador (Windows con Npcap). Es el único permiso especial.
2. Que esa máquina esté **conectada a la misma red** que quieres controlar
   (por cable o WiFi).
3. **Ningún** acceso al módem/router — ese es justamente el punto.

No necesita internet externo, ni cuentas, ni la nube: todo es local.

---

## Instalación

```bash
pip install -r requirements.txt
```

En **Windows** instala además [Npcap](https://npcap.com/) (marca "WinPcap API
compatible") para que Scapy pueda enviar paquetes.

## Uso

Primero **pruébalo sin tocar la red** (modo simulación, con equipos de ejemplo):

```bash
DRY_RUN=1 CONTROL_PIN=1234 python3 control.py
```

Cuando estés listo, en la red real (requiere privilegios):

```bash
# Linux / macOS
sudo CONTROL_PIN=1234 python3 control.py

# Windows (PowerShell como administrador)
$env:CONTROL_PIN="1234"; python control.py
```

Verás en pantalla la IP del panel, por ejemplo `http://192.168.1.10:8080`.

## Controlarlo desde el celular

1. Conecta el celular a la **misma red WiFi** que la máquina donde corre.
2. Abre en el navegador del celular la dirección que muestra el programa,
   por ejemplo `http://192.168.1.10:8080`.
3. Ingresa tu **PIN**.
4. Toca el botón de cada equipo para **Bloquear** o **Habilitar**.

> Tip: para que la IP de la máquina no cambie, asígnale una IP fija o resérvala.

---

## Variables de configuración

| Variable | Por defecto | Descripción |
|---|---|---|
| `CONTROL_PIN` | *(vacío)* | PIN para entrar al panel. **Defínelo siempre** para que tus hijos no se desbloqueen solos. |
| `CONTROL_PORT` | `8080` | Puerto del panel web. |
| `CONTROL_HOST` | `0.0.0.0` | Interfaz de escucha (déjalo así para acceder desde el celular). |
| `DRY_RUN` | — | `1` = modo simulación, no envía paquetes a la red. |
| `CONTROL_SECRET` | *(aleatorio)* | Clave de sesión de Flask (opcional). |

---

## Cómo funciona el bloqueo (resumen honesto)

Al bloquear un equipo, el programa le envía anuncios ARP falsos diciéndole que
"el router soy yo". Como esta máquina **no reenvía** ese tráfico, los paquetes
del equipo hacia internet se descartan y queda sin conexión. Al desbloquear se
restaura la información ARP correcta.

Limitaciones a tener en cuenta:
- Es **frágil**: si apagas el programa, la máquina o reinicias, el bloqueo cesa
  (por diseño, al salir se **restauran** todos los equipos).
- Puede meter **ruido** en la red; algunos sistemas detectan/resisten ARP spoofing.
- La solución realmente estable es controlar el gateway (admin del módem o un
  router/Raspberry Pi propio). Si algún día consigues eso, es el camino recomendado.

## Seguridad y responsabilidad

- Úsalo **solo en tu red**.
- Nunca se puede bloquear el **router** ni **este mismo equipo** (protegido en código).
- Al cerrar el programa (Ctrl+C) se **restaura la conexión de todos**.

## Estructura

```
control.py              # arranque
netcontrol/
  netutils.py           # detección de gateway/IP/MAC
  scanner.py            # descubrimiento de equipos
  blocker.py            # motor de bloqueo ARP
  webapp.py             # API + panel Flask
templates/
  index.html            # panel (móvil)
  login.html            # acceso por PIN
```
