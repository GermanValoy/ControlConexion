# ControlConexion 📡

Control parental para **tu propia red doméstica**: monitorea todos los equipos
y bloquea/habilita la conexión de los dispositivos de tus hijos desde una
interfaz web que abres también **desde el celular**.

Pensado para el caso en que **no tienes acceso admin al módem ni router propio**:
el bloqueo se hace por **ARP spoofing** dirigido a los equipos que tú elijas
(la misma técnica de apps tipo *NetCut*).

**Incluye:**
- 📶 Monitoreo y bloqueo/habilitación de cada equipo con un toque.
- ⏰ **Horarios** que activas/desactivas cuando quieras (ej. "tablet, lun–vie 22:00–06:00").
- 💬 **Mensaje personalizado**: cuando un equipo está bloqueado, tu hijo ve tu
  mensaje al abrir el navegador (portal cautivo — ver limitación abajo).

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

## 🪟 Guía rápida para Windows 11

1. **Instala Python 3** desde [python.org](https://www.python.org/downloads/)
   (marca la casilla *"Add Python to PATH"* durante la instalación).
2. **Instala [Npcap](https://npcap.com/#download)** (necesario para que Scapy
   envíe paquetes). Durante la instalación **marca "Install Npcap in WinPcap API-compatible Mode"**.
3. Descarga este proyecto y, en su carpeta, abre **PowerShell** y ejecuta:
   ```powershell
   pip install -r requirements.txt
   ```
4. Abre el archivo **`iniciar_windows.bat`** con el Bloc de notas y cambia el
   PIN (`set CONTROL_PIN=1234`) por uno tuyo. Guárdalo.
5. **Doble clic en `iniciar_windows.bat`**. Windows pedirá permiso de
   administrador (di que sí) — es necesario para controlar la red.
6. La primera vez, Windows preguntará si permites la app en la red: elige
   **Redes privadas → Permitir** (si no, el celular no podrá conectarse).
7. En la ventana negra verás la dirección del panel, por ejemplo
   `http://192.168.1.10:8080`. Ábrela en tu celular (mismo WiFi) e ingresa tu PIN.

> Para cerrarlo: cierra la ventana negra. Al salir se **restaura la conexión**
> de todos los equipos automáticamente.

## Instalación (Linux / macOS)

```bash
pip install -r requirements.txt
```

## Uso

Primero **pruébalo sin tocar la red** (modo simulación, con equipos de ejemplo):

```bash
DRY_RUN=1 CONTROL_PIN=1234 python3 control.py
```

Cuando estés listo, en la red real (requiere privilegios):

```bash
# Linux / macOS
sudo CONTROL_PIN=1234 python3 control.py

# Windows: usa iniciar_windows.bat (ver guía arriba), o en PowerShell como admin:
#   $env:CONTROL_PIN="1234"; python control.py
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

## Horarios ⏰

En la pestaña **Horarios** del panel:
1. Elige el equipo, ponle un nombre, marca los **días** y el rango **Desde/Hasta**
   (admite rangos que cruzan la medianoche, ej. 22:00–06:00).
2. Opcional: escribe un **mensaje** para ese horario.
3. Cada horario tiene un **interruptor** para activarlo o desactivarlo cuando quieras,
   sin borrarlo. Queda guardado aunque reinicies el programa.

Los bloqueos manuales y los de horario no se pisan: si bloqueas algo a mano, el
horario no lo libera, y al terminar un horario solo se libera lo que él bloqueó.

## Mensaje personalizado 💬

En cada equipo (pestaña **Equipos**) hay un campo "💬 Mensaje". Lo escribes y
guardas. Cuando ese equipo quede bloqueado, al abrir el navegador tu hijo verá
una página con tu mensaje (ej. *"A dormir, mañana hay escuela 😴"*).

Funciona en **Windows, macOS y Linux** (usa spoofing de DNS con Scapy; no
necesita iptables ni drivers extra además de Npcap en Windows).

> **Limitaciones honestas:**
> - Las webs **HTTPS** no mostrarán el mensaje (el navegador solo dirá que no hay
>   conexión); el mensaje se ve claro en el aviso de *"iniciar sesión en la red"*
>   del celular y en cualquier web `http://`.
> - El mensaje usa el **puerto 80**. Si otro programa lo ocupa (ej. un servidor
>   web local), el mensaje no se mostrará, pero el bloqueo seguirá funcionando.
>   Puedes cambiarlo con la variable `CONTROL_PORTAL_PORT`, aunque el navegador
>   del equipo abre el 80 por defecto, así que lo normal es dejarlo en 80.

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
  blocker.py            # motor de bloqueo ARP (+ integración portal)
  portal.py             # portal cautivo: mensaje personalizado (multiplataforma)
  scheduler.py          # aplicación de horarios en segundo plano
  store.py              # persistencia (mensajes y horarios) en config.json
  webapp.py             # API + panel Flask
templates/
  index.html            # panel móvil (pestañas Equipos / Horarios)
  login.html            # acceso por PIN
```
