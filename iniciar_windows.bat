@echo off
REM ControlConexion - lanzador para Windows 11
REM Se eleva a Administrador automaticamente (necesario para controlar la red).

REM --- CAMBIA ESTE PIN por el tuyo ---
set CONTROL_PIN=1234

REM --- Si "solo ves tu ordenador", ejecuta diagnostico_windows.bat y pon aqui
REM     el nombre de la tarjeta correcta que te indique (quita el REM):
REM set CONTROL_IFACE=Wi-Fi

REM Comprueba si ya somos administrador; si no, re-lanza elevado.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ============================================================
echo  ControlConexion - iniciando...
echo  Abre la direccion que aparece abajo en tu celular.
echo ============================================================
python control.py
pause
