@echo off
REM Diagnostico de ControlConexion (Windows) - se eleva a Administrador.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
python diagnostico.py
echo.
pause
