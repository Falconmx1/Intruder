# 🕵️ Intruder - Anti-Intrusion & Malware Scanner

**Intruder** es una herramienta ligera para detectar:
- Conexiones y procesos sospechosos (Windows/Linux)
- Malware conocido (hash check + patrones)
- Escaneo de puertos locales anómalos
- Persistencia no autorizada (cron, tareas programadas, runkeys)

> ⚠️ Uso autorizado únicamente en entornos propios o con permiso explícito.

## 🚀 Características
- Banner sencillo con efecto ASCII
- Compatible con PowerShell (Win) y Bash (Linux)
- Modo rápido y modo verbose
- Reporte en JSON / TXT
- No requiere dependencias externas (usa comandos nativos)

## 📦 Instalación

```bash
git clone https://github.com/Falconmx1/Intruder.git
cd Intruder
chmod +x intruder.sh  # Linux
# Para Windows: ejecutar PowerShell como admin

🧪 Uso
Linux
bash

./intruder.sh
./intruder.sh --verbose
./intruder.sh --report

Windows (PowerShell)
powershell

Set-ExecutionPolicy Bypass -Scope Process
.\intruder.ps1

