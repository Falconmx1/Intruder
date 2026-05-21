# Changelog - Intruder

Todas las versiones notables de Intruder serán documentadas aquí.

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), y el versionado sigue [SemVer](https://semver.org/lang/es/).

## [Unreleased]

### Próximamente
- Integración con Slack/Telegram para alertas
- Escaneo de puertos abiertos (port knocking detection)
- Modo "honeypot" ligero

---

## [1.0.0] - 2026-05-21

### ✨ Añadido (Features)
- **Detección de conexiones externas** no autorizadas
- **Procesos con nombres ofuscados** (largo >30 o random)
- **Chequeo de malware por hash** (archivo `malware_hashes.txt`)
- **Usuarios nuevos o extraños** (UID >=1000 en Linux, no estándar en Windows)
- **Puertos en escucha >1024** (no autorizados)
- **Integración opcional con VirusTotal API**
- **Modo server** (monitoreo continuo cada N segundos)
- **Whitelisting** por IP y proceso
- **Banner ASCII** con efecto visual
- **Reporte en TXT** con timestamp

### 🐛 Corregido (Fixed)
- N/A (versión inicial)

### 🔧 Cambiado (Changed)
- N/A (versión inicial)

### 🗑️ Deprecado (Deprecated)
- N/A (versión inicial)

### 🛡️ Seguridad
- Chequeo de hashes MD5 contra lista local
- Detección de patrones comunes de malware en nombres de proceso

---

## [0.1.0] - 2026-05-20 (Pre-release)

### ✨ Añadido
- Esqueleto básico de scripts
- README.md con instrucciones
- Licencia MIT

### 🔧 Cambiado
- N/A (versión inicial de concepto)

---

## Cómo actualizar

### Linux
```bash
cd /path/to/Intruder
git pull origin main
chmod +x intruder.sh
