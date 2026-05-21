# Política de Seguridad - Intruder

## 🔒 Reportando vulnerabilidades

**Si descubres una vulnerabilidad de seguridad en Intruder:**

1. **NO** abras un issue público
2. Envía un reporte detallado a través de [GitHub Security Advisories](https://github.com/Falconmx1/Intruder/security/advisories/new)
3. Alternativamente, contacta directamente al mantenedor via [GitHub Issues](https://github.com/Falconmx1/Intruder/issues) con el prefijo `[SECURITY]`

### Qué incluir en tu reporte:
- Versión afectada (ej: v1.0.0, main branch)
- Pasos para reproducir la vulnerabilidad
- Impacto potencial (ej: ejecución de código, escalada de privilegios)
- Propuesta de fix (opcional)

### Expectativas:
- **Respuesta inicial**: dentro de 48 horas
- **Actualizaciones**: cada 7 días hasta resolver
- **Crédito público**: serás reconocido (si lo deseas) después del fix

## ✅ Versiones soportadas

| Versión | Soportada | SO |
|---------|-----------|-----|
| v1.0.x   | ✅ | Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+) |
| v1.0.x   | ✅ | Windows (10, 11, Server 2019/2022) |
| < 1.0    | ❌ | No recomendado para producción |

## 🛡️ Buenas prácticas al usar Intruder

### Para usuarios:
1. **Ejecutar siempre con privilegios mínimos** (no root/admin si no es necesario)
2. **Revisar `malware_hashes.txt`** - actualiza la lista regularmente
3. **Usar whitelisting** para evitar falsos positivos
4. **API keys** (VirusTotal, Telegram, Slack) - almacenar como variables de entorno, no hardcodear

### Para contribuyentes:
1. **No introducir backdoors** - el código es revisado
2. **Escapar correctamente inputs** para evitar injection
3. **Evitar dependencias externas** siempre que sea posible
4. **No loguear información sensible** (contraseñas, keys)

## 🔐 Autenticación y permisos

Intruder **no requiere**:
- Acceso a red externa (excepto API opcionales)
- Elevación de privilegios permanente (solo durante ejecución)
- Modificar configuraciones del sistema

Intruder **puede requerir** para funciones completas:
- En Linux: `sudo` para ver conexiones de otros usuarios
- En Windows: Ejecutar como Administrator para procesos del sistema

## 📦 Integridad del código

Verifica la autenticidad de los scripts:

```bash
# Linux - Verificar hash del script descargado
curl -s https://raw.githubusercontent.com/Falconmx1/Intruder/main/intruder.sh | sha256sum

# Windows - Verificar hash
(Get-FileHash .\intruder.ps1 -Algorithm SHA256).Hash
