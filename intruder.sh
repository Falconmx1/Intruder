#!/usr/bin/env bash

# ============================================
# INTRUDER v2.0 - Linux Security Scanner
# Features: External connections, suspicious processes,
# malware hashes, new users, listening ports, SUID files,
# email alerts, JSON output, file monitoring, diff mode
# ============================================

# ----- Configuración -----
WHITELIST_IPS=("127.0.0.1" "192.168.1.1")
WHITELIST_PROC=("sshd" "cron" "systemd")
MALWARE_HASH_FILE="malware_hashes.txt"
VT_API_KEY=""  # Opcional: pon tu clave o déjala vacía
ALERT_EMAIL="admin@example.com"  # Cambiar por email real
SMTP_SERVER=""  # Opcional para mail alternativo
REPORT_FILE="intruder_report_$(date +%Y%m%d_%H%M%S).txt"
JSON_FILE="intruder_$(date +%Y%m%d_%H%M%S).json"
MODE="quick"   # quick, verbose, server, watch, diff
SLEEP_SERVER=10  # segundos en modo server
ALERT_LEVEL=0  # 0=no alerts, 1=only critical, 2=all
MONITOR_DIRS=("/etc" "/usr/bin" "/home")
TEMP_ALERTS="/tmp/intruder_alerts.tmp"

# ----- Funciones Base -----
banner() {
    echo -e "\033[1;31m"
    cat << "EOF"
  ___        _           _           
 |_ _|_ __  (_)_ __   __| |_ __ ___  
  | || '_ \ | | '_ \ / _` | '__/ _ \ 
  | || | | || | | | | (_| | | |  __/ 
 |___|_| |_|/ |_| |_|\__,_|_|  \___|
          |__/                       
EOF
    echo -e "\033[0m"
    echo "===[ Linux Intruder Detector v2.0 ]====================="
    echo "[+] Modo: $MODE"
    echo "[+] Reporte: $REPORT_FILE"
    echo "========================================================"
}

log() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo -e "$msg"
    echo -e "$msg" >> "$REPORT_FILE"
    
    # Alertas por email si es crítico
    if [[ "$1" == *"ALERTA"* ]] || [[ "$1" == *"CRITICO"* ]]; then
        echo "$1" >> "$TEMP_ALERTS"
        if [[ "$ALERT_LEVEL" -ge 1 ]]; then
            send_email_alert "Intruder Alert" "$1"
        fi
    fi
}

check_deps() {
    local deps=("ss" "lsof" "systemctl" "crontab" "md5sum" "curl" "mail" "inotifywait")
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "[-] Faltan dependencias: ${missing[*]}"
        log "[*] Instalar con: apt install inotify-tools mailutils -y"
    fi
}

# ----- FEATURE: Email Alerts -----
send_email_alert() {
    local subject="$1"
    local body="$2"
    if command -v mail &> /dev/null; then
        echo -e "Intruder Detection Report\nTime: $(date)\n\n$body" | mail -s "[INTRUDER] $subject" "$ALERT_EMAIL"
        log "[+] Alerta enviada a $ALERT_EMAIL"
    else
        log "[-] Mail no disponible. Instalar mailutils"
    fi
}

# ----- FEATURE: JSON Output -----
init_json() {
    cat > "$JSON_FILE" << EOF
{
  "scan_time": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "mode": "$MODE",
  "alerts": []
}
EOF
}

add_json_alert() {
    local severity="$1"
    local finding="$2"
    local details="$3"
    local tmp_file=$(mktemp)
    jq --arg sev "$severity" --arg find "$finding" --arg det "$details" \
       '.alerts += [{"severity": $sev, "finding": $find, "details": $det}]' "$JSON_FILE" > "$tmp_file"
    mv "$tmp_file" "$JSON_FILE"
}

# ----- Core Detection Functions -----
check_external_connections() {
    log "\n[+] Conexiones externas activas (IPv4):"
    ss -tnu4 | tail -n +2 | while read -r line; do
        local ip_port=$(echo "$line" | awk '{print $5}')
        local ip=$(echo "$ip_port" | cut -d: -f1)
        if [[ " ${WHITELIST_IPS[@]} " =~ " ${ip} " ]]; then
            [[ "$MODE" == "verbose" ]] && log "    [INFO] Conexión whitelist: $line"
        elif [[ "$ip" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|127\.) ]]; then
            [[ "$MODE" == "verbose" ]] && log "    [INFO] Conexión local: $line"
        elif [[ "$ip" == "0.0.0.0" ]] || [[ -z "$ip" ]]; then
            log "    [WARN] Conexión a dirección wildcard: $line"
        else
            log "    [ALERTA] Conexión externa no autorizada: $line"
            add_json_alert "HIGH" "External Connection" "$line"
        fi
    done
}

check_suspicious_processes() {
    log "\n[+] Procesos con nombres sospechosos (ofuscación común):"
    ps aux | awk '{print $11}' | grep -v "^\[" | sort -u | while read -r proc; do
        [[ -z "$proc" ]] && continue
        base=$(basename "$proc")
        if [[ ${#base} -gt 30 ]] || [[ "$base" =~ ^[0-9a-zA-Z]{15,}$ ]]; then
            log "    [ALERTA] Proceso nombre largo/ofuscado: $proc"
            add_json_alert "MEDIUM" "Obfuscated Process" "$proc"
        elif [[ "$base" =~ (crypt|miner|backdoor|shell|reverse|payload|ransom|trojan) ]]; then
            log "    [CRITICO] Proceso malware naming: $proc"
            add_json_alert "CRITICAL" "Malware Pattern" "$proc"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Proceso normal: $proc"
        fi
    done
}

check_malware_hashes() {
    if [[ ! -f "$MALWARE_HASH_FILE" ]]; then
        log "\n[-] Archivo $MALWARE_HASH_FILE no encontrado."
        return
    fi
    log "\n[+] Buscando coincidencias con hashes maliciosos:"
    local count=0
    find /usr/bin /usr/sbin /bin /sbin /usr/local/bin -type f 2>/dev/null | while read -r bin; do
        hash=$(md5sum "$bin" 2>/dev/null | awk '{print $1}')
        if grep -qi "$hash" "$MALWARE_HASH_FILE"; then
            log "    [CRITICO] Hash malicioso: $bin (MD5: $hash)"
            add_json_alert "CRITICAL" "Malware Hash" "$bin - $hash"
            ((count++))
        fi
    done
}

check_new_users() {
    log "\n[+] Usuarios nuevos o extraños (UID >= 1000):"
    awk -F: '($3 >= 1000) {print $1":"$3":"$6}' /etc/passwd | while IFS=: read -r user uid home; do
        if [[ "$user" != "$(whoami)" ]] && [[ "$user" != "vagrant" ]] && [[ "$user" != "ubuntu" ]]; then
            log "    [ALERTA] Usuario no estándar: $user (UID: $uid, Home: $home)"
            add_json_alert "MEDIUM" "Suspicious User" "$user UID:$uid"
        fi
    done
}

check_listening_ports() {
    log "\n[+] Puertos en escucha (>1024 no autorizados):"
    ss -tln | awk 'NR>1 {print $4}' | cut -d: -f2 | sort -u | while read -r port; do
        if [[ "$port" -gt 1024 ]] && [[ "$port" -ne 8080 ]] && [[ "$port" -ne 3000 ]]; then
            log "    [ALERTA] Puerto alto en escucha: $port"
            add_json_alert "MEDIUM" "High Port Listening" "Port $port"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Puerto en escucha: $port"
        fi
    done
}

# ----- FEATURE: SUID Files -----
check_suid_files() {
    log "\n[+] Buscando archivos SUID/SGID sospechosos:"
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r file; do
        if [[ ! "$file" =~ ^/(usr/bin|usr/sbin|bin|sbin|usr/lib) ]]; then
            log "    [ALERTA] SUID/SGID inusual: $file"
            add_json_alert "HIGH" "Suspicious SUID" "$file"
        fi
    done
}

# ----- FEATURE: Persistencia (cron) -----
check_persistence() {
    log "\n[+] Tareas cron no estándar:"
    for user_cron in /var/spool/cron/crontabs/*; do
        [[ -f "$user_cron" ]] || continue
        while read -r line; do
            if [[ ! "$line" =~ ^# ]] && [[ -n "$line" ]]; then
                log "    [INFO] Cron job: $(basename "$user_cron") - $line"
                add_json_alert "LOW" "Cron Job" "$(basename $user_cron): $line"
            fi
        done < "$user_cron"
    done
}

# ----- FEATURE: VirusTotal API -----
vt_lookup() {
    if [[ -z "$VT_API_KEY" ]]; then
        log "\n[-] VirusTotal API key no configurada."
        return
    fi
    log "\n[+] Consultando VirusTotal para binarios sospechosos:"
    find /usr/bin /usr/sbin /bin /sbin -type f 2>/dev/null | head -5 | while read -r bin; do
        hash=$(md5sum "$bin" | awk '{print $1}')
        resp=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/$hash" --header "x-apikey: $VT_API_KEY" 2>/dev/null)
        if echo "$resp" | grep -q '"malicious":[1-9]'; then
            log "    [VT] ALERTA: $bin -> Posible malware"
            add_json_alert "CRITICAL" "VirusTotal Match" "$bin"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [VT] $bin -> Limpio"
        fi
        sleep 1  # Evitar rate limiting
    done
}

# ----- FEATURE: Monitoreo de archivos en tiempo real -----
watch_filesystem() {
    log "\n[!!] MODO WATCH ACTIVO - Monitoreando directorios: ${MONITOR_DIRS[*]}"
    log "[*] Eventos: create, modify, delete, move"
    if ! command -v inotifywait &> /dev/null; then
        log "[-] inotifywait no instalado. Ejecuta: apt install inotify-tools"
        return
    fi
    while true; do
        inotifywait -r -e create,modify,delete,move "${MONITOR_DIRS[@]}" 2>/dev/null | while read -r event; do
            log "    [ALERTA] Cambio en sistema de archivos: $event"
            add_json_alert "MEDIUM" "File System Change" "$event"
        done
    done
}

# ----- FEATURE: Modo comparativo (diff) -----
compare_with_last() {
    local last_report=$(ls -t intruder_report_*.txt 2>/dev/null | head -n2 | tail -n1)
    if [[ -f "$last_report" ]]; then
        log "\n[++] Cambios desde última ejecución ($last_report):"
        log "============================================="
        diff "$last_report" "$REPORT_FILE" | grep "^[<>]" | head -20 | while read -r line; do
            log "$line"
        done
    else
        log "\n[-] No hay reporte previo para comparar."
    fi
}

# ----- FEATURE: Modo server (monitoreo continuo) -----
server_loop() {
    log "\n[!!] MODO SERVER ACTIVO - Monitoreando cada $SLEEP_SERVER segundos (Ctrl+C para salir)"
    while true; do
        echo -e "\n--- $(date) ---" >> "$REPORT_FILE"
        check_external_connections
        check_suspicious_processes
        check_malware_hashes
        check_new_users
        check_listening_ports
        check_suid_files
        check_persistence
        if [[ -n "$VT_API_KEY" ]]; then vt_lookup; fi
        sleep "$SLEEP_SERVER"
    done
}

# ----- Main -----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) MODE="verbose" ;;
        --report) MODE="report" ;;
        --server) MODE="server"; SERVER_MODE=1 ;;
        --watch) MODE="watch"; WATCH_MODE=1 ;;
        --diff) MODE="diff" ;;
        --alert-level) ALERT_LEVEL="$2"; shift ;;
        --email) ALERT_EMAIL="$2"; shift ;;
        --vt-key) VT_API_KEY="$2"; shift ;;
        --whitelist-ip) WHITELIST_IPS+=("$2"); shift ;;
        --whitelist-proc) WHITELIST_PROC+=("$2"); shift ;;
        --help)
            echo "Uso: $0 [OPTIONS]"
            echo "Opciones:"
            echo "  --verbose           Modo verboso"
            echo "  --report            Generar reporte detallado"
            echo "  --server            Modo servidor (monitoreo continuo)"
            echo "  --watch             Monitorear sistema de archivos"
            echo "  --diff              Comparar con último reporte"
            echo "  --email EMAIL       Enviar alertas a EMAIL"
            echo "  --vt-key KEY        API key de VirusTotal"
            echo "  --whitelist-ip IP   Añadir IP a whitelist"
            exit 0
            ;;
        *) echo "Opción desconocida: $1"; exit 1 ;;
    esac
    shift
done

banner
check_deps
init_json

if [[ "$MODE" == "server" ]]; then
    server_loop
elif [[ "$MODE" == "watch" ]]; then
    watch_filesystem
else
    check_external_connections
    check_suspicious_processes
    check_malware_hashes
    check_new_users
    check_listening_ports
    check_suid_files
    check_persistence
    [[ -n "$VT_API_KEY" ]] && vt_lookup
    
    if [[ "$MODE" == "diff" ]]; then
        compare_with_last
    fi
    
    log "\n[+] Escaneo completado. Revisa $REPORT_FILE"
    log "[+] JSON exportado: $JSON_FILE"
    
    # Resumen de alertas
    if [[ -f "$TEMP_ALERTS" ]]; then
        alert_count=$(wc -l < "$TEMP_ALERTS")
        log "\n[!!!] Total de alertas: $alert_count"
        rm -f "$TEMP_ALERTS"
    fi
fi
