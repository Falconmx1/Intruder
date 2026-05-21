#!/usr/bin/env bash

# ============================================
# INTRUDER v2.0 - Linux Security Scanner
# Complete features: CIDR whitelist, Telegram/Slack alerts,
# Honeypot mode, VirusTotal API, JSON output, file watching,
# SUID checks, persistence monitoring, email alerts
# ============================================

# ----- Configuración -----
WHITELIST_IPS=("127.0.0.1")
WHITELIST_CIDR=("192.168.1.0/24" "10.0.0.0/8")
WHITELIST_PROC=("sshd" "cron" "systemd" "systemd-resolved")
MALWARE_HASH_FILE="malware_hashes.txt"
VT_API_KEY=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
SLACK_WEBHOOK_URL=""
ALERT_EMAIL="admin@example.com"
SMTP_SERVER=""
REPORT_FILE="intruder_report_$(date +%Y%m%d_%H%M%S).txt"
JSON_FILE="intruder_$(date +%Y%m%d_%H%M%S).json"
MODE="quick"
SLEEP_SERVER=10
ALERT_LEVEL=1
MONITOR_DIRS=("/etc" "/usr/bin" "/home")
HONEYPOT_PORTS=(22 23 80 443 8080 3389 5900)
HONEYPOT_LOG="honeypot_$(date +%Y%m%d).log"
TEMP_ALERTS="/tmp/intruder_alerts.tmp"

# ----- Colores para output -----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ----- Funciones Base -----
banner() {
    echo -e "${RED}"
    cat << "EOF"
  ___        _           _           
 |_ _|_ __  (_)_ __   __| |_ __ ___  
  | || '_ \ | | '_ \ / _` | '__/ _ \ 
  | || | | || | | | | (_| | | |  __/ 
 |___|_| |_|/ |_| |_|\__,_|_|  \___|
          |__/                       
EOF
    echo -e "${NC}"
    echo -e "${GREEN}===[ Linux Intruder Detector v2.0 ]=====================${NC}"
    echo "[+] Modo: $MODE"
    echo "[+] Reporte: $REPORT_FILE"
    echo "========================================================"
}

log() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo -e "$msg"
    echo -e "$msg" >> "$REPORT_FILE"
    
    if [[ "$1" == *"ALERTA"* ]] || [[ "$1" == *"CRITICO"* ]]; then
        echo "$1" >> "$TEMP_ALERTS"
        if [[ "$ALERT_LEVEL" -ge 1 ]]; then
            send_telegram_alert "$1"
            send_slack_alert "$1"
            send_email_alert "Intruder Alert" "$1"
        fi
    fi
}

check_deps() {
    local deps=("ss" "lsof" "systemctl" "crontab" "md5sum" "curl")
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "[-] Faltan dependencias: ${missing[*]}"
        log "[*] Instalar con: apt install -y curl netcat mailutils"
    fi
}

# ----- Alert Functions -----
send_telegram_alert() {
    local message="$1"
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="🚨 INTRUDER ALERT 🚨%0AHost: $(hostname)%0ATime: $(date)%0A%0A$message" \
            --max-time 5 > /dev/null 2>&1 &
    fi
}

send_slack_alert() {
    local message="$1"
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        local payload=$(cat <<EOF
{
  "text": "🚨 *INTRUDER ALERT* 🚨\nHost: $(hostname)\nTime: $(date)\n\n$message",
  "username": "Intruder Bot",
  "icon_emoji": ":shield:"
}
EOF
)
        curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK_URL" --max-time 5 > /dev/null 2>&1 &
    fi
}

send_email_alert() {
    local subject="$1"
    local body="$2"
    if command -v mail &> /dev/null; then
        echo -e "Intruder Detection Report\nTime: $(date)\nHost: $(hostname)\n\n$body" | \
            mail -s "[INTRUDER] $subject" "$ALERT_EMAIL" 2>/dev/null &
    fi
}

# ----- CIDR Functions -----
ip_to_dec() {
    local ip="$1"
    local a b c d
    IFS=. read -r a b c d <<< "$ip"
    echo $((a * 256**3 + b * 256**2 + c * 256 + d))
}

is_ip_in_cidr() {
    local ip="$1"
    local cidr="$2"
    local network=$(echo "$cidr" | cut -d'/' -f1)
    local mask=$(echo "$cidr" | cut -d'/' -f2)
    local ip_dec=$(ip_to_dec "$ip")
    local network_dec=$(ip_to_dec "$network")
    local mask_dec=$((0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF))
    (( (ip_dec & mask_dec) == (network_dec & mask_dec) ))
}

is_ip_whitelisted() {
    local ip="$1"
    [[ -z "$ip" || "$ip" == "0.0.0.0" ]] && return 0
    for wl_ip in "${WHITELIST_IPS[@]}"; do
        [[ "$wl_ip" == "$ip" ]] && return 0
    done
    for wl_cidr in "${WHITELIST_CIDR[@]}"; do
        is_ip_in_cidr "$ip" "$wl_cidr" && return 0
    done
    return 1
}

# ----- JSON Functions -----
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
    if command -v jq &> /dev/null; then
        jq --arg sev "$severity" --arg find "$finding" --arg det "$details" \
           '.alerts += [{"severity": $sev, "finding": $find, "details": $det, "time": "'$(date -Iseconds)'"}]' \
           "$JSON_FILE" > "$tmp_file" 2>/dev/null && mv "$tmp_file" "$JSON_FILE"
    fi
}

# ----- Core Detection Functions -----
check_external_connections() {
    log "\n[+] Conexiones externas activas (IPv4):"
    local count=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
        local port=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
        
        if is_ip_whitelisted "$ip"; then
            [[ "$MODE" == "verbose" ]] && log "    [INFO] Conexión whitelist: $ip:$port"
        elif [[ "$ip" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|127\.) ]]; then
            [[ "$MODE" == "verbose" ]] && log "    [INFO] Conexión local: $ip:$port"
        else
            log "    ${RED}[ALERTA] Conexión externa no autorizada: $ip:$port${NC}"
            add_json_alert "HIGH" "External Connection" "$ip:$port"
            ((count++))
        fi
    done < <(ss -tnu4 2>/dev/null | tail -n +2)
    
    [[ $count -eq 0 ]] && log "    No se encontraron conexiones externas sospechosas"
}

check_suspicious_processes() {
    log "\n[+] Procesos con nombres sospechosos:"
    local count=0
    while IFS= read -r proc; do
        [[ -z "$proc" ]] && continue
        local base=$(basename "$proc")
        if [[ ${#base} -gt 35 ]]; then
            log "    ${YELLOW}[ALERTA] Nombre de proceso muy largo: $proc${NC}"
            add_json_alert "MEDIUM" "Long Process Name" "$proc"
            ((count++))
        elif [[ "$base" =~ (crypt|miner|backdoor|shell|reverse|payload|ransom|trojan|rootkit|keylog|rat) ]]; then
            log "    ${RED}[CRITICO] Patrón de malware detectado: $proc${NC}"
            add_json_alert "CRITICAL" "Malware Pattern" "$proc"
            ((count++))
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Proceso: $proc"
        fi
    done < <(ps aux 2>/dev/null | awk '{print $11}' | grep -v "^\[" | sort -u)
    
    [[ $count -eq 0 ]] && log "    No se encontraron procesos sospechosos"
}

check_malware_hashes() {
    if [[ ! -f "$MALWARE_HASH_FILE" ]]; then
        log "\n[-] Archivo $MALWARE_HASH_FILE no encontrado"
        return
    fi
    log "\n[+] Buscando coincidencias con hashes maliciosos:"
    local count=0
    while IFS= read -r bin; do
        local hash=$(md5sum "$bin" 2>/dev/null | awk '{print $1}')
        if grep -qi "$hash" "$MALWARE_HASH_FILE" 2>/dev/null; then
            log "    ${RED}[CRITICO] Hash malicioso: $bin (MD5: $hash)${NC}"
            add_json_alert "CRITICAL" "Malware Hash" "$bin"
            ((count++))
        fi
    done < <(find /usr/bin /usr/sbin /bin /sbin /usr/local/bin -type f 2>/dev/null | head -50)
    
    [[ $count -eq 0 ]] && log "    No se encontraron hashes maliciosos"
}

check_new_users() {
    log "\n[+] Usuarios nuevos o extraños (UID >= 1000):"
    local count=0
    while IFS=: read -r user uid home; do
        if [[ "$user" != "$(whoami)" ]] && [[ "$user" != "vagrant" ]] && [[ "$user" != "ubuntu" ]] && [[ "$user" != "nobody" ]]; then
            log "    ${YELLOW}[ALERTA] Usuario no estándar: $user (UID: $uid, Home: $home)${NC}"
            add_json_alert "MEDIUM" "Suspicious User" "$user UID:$uid"
            ((count++))
        fi
    done < <(awk -F: '($3 >= 1000) {print $1":"$3":"$6}' /etc/passwd)
    
    [[ $count -eq 0 ]] && log "    No se encontraron usuarios extraños"
}

check_listening_ports() {
    log "\n[+] Puertos en escucha (>1024 no autorizados):"
    local count=0
    while IFS= read -r port; do
        if [[ "$port" -gt 1024 ]] && [[ "$port" -ne 8080 ]] && [[ "$port" -ne 3000 ]] && [[ "$port" -ne 5000 ]]; then
            log "    ${YELLOW}[ALERTA] Puerto alto en escucha: $port${NC}"
            add_json_alert "MEDIUM" "High Port Listening" "Port $port"
            ((count++))
        fi
    done < <(ss -tln 2>/dev/null | awk 'NR>1 {print $4}' | cut -d: -f2 | sort -u)
    
    [[ $count -eq 0 ]] && log "    No se encontraron puertos altos sospechosos"
}

check_suid_files() {
    log "\n[+] Buscando archivos SUID/SGID sospechosos:"
    local count=0
    while IFS= read -r file; do
        if [[ ! "$file" =~ ^/(usr/bin|usr/sbin|bin|sbin|usr/lib) ]]; then
            log "    ${YELLOW}[ALERTA] SUID/SGID inusual: $file${NC}"
            add_json_alert "HIGH" "Suspicious SUID" "$file"
            ((count++))
        fi
    done < <(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -30)
    
    [[ $count -eq 0 ]] && log "    No se encontraron SUID sospechosos"
}

check_persistence() {
    log "\n[+] Tareas cron no estándar:"
    local count=0
    for user_cron in /var/spool/cron/crontabs/*; do
        [[ -f "$user_cron" ]] || continue
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^# ]] && [[ -n "$line" ]]; then
                log "    ${YELLOW}[INFO] Cron job: $(basename "$user_cron") - $line${NC}"
                add_json_alert "LOW" "Cron Job" "$(basename $user_cron): $line"
                ((count++))
            fi
        done < "$user_cron"
    done
    
    [[ $count -eq 0 ]] && log "    No se encontraron cron jobs personalizados"
}

vt_lookup() {
    if [[ -z "$VT_API_KEY" ]]; then
        log "\n[-] VirusTotal API key no configurada"
        return
    fi
    log "\n[+] Consultando VirusTotal para binarios (primeros 5):"
    local count=0
    while IFS= read -r bin; do
        local hash=$(md5sum "$bin" 2>/dev/null | awk '{print $1}')
        local resp=$(curl -s --max-time 10 --request GET \
            --url "https://www.virustotal.com/api/v3/files/$hash" \
            --header "x-apikey: $VT_API_KEY" 2>/dev/null)
        
        if echo "$resp" | grep -q '"malicious":[1-9]'; then
            log "    ${RED}[VT] ALERTA: $bin -> Posible malware${NC}"
            add_json_alert "CRITICAL" "VirusTotal Match" "$bin"
            ((count++))
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [VT] $bin -> Limpio"
        fi
        sleep 1
    done < <(find /usr/bin /usr/sbin /bin /sbin -type f 2>/dev/null | head -5)
    
    [[ $count -eq 0 ]] && log "    No se detectaron amenazas en VirusTotal"
}

# ----- Honeypot Mode -----
start_honeypot() {
    log "\n${RED}[🍯] MODO HONEYPOT ACTIVADO${NC}"
    log "[*] Escuchando en puertos: ${HONEYPOT_PORTS[*]}"
    log "[*] Cualquier conexión será registrada como intruso"
    
    if ! command -v nc &> /dev/null; then
        log "[-] Netcat no instalado. Instalando..."
        sudo apt update && sudo apt install -y netcat-openbsd
    fi
    
    for port in "${HONEYPOT_PORTS[@]}"; do
        (
            while true; do
                local output=$(nc -lvnp "$port" 2>&1)
                if [[ -n "$output" ]]; then
                    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    local alert_msg="🍯 HONEYPOT: Conexión a puerto $port - $output"
                    echo "$timestamp - $alert_msg" | tee -a "$HONEYPOT_LOG"
                    log "    ${RED}[🍯 ALERTA] $alert_msg${NC}"
                    send_telegram_alert "$alert_msg"
                    send_slack_alert "$alert_msg"
                    add_json_alert "HIGH" "Honeypot Trigger" "Port $port - $output"
                fi
                sleep 1
            done
        ) &
        log "[+] Honeypot activo en puerto $port (PID: $!)"
    done
    
    log "\n[*] Honeypot corriendo. Presiona Ctrl+C para detener."
    wait
}

# ----- File System Watcher -----
watch_filesystem() {
    log "\n[!!] MODO WATCH ACTIVO - Monitoreando: ${MONITOR_DIRS[*]}"
    
    if ! command -v inotifywait &> /dev/null; then
        log "[-] inotifywait no instalado. Instalar con: apt install inotify-tools"
        return
    fi
    
    while true; do
        inotifywait -r -e create,modify,delete,move "${MONITOR_DIRS[@]}" 2>/dev/null | while read -r event; do
            log "    ${YELLOW}[ALERTA] Cambio en sistema de archivos: $event${NC}"
            add_json_alert "MEDIUM" "File System Change" "$event"
            send_telegram_alert "File system change: $event"
        done
    done
}

# ----- Server Mode -----
server_loop() {
    log "\n${GREEN}[!!] MODO SERVER ACTIVO - Monitoreando cada $SLEEP_SERVER segundos${NC}"
    log "[*] Presiona Ctrl+C para detener"
    
    while true; do
        echo -e "\n--- $(date) ---" >> "$REPORT_FILE"
        check_external_connections
        check_suspicious_processes
        check_malware_hashes
        check_new_users
        check_listening_ports
        check_suid_files
        check_persistence
        [[ -n "$VT_API_KEY" ]] && vt_lookup
        sleep "$SLEEP_SERVER"
    done
}

# ----- Compare Mode -----
compare_with_last() {
    local last_report=$(ls -t intruder_report_*.txt 2>/dev/null | head -n2 | tail -n1)
    if [[ -f "$last_report" ]]; then
        log "\n${GREEN}[++] Cambios desde última ejecución ($last_report):${NC}"
        log "============================================="
        diff "$last_report" "$REPORT_FILE" | grep "^[<>]" | head -20 | while read -r line; do
            log "$line"
        done
    else
        log "\n[-] No hay reporte previo para comparar"
    fi
}

# ----- Main -----
show_help() {
    cat << EOF
Uso: $0 [OPCIONES]

OPCIONES:
  --verbose               Modo verboso (muestra todo)
  --report                Generar reporte detallado
  --server                Modo servidor (monitoreo continuo)
  --watch                 Monitorear sistema de archivos
  --honeypot              Activar modo honeypot
  --diff                  Comparar con último reporte
  
  --email EMAIL           Enviar alertas a EMAIL
  --vt-key KEY            API key de VirusTotal
  --telegram-token TOKEN  Token de bot de Telegram
  --telegram-chat ID      Chat ID de Telegram
  --slack-webhook URL     Webhook URL de Slack
  
  --whitelist-ip IP       Añadir IP a whitelist
  --cidr-whitelist CIDR   Añadir rango CIDR a whitelist
  --whitelist-proc PROC   Añadir proceso a whitelist
  
  --help                  Mostrar esta ayuda

EJEMPLOS:
  $0 --verbose
  $0 --honeypot
  $0 --server --email admin@example.com
  $0 --telegram-token 123:abc --telegram-chat 456
EOF
    exit 0
}

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) MODE="verbose" ;;
        --report) MODE="report" ;;
        --server) MODE="server" ;;
        --watch) MODE="watch" ;;
        --honeypot) MODE="honeypot" ;;
        --diff) MODE="diff" ;;
        --email) ALERT_EMAIL="$2"; shift ;;
        --vt-key) VT_API_KEY="$2"; shift ;;
        --telegram-token) TELEGRAM_BOT_TOKEN="$2"; shift ;;
        --telegram-chat) TELEGRAM_CHAT_ID="$2"; shift ;;
        --slack-webhook) SLACK_WEBHOOK_URL="$2"; shift ;;
        --whitelist-ip) WHITELIST_IPS+=("$2"); shift ;;
        --cidr-whitelist) WHITELIST_CIDR+=("$2"); shift ;;
        --whitelist-proc) WHITELIST_PROC+=("$2"); shift ;;
        --help) show_help ;;
        *) echo "Opción desconocida: $1"; show_help ;;
    esac
    shift
done

# Ejecutar
banner
check_deps
init_json

case "$MODE" in
    server) server_loop ;;
    watch) watch_filesystem ;;
    honeypot) start_honeypot ;;
    *)
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
        
        log "\n${GREEN}[+] Escaneo completado. Revisa $REPORT_FILE${NC}"
        log "[+] JSON exportado: $JSON_FILE"
        
        if [[ -f "$TEMP_ALERTS" ]]; then
            local alert_count=$(wc -l < "$TEMP_ALERTS")
            log "${RED}[!!!] Total de alertas: $alert_count${NC}"
            rm -f "$TEMP_ALERTS"
        fi
        ;;
esac
