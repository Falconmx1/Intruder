#!/usr/bin/env bash

# ============================================
# INTRUDER v1.0 - Linux Security Scanner
# Features: External connections, suspicious processes,
# malware hashes, new users, listening ports,
# VirusTotal API (opt), server mode, whitelisting
# ============================================

# ----- Configuración -----
WHITELIST_IPS=("127.0.0.1" "192.168.1.1")
WHITELIST_PROC=("sshd" "cron" "systemd")
MALWARE_HASH_FILE="malware_hashes.txt"
VT_API_KEY=""  # Opcional: pon tu clave o déjala vacía
REPORT_FILE="intruder_report_$(date +%Y%m%d_%H%M%S).txt"
MODE="quick"   # quick, verbose, server
SLEEP_SERVER=10  # segundos en modo server

# ----- Funciones -----
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
    echo "===[ Linux Intruder Detector v1.0 ]====================="
    echo "[+] Modo: $MODE"
    echo "[+] Reporte: $REPORT_FILE"
    echo "========================================================"
}

log() {
    echo -e "$1"
    echo -e "$1" >> "$REPORT_FILE"
}

check_deps() {
    local deps=("ss" "lsof" "systemctl" "crontab" "md5sum" "curl")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log "[-] Falta dependencia: $dep (instala con tu gestor de paquetes)"
        fi
    done
}

check_external_connections() {
    log "\n[+] Conexiones externas activas (IPv4):"
    ss -tnu4 | tail -n +2 | while read -r line; do
        local ip_port=$(echo "$line" | awk '{print $5}')
        local ip=$(echo "$ip_port" | cut -d: -f1)
        if [[ ! " ${WHITELIST_IPS[@]} " =~ " ${ip} " ]] && [[ ! "$ip" =~ ^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.|^127\. ]]; then
            log "    [ALERTA] Conexión externa no autorizada: $line"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Conexión whitelist/local: $line"
        fi
    done
}

check_suspicious_processes() {
    log "\n[+] Procesos con nombres sospechosos (ofuscación común):"
    ps aux | awk '{print $11}' | grep -v "^\[" | while read -r proc; do
        base=$(basename "$proc")
        if [[ ${#base} -gt 30 ]] || [[ "$base" =~ ^[0-9a-zA-Z]{15,}$ ]] || [[ "$base" =~ (crypt|miner|backdoor|shell|reverse|payload) ]]; then
            log "    [ALERTA] Proceso ofuscado/sospechoso: $proc"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Proceso normal: $proc"
        fi
    done
}

check_malware_hashes() {
    if [[ ! -f "$MALWARE_HASH_FILE" ]]; then
        log "\n[-] Archivo $MALWARE_HASH_FILE no encontrado. Omisión de chequeo por hash."
        return
    fi
    log "\n[+] Buscando coincidencias con hashes maliciosos:"
    find /usr/bin /usr/sbin /bin /sbin /usr/local/bin -type f 2>/dev/null | while read -r bin; do
        hash=$(md5sum "$bin" 2>/dev/null | awk '{print $1}')
        if grep -qi "$hash" "$MALWARE_HASH_FILE"; then
            log "    [CRITICO] Hash malicioso detectado en: $bin (MD5: $hash)"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Hash limpio: $bin"
        fi
    done
}

check_new_users() {
    log "\n[+] Usuarios nuevos o extraños (UID >= 1000):"
    awk -F: '($3 >= 1000) {print $1}' /etc/passwd | while read -r user; do
        if [[ "$user" != "$(whoami)" ]] && [[ "$user" != "vagrant" ]]; then
            log "    [ALERTA] Usuario no estándar detectado: $user"
        fi
    done
}

check_listening_ports() {
    log "\n[+] Puertos en escucha (>1024 no autorizados):"
    ss -tln | awk 'NR>1 {print $4}' | cut -d: -f2 | sort -u | while read -r port; do
        if [[ "$port" -gt 1024 ]]; then
            log "    [ALERTA] Puerto >1024 en escucha: $port"
        elif [[ "$MODE" == "verbose" ]]; then
            log "    [INFO] Puerto privilegiado en escucha: $port"
        fi
    done
}

vt_lookup() {
    if [[ -z "$VT_API_KEY" ]]; then
        log "\n[-] VirusTotal API key no configurada."
        return
    fi
    log "\n[+] Consultando VirusTotal para hashes de binarios sospechosos (primeros 5):"
    find /usr/bin /usr/sbin /bin /sbin -type f 2>/dev/null | head -5 | while read -r bin; do
        hash=$(md5sum "$bin" | awk '{print $1}')
        resp=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/$hash" --header "x-apikey: $VT_API_KEY")
        if echo "$resp" | grep -q '"malicious":'; then
            log "    [VT] $bin -> Posible malware según VT"
        fi
    done
}

server_loop() {
    log "\n[!!] MODO SERVER ACTIVO - Monitoreando cada $SLEEP_SERVER segundos (Ctrl+C para salir)"
    while true; do
        echo -e "\n--- $(date) ---" >> "$REPORT_FILE"
        check_external_connections
        check_suspicious_processes
        check_malware_hashes
        check_new_users
        check_listening_ports
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
        --whitelist-ip) WHITELIST_IPS+=("$2"); shift ;;
        --whitelist-proc) WHITELIST_PROC+=("$2"); shift ;;
        --vt-key) VT_API_KEY="$2"; shift ;;
        *) echo "Uso: $0 [--verbose] [--report] [--server] [--whitelist-ip IP] [--whitelist-proc PROC] [--vt-key KEY]" ; exit 1 ;;
    esac
    shift
done

banner
check_deps

if [[ "$MODE" == "server" ]]; then
    server_loop
else
    check_external_connections
    check_suspicious_processes
    check_malware_hashes
    check_new_users
    check_listening_ports
    if [[ -n "$VT_API_KEY" ]]; then vt_lookup; fi
    log "\n[+] Escaneo completado. Revisa $REPORT_FILE"
fi
