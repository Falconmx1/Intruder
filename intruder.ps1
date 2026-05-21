# ============================================
# INTRUDER v1.0 - Windows Security Scanner
# Features: External connections, suspicious processes,
# malware hashes, new users, listening ports,
# VirusTotal API (opt), server mode, whitelisting
# ============================================

# ----- Configuración -----
$WHITELIST_IPS = @("127.0.0.1", "192.168.1.1")
$WHITELIST_PROC = @("System", "svchost", "explorer")
$MALWARE_HASH_FILE = "malware_hashes.txt"
$VT_API_KEY = ""  # Opcional: pon tu clave
$REPORT_FILE = "intruder_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$MODE = "quick"
$SLEEP_SERVER = 10

# ----- Funciones -----
function Show-Banner {
    Write-Host @"
  ___        _           _           
 |_ _|_ __  (_)_ __   __| |_ __ ___  
  | || '_ \ | | '_ \ / _` | '__/ _ \ 
  | || | | || | | | | (_| | | |  __/ 
 |___|_| |_|/ |_| |_|\__,_|_|  \___|
          |__/                       
"@ -ForegroundColor Red
    Write-Host "===[ Windows Intruder Detector v1.0 ]====================="
    Write-Host "[+] Modo: $MODE"
    Write-Host "[+] Reporte: $REPORT_FILE"
    Write-Host "========================================================"
}

function Log-Message {
    param([string]$Message)
    $timestamped = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $timestamped
    Add-Content -Path $REPORT_FILE -Value $timestamped
}

function Check-ExternalConnections {
    Log-Message "`n[+] Conexiones externas activas (IPv4):"
    $connections = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -ne "::" -and $_.RemoteAddress -ne "0.0.0.0" -and $_.State -eq "Established" }
    foreach ($conn in $connections) {
        $ip = $conn.RemoteAddress
        if ($WHITELIST_IPS -notcontains $ip -and $ip -notmatch "^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.|^127\.") {
            Log-Message "    [ALERTA] Conexión externa no autorizada: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
        } elseif ($MODE -eq "verbose") {
            Log-Message "    [INFO] Conexión whitelist/local: $($conn.RemoteAddress)"
        }
    }
}

function Check-SuspiciousProcesses {
    Log-Message "`n[+] Procesos con nombres sospechosos (ofuscación común):"
    $procs = Get-Process | Where-Object { $_.Path -ne $null }
    foreach ($proc in $procs) {
        $name = $proc.ProcessName
        if ($name.Length -gt 30 -or $name -match '^[0-9a-zA-Z]{15,}$' -or $name -match '(crypt|miner|backdoor|shell|reverse|payload)') {
            Log-Message "    [ALERTA] Proceso ofuscado/sospechoso: $name (PID: $($proc.Id))"
        } elseif ($MODE -eq "verbose") {
            Log-Message "    [INFO] Proceso normal: $name"
        }
    }
}

function Check-MalwareHashes {
    if (-not (Test-Path $MALWARE_HASH_FILE)) {
        Log-Message "`n[-] Archivo $MALWARE_HASH_FILE no encontrado. Omisión de chequeo por hash."
        return
    }
    Log-Message "`n[+] Buscando coincidencias con hashes maliciosos (solo System32):"
    $files = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 20
    foreach ($file in $files) {
        $hash = (Get-FileHash $file.FullName -Algorithm MD5).Hash
        if (Select-String -Path $MALWARE_HASH_FILE -Pattern $hash -Quiet) {
            Log-Message "    [CRITICO] Hash malicioso detectado en: $($file.Name) (MD5: $hash)"
        } elseif ($MODE -eq "verbose") {
            Log-Message "    [INFO] Hash limpio: $($file.Name)"
        }
    }
}

function Check-NewUsers {
    Log-Message "`n[+] Usuarios locales nuevos o extraños (no built-in):"
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notin @("Administrator", "DefaultAccount", "Guest") }
    foreach ($user in $users) {
        Log-Message "    [ALERTA] Usuario no estándar detectado: $($user.Name)"
    }
}

function Check-ListeningPorts {
    Log-Message "`n[+] Puertos en escucha (>1024 no autorizados):"
    $ports = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object -ExpandProperty LocalPort -Unique
    foreach ($port in $ports) {
        if ($port -gt 1024) {
            Log-Message "    [ALERTA] Puerto >1024 en escucha: $port"
        } elseif ($MODE -eq "verbose") {
            Log-Message "    [INFO] Puerto privilegiado en escucha: $port"
        }
    }
}

function Invoke-VirusTotalLookup {
    if ([string]::IsNullOrEmpty($VT_API_KEY)) {
        Log-Message "`n[-] VirusTotal API key no configurada."
        return
    }
    Log-Message "`n[+] Consultando VirusTotal para hashes de binarios sospechosos (primeros 5):"
    $files = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 5
    foreach ($file in $files) {
        $hash = (Get-FileHash $file.FullName -Algorithm MD5).Hash
        $headers = @{ "x-apikey" = $VT_API_KEY }
        $uri = "https://www.virustotal.com/api/v3/files/$hash"
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            if ($resp.data.attributes.last_analysis_stats.malicious -gt 0) {
                Log-Message "    [VT] $($file.Name) -> Posible malware según VT"
            }
        } catch {
            Log-Message "    [VT] Error consultando $($file.Name)"
        }
    }
}

function Start-ServerLoop {
    Log-Message "`n[!!] MODO SERVER ACTIVO - Monitoreando cada $SLEEP_SERVER segundos (Ctrl+C para salir)"
    while ($true) {
        Add-Content -Path $REPORT_FILE -Value "`n--- $(Get-Date) ---"
        Check-ExternalConnections
        Check-SuspiciousProcesses
        Check-MalwareHashes
        Check-NewUsers
        Check-ListeningPorts
        if ($VT_API_KEY) { Invoke-VirusTotalLookup }
        Start-Sleep -Seconds $SLEEP_SERVER
    }
}

# ----- Main -----
# Parsear argumentos estilo PowerShell (--opcion valor)
for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "--verbose" { $MODE = "verbose" }
        "--report" { $MODE = "report" }
        "--server" { $MODE = "server"; $global:SERVER_MODE = $true }
        "--whitelist-ip" { $WHITELIST_IPS += $args[$i+1]; $i++ }
        "--whitelist-proc" { $WHITELIST_PROC += $args[$i+1]; $i++ }
        "--vt-key" { $VT_API_KEY = $args[$i+1]; $i++ }
        default { Write-Host "Uso: .\intruder.ps1 [--verbose] [--report] [--server] [--whitelist-ip IP] [--whitelist-proc PROC] [--vt-key KEY]"; exit 1 }
    }
}

Show-Banner

if ($MODE -eq "server") {
    Start-ServerLoop
} else {
    Check-ExternalConnections
    Check-SuspiciousProcesses
    Check-MalwareHashes
    Check-NewUsers
    Check-ListeningPorts
    if ($VT_API_KEY) { Invoke-VirusTotalLookup }
    Log-Message "`n[+] Escaneo completado. Revisa $REPORT_FILE"
}
