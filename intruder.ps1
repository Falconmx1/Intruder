# ============================================
# INTRUDER v2.0 - Windows Security Scanner
# Complete features: CIDR whitelist, Telegram/Slack alerts,
# Honeypot mode, VirusTotal API, JSON output,
# Scheduled tasks, file watcher, email alerts
# ============================================

# ----- Configuración -----
$WHITELIST_IPS = @("127.0.0.1")
$WHITELIST_CIDR = @("192.168.1.0/24", "10.0.0.0/8")
$WHITELIST_PROC = @("System", "svchost", "explorer", "Idle")
$MALWARE_HASH_FILE = "malware_hashes.txt"
$VT_API_KEY = ""
$TELEGRAM_BOT_TOKEN = ""
$TELEGRAM_CHAT_ID = ""
$SLACK_WEBHOOK_URL = ""
$ALERT_EMAIL = "admin@example.com"
$SMTP_SERVER = "smtp.gmail.com"
$SMTP_PORT = 587
$REPORT_FILE = "intruder_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$JSON_FILE = "intruder_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$MODE = "quick"
$SLEEP_SERVER = 10
$ALERT_LEVEL = 1
$MONITOR_DIRS = @("$env:SystemRoot\System32", "$env:ProgramFiles")
$HONEYPOT_PORTS = @(22, 23, 80, 443, 3389, 8080, 5900)
$HONEYPOT_LOG = "honeypot_$(Get-Date -Format 'yyyyMMdd').log"
$TEMP_ALERTS = "$env:TEMP\intruder_alerts.txt"

# ----- Colores -----
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"

# ----- Funciones Base -----
function Show-Banner {
    Write-Host @"
  ___        _           _           
 |_ _|_ __  (_)_ __   __| |_ __ ___  
  | || '_ \ | | '_ \ / _` | '__/ _ \ 
  | || | | || | | | | (_| | | |  __/ 
 |___|_| |_|/ |_| |_|\__,_|_|  \___|
          |__/                       
"@ -ForegroundColor $RED
    Write-Host "===[ Windows Intruder Detector v2.0 ]=====================" -ForegroundColor $GREEN
    Write-Host "[+] Modo: $MODE"
    Write-Host "[+] Reporte: $REPORT_FILE"
    Write-Host "========================================================"
}

function Log-Message {
    param([string]$Message)
    $timestamped = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    
    if ($Message -match "ALERTA") {
        Write-Host $timestamped -ForegroundColor $YELLOW
    } elseif ($Message -match "CRITICO") {
        Write-Host $timestamped -ForegroundColor $RED
    } else {
        Write-Host $timestamped
    }
    
    Add-Content -Path $REPORT_FILE -Value $timestamped
    
    if ($Message -match "ALERTA|CRITICO" -and $ALERT_LEVEL -ge 1) {
        Add-Content -Path $TEMP_ALERTS -Value $Message
        Send-TelegramAlert $Message
        Send-SlackAlert $Message
        Send-EmailAlert "Intruder Alert" $Message
    }
}

# ----- Alert Functions -----
function Send-TelegramAlert {
    param([string]$Message)
    if ($TELEGRAM_BOT_TOKEN -and $TELEGRAM_CHAT_ID) {
        $text = [uri]::EscapeDataString("🚨 INTRUDER ALERT 🚨`nHost: $env:COMPUTERNAME`nTime: $(Get-Date)`n`n$Message")
        $url = "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage?chat_id=${TELEGRAM_CHAT_ID}&text=$text"
        try {
            Invoke-RestMethod -Uri $url -Method Get -ErrorAction SilentlyContinue
        } catch {}
    }
}

function Send-SlackAlert {
    param([string]$Message)
    if ($SLACK_WEBHOOK_URL) {
        $payload = @{
            text = "🚨 *INTRUDER ALERT* 🚨`nHost: $env:COMPUTERNAME`nTime: $(Get-Date)`n`n$Message"
            username = "Intruder Bot"
            icon_emoji = ":shield:"
        } | ConvertTo-Json
        try {
            Invoke-RestMethod -Uri $SLACK_WEBHOOK_URL -Method Post -Body $payload -ContentType "application/json" -ErrorAction SilentlyContinue
        } catch {}
    }
}

function Send-EmailAlert {
    param($Subject, $Body)
    if ($ALERT_EMAIL -ne "admin@example.com" -and $SMTP_SERVER) {
        try {
            Send-MailMessage -SmtpServer $SMTP_SERVER -Port $SMTP_PORT -UseSsl `
                -From $ALERT_EMAIL -To $ALERT_EMAIL -Subject "[INTRUDER] $Subject" `
                -Body "Time: $(Get-Date)`nHost: $env:COMPUTERNAME`n`n$Body" `
                -ErrorAction SilentlyContinue
        } catch {}
    }
}

# ----- CIDR Functions -----
function Test-IpInCidr {
    param([string]$IP, [string]$CIDR)
    $network, $maskBits = $CIDR -split '/'
    $maskBits = [int]$maskBits
    $ipInt = ([System.Net.IPAddress]$IP).Address
    $networkInt = ([System.Net.IPAddress]$network).Address
    $mask = [uint32]::MaxValue -shl (32 - $maskBits)
    ($ipInt -band $mask) -eq ($networkInt -band $mask)
}

function Test-IpWhitelisted {
    param([string]$IP)
    if (-not $IP -or $IP -eq "0.0.0.0") { return $true }
    if ($WHITELIST_IPS -contains $IP) { return $true }
    foreach ($cidr in $WHITELIST_CIDR) {
        if (Test-IpInCidr -IP $IP -CIDR $cidr) { return $true }
    }
    return $false
}

# ----- JSON Functions -----
function Initialize-Json {
    $jsonObj = @{
        scan_time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        hostname = $env:COMPUTERNAME
        mode = $MODE
        alerts = @()
    }
    $jsonObj | ConvertTo-Json -Depth 3 | Set-Content -Path $JSON_FILE
}

function Add-JsonAlert {
    param($Severity, $Finding, $Details)
    if (Test-Path $JSON_FILE) {
        try {
            $json = Get-Content $JSON_FILE -Raw | ConvertFrom-Json
            $json.alerts += @{
                severity = $Severity
                finding = $Finding
                details = $Details
                time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $json | ConvertTo-Json -Depth 3 | Set-Content -Path $JSON_FILE
        } catch {}
    }
}

# ----- Core Detection Functions -----
function Check-ExternalConnections {
    Log-Message "`n[+] Conexiones externas activas (IPv4):"
    $count = 0
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { 
            $_.State -eq "Established" -and $_.RemoteAddress -notin @("::", "0.0.0.0")
        }
        foreach ($conn in $connections) {
            $ip = $conn.RemoteAddress
            if (Test-IpWhitelisted $ip) {
                if ($MODE -eq "verbose") { Log-Message "    [INFO] Conexión whitelist: $ip" }
            }
            elseif ($ip -match "^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.|^127\.") {
                if ($MODE -eq "verbose") { Log-Message "    [INFO] Conexión local: $ip" }
            }
            else {
                Log-Message "    [ALERTA] Conexión externa: $($conn.LocalAddress):$($conn.LocalPort) -> $ip`:$($conn.RemotePort)"
                Add-JsonAlert -Severity "HIGH" -Finding "External Connection" -Details "$ip`:$($conn.RemotePort)"
                $count++
            }
        }
    } catch {}
    if ($count -eq 0) { Log-Message "    No se encontraron conexiones externas sospechosas" }
}

function Check-SuspiciousProcesses {
    Log-Message "`n[+] Procesos con nombres sospechosos:"
    $count = 0
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
        foreach ($proc in $procs) {
            $name = $proc.ProcessName
            if ($name.Length -gt 35) {
                Log-Message "    [ALERTA] Nombre muy largo: $name (PID: $($proc.Id))"
                Add-JsonAlert -Severity "MEDIUM" -Finding "Long Process Name" -Details "$name PID:$($proc.Id)"
                $count++
            }
            elseif ($name -match '(crypt|miner|backdoor|shell|reverse|payload|ransom|trojan|keylog|rat)') {
                Log-Message "    [CRITICO] Patrón malware: $name (PID: $($proc.Id))"
                Add-JsonAlert -Severity "CRITICAL" -Finding "Malware Pattern" -Details "$name PID:$($proc.Id)"
                $count++
            }
            elseif ($MODE -eq "verbose") {
                Log-Message "    [INFO] Proceso: $name"
            }
        }
    } catch {}
    if ($count -eq 0) { Log-Message "    No se encontraron procesos sospechosos" }
}

function Check-MalwareHashes {
    if (-not (Test-Path $MALWARE_HASH_FILE)) {
        Log-Message "`n[-] Archivo $MALWARE_HASH_FILE no encontrado"
        return
    }
    Log-Message "`n[+] Buscando coincidencias con hashes maliciosos:"
    $count = 0
    try {
        $files = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 30
        foreach ($file in $files) {
            $hash = (Get-FileHash $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            if ($hash -and (Select-String -Path $MALWARE_HASH_FILE -Pattern $hash -Quiet -ErrorAction SilentlyContinue)) {
                Log-Message "    [CRITICO] Hash malicioso: $($file.Name) (MD5: $hash)"
                Add-JsonAlert -Severity "CRITICAL" -Finding "Malware Hash" -Details "$($file.Name) - $hash"
                $count++
            }
        }
    } catch {}
    if ($count -eq 0) { Log-Message "    No se encontraron hashes maliciosos" }
}

function Check-NewUsers {
    Log-Message "`n[+] Usuarios locales nuevos o extraños:"
    $count = 0
    try {
        $users = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { 
            $_.Enabled -and $_.Name -notin @("Administrator", "DefaultAccount", "Guest")
        }
        foreach ($user in $users) {
            Log-Message "    [ALERTA] Usuario no estándar: $($user.Name)"
            Add-JsonAlert -Severity "MEDIUM" -Finding "Suspicious User" -Details $user.Name
            $count++
        }
    } catch {}
    if ($count -eq 0) { Log-Message "    No se encontraron usuarios extraños" }
}

function Check-ListeningPorts {
    Log-Message "`n[+] Puertos en escucha (>1024 no autorizados):"
    $count = 0
    try {
        $ports = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Listen" } | 
                 Select-Object -ExpandProperty LocalPort -Unique
        foreach ($port in $ports) {
            if ($port -gt 1024 -and $port -notin @(8080, 3000, 5000, 8000)) {
                Log-Message "    [ALERTA] Puerto alto escuchando: $port"
                Add-JsonAlert -Severity "MEDIUM" -Finding "High Port Listening" -Details "Port $port"
                $count++
            }
        }
    } catch {}
    if ($count -eq 0) { Log-Message "    No se encontraron puertos altos sospechosos" }
}

function Check-ScheduledTasks {
    Log-Message "`n[+] Tareas programadas sospechosas:"
    $count = 0
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
            $_.TaskPath -notlike "*Microsoft*" -and $_.State -ne "Disabled"
        } | Select-Object -First 20
        foreach ($task in $tasks) {
            Log-Message "    [ALERTA] Tarea no Microsoft: $($task.TaskName) (Path: $($task.TaskPath))"
            Add-JsonAlert -Severity "MEDIUM" -Finding "Suspicious Scheduled Task" -Details $task.TaskName
            $count++
        }
    } catch {}
    if ($count -eq 0) { Log-Message "    No se encontraron tareas programadas sospechosas" }
}

function Invoke-VirusTotalLookup {
    if ([string]::IsNullOrEmpty($VT_API_KEY)) {
        Log-Message "`n[-] VirusTotal API key no configurada"
        return
    }
    Log-Message "`n[+] Consultando VirusTotal para binarios (primeros 5):"
    $count = 0
    try {
        $files = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 5
        foreach ($file in $files) {
            $hash = (Get-FileHash $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            if ($hash) {
                $headers = @{ "x-apikey" = $VT_API_KEY }
                $uri = "https://www.virustotal.com/api/v3/files/$hash"
                try {
                    $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                    if ($resp.data.attributes.last_analysis_stats.malicious -gt 0) {
                        Log-Message "    [VT] ALERTA: $($file.Name) -> Posible malware"
                        Add-JsonAlert -Severity "CRITICAL" -Finding "VirusTotal Match" -Details $file.Name
                        $count++
                    } elseif ($MODE -eq "verbose") {
                        Log-Message "    [VT] $($file.Name) -> Limpio"
                    }
                } catch {}
                Start-Sleep -Seconds 1
            }
        }
    } catch {}
    if ($count -eq 0 -and $MODE -eq "verbose") { Log-Message "    No se detectaron amenazas en VirusTotal" }
}

# ----- Honeypot Mode -----
function Start-Honeypot {
    Log-Message "`n[🍯] MODO HONEYPOT ACTIVADO" -ForegroundColor $RED
    Log-Message "[*] Escuchando en puertos: $($HONEYPOT_PORTS -join ', ')"
    
    foreach ($port in $HONEYPOT_PORTS) {
        Start-Job -ScriptBlock {
            param($p, $logFile)
            try {
                $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $p)
                $listener.Start()
                while ($true) {
                    $client = $listener.AcceptTcpClient()
                    $ip = $client.Client.RemoteEndPoint.Address.ToString()
                    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    $alert = "🍯 HONEYPOT: Conexión a puerto $p desde $ip"
                    Add-Content -Path $logFile -Value "$timestamp - $alert"
                    Write-Host "    [🍯 ALERTA] $alert" -ForegroundColor Yellow
                    $client.Close()
                    
                    # Enviar alertas
                    if ($using:TELEGRAM_BOT_TOKEN) { 
                        # Telegram alert simplificado
                    }
                }
            } catch {}
        } -ArgumentList $port, $HONEYPOT_LOG
        Log-Message "[+] Honeypot activo en puerto $port"
    }
    
    Log-Message "[*] Presiona Ctrl+C para detener todos los honeypots"
    Get-Job | Wait-Job
}

# ----- File System Watcher -----
function Watch-FileSystem {
    Log-Message "`n[!!] MODO WATCH ACTIVO - Monitoreando: $MONITOR_DIRS"
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    
    $action = {
        $details = $Event.SourceEventArgs
        $changeType = $details.ChangeType
        $path = $details.FullPath
        Log-Message "    [ALERTA] Cambio FS: $changeType - $path"
        Add-JsonAlert -Severity "MEDIUM" -Finding "File System Change" -Details "$changeType - $path"
    }
    
    foreach ($dir in $MONITOR_DIRS) {
        if (Test-Path $dir) {
            $watcher.Path = $dir
            Register-ObjectEvent $watcher "Created" -Action $action
            Register-ObjectEvent $watcher "Changed" -Action $action
            Register-ObjectEvent $watcher "Deleted" -Action $action
            Log-Message "[+] Monitoreando: $dir"
        }
    }
    
    Log-Message "[*] Presiona Ctrl+C para detener..."
    while ($true) { Start-Sleep -Seconds 1 }
}

# ----- Server Mode -----
function Start-ServerLoop {
    Log-Message "`n[!!] MODO SERVER ACTIVO - Monitoreando cada $SLEEP_SERVER segundos"
    while ($true) {
        Add-Content -Path $REPORT_FILE -Value "`n--- $(Get-Date) ---"
        Check-ExternalConnections
        Check-SuspiciousProcesses
        Check-MalwareHashes
        Check-NewUsers
        Check-ListeningPorts
        Check-ScheduledTasks
        if ($VT_API_KEY) { Invoke-VirusTotalLookup }
        Start-Sleep -Seconds $SLEEP_SERVER
    }
}

# ----- Compare Mode -----
function Compare-WithLast {
    $reports = Get-ChildItem "intruder_report_*.txt" | Sort-Object LastWriteTime -Descending
    if ($reports.Count -ge 2) {
        $last = $reports[1].FullName
        Log-Message "`n[++] Cambios desde última ejecución:"
        $diff = Compare-Object (Get-Content $last) (Get-Content $REPORT_FILE) | Select-Object -First 20
        foreach ($line in $diff) {
            Log-Message "$($line.InputObject)"
        }
    } else {
        Log-Message "`n[-] No hay reporte previo para comparar"
    }
}

# ----- Help -----
function Show-Help {
    Write-Host @"
Uso: .\intruder.ps1 [OPCIONES]

OPCIONES:
  --verbose               Modo verboso
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

EJEMPLOS:
  .\intruder.ps1 --verbose
  .\intruder.ps1 --honeypot
  .\intruder.ps1 --server --email admin@example.com
"@
    exit 0
}

# ----- Main -----
# Parse arguments
for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "--verbose" { $MODE = "verbose" }
        "--server" { $MODE = "server" }
        "--watch" { $MODE = "watch" }
        "--honeypot" { $MODE = "honeypot" }
        "--diff" { $MODE = "diff" }
        "--email" { $ALERT_EMAIL = $args[$i+1]; $i++ }
        "--vt-key" { $VT_API_KEY = $args[$i+1]; $i++ }
        "--telegram-token" { $TELEGRAM_BOT_TOKEN = $args[$i+1]; $i++ }
        "--telegram-chat" { $TELEGRAM_CHAT_ID = $args[$i+1]; $i++ }
        "--slack-webhook" { $SLACK_WEBHOOK_URL = $args[$i+1]; $i++ }
        "--whitelist-ip" { $WHITELIST_IPS += $args[$i+1]; $i++ }
        "--cidr-whitelist" { $WHITELIST_CIDR += $args[$i+1]; $i++ }
        "--help" { Show-Help }
        default { Write-Host "Opción desconocida: $($args[$i])"; Show-Help }
    }
}

# Ejecutar
Show-Banner
Initialize-Json

switch ($MODE) {
    "server" { Start-ServerLoop }
    "watch" { Watch-FileSystem }
    "honeypot" { Start-Honeypot }
    default {
        Check-ExternalConnections
        Check-SuspiciousProcesses
        Check-MalwareHashes
        Check-NewUsers
        Check-ListeningPorts
        Check-ScheduledTasks
        if ($VT_API_KEY) { Invoke-VirusTotalLookup }
        if ($MODE -eq "diff") { Compare-WithLast }
        
        Log-Message "`n[+] Escaneo completado. Revisa $REPORT_FILE"
        Log-Message "[+] JSON exportado: $JSON_FILE"
        
        if (Test-Path $TEMP_ALERTS) {
            $alertCount = (Get-Content $TEMP_ALERTS).Count
            Log-Message "[!!!] Total de alertas: $alertCount"
            Remove-Item $TEMP_ALERTS -Force
        }
    }
}
