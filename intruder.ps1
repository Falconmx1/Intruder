# ============================================
# INTRUDER v2.0 - Windows Security Scanner
# Features: External connections, suspicious processes,
# malware hashes, new users, listening ports, scheduled tasks,
# email alerts, JSON output, file watcher, diff mode
# ============================================

# ----- Configuración -----
$WHITELIST_IPS = @("127.0.0.1", "192.168.1.1")
$WHITELIST_PROC = @("System", "svchost", "explorer")
$MALWARE_HASH_FILE = "malware_hashes.txt"
$VT_API_KEY = ""  # Opcional
$ALERT_EMAIL = "admin@example.com"
$SMTP_SERVER = "smtp.gmail.com"
$SMTP_PORT = 587
$REPORT_FILE = "intruder_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$JSON_FILE = "intruder_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$MODE = "quick"
$SLEEP_SERVER = 10
$ALERT_LEVEL = 0
$MONITOR_DIRS = @("$env:SystemRoot\System32", "$env:ProgramFiles")
$TEMP_ALERTS = "$env:TEMP\intruder_alerts.txt"

# ----- Funciones Base -----
function Show-Banner {
    Write-Host @"
  ___        _           _           
 |_ _|_ __  (_)_ __   __| |_ __ ___  
  | || '_ \ | | '_ \ / _` | '__/ _ \ 
  | || | | || | | | | (_| | | |  __/ 
 |___|_| |_|/ |_| |_|\__,_|_|  \___|
          |__/                       
"@ -ForegroundColor Red
    Write-Host "===[ Windows Intruder Detector v2.0 ]====================="
    Write-Host "[+] Modo: $MODE"
    Write-Host "[+] Reporte: $REPORT_FILE"
    Write-Host "========================================================"
}

function Log-Message {
    param([string]$Message)
    $timestamped = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $timestamped
    Add-Content -Path $REPORT_FILE -Value $timestamped
    
    if ($Message -match "ALERTA|CRITICO" -and $ALERT_LEVEL -ge 1) {
        Add-Content -Path $TEMP_ALERTS -Value $Message
        Send-EmailAlert -Subject "Intruder Alert" -Body $Message
    }
}

# ----- FEATURE: Email Alerts -----
function Send-EmailAlert {
    param($Subject, $Body)
    if (-not $SMTP_SERVER) { return }
    try {
        $credentials = $null
        if ($ALERT_EMAIL -ne "admin@example.com") {
            $cred = Get-Credential -Message "Credenciales para $ALERT_EMAIL" -ErrorAction Stop
        }
        Send-MailMessage -SmtpServer $SMTP_SERVER -Port $SMTP_PORT -UseSsl `
            -From $ALERT_EMAIL -To $ALERT_EMAIL -Subject "[INTRUDER] $Subject" `
            -Body "Time: $(Get-Date)`n`n$Body" -ErrorAction Stop
        Log-Message "[+] Alerta enviada a $ALERT_EMAIL"
    } catch {
        Log-Message "[-] Error enviando email: $($_.Exception.Message)"
    }
}

# ----- FEATURE: JSON Output -----
function Initialize-Json {
    $jsonObj = @{
        scan_time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        hostname = $env:COMPUTERNAME
        mode = $MODE
        alerts = @()
    }
    $jsonObj | ConvertTo-Json | Set-Content -Path $JSON_FILE
}

function Add-JsonAlert {
    param($Severity, $Finding, $Details)
    if (Test-Path $JSON_FILE) {
        $json = Get-Content $JSON_FILE | ConvertFrom-Json
        $json.alerts += @{
            severity = $Severity
            finding = $Finding
            details = $Details
            time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        $json | ConvertTo-Json | Set-Content -Path $JSON_FILE
    }
}

# ----- Core Detection Functions -----
function Check-ExternalConnections {
    Log-Message "`n[+] Conexiones externas activas (IPv4):"
    $connections = Get-NetTCPConnection | Where-Object { 
        $_.RemoteAddress -ne "::" -and $_.RemoteAddress -ne "0.0.0.0" -and $_.State -eq "Established"
    }
    foreach ($conn in $connections) {
        $ip = $conn.RemoteAddress
        if ($WHITELIST_IPS -contains $ip) {
            if ($MODE -eq "verbose") { Log-Message "    [INFO] Conexión whitelist: $ip" }
        }
        elseif ($ip -match "^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.|^127\.") {
            if ($MODE -eq "verbose") { Log-Message "    [INFO] Conexión local: $ip" }
        }
        else {
            Log-Message "    [ALERTA] Conexión externa: $($conn.LocalAddress):$($conn.LocalPort) -> $ip`:$($conn.RemotePort)"
            Add-JsonAlert -Severity "HIGH" -Finding "External Connection" -Details "$ip`:$($conn.RemotePort)"
        }
    }
}

function Check-SuspiciousProcesses {
    Log-Message "`n[+] Procesos con nombres sospechosos:"
    $procs = Get-Process | Where-Object { $_.Path -ne $null }
    foreach ($proc in $procs) {
        $name = $proc.ProcessName
        if ($name.Length -gt 30 -or $name -match '^[0-9a-zA-Z]{15,}$') {
            Log-Message "    [ALERTA] Nombre ofuscado: $name (PID: $($proc.Id))"
            Add-JsonAlert -Severity "MEDIUM" -Finding "Obfuscated Process" -Details "$name PID:$($proc.Id)"
        }
        elseif ($name -match '(crypt|miner|backdoor|shell|reverse|payload|ransom)') {
            Log-Message "    [CRITICO] Malware pattern: $name (PID: $($proc.Id))"
            Add-JsonAlert -Severity "CRITICAL" -Finding "Malware Pattern" -Details "$name PID:$($proc.Id)"
        }
        elseif ($MODE -eq "verbose") {
            Log-Message "    [INFO] Proceso: $name"
        }
    }
}

function Check-MalwareHashes {
    if (-not (Test-Path $MALWARE_HASH_FILE)) {
        Log-Message "`n[-] Archivo $MALWARE_HASH_FILE no encontrado."
        return
    }
    Log-Message "`n[+] Buscando coincidencias con hashes maliciosos:"
    $files = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 30
    foreach ($file in $files) {
        $hash = (Get-FileHash $file.FullName -Algorithm MD5).Hash
        if (Select-String -Path $MALWARE_HASH_FILE -Pattern $hash -Quiet) {
            Log-Message "    [CRITICO] Hash malicioso: $($file.Name) (MD5: $hash)"
            Add-JsonAlert -Severity "CRITICAL" -Finding "Malware Hash" -Details "$($file.Name) - $hash"
        }
    }
}

function Check-NewUsers {
    Log-Message "`n[+] Usuarios locales nuevos o extraños:"
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notin @("Administrator", "DefaultAccount", "Guest") }
    foreach ($user in $users) {
        Log-Message "    [ALERTA] Usuario no estándar: $($user.Name)"
        Add-JsonAlert -Severity "MEDIUM" -Finding "Suspicious User" -Details $user.Name
    }
}

function Check-ListeningPorts {
    Log-Message "`n[+] Puertos en escucha (>1024 no autorizados):"
    $ports = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object -ExpandProperty LocalPort -Unique
    foreach ($port in $ports) {
        if ($port -gt 1024 -and $port -notin @(8080, 3000, 5000)) {
            Log-Message "    [ALERTA] Puerto alto escuchando: $port"
            Add-JsonAlert -Severity "MEDIUM" -Finding "High Port Listening" -Details "Port $port"
        }
    }
}

# ----- FEATURE: Scheduled Tasks -----
function Check-ScheduledTasks {
    Log-Message "`n[+] Tareas programadas sospechosas:"
    $tasks = Get-ScheduledTask | Where-Object { 
        $_.TaskPath -notlike "*Microsoft*" -and $_.State -ne "Disabled"
    }
    foreach ($task in $tasks) {
        Log-Message "    [ALERTA] Tarea no Microsoft: $($task.TaskName) (Path: $($task.TaskPath))"
        Add-JsonAlert -Severity "MEDIUM" -Finding "Suspicious Scheduled Task" -Details $task.TaskName
    }
}

# ----- FEATURE: VirusTotal API -----
function Invoke-VirusTotalLookup {
    if ([string]::IsNullOrEmpty($VT_API_KEY)) {
        Log-Message "`n[-] VirusTotal API key no configurada."
        return
    }
    Log-Message "`n[+] Consultando VirusTotal para binarios:"
    $files = Get-ChildItem "C:\Windows\System32\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 5
    foreach ($file in $files) {
        $hash = (Get-FileHash $file.FullName -Algorithm MD5).Hash
        $headers = @{ "x-apikey" = $VT_API_KEY }
        $uri = "https://www.virustotal.com/api/v3/files/$hash"
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            if ($resp.data.attributes.last_analysis_stats.malicious -gt 0) {
                Log-Message "    [VT] ALERTA: $($file.Name) -> Posible malware"
                Add-JsonAlert -Severity "CRITICAL" -Finding "VirusTotal Match" -Details $file.Name
            } elseif ($MODE -eq "verbose") {
                Log-Message "    [VT] $($file.Name) -> Limpio"
            }
        } catch {
            if ($MODE -eq "verbose") { Log-Message "    [VT] Error consultando $($file.Name)" }
        }
        Start-Sleep -Seconds 1
    }
}

# ----- FEATURE: File System Watcher -----
function Watch-FileSystem {
    Log-Message "`n[!!] MODO WATCH ACTIVO - Monitoreando: $MONITOR_DIRS"
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    
    foreach ($dir in $MONITOR_DIRS) {
        if (Test-Path $dir) {
            $watcher.Path = $dir
            $action = {
                $details = $Event.SourceEventArgs
                $changeType = $details.ChangeType
                $path = $details.FullPath
                Log-Message "    [ALERTA] Cambio FS: $changeType - $path"
                Add-JsonAlert -Severity "MEDIUM" -Finding "File System Change" -Details "$changeType - $path"
            }
            Register-ObjectEvent $watcher "Created" -Action $action
            Register-ObjectEvent $watcher "Changed" -Action $action
            Register-ObjectEvent $watcher "Deleted" -Action $action
            Log-Message "[+] Monitoreando: $dir"
        }
    }
    
    Log-Message "[*] Presiona Ctrl+C para detener..."
    while ($true) { Start-Sleep -Seconds 1 }
}

# ----- FEATURE: Modo comparativo (diff) -----
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
        Log-Message "`n[-] No hay reporte previo para comparar."
    }
}

# ----- FEATURE: Server Mode -----
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

# ----- Main -----
# Parse arguments
for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "--verbose" { $MODE = "verbose" }
        "--server" { $MODE = "server" }
        "--watch" { $MODE = "watch" }
        "--diff" { $MODE = "diff" }
        "--email" { $ALERT_EMAIL = $args[$i+1]; $i++ }
        "--vt-key" { $VT_API_KEY = $args[$i+1]; $i++ }
        "--whitelist-ip" { $WHITELIST_IPS += $args[$i+1]; $i++ }
        "--help" {
            Write-Host @"
Uso: .\intruder.ps1 [OPTIONS]
Opciones:
  --verbose           Modo verboso
  --server            Modo servidor (monitoreo continuo)
  --watch             Monitorear sistema de archivos
  --diff              Comparar con último reporte
  --email EMAIL       Enviar alertas a EMAIL
  --vt-key KEY        API key de VirusTotal
  --whitelist-ip IP   Añadir IP a whitelist
"@
            exit 0
        }
    }
}

Show-Banner
Initialize-Json

switch ($MODE) {
    "server" { Start-ServerLoop }
    "watch" { Watch-FileSystem }
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
            Remove-Item $TEMP_ALERTS
        }
    }
}
