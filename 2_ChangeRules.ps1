# Asegurar que la consola utilice UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Configuración
$findtimeMinutes = 3  # Tiempo de monitoreo en minutos
$bantimeMinutes = 30   # Tiempo de bloqueo en minutos, se recomienda q sea mayor a FindTimeMinutes.
$maxretry = 3         # Máximo número de intentos fallidos permitidos
$rulePrefix = "IP Baneada - " # Prefijo de las reglas de firewall

# Conversión a TimeSpan
$findtime = [TimeSpan]::FromMinutes($findtimeMinutes)
$bantime = [TimeSpan]::FromMinutes($bantimeMinutes)

# Diccionario para contar los intentos de cada IP y tiempos de bloqueo
$ipAttempts = @{}
$banLogPath = "C:\scripts\ban-log.txt"
$banLogHistoricoPath = "C:\scripts\ban-log-historico.txt"

# Leer el archivo de log
$logPath = "C:\scripts\rdp-log.txt"
$logEntries = Get-Content -Path $logPath | Where-Object { $_ -match "\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} - IP:" }

# Leer o inicializar el registro de IPs bloqueadas y tiempos
if (Test-Path $banLogPath) {
    $banLog = Import-Csv -Path $banLogPath
} else {
    $banLog = @()
}

# Inicializar lista de histórico
$banLogHistorico = @()

# Leer o inicializar el archivo histórico de bloqueos
if (Test-Path $banLogHistoricoPath) {
    $banLogHistorico += Import-Csv -Path $banLogHistoricoPath
}

# Obtener la hora actual del sistema
$currentTime = Get-Date

# Procesar las entradas del log
foreach ($entry in $logEntries) {
    if ($entry -match "(?<time>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) - IP: (?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
        $entryTime = [datetime]::ParseExact($matches['time'], 'MM/dd/yyyy HH:mm:ss', $null)
        $ipAddress = $matches['ip']

        # Comparar el tiempo de la entrada con el tiempo actual
        if ($currentTime - $entryTime -lt $findtime) {
            if (-not $ipAttempts.ContainsKey($ipAddress)) {
                $ipAttempts[$ipAddress] = 0
            }
            $ipAttempts[$ipAddress]++
        }
    }
}

# Verificar si alguna IP excedió el número de intentos fallidos permitidos
foreach ($ipAddress in $ipAttempts.Keys) {
    if ($ipAttempts[$ipAddress] -ge $maxretry) {
        # Comprobar si la IP ya está bloqueada
        $existingRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "$rulePrefix$ipAddress" }
        if (-not $existingRule) {
            #Write-Host "Bloqueando IP: $ipAddress por exceder $maxretry intentos fallidos"
            New-NetFirewallRule -DisplayName "$rulePrefix$ipAddress" -Direction Inbound -RemoteAddress $ipAddress -Action Block | Out-Null

            # Registrar el tiempo de bloqueo en el ban-log y en el histórico
            $banLog += [pscustomobject]@{ IPAddress = $ipAddress; BlockedTime = $currentTime.ToString('MM/dd/yyyy HH:mm:ss') }
            $banLogHistorico += [pscustomobject]@{ IPAddress = $ipAddress; BlockedTime = $currentTime.ToString('MM/dd/yyyy HH:mm:ss') }
        }
    }
}

# Guardar el registro de bloqueos en un archivo CSV sin duplicar IPs
$banLog | Sort-Object IPAddress -Unique | Export-Csv -Path $banLogPath -NoTypeInformation

# Guardar el histórico completo
$banLogHistorico | Sort-Object IPAddress, BlockedTime -Unique | Export-Csv -Path $banLogHistoricoPath -NoTypeInformation

# Revisar reglas expiradas y eliminar después de que pasa el tiempo de baneo
$firewallRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$rulePrefix*" }
foreach ($rule in $firewallRules) {
    $ipAddress = $rule.DisplayName -replace $rulePrefix, ""

    # Comprobar si el tiempo de baneo ha pasado
    $banEntry = $banLog | Where-Object { $_.IPAddress -eq $ipAddress }
    if ($banEntry) {
        $banStartTime = [datetime]::ParseExact($banEntry.BlockedTime, 'MM/dd/yyyy HH:mm:ss', $null)
        $remainingTime = $bantime - ($currentTime - $banStartTime)

        if ($remainingTime.TotalSeconds -le 0) {
            # Si el tiempo de baneo ha pasado, eliminar la regla
            Write-Host "Desbloqueando IP: $ipAddress"
            Remove-NetFirewallRule -DisplayName "$rulePrefix$ipAddress" | Out-Null

            # Remover la IP del registro de bloqueos actual (pero no del histórico)
            $banLog = $banLog | Where-Object { $_.IPAddress -ne $ipAddress }
        } else {
            # Mostrar el tiempo restante para el desbloqueo
            Write-Host "$rulePrefix$ipAddress | Por exceder $maxretry intentos fallidos | Tiempo restante: $remainingTime"
        }
    }
}

# Guardar el registro actualizado de bloqueos
$banLog | Sort-Object IPAddress -Unique | Export-Csv -Path $banLogPath -NoTypeInformation
