# Definir la ruta del archivo de registro
$logPath = "C:\scripts\rdp-log.txt"

# Verificar si el archivo ya existe. Si no, agregar encabezados
if (-not (Test-Path $logPath)) {
    Add-Content -Path $logPath -Value "TimeCreated - IP" -Encoding utf8
}

# Leer el contenido actual del archivo de log para evitar duplicados
$existingLogs = Get-Content $logPath -Encoding utf8

# Procesar eventos
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | ForEach-Object {
    $message = $_.Message

    # Expresión regular mejorada para capturar cualquier dirección IP en el mensaje
    if ($message -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
        $ipAddress = $matches[1]
        $logEntry = "$($_.TimeCreated) - IP: $ipAddress"

        # Verificar si la entrada ya existe
        if (-not ($existingLogs -contains $logEntry)) {
            Add-Content -Path $logPath -Value $logEntry -Encoding utf8
        }
    }
} | Out-Null


Start-Process powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File "C:\scripts\2_ChangeRules.ps1"'