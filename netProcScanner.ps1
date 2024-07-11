# VirusTotal API key
$apiKey = 'YourVirusTotalApiKey'
$logFile = "ScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$timestamp - $message"
    Write-Output $entry
    $entry | Out-File -FilePath $logFile -Append
}

function Get-FilePath {
    param (
        [string]$processName
    )
    if ($os -match 'Windows') {
        return (Get-Process -Name $processName -ErrorAction SilentlyContinue).Path
    } elseif ($os -match 'Linux' -or $os -match 'Darwin') {
        return "/proc/$(pgrep $processName)/exe"
    } else {
        return $null
    }
}

# Check OS
$os = $PSVersionTable.OS
$report = @()

if ($os -match 'Windows') {
    Log-Message "Running on Windows"
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $filePath = $process.Path
        $report += New-Object PSObject -Property @{
            Protocol = $conn.Protocol
            LocalAddress = $conn.LocalAddress
            LocalPort = $conn.LocalPort
            ProcessName = $process.Name
            Path = $filePath
        }
    }

    $processes = Get-Process | Where-Object { $_.Path } | ForEach-Object { $_.Path }
} elseif ($os -match 'Linux' -or $os -match 'Darwin') {
    Log-Message "Running on Linux or MacOS"
    $connections = bash -c "sudo netstat -plnt" | Where-Object { $_ -match 'LISTEN' }
    foreach ($conn in $connections) {
        if ($conn -match '\s*(\S+)\s+\S+\s+(\S+):(\S+)\s+\S+\s+\S+\s+(\S+).+') {
            $processName = ($Matches[4] -split '/')[1]
            $filePath = "/proc/$($Matches[4] -split '/')[0]/exe"
            $report += New-Object PSObject -Property @{
                Protocol = $Matches[1]
                LocalAddress = $Matches[2]
                LocalPort = $Matches[3]
                ProcessName = $processName
                Path = $filePath
            }
        }
    }

    $processes = bash -c "ps -eo cmd" | ForEach-Object { $_.Trim() }
} else {
    Log-Message "Unsupported operating system."
    exit
}

foreach ($process in $processes) {
    # Get File Hash
    try {
        $hash = Get-FileHash -Algorithm SHA256 -Path $process
        Log-Message "Hash for $process: $($hash.Hash)"
    } catch {
        Log-Message "An error occurred while retrieving the file hash for $process: $_"
        continue
    }

    # VirusTotal Query
    try {
        $uri = "https://www.virustotal.com/api/v3/files/$($hash.Hash)"
        $headers = @{ 'x-apikey' = $apiKey }
        $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers

        # Check file score
        if ($response.data.attributes.last_analysis_stats.malicious -gt 0) {
            Log-Message "Suspicious file found: $process ($($hash.Hash))"
        } else {
            Log-Message "File $process ($($hash.Hash)) is clean."
        }
    } catch {
        Log-Message "An error occurred during VirusTotal Query for $process: $_"
    }
}

$report | Format-Table | Out-File -FilePath $logFile -Append
Log-Message "Scan completed. Results saved to $logFile."
