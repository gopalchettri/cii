<#
.SYNOPSIS
    Run or stop TSG v2 on this laptop: the API, the job worker, the maintenance worker, beat and the monitoring tools.

.DESCRIPTION
    .\run.ps1            start everything, wait until /ready answers, open Grafana
    .\run.ps1 stop       stop everything this script started (or .\stop.ps1, the same)
    .\run.ps1 status     what is running, and what /ready says

    The API, the worker and beat each get their own window ("TSG api", "TSG worker", "TSG beat"). A window stays
    open when its program stops, so an error stays readable. The monitoring tools (Grafana, Prometheus,
    Alertmanager, Loki, Alloy, Flower, redis_exporter) are started and stopped by scripts\monitoring.py.

    MongoDB, SQL Server and Redis must already run (docs\RUNNING.md step 3). v1 and v2 share Redis databases 0
    and 1 on this laptop (owner, 2026-10-09), so start refuses while v1's worker or beat runs.

.PARAMETER Action
    start (default), stop or status.

.PARAMETER Reload
    Restart the API when a code file is saved.

.PARAMETER NoBrowser
    Do not open Grafana after the start.

.PARAMETER DrainSeconds
    How long stop waits for the worker to finish its running jobs before it closes the window. Default 60.

.EXAMPLE
    .\run.ps1

.EXAMPLE
    .\run.ps1 stop
#>
#Requires -PSEdition Desktop
# Windows PowerShell 5.1 only: PowerShell 7 reads the saved start times as dates, and stop then finds no
# window to stop.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'stop', 'status')]
    [string]$Action = 'start',
    [switch]$Reload,
    [switch]$NoBrowser,
    [int]$DrainSeconds = 60
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
# Whether this shell has administrator rights: recorded with each window it starts (see Get-Owned).
$Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$Python = Join-Path $Root '.venv\Scripts\python.exe'
$EnvFile = Join-Path $Root '.env'
$StateFile = Join-Path $Root '.run\processes.json'
$Monitoring = Join-Path $Root 'scripts\monitoring.py'
$WorkerName = "scenarios@$env:COMPUTERNAME"  # named by module: logs/worker-scenarios.log
$MapperWorkerName = "mapper@$env:COMPUTERNAME"
$MaintenanceName = "maintenance@$env:COMPUTERNAME"
$ReadyUrl = 'http://127.0.0.1:8000/ready'
$GrafanaUrl = 'http://localhost:3000/grafana/'

# The commands of docs\RUNNING.md steps 8 and 9. The workers' names are explicit so stop can address them.
# The maintenance worker has its own 3 threads (BLUEPRINT worker-maintenance, G198): the reaper and the controls
# sweep never wait behind long jobs. With one worker for all queues, ten long mappings held every thread and a
# lost job was never re-sent (live test 2026-10-11).
# tsg_controls stays in the job worker: the laptop's local CPU reranker is shared within one process.
$Programs = [ordered]@{
    api         = @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000')
    worker      = @('-m', 'celery', '-A', 'app.worker', 'worker', '--pool=threads', '-c', '10',
                    '-Q', 'tsg_threats,tsg_scenarios,tsg_controls,tsg_remediation', '-n', $WorkerName,
                    '--loglevel=INFO')
    service_mapper = @('-m', 'celery', '-A', 'app.worker', 'worker', '--pool=threads', '-c', '2',
                       '-Q', 'tsg_servicemapper', '-n', $MapperWorkerName, '--loglevel=INFO')
    maintenance = @('-m', 'celery', '-A', 'app.worker', 'worker', '--pool=threads', '-c', '3',
                    '-Q', 'tsg_maintenance', '-n', $MaintenanceName, '--loglevel=INFO')
    beat        = @('-m', 'celery', '-A', 'app.worker', 'beat', '--loglevel=INFO')
}
# Settings a program's window gets on top of .env: each worker serves its metrics on its own port (9101 is the
# VS Code debug worker's).
$ProgramEnv = @{
    maintenance = @{ CII_WORKER_METRICS_PORT = '9102' }
    service_mapper = @{ CII_WORKER_METRICS_PORT = '9103' }
}

# PowerShell also takes the typographic apostrophes as quotes: each is doubled, or a folder such as
# "Gopal's" typed with a curly apostrophe would break the window's command.
function Quote([string]$Text) { "'" + ($Text -replace "['\u2018\u2019\u201A\u201B]", '$0$0') + "'" }

function Invoke-Native([scriptblock]$Command) {
    # A program's error output is shown, never turned into a script-ending error. Windows PowerShell 5.1 does
    # that when the output is redirected (.\stop.ps1 *> stop.log): celery's harmless "No nodes replied" to a
    # shutdown request then ended stop halfway, leaving the windows open. The program's exit code stays in
    # $LASTEXITCODE.
    $ErrorActionPreference = 'Continue'
    & $Command 2>&1 | ForEach-Object { "$_" }
}

function Read-State {
    $state = [ordered]@{}
    if (Test-Path -LiteralPath $StateFile) {
        try {
            foreach ($entry in (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json).PSObject.Properties) {
                $state[$entry.Name] = @{ pid = [int]$entry.Value.pid; started = [string]$entry.Value.started
                                         elevated = $entry.Value.elevated }
            }
        } catch {
            Write-Warning "$StateFile is unreadable and is ignored (the port checks still catch a running stack)."
        }
    }
    return , $state
}

function Save-State($State) {
    New-Item -ItemType Directory -Force -Path (Split-Path $StateFile) | Out-Null
    $State | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding ASCII
}

function Get-Owned($Entry) {
    # The very window this script started: same id AND same start time (Windows reuses ids after a reboot).
    try { $process = Get-Process -Id $Entry.pid -ErrorAction Stop } catch { return $null }  # no such process
    try {
        # Recorded in UTC, so a clock or time-zone change cannot hide the window (local time was used before).
        $times = $process.StartTime.ToUniversalTime().ToString('o'), $process.StartTime.ToString('o')
    } catch {
        # Windows hides the start time of a program run as administrator from a window that is not. Before,
        # that read as "gone": stop deleted the record while the window kept running. A powershell window may be
        # ours, so stop refuses instead; any other program only reused the id.
        if ($process.ProcessName -ne 'powershell') { return $null }
        # A window this script started without administrator rights can always be read: an unreadable one with
        # its id is an administrator program that reused the id after the window closed (live stop 2026-10-11).
        if ($Entry.elevated -eq $false) { return $null }
        throw "Cannot check window $($Entry.pid): it runs as administrator. Run this from an administrator window."
    }
    if ($times -contains $Entry.started) { return $process }
    return $null
}

function Get-EnvValue([string]$Name) {
    # The value only decides what to do; it is never printed. Read as the app's python-dotenv reads it: quotes
    # removed, an unquoted value ends at whitespace followed by '#' (so a password may hold '#'), a later line
    # for the same key wins, and a missing .env reads as empty (stop must still work).
    if (-not (Test-Path -LiteralPath $EnvFile)) { return '' }
    $value = ''
    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        if ($line -match "^\s*$Name\s*=\s*(?:""([^""]*)""|'([^']*)'|(.*?))(?:\s+#.*)?\s*$") {
            $value = if ($null -ne $Matches[1]) { $Matches[1] } elseif ($null -ne $Matches[2]) { $Matches[2] } else { $Matches[3] }
        }
    }
    return $value.Trim()
}

function Get-ShadowedSettings {
    # The names (never the values) of the settings .env owns that this shell also sets: every key .env names,
    # set, blank or commented out (blank or missing means the default), and every GF_ key (a GF_ line left out
    # means Grafana's default). A setting in the environment beats .env, and VS Code's
    # python.terminal.useEnvFile copies .env into a terminal once, when it opens.
    $lines = if (Test-Path -LiteralPath $EnvFile) { Get-Content -LiteralPath $EnvFile } else { @() }
    $named = foreach ($line in $lines) { if ($line -match '^\s*#?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=') { $Matches[1] } }
    $grafana = Get-ChildItem -Path 'Env:GF_*' | ForEach-Object { $_.Name }
    @($named) + @($grafana) | Where-Object { $_ -and (Test-Path -LiteralPath "Env:$_") } | Sort-Object -Unique
}

function Hide-ShadowedSettings([hashtable]$Saved) {
    # Unsets those keys while the script runs, so every check and program it starts reads .env; each value is
    # kept in $Saved before it goes, for Restore-Settings. Returns the names whose value differs from .env's
    # (compared here, never shown): with useEnvFile every key is a copy, and only a stale one needs a warning.
    foreach ($key in Get-ShadowedSettings) {
        $Saved[$key] = [Environment]::GetEnvironmentVariable($key)
        Remove-Item -LiteralPath "Env:$key"
        if ($Saved[$key] -cne (Get-EnvValue $key)) { $key }
    }
}

function Restore-Settings([hashtable]$Saved) {
    # Puts back what Hide-ShadowedSettings unset: the caller's shell stays as it was.
    foreach ($entry in $Saved.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value) }
}

function Get-Program($Window) {
    # The python program inside a window (the window stays open after it ends, so its error stays readable).
    Get-CimInstance Win32_Process -Filter "ParentProcessId = $($Window.Id) AND Name = 'python.exe'"
}

function Get-Arguments([string]$Name) {
    if ($Name -eq 'api' -and $Reload) {
        # uvicorn's own --reload did not survive a restart on this machine (v1, 2026-09-24): watchfiles runs the
        # API from outside and restarts it on a change. It splits its command at spaces, hence the path check.
        if ($Python.Contains(' ')) { throw "-Reload needs a project path without spaces: $Root" }
        return @('-m', 'watchfiles', '--filter', 'python', "$Python $($Programs.api -join ' ')", 'app')
    }
    return $Programs[$Name]
}

function Start-Window([string]$Name) {
    $arguments = (Get-Arguments $Name | ForEach-Object { Quote $_ }) -join ' '
    $settings = ''
    if ($ProgramEnv.Contains($Name)) {
        foreach ($entry in $ProgramEnv[$Name].GetEnumerator()) { $settings += "`$env:$($entry.Key) = $(Quote $entry.Value); " }
    }
    $inner = "`$Host.UI.RawUI.WindowTitle = 'TSG $Name'; Set-Location -LiteralPath $(Quote $Root); $settings" +
             "& $(Quote $Python) $arguments"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    return Start-Process powershell.exe -ArgumentList '-NoProfile', '-NoExit', '-EncodedCommand', $encoded `
        -WorkingDirectory $Root -PassThru
}

function Assert-CanStart {
    if (-not (Test-Path -LiteralPath $Python)) {
        throw "No Python environment at $Python. Create it first (docs\RUNNING.md step 4)."
    }
    if (-not (Test-Path -LiteralPath $EnvFile)) {
        throw 'No .env file. Copy .env.example to .env and fill it in (docs\RUNNING.md step 6).'
    }
    $v1 = @(Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'celery.exe'" |
            Where-Object { $_.CommandLine -like '*app.pipeline.celery*' })
    if ($v1) {
        throw ("v1's worker or beat is running (process $($v1.ProcessId -join ', ')). v1 and v2 share Redis " +
               'databases 0 and 1: stop v1 first (its stop.ps1).')
    }
    foreach ($port in 8000, 9100, 9102, 9103) {
        $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
                    Select-Object -First 1
        if ($listener) {
            $owner = (Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            throw "Port $port is in use by $owner (process $($listener.OwningProcess)). Stop it first."
        }
    }
    Assert-StoresAnswer
}

function Assert-StoresAnswer {
    # The same MongoDB / SQL Server / Redis checks /ready runs, before any window opens: a stopped store is named
    # now, instead of three windows retrying it and /ready saying 503 after 90 s.
    Write-Host 'Checking MongoDB, SQL Server and Redis...' -ForegroundColor Cyan
    $check = 'import json; from app.core.readiness import check_readiness; print(json.dumps(check_readiness()[0]))'
    $answer = Invoke-Native { & $Python -c $check } | Select-Object -Last 1
    try { $stores = $answer | ConvertFrom-Json } catch { $stores = $null }
    if ($null -eq $stores) { throw "Could not check the stores. Run this to see why: $Python -c `"$check`"" }
    $down = @($stores.PSObject.Properties | Where-Object { -not $_.Value } | ForEach-Object { $_.Name })
    if ($down) {
        throw ("Not reachable: $($down -join ', '). Start it first (docs\RUNNING.md step 3); a Windows service " +
               "starts in an administrator PowerShell, e.g. Start-Service Memurai for Redis.")
    }
}

function Test-Broker {
    # Is the job queue (Redis) reachable? Only its host and port are read; the URL is never printed.
    $value = if ($env:CII_REDIS_CELERY_BROKER_URL) { $env:CII_REDIS_CELERY_BROKER_URL } else { Get-EnvValue 'CII_REDIS_CELERY_BROKER_URL' }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $uri = [uri]$value
        $port = if ($uri.Port -gt 0) { $uri.Port } else { 6379 }
        return $client.ConnectAsync($uri.Host, $port).Wait(2000)
    } catch { return $false } finally { $client.Dispose() }
}

function Get-Ready {
    # HttpWebRequest, not Invoke-WebRequest: on Windows PowerShell 5.1 the body of a 503 is lost by the time
    # Invoke-WebRequest's error is caught, and that body is what says which store or queue is missing.
    $request = [System.Net.HttpWebRequest]::Create($ReadyUrl)
    $request.Timeout = 10000
    $request.Proxy = $null
    try {
        $response = $request.GetResponse()
    } catch {
        $failure = $_.Exception
        while ($failure -and $failure -isnot [System.Net.WebException]) { $failure = $failure.InnerException }
        if ($null -eq $failure -or $null -eq $failure.Response) { return $null }  # nothing answers on the port
        $response = $failure.Response
    }
    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        return @{ Code = [int]$response.StatusCode; Body = $reader.ReadToEnd() }
    } finally { $response.Close() }
}

function Wait-Ready([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $ready = Get-Ready
        if ($ready -and $ready.Code -eq 200) { return $ready }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $ready
}

function Show-Ready($Ready) {
    if ($null -eq $Ready) { Write-Host "  /ready: the API is not answering ($ReadyUrl)" -ForegroundColor Yellow; return }
    $colour = if ($Ready.Code -eq 200) { 'Green' } else { 'Yellow' }
    Write-Host "  /ready: $($Ready.Code) $($Ready.Body)" -ForegroundColor $colour
}

function Invoke-Start {
    $state = Read-State
    $alive = @($state.Keys | Where-Object { Get-Owned $state[$_] })
    if ($alive) { throw "Already running ($($alive -join ', ')). See .\run.ps1 status, or stop it with .\stop.ps1." }
    Assert-CanStart
    # Grafana's logs and audit panels read the log files (scripts\monitoring_commands.py: Alloy reads logs\).
    $setLogDir = -not (Get-EnvValue 'CII_LOG_DIR') -and -not $env:CII_LOG_DIR
    if ($setLogDir) { $env:CII_LOG_DIR = 'logs' }
    $state = [ordered]@{}
    try {
        foreach ($name in $Programs.Keys) {
            $window = Start-Window $name
            $state[$name] = @{ pid = $window.Id; started = $window.StartTime.ToUniversalTime().ToString('o')
                               elevated = $Elevated }
            Save-State $state  # saved at once: stop finds every window even if a later step fails
            Write-Host "  started $name (window 'TSG $name')"
        }
    } finally {
        if ($setLogDir) { Remove-Item Env:CII_LOG_DIR }  # the windows have it; this shell stays as it was
    }
    Write-Host 'Starting the monitoring tools (the first time downloads about 500 MB)...' -ForegroundColor Cyan
    Invoke-Native { & $Python $Monitoring start } | Out-Host
    $monitoringUp = $LASTEXITCODE -eq 0
    if (-not $monitoringUp) {
        Write-Warning 'The monitoring tools did not start (reason above). The API, the workers and beat keep running.'
    }
    Write-Host 'Waiting for /ready (up to 90 s)...' -ForegroundColor Cyan
    $ready = Wait-Ready 90
    Show-Ready $ready
    if ($monitoringUp -and -not $NoBrowser) { Start-Process $GrafanaUrl }
    Write-Host ''
    Write-Host '  API docs      http://localhost:8000/docs'
    if ($monitoringUp) {  # only addresses that answer
        Write-Host "  Grafana       $GrafanaUrl  (start here)"
        Write-Host '  Prometheus    http://localhost:9090/prometheus/'
        Write-Host '  Alertmanager  http://localhost:9093/alertmanager/'
        Write-Host '  Flower        http://localhost:5555/flower/'
    }
    Write-Host '  Stop it all   .\stop.ps1'
    # /ready does not cover beat, which sends the reaper (the only repair of lost jobs): every window's program
    # must still be running.
    $ended = @($state.Keys | Where-Object { $window = Get-Owned $state[$_]; -not ($window -and (Get-Program $window)) })
    foreach ($name in $ended) { Write-Warning "The $name program has ended: read the error in window 'TSG $name'." }
    if (-not $ready -or $ready.Code -ne 200) {
        Write-Warning 'Not ready yet: the /ready answer above says which store or queue is missing.'
        return 1
    }
    if ($ended -or -not $monitoringUp) { return 1 }  # a script or CI step sees the failure, not only the warning
    return 0
}

function Invoke-Stop {
    $state = Read-State
    $workers = @(foreach ($name in 'worker', 'service_mapper', 'maintenance') {
        if ($state.Contains($name)) { try { Get-Owned $state[$name] } catch { $null } }
    }) | Where-Object { $_ }
    if ($workers -and -not (Test-Broker)) {
        Write-Host '  Redis is not reachable: the workers cannot be asked to finish first; they are closed.' -ForegroundColor Yellow
    } elseif ($workers) {
        # A warm stop finishes the running jobs and removes the worker's heartbeat at once. A killed worker's job
        # stays "running" until its lease runs out (2 min), and /ready counts the dead worker for up to 1 min.
        Write-Host "Asking the workers to finish their running jobs (up to $DrainSeconds s)..." -ForegroundColor Cyan
        # A worker shuts down instead of answering, so celery reports "No nodes replied": expected.
        $names = "$WorkerName,$MapperWorkerName,$MaintenanceName"
        Invoke-Native { & $Python -m celery -A app.worker control shutdown --destination $names --timeout 5 } |
            Out-Null
        $deadline = (Get-Date).AddSeconds($DrainSeconds)
        while (($workers | Where-Object { Get-Program $_ }) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    }
    $stopped = @()
    $left = [ordered]@{}
    foreach ($name in $state.Keys) {
        # One window that cannot be checked (started as administrator) is kept and named; the others, and the
        # monitoring tools, are still stopped (before, its error ended stop halfway).
        try { $window = Get-Owned $state[$name] } catch { Write-Warning $_.Exception.Message; $left[$name] = $state[$name]; continue }
        if (-not $window) { continue }
        Invoke-Native { & taskkill.exe /T /F /PID $window.Id } | Out-Null  # the window and its program
        $gone = (Get-Date).AddSeconds(5)
        while ((Get-Owned $state[$name]) -and (Get-Date) -lt $gone) { Start-Sleep -Milliseconds 200 }
        if (Get-Owned $state[$name]) { $left[$name] = $state[$name] } else { $stopped += $name }
    }
    if ($left.Count) {
        Save-State $left  # kept, so the next stop still finds them
        Write-Warning "Could not stop $($left.Keys -join ', '): close the windows by hand, then run .\stop.ps1 again."
    } elseif (Test-Path -LiteralPath $StateFile) {
        Remove-Item -LiteralPath $StateFile
    }
    if ($stopped) { Write-Host "  stopped $($stopped -join ', ')" } else { Write-Host '  no API, worker or beat window to stop' }
    Write-Host 'Stopping the monitoring tools...' -ForegroundColor Cyan
    Invoke-Native { & $Python $Monitoring stop } | Out-Host
    if ($LASTEXITCODE -or $left.Count) { return 1 }  # what was not stopped is named above
    return 0
}

function Show-Status {
    $state = Read-State
    if (-not $state.Count) { Write-Host '  no API, worker or beat window started by this script' }
    foreach ($name in $state.Keys) {
        $window = Get-Owned $state[$name]
        $text = 'stopped'
        if ($window -and (Get-Program $window)) { $text = "running (window 'TSG $name')" }
        elseif ($window) { $text = "its program has ended: read the error in window 'TSG $name'" }
        Write-Host ('  {0,-11} {1}' -f $name, $text)
    }
    Show-Ready (Get-Ready)
    Invoke-Native { & $Python $Monitoring status } | Out-Host
}

# Every python call reads .env and imports app\ from the project folder, so the script works from there
# wherever it is started; the caller's shell is put back afterwards.
$exitCode = 0
$shadowed = @{}
Push-Location -LiteralPath $Root
try {
    $stale = @(Hide-ShadowedSettings $shadowed)
    if ($stale) { Write-Warning "Set differently in this shell; .env's are used: $($stale -join ', ')" }
    switch ($Action) {
        'start' { $exitCode = Invoke-Start }
        'stop' { $exitCode = Invoke-Stop }
        'status' { Show-Status }
    }
} finally {
    Restore-Settings $shadowed
    Pop-Location
}
exit $exitCode
