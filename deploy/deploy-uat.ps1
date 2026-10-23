<#
.SYNOPSIS
    TSG v2 to UAT in one command, laid out as v1 was: checks, safety copies, v1 stopped, settings, the app in both
    projects, the monitoring and a smoke test, then the addresses to open.

.DESCRIPTION
    It stops at the first step that fails and names it; after a fix, run it again (every step can be repeated).

    Before: the image is built and pushed (deploy\build-image.ps1), you are logged in (oc login ...), and the
    DBA has installed the procedures (every scripts\sql\tsg_*.sql except the "copy" backup, then grants.sql),
    including tsg_GetServiceMapperAssociations, and the three existing Onboarding catalog procedures are present.

    What goes where (UAT is production):
      ai-threatgen    deploy\deploy.yaml (API, one worker per queue, beat) and deploy\networkpolicy.yaml
      ai-remediation  deploy\deploy.ai-remediation.yaml (a second worker per queue) and
                      deploy\networkpolicy.ai-remediation.yaml
      ai-common       the monitoring (deploy\observability.ps1 applies deploy\observability.yaml) and Flower
                      (deploy\flower.yaml); shared with the chatbot
      all three       the settings (ConfigMap tsg-config, Secret tsg-secrets), made from the env file (ai-common
                      only with the monitoring: Flower and redis-exporter read them)

    Never prints a secret. Safety copies of the projects (they hold passwords) and a ready rollback.ps1 go to
    %USERPROFILE%\.tsg\uat-backups\<time>\, outside the repo; copies of v1's Routes go to ...\uat-backups\v1\,
    kept across runs. v1's Deployments are scaled to 0, never deleted, except the monitoring programs in
    ai-remediation (prometheus, grafana ...: v1's, and v2's own from before the move to ai-common) and their
    Routes, which hold the monitoring host ai-common needs: those are deleted, after asking (v1's own
    .\deploy\deploy-uat.ps1 -MonitoringOnly brings v1's back; the rollback says so). Their volumes are kept.
    -SkipMonitoring leaves all of the monitoring in ai-remediation running.

.PARAMETER AppImage
    The image deploy\build-image.ps1 printed (<registry>/tsg-api:v2-<commit>): a pinned tag, never :latest.

.PARAMETER EnvFile
    The tested settings file, at the repo root. The monitoring always reads .env.uat (deploy\observability.ps1).

.PARAMETER SkipMonitoring
    Leave the monitoring and Flower as they are: v2's are not installed, and v1's (its Flower, exporters,
    monitoring programs and their Route) keep running.

.EXAMPLE
    .\deploy\deploy-uat.ps1 -AppImage quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:v2-1a2b3c4d5e6f
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $AppImage,
    [string] $EnvFile = '.env.uat',
    [switch] $SkipMonitoring,
    [int] $RolloutTimeoutSeconds = 600
)
$ErrorActionPreference = 'Stop'

$App = 'ai-threatgen'
$Extra = 'ai-remediation'
$Common = 'ai-common'  # the monitoring, shared with the chatbot
# The projects this run changes: ai-common only with the monitoring.
$Projects = if ($SkipMonitoring) { @($App, $Extra) } else { @($App, $Extra, $Common) }
$ApiHost = 'threatgen-api.apps.dda-desc-az1-01.desccii.local'
$MonitoringHost = 'threatgen-grafana.apps.dda-desc-az1-01.desccii.local'
$Hosts = [ordered]@{ $App = $ApiHost; $Extra = $MonitoringHost }
# Every app file carries these two lines until this script puts the real image and the settings fingerprint in.
$ImagePlaceholder = 'quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:v2-COMMIT'
$FingerprintPlaceholder = 'tsg/settings-fingerprint: none'
# v2's app Deployments in rollout order: every worker of both projects first (ai-remediation's, then
# ai-threatgen's and its beat), the API last of the whole run. A new API may queue work only a new worker can
# do (D18: a plan version stored without its snapshot), and an API pod is ready only when every queue has a
# live worker. One at a time: only one extra pod is ever starting.
$Rollout = [ordered]@{
    $Extra = @('worker-threats', 'worker-scenarios', 'worker-service-mapper', 'worker-maintenance')
    $App   = @('worker-threats', 'worker-scenarios', 'worker-service-mapper', 'worker-maintenance', 'beat', 'api')
}
# v2's monitoring programs (deploy\observability.yaml, deploy\flower.yaml), in ai-common. In ai-remediation a
# program of one of these names is v1's, or v2's own from before the move: either is deleted with its Route.
$Monitoring = @('prometheus', 'alertmanager', 'loki', 'alloy', 'grafana', 'redis-exporter', 'kube-state-metrics', 'flower')
# v1, stopped first: it shares Redis with v2. Scaled to 0, never deleted.
$V1 = [ordered]@{
    $App   = @('tsg-api', 'celery-worker', 'celery-worker-admin', 'tsg-beat', 'tsg-flower')
    $Extra = @('celery-worker', 'celery-exporter', 'mssql-exporter', 'mongodb-exporter')
}
# Of those, v1's monitoring: with -SkipMonitoring v2's is not installed, so these keep running, as do v1's
# programs under v2's monitoring names and v1's Route on the monitoring host.
$V1Monitoring = @('tsg-flower', 'celery-exporter', 'mssql-exporter', 'mongodb-exporter')
$Ours = @('tsg', 'tsg-observability')  # the app.kubernetes.io/part-of label of everything v2 creates
$Backups = Join-Path $env:USERPROFILE '.tsg\uat-backups'
$V1Dir = Join-Path $Backups 'v1'

# Windows PowerShell 5.1 passes text between programs as ASCII and may add a byte-order mark: UTF-8 without
# a mark, both ways (the generated YAML is plain ASCII anyway).
$utf8 = New-Object System.Text.UTF8Encoding $false
$OutputEncoding = $utf8
[Console]::OutputEncoding = $utf8

# Every oc / python call goes through here: a non-zero exit stops the run and names the step. Native stderr is
# never redirected (in 5.1, 2>&1 turns each stderr line into an error record).
# Its own variable names are used nowhere else: PowerShell looks a name up the call stack, so a step's block
# would read Invoke-Step's $Name in place of the caller's $name.
function Invoke-Step([string] $StepName, [scriptblock] $StepCommand) {
    Write-Host "==> $StepName" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    $stepOutput = & $StepCommand
    if ($LASTEXITCODE) { throw "Step '$StepName' failed (exit code $LASTEXITCODE)" }
    return $stepOutput
}

# The items oc lists, as objects (JSON, not jsonpath: 5.1 mangles quotes inside native arguments).
function Get-Items([string] $Ns, [string[]] $What) {
    $json = Invoke-Step "read $($What -join ' ') in $Ns" { oc -n $Ns get @What -o json }
    return @(($json -join "`n" | ConvertFrom-Json).items)
}

# An app file with the real image and the settings fingerprint in place of its two placeholder lines.
function Get-Manifest([string] $File) {
    $text = [IO.File]::ReadAllText((Join-Path (Get-Location) $File), $utf8)
    if (-not $text.Contains($ImagePlaceholder)) { throw "Step 'apply $File' failed: no $ImagePlaceholder in it" }
    return $text.Replace($ImagePlaceholder, $AppImage).Replace(
        $FingerprintPlaceholder, "tsg/settings-fingerprint: `"$fingerprint`"")
}

# A rollout that is not ready in time is almost always explained by the pods and the newest events
# (ImagePullBackOff, "exceeded quota", CreateContainerConfigError): print both before stopping.
function Wait-Rollout([string] $Ns, [string] $Deployment) {
    Write-Host "==> wait for $Ns/$Deployment (up to $RolloutTimeoutSeconds s)" -ForegroundColor Cyan
    oc -n $Ns rollout status "deployment/$Deployment" "--timeout=$($RolloutTimeoutSeconds)s"
    if ($LASTEXITCODE) {
        oc -n $Ns get pods | Out-Host
        oc -n $Ns get events --sort-by=.lastTimestamp | Select-Object -Last 25 | Out-Host
        throw "Step 'roll out $Ns/$Deployment' failed: not ready within $RolloutTimeoutSeconds s (pods and events above)"
    }
}

# ai-remediation's and ai-common's pods pull the images with ai-threatgen's pull secret (v1 copied it the same way).
function Copy-PullSecret([string] $Into) {
    if (oc -n $Into get secret quay-pull --ignore-not-found -o name) { return }
    $json = Invoke-Step "read quay-pull in $App" { oc -n $App get secret quay-pull -o json }
    $secret = $json -join "`n" | ConvertFrom-Json
    foreach ($field in 'resourceVersion', 'uid', 'creationTimestamp', 'managedFields', 'ownerReferences') {
        $secret.metadata.PSObject.Properties.Remove($field)
    }
    $secret.metadata.namespace = $Into
    Invoke-Step "copy quay-pull into $Into" { $secret | ConvertTo-Json -Depth 30 | oc apply -f - }
}

function Test-Url([string] $Url) {
    # -k: the router's certificate may be the company's own; nothing secret is sent.
    $code = curl.exe -sk -o NUL -w '%{http_code}' --max-time 20 $Url
    if ($code -ne '200') { throw "Step 'smoke test' failed: $Url answered $code" }
    Write-Host "    $Url  200"
}

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $Python = Join-Path (Get-Location) '.venv\Scripts\python.exe'
    $Generator = 'scripts\gen_openshift_config.py'

    # ---------------------------------------------------------------- 1. Preflight
    if ($AppImage -notmatch ':[\w][\w.-]*$' -or $AppImage -match ':latest$') {
        throw "-AppImage must end in a pinned tag (v2-<commit>, from deploy\build-image.ps1), never :latest"
    }
    if (-not (Test-Path $Python)) { throw "No ${Python}: create the virtual environment first (docs\RUNNING.md step 4)" }
    if (-not (Test-Path $EnvFile -PathType Leaf)) { throw "No $EnvFile in $(Get-Location)" }
    Invoke-Step 'logged in to the cluster' { oc whoami }
    foreach ($ns in $Projects) {
        Invoke-Step "may deploy to $ns" { oc auth can-i create deployments -n $ns }
        Invoke-Step "$ns's CPU and memory budget" { oc -n $ns describe quota }
    }
    foreach ($name in $Hosts.Values) {
        try { Resolve-DnsName -Name $name -ErrorAction Stop | Out-Null }
        catch { throw "$name does not resolve from this computer: connect to the company network (or use the jump server)" }
    }

    # ---------------------------------------------------------------- 2. Safety gate
    $gate = @($Generator, $EnvFile, '--gate')
    if (-not $SkipMonitoring) { $gate += '--monitoring' }
    Invoke-Step 'safety gate (must end GATE OK)' { & $Python @gate }

    # ---------------------------------------------------------------- 3. Safety copies and the rollback script
    $BackupDir = Join-Path $Backups (Get-Date -Format 'yyyyMMdd-HHmmss')
    New-Item -ItemType Directory -Force -Path $BackupDir, $V1Dir | Out-Null
    foreach ($ns in $Projects) {
        $everything = Invoke-Step "safety copy of $ns" {
            oc -n $ns get deployment,service,route,configmap,secret,poddisruptionbudget,networkpolicy -o yaml
        }
        [IO.File]::WriteAllLines((Join-Path $BackupDir "$ns.yaml"), [string[]]@($everything), $utf8)
    }
    $everything = $null

    # v1's replica counts: from the Deployment, or from the note a previous run left on it when it stopped it.
    $v1Found = @(); $replaced = @(); $theirRoutes = @(); $oldRoutes = @()
    foreach ($ns in $App, $Extra) {
        foreach ($item in Get-Items $ns @('deployment')) {
            $name = $item.metadata.name
            if ($V1[$ns] -contains $name) {
                if ($SkipMonitoring -and $V1Monitoring -contains $name) { continue }
                $now = [int]$item.spec.replicas
                $before = [math]::Max($now, [int]$item.metadata.annotations.'tsg/replicas-before-v2')
                $v1Found += [pscustomobject]@{ Ns = $ns; Name = $name; Now = $now; Before = $before }
            }
            elseif (-not $SkipMonitoring -and $ns -eq $Extra -and $Monitoring -contains $name) {
                $whose = if ($Ours -contains $item.metadata.labels.'app.kubernetes.io/part-of') { "v2's old" } else { "v1's" }
                $replaced += [pscustomobject]@{ Ns = $ns; Name = $name; Whose = $whose }
            }
        }
        if ($SkipMonitoring -and $ns -eq $Extra) { continue }  # its Route is the monitoring host's
        $onHost = @(Get-Items $ns @('route') | Where-Object { $_.spec.host -eq $Hosts[$ns] })
        $theirRoutes += @($onHost | Where-Object { $Ours -notcontains $_.metadata.labels.'app.kubernetes.io/part-of' })
        # v2's own Routes on the monitoring host in ai-remediation, from before the move: ai-common needs the host
        # (the router gives a host to the first project that claims it).
        if ($ns -eq $Extra) {
            $oldRoutes += @($onHost | Where-Object { $Ours -contains $_.metadata.labels.'app.kubernetes.io/part-of' })
        }
    }
    $running = @($v1Found | Where-Object { $_.Now -gt 0 })
    foreach ($route in $theirRoutes) {
        $copy = $route | ConvertTo-Json -Depth 30 | ConvertFrom-Json  # restorable: without the server's fields
        foreach ($field in 'resourceVersion', 'uid', 'creationTimestamp', 'managedFields', 'generation') {
            $copy.metadata.PSObject.Properties.Remove($field)
        }
        $copy.PSObject.Properties.Remove('status')
        $file = Join-Path $V1Dir "route-$($route.metadata.namespace)-$($route.metadata.name).json"
        [IO.File]::WriteAllText($file, ($copy | ConvertTo-Json -Depth 30), $utf8)
    }
    $rollback = @(
        "# Written by deploy-uat.ps1 on $(Get-Date -Format s). Stops v2 and brings v1 back as it was.",
        '# Run: powershell -File <this file>',
        "oc -n $App scale deployment -l app.kubernetes.io/part-of=tsg --replicas=0",
        "oc -n $Extra scale deployment -l app.kubernetes.io/part-of=tsg --replicas=0",
        "oc -n $App delete route -l app.kubernetes.io/part-of=tsg",
        "oc -n $Common delete deployment,route -l app.kubernetes.io/part-of=tsg-observability"
    )
    $rollback += @(Get-ChildItem $V1Dir -Filter 'route-*.json' | ForEach-Object { "oc apply -f `"$($_.FullName)`"" })
    $rollback += @($v1Found | Where-Object { $_.Before -gt 0 } | ForEach-Object {
        "oc -n $($_.Ns) scale deployment $($_.Name) --replicas=$($_.Before)"
    })
    $rollback += "# v1's monitoring: from the v1 repo, run .\deploy\deploy-uat.ps1 -MonitoringOnly"
    [IO.File]::WriteAllLines((Join-Path $BackupDir 'rollback.ps1'), [string[]]$rollback, $utf8)
    Write-Host "    safety copies and rollback.ps1 in $BackupDir (they hold passwords: keep them, never commit them)"

    # ---------------------------------------------------------------- 4. Stop v1
    if ($running.Count -or $replaced.Count -or $theirRoutes.Count -or $oldRoutes.Count) {
        Write-Host ''
        Write-Host 'v1 must stop first (it shares Redis with v2). This run will:' -ForegroundColor Yellow
        $running | ForEach-Object { Write-Host "    scale $($_.Ns)/$($_.Name) from $($_.Now) to 0" }
        $replaced | ForEach-Object { Write-Host "    delete $($_.Whose) monitoring program $($_.Ns)/$($_.Name) (v2's runs in $Common)" }
        $theirRoutes | ForEach-Object { Write-Host "    delete Route $($_.metadata.namespace)/$($_.metadata.name) on $($_.spec.host) (copy in $V1Dir)" }
        $oldRoutes | ForEach-Object { Write-Host "    delete v2's old Route $($_.metadata.namespace)/$($_.metadata.name) on $($_.spec.host) ($Common takes the host)" }
        if ((Read-Host 'Type YES to go on') -cne 'YES') { throw 'Stopped before changing anything: v1 is still running.' }
        foreach ($item in $running) {
            Invoke-Step "note v1 $($item.Ns)/$($item.Name)'s $($item.Now) replicas" {
                oc -n $item.Ns annotate "deployment/$($item.Name)" "tsg/replicas-before-v2=$($item.Now)" --overwrite
            }
            Invoke-Step "stop v1 $($item.Ns)/$($item.Name)" { oc -n $item.Ns scale "deployment/$($item.Name)" --replicas=0 }
        }
        foreach ($item in $replaced) {
            Invoke-Step "delete $($item.Whose) $($item.Ns)/$($item.Name)" { oc -n $item.Ns delete deployment $item.Name }
        }
        foreach ($route in $theirRoutes) {
            Invoke-Step "delete v1 Route $($route.metadata.name)" { oc -n $route.metadata.namespace delete route $route.metadata.name }
        }
        foreach ($route in $oldRoutes) {
            Invoke-Step "delete v2's old Route $($route.metadata.name)" { oc -n $route.metadata.namespace delete route $route.metadata.name }
        }
        # A v1 worker may take its whole 740 s grace period to finish what it is doing.
        $deadline = (Get-Date).AddSeconds(900)
        foreach ($ns in $App, $Extra) {
            while (oc -n $ns get pods -l app=tsg-api -o name) {
                if ((Get-Date) -gt $deadline) { throw "Step 'stop v1' failed: v1 pods still running in $ns after 900 s" }
                Write-Host "    waiting for v1's pods in $ns to finish ..."
                Start-Sleep -Seconds 10
            }
        }
    }

    # ---------------------------------------------------------------- 5. Settings and network rules, every project
    foreach ($ns in $Projects) {
        if ($ns -ne $App) { Copy-PullSecret $ns }
    }
    foreach ($ns in $Projects) {
        Invoke-Step "settings in $ns (ConfigMap and Secret from $EnvFile)" { & $Python $Generator $EnvFile | oc -n $ns apply -f - }
    }
    $fingerprint = Invoke-Step 'settings fingerprint' { & $Python $Generator $EnvFile --fingerprint }
    Invoke-Step 'network rules' { oc apply -f deploy\networkpolicy.yaml -f deploy\networkpolicy.ai-remediation.yaml }

    # ---------------------------------------------------------------- 6. The app, one Deployment at a time
    foreach ($ns in $Rollout.Keys) {  # hold each existing one, so the new files roll them one by one below
        foreach ($deployment in Get-Items $ns @('deployment', '-l', 'app.kubernetes.io/part-of=tsg')) {
            if (-not $deployment.spec.paused) {
                Invoke-Step "hold $ns/$($deployment.metadata.name)" { oc -n $ns rollout pause "deployment/$($deployment.metadata.name)" }
            }
        }
    }
    Invoke-Step "the app in $App (deploy\deploy.yaml)" { Get-Manifest 'deploy\deploy.yaml' | oc apply -f - }
    Invoke-Step "the workers in $Extra (deploy\deploy.ai-remediation.yaml)" { Get-Manifest 'deploy\deploy.ai-remediation.yaml' | oc apply -f - }
    foreach ($ns in $Rollout.Keys) {
        foreach ($name in $Rollout[$ns]) {
            if ((Invoke-Step "is $ns/$name held" { oc -n $ns get deployment $name -o 'jsonpath={.spec.paused}' }) -eq 'true') {
                Invoke-Step "release $ns/$name" { oc -n $ns rollout resume "deployment/$name" }
            }
            Wait-Rollout $ns $name
        }
    }
    $deadline = (Get-Date).AddSeconds(60)
    do {  # the router reports a new Route a few seconds after it is applied
        $admitted = oc -n $App get route api -o 'jsonpath={.status.ingress[0].conditions[0].status}'
        if ($admitted -eq 'True') { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ($admitted -ne 'True') { throw "Step 'Route api' failed: not admitted. Is $ApiHost path / used by another Route (oc get route -A)?" }

    # ---------------------------------------------------------------- 7. Monitoring and Flower (ai-common)
    if (-not $SkipMonitoring) {
        Write-Host '==> monitoring (deploy\observability.ps1)' -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot 'observability.ps1')
        Invoke-Step "Flower in $Common (deploy\flower.yaml)" { Get-Manifest 'deploy\flower.yaml' | oc apply -f - }
        Wait-Rollout $Common 'flower'
    }

    # ---------------------------------------------------------------- 8. Smoke test
    Write-Host '==> smoke test' -ForegroundColor Cyan
    Test-Url "https://$ApiHost/health"
    Test-Url "https://$ApiHost/ready"
    if (-not $SkipMonitoring) {
        Test-Url "https://$MonitoringHost/grafana/api/health"
        Test-Url "https://$MonitoringHost/flower/healthcheck"
    }

    Write-Host ''
    Write-Host 'Done. Open (no login needed to look):' -ForegroundColor Green
    Write-Host "  API          https://$ApiHost/docs"
    Write-Host "  Grafana      https://$MonitoringHost/grafana/"
    Write-Host "  Flower       https://$MonitoringHost/flower/"
    Write-Host "  Prometheus   https://$MonitoringHost/prometheus/"
    Write-Host "  Alertmanager https://$MonitoringHost/alertmanager/"
    Write-Host ''
    Write-Host 'Next, once: an API key for each calling system (POST /v1/tsg/api-clients, docs\RUNNING.md 10.1) and,'
    Write-Host 'with external intelligence on, POST /v1/tsg/intel/refresh (docs\RUNNING.md, External intelligence).'
    Write-Host "Undo: powershell -File `"$BackupDir\rollback.ps1`""
}
finally {
    Pop-Location
}
