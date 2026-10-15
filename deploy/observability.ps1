<#
Apply TSG monitoring (deploy/observability.yaml) to project ai-remediation, as v1 kept it there (log in with
`oc login` first; this makes ai-remediation the current project):

    .\deploy\observability.ps1

Reads the UAT settings file .env.uat (repo root; never commit it): Grafana's admin password
(GRAFANA_ADMIN_PASSWORD), every Grafana setting (GF_ lines) and the broker URL (its database holds the queues).
Safe to run again: every step is an apply. Images must be in the mirror first (STEP 0 in observability.yaml).
Flower (deploy/flower.yaml) runs from the app image: deploy/deploy-uat.ps1 applies it.
#>
$ErrorActionPreference = "Stop"
$Namespace = 'ai-remediation'
# Windows PowerShell 5.1 passes text between programs (oc ... | oc apply) as ASCII and may add a byte-order
# mark: every non-ASCII character in the settings would arrive as "?". UTF-8 without a mark, both ways, keeps
# them intact.
$utf8 = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8
[Console]::OutputEncoding = $utf8
[Console]::InputEncoding = $utf8
$repo = Split-Path $PSScriptRoot -Parent
$obs = Join-Path $repo "observability"
$appEnv = Join-Path $repo ".env.uat"
# Grafana settings the scripts set themselves (the same list as FIXED_GRAFANA_SETTINGS in
# scripts/monitoring_commands.py): a GF_ line for one of these in .env.uat is ignored.
$fixedGrafana = @('GF_SERVER_ROOT_URL', 'GF_SERVER_SERVE_FROM_SUB_PATH', 'GF_SERVER_HTTP_ADDR', 'GF_SERVER_HTTP_PORT',
    'GF_SECURITY_ADMIN_PASSWORD', 'GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH', 'GF_LOG_MODE', 'GF_PATHS_')

function Assert-Ok([string] $step) {
    if ($LASTEXITCODE) { throw "$step failed (exit code $LASTEXITCODE)" }
}

function Read-EnvFile([string] $path) {
    # KEY=value lines read as the app's python-dotenv reads them: comment lines skipped, quotes removed, an
    # unquoted value ends at whitespace followed by '#', and a later line for the same key wins.
    $values = [ordered]@{}
    foreach ($line in [IO.File]::ReadAllLines($path, $utf8)) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"([^"]*)"|''([^'']*)''|(.*?))(?:\s+#.*)?\s*$') {
            $value = if ($null -ne $Matches[2]) { $Matches[2] } elseif ($null -ne $Matches[3]) { $Matches[3] } else { $Matches[4] }
            $values[$Matches[1]] = $value.Trim()
        }
    }
    return $values
}

# The ConfigMaps are built straight from the files in observability/, so the laptop and UAT use the same ones.
function Set-ConfigMap([string] $name, [string[]] $files) {
    $fromFiles = $files | ForEach-Object { "--from-file=$_" }
    oc create configmap $name @fromFiles --dry-run=client -o yaml | oc apply -f -
    Assert-Ok "ConfigMap $name"
}

function Set-Secret([string] $name, $values) {
    # Grafana reads tsg-grafana-settings, so it must exist even when .env.uat has no GF_ line: then it is
    # applied empty, with no env file (an empty one is not something every oc version accepts).
    if (-not $values.Count) {
        oc create secret generic $name --dry-run=client -o yaml | oc apply -f -
        Assert-Ok "Secret $name"
        return
    }
    # Through a temporary file, not --from-literal: a command line is visible to every program on this PC.
    $file = [IO.Path]::GetTempFileName()
    try {
        $lines = [string[]]@($values.Keys | ForEach-Object { "$_=$($values[$_])" })
        [IO.File]::WriteAllLines($file, $lines, $utf8)
        oc create secret generic $name --from-env-file="$file" --dry-run=client -o yaml | oc apply -f -
        Assert-Ok "Secret $name"
    } finally {
        Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue
    }
}

# Every setting is checked before anything is applied.
if (-not (Test-Path $appEnv)) { throw "Missing $appEnv - the UAT settings file (copy .env.example and fill it in)." }
$settings = Read-EnvFile $appEnv
$password = [string]$settings['GRAFANA_ADMIN_PASSWORD']
if (-not $password) {
    # No line (owner, 2026-10-15: "no id pass for grafana"): everyone views without a login (anonymous viewer);
    # the admin account gets a random password that is never shown, so nobody can log in to change Grafana.
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = [Convert]::ToBase64String($bytes)
} elseif ($password.Length -lt 16) {
    throw "GRAFANA_ADMIN_PASSWORD in ${appEnv}: 16 or more characters, or leave the line out (no Grafana login)."
}
$broker = [string]$settings['CII_REDIS_CELERY_BROKER_URL']
if (-not $broker) { throw "CII_REDIS_CELERY_BROKER_URL is not set in $appEnv" }
# The queues' database is the number at the end of the broker URL (as on the laptop): never typed a second time.
$redisDb = ([Uri]$broker).AbsolutePath.Trim('/')
if (-not $redisDb) { $redisDb = '0' }
$grafana = [ordered]@{}
foreach ($key in $settings.Keys) {
    $fixed = @($fixedGrafana | Where-Object { $key.StartsWith($_) })
    if ($key.StartsWith('GF_') -and -not $fixed.Count) { $grafana[$key] = $settings[$key] }
}

# The ConfigMaps and Secrets below are applied to the current project: make it ai-remediation.
oc project $Namespace
Assert-Ok "oc project $Namespace"
Set-ConfigMap prometheus-config @("$obs/prometheus/prometheus.yml", "$obs/prometheus/rules.yml")
Set-ConfigMap alertmanager-config @("$obs/alertmanager/alertmanager.yml")
Set-ConfigMap loki-config @("$obs/loki/loki.yaml")
Set-ConfigMap alloy-config @("config.alloy=$obs/alloy/uat.alloy")
Set-ConfigMap grafana-provisioning @(
    "$obs/grafana/provisioning/datasources/datasources.yaml",
    "$obs/grafana/provisioning/dashboards/dashboards.yaml")
Set-ConfigMap grafana-dashboards @("$obs/grafana/dashboards/tsg.json")
Set-Secret tsg-monitoring ([ordered]@{ GF_SECURITY_ADMIN_PASSWORD = $password; REDIS_DB = $redisDb })
Set-Secret tsg-grafana-settings $grafana

oc apply -f "$PSScriptRoot/observability.yaml"
Assert-Ok "oc apply observability.yaml"

# A Route whose host another namespace already claimed is stored but never served: check each was admitted.
# The router reports a new Route a few seconds after it is applied (its status is empty until then), so each is
# judged on the router's answer, waited for up to 60 s; before, a first deploy could fail on the empty status.
foreach ($route in oc get route -l app.kubernetes.io/part-of=tsg-observability -o name) {
    $deadline = (Get-Date).AddSeconds(60)
    do {
        $admitted = oc get $route -o "jsonpath={.status.ingress[0].conditions[?(@.type=='Admitted')].status}"
        if ($admitted) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ($admitted -ne "True") { throw "$route was not admitted: is its host used by another project or Route?" }
}

# A running pod never sees a changed ConfigMap or Secret: restart them all (each has one replica), then wait
# until each is running again, so "applied" means working.
oc rollout restart deployment -l app.kubernetes.io/part-of=tsg-observability
Assert-Ok "rollout restart"
foreach ($deployment in oc get deployment -l app.kubernetes.io/part-of=tsg-observability -o name) {
    oc rollout status $deployment --timeout=300s
    Assert-Ok "$deployment did not start (oc describe $deployment; oc get events)"
}

$monitoringHost = oc get route grafana -o 'jsonpath={.spec.host}'
Write-Host "Monitoring applied and running. Open https://$monitoringHost/grafana/ (no login needed)."
