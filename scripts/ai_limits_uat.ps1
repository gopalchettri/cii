<#
.SYNOPSIS
    Check the UAT AI gateway's limits for every AI key, from inside the UAT api pod.

.DESCRIPTION
    Sends scripts\ai_limits_check.py into the api pod, which runs it with the keys it already holds (the key is
    never shown or copied). Shows the report and saves it to ai_limits_uat_<time>.txt in the current folder.
    Log in first: oc login.

.EXAMPLE
    .\scripts\ai_limits_uat.ps1
#>

$Namespace = 'ai-threatgen'
$Gateway = 'https://llmapi.govai.ae'
# Each key variable in the pod, and the model it is checked against.
$Checks = @(
    @('CII_SCENARIO_CHAT_API_KEY', '--model', 'kimi-k2.5'),
    @('CII_REMEDIATION_CHAT_API_KEY', '--model', 'glm-5.3'),
    @('CII_SERVICE_MAPPER_CHAT_API_KEY', '--model', 'glm-5.3'),
    @('CII_EMBEDDING_API_KEY', '--embedding-model', 'qwen3-embedding-8b'),
    @('CII_RERANK_API_KEY', '--rerank-model', 'qwen3-reranker-8b')
)

$Check = Get-Content (Join-Path $PSScriptRoot 'ai_limits_check.py') -Raw
$Report = foreach ($One in $Checks) {
    "=== Key: $($One[0]) ==="
    $Check | oc exec -i -n $Namespace deploy/api -- python - --base-url $Gateway $One[1] $One[2] `
        --key-env $One[0] --out /tmp/ai_limits.txt | Where-Object { $_ -notlike 'Saved to /tmp*' }
    if ($LASTEXITCODE -ne 0) { "(this check failed: is 'oc login' done?)" }
    ''
}
$File = "ai_limits_uat_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
$Report | Out-File $File -Encoding utf8
$Report
"Saved to $((Resolve-Path $File).Path)"
