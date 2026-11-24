<#
.SYNOPSIS
    Stop everything .\run_dev.ps1 (or, on the UAT server, .\run_uat.ps1) started: the API, worker and beat
    windows and the monitoring tools.

.DESCRIPTION
    The worker is asked to finish its running jobs first (up to -DrainSeconds), then the three windows close and
    the monitoring tools stop. Safe to run twice. Only what the run script started is stopped: each window is
    noted in .run\processes.json, and a process is stopped only if its id AND start time still match.

    Same as .\run_dev.ps1 stop (on UAT, .\run_uat.ps1 stop does the same): the steps live in the run script, so
    the two can never stop things differently.

.PARAMETER DrainSeconds
    How long to wait for the worker to finish its running jobs. Default 60.

.EXAMPLE
    .\stop.ps1

.EXAMPLE
    .\stop.ps1 -DrainSeconds 0
#>
#Requires -PSEdition Desktop
# Windows PowerShell 5.1 only: PowerShell 7 reads the run script's saved start times as dates, and stop then finds no
# window to stop.

[CmdletBinding()]
param(
    [int]$DrainSeconds = 60
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'run_dev.ps1') stop -DrainSeconds $DrainSeconds
exit $LASTEXITCODE  # 1 when something could not be stopped (named above)
