<#
Build the TSG v2 image from the committed code, check that it loads, and push it to the registry.

    .\deploy\build-image.ps1            build, check, push
    .\deploy\build-image.ps1 -NoPush    build and check only (then move it with docker save / docker load)

The tag is v2-<commit>, so an image always names the exact code inside it: the build stops while any file it
copies (app/, pyproject.toml, requirements.txt, Dockerfile, .dockerignore) differs from the commit.
Log in to the registry first: docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
Prints the image name to give deploy-uat.ps1.
#>
param(
    [string] $Registry = 'quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc',
    # v1's repository: the cluster's pull secret (quay-pull) can already read it; the v2- tags keep v2 apart.
    [string] $Repository = 'tsg-api',
    [switch] $NoPush
)
$ErrorActionPreference = 'Stop'

function Assert-Ok([string] $step) {
    if ($LASTEXITCODE) { throw "$step failed (exit code $LASTEXITCODE)" }
}

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $changed = git status --porcelain --untracked-files=all -- app pyproject.toml requirements.txt Dockerfile .dockerignore
    Assert-Ok 'git status'
    if ($changed) {
        throw "These build files differ from the last commit (commit them first, so the image matches its tag):`n$($changed -join "`n")"
    }
    $commit = git rev-parse --short=12 HEAD
    Assert-Ok 'git rev-parse'
    $image = "$Registry/${Repository}:v2-$commit"

    docker build --platform linux/amd64 -t $image .
    Assert-Ok 'docker build'
    # The image must load the API, the worker code and the SQL Server driver. .env.example has a value for
    # every setting; an import calls no store and no AI.
    docker run --rm --env-file .env.example $image python -c "import pyodbc, app.main, app.worker; print('image OK')"
    Assert-Ok 'image check'
    if (-not $NoPush) {
        docker push $image
        Assert-Ok 'docker push'
    }
    Write-Host ''
    Write-Host "Image: $image" -ForegroundColor Green
    Write-Host "Next:  .\deploy\deploy-uat.ps1 -AppImage $image"
}
finally {
    Pop-Location
}
