<#
Build the TSG v2 image from the committed code, check that it loads, and push it to the registry.

    .\deploy\build-image.ps1            build, check, push
    .\deploy\build-image.ps1 -NoPush    build and check only (then move it with docker save / docker load)

The tag is v2-<commit>, where <commit> is the last commit that changed a file the image is built from
(app/, pyproject.toml, requirements.txt, Dockerfile, .dockerignore): a commit that changes only YAML or docs keeps
the same tag, and an image always names the exact code inside it. The build stops while any of those files
differs from the last commit.
Log in to the registry first: docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
Prints the image tag to put in deploy\deploy_threatgen.yaml, deploy_remediation.yaml and deploy_common.yaml
(step by step: deploy\DEPLOYMENT_GUIDE.md).
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
    $buildInputs = @('app', 'pyproject.toml', 'requirements.txt', 'Dockerfile', '.dockerignore')
    $changed = git status --porcelain --untracked-files=all -- $buildInputs
    Assert-Ok 'git status'
    if ($changed) {
        throw "These build files differ from the last commit (commit them first, so the image matches its tag):`n$($changed -join "`n")"
    }
    # The last commit that changed the image's inputs, not HEAD: a YAML-only commit keeps the tag.
    $commit = git log -1 --format=%h --abbrev=12 -- $buildInputs
    Assert-Ok 'git log'
    $tag = "v2-$commit"
    $image = "$Registry/${Repository}:$tag"

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
    Write-Host "Tag:   $tag" -ForegroundColor Green
    Write-Host "Next:  put $tag in deploy\deploy_threatgen.yaml, deploy\deploy_remediation.yaml and deploy\deploy_common.yaml,"
    Write-Host "       then follow deploy\DEPLOYMENT_GUIDE.md"
}
finally {
    Pop-Location
}
