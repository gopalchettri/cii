@echo off
rem Build the TSG image from the committed code, check that it starts, and push it to Quay.
rem
rem   deploy\build-image.bat                   tag = today's date, e.g. 24-Oct-2026; build, check, push
rem   deploy\build-image.bat 24-Oct-2026-2     use this tag (a second build on the same day)
rem   deploy\build-image.bat --no-push         build and check only
rem
rem Log in first: docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
rem Then put the printed tag in deploy\deploy_threatgen.yaml, deploy_remediation.yaml and deploy_common.yaml.
setlocal EnableExtensions DisableDelayedExpansion

set "REGISTRY=quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc"
set "REPOSITORY=tsg-api"
set "INPUTS=app pyproject.toml requirements.txt Dockerfile .dockerignore"
set "TAG="
set "PUSH=1"
rem The repo root (the folder above deploy\), saved before shift moves %%0.
set "ROOT=%~dp0.."

rem Read the arguments: --no-push, or a tag.
:read_args
if "%~1"=="" goto args_read
if /i "%~1"=="--no-push" (set "PUSH=0") else (set "TAG=%~1")
shift
goto read_args
:args_read

rem Work from the repo root, wherever this was started from.
pushd "%ROOT%" || (echo ERROR: cannot open the repo folder %ROOT%. & exit /b 1)

rem 1. Git must work here, and the build files must match the last commit.
call git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (echo ERROR: git does not work in %CD%. & goto fail)
set "DIRTY="
for /f "delims=" %%L in ('git status --porcelain --untracked-files^=all -- %INPUTS%') do (
    set "DIRTY=1"
    echo   changed: %%L
)
if defined DIRTY (
    echo ERROR: these build files differ from the last commit. Commit them first, so the image is the committed code.
    goto fail
)

rem 2. The last commit that changed the build files: written on the image as a label.
set "COMMIT="
for /f %%C in ('git log -1 "--format=%%h" --abbrev^=12 -- %INPUTS%') do set "COMMIT=%%C"
if not defined COMMIT (echo ERROR: git log found no commit for the build files. & goto fail)

rem 3. The tag: today's date with an English month name (24-Oct-2026), unless one was given.
if not defined TAG for /f %%D in ('powershell -NoProfile -Command "(Get-Date).ToString('dd-MMM-yyyy', [Globalization.CultureInfo]::InvariantCulture)"') do set "TAG=%%D"
if not defined TAG (echo ERROR: could not read today's date from PowerShell. Pass the tag: deploy\build-image.bat 24-Oct-2026 & goto fail)
set "IMAGE=%REGISTRY%/%REPOSITORY%:%TAG%"

rem 4. Never overwrite a tag in Quay: the pods would keep running the old image.
if "%PUSH%"=="0" goto build
call docker manifest inspect "%IMAGE%" >nul 2>&1
if errorlevel 1 goto build
echo ERROR: %IMAGE% is already in Quay. Use a new tag, e.g.: deploy\build-image.bat %TAG%-2
goto fail

rem 5. Build the image.
:build
echo Building %IMAGE% (commit %COMMIT%)
call docker build --platform linux/amd64 --label "org.opencontainers.image.revision=%COMMIT%" -t "%IMAGE%" .
if errorlevel 1 (echo ERROR: docker build failed. & goto fail)

rem 6. Check the image loads the API, the worker and the SQL Server driver (.env.example has every setting).
call docker run --rm --env-file .env.example "%IMAGE%" python -c "import pyodbc, app.main, app.worker; print('image OK')"
if errorlevel 1 (echo ERROR: the image check failed: the image does not start. & goto fail)

rem 7. Push it to Quay.
if "%PUSH%"=="0" goto done
call docker push "%IMAGE%"
if errorlevel 1 (echo ERROR: docker push failed. Run docker login first. & goto fail)

:done
echo.
echo Image:  %IMAGE%
echo Tag:    %TAG%
echo Commit: %COMMIT%
echo Next:   put %TAG% in deploy\deploy_threatgen.yaml, deploy\deploy_remediation.yaml and deploy\deploy_common.yaml,
echo         then follow deploy\DEPLOYMENT_GUIDE.md
popd
endlocal
exit /b 0

:fail
popd
endlocal
exit /b 1
