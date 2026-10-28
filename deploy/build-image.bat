@echo off
rem Build the TSG image from the code in this folder (a git checkout or a downloaded ZIP), check that it starts,
rem and push it to Quay.
rem
rem   deploy\build-image.bat                   tag = today's date, e.g. 24-Oct-2026; build, check, push
rem   deploy\build-image.bat 24-Oct-2026-2     use this tag (a second build on the same day)
rem   deploy\build-image.bat --no-push         build and check only
rem
rem Log in first: docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
rem Then put the printed tag in deploy\deploy_threatgen.yaml and deploy_common.yaml.
setlocal EnableExtensions DisableDelayedExpansion

set "REGISTRY=quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc"
set "REPOSITORY=tsg-api"
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
pushd "%ROOT%" || (echo ERROR: cannot open the folder above deploy\. & exit /b 1)

rem 1. The tag: today's date with an English month name (24-Oct-2026), unless one was given.
if not defined TAG for /f %%D in ('powershell -NoProfile -Command "(Get-Date).ToString('dd-MMM-yyyy', [Globalization.CultureInfo]::InvariantCulture)"') do set "TAG=%%D"
if not defined TAG (echo ERROR: could not read today's date from PowerShell. Pass the tag: deploy\build-image.bat 24-Oct-2026 & goto fail)
set "IMAGE=%REGISTRY%/%REPOSITORY%:%TAG%"

rem 2. Never overwrite a tag in Quay: the pods would keep running the old image. Only "no such manifest" means
rem    it is not there; any other error (certificate, network) stops the build rather than risk an overwrite.
if "%PUSH%"=="0" goto build
set "OUT=%TEMP%\build-image-manifest.txt"
call docker manifest inspect "%IMAGE%" >"%OUT%" 2>&1
if not errorlevel 1 (echo ERROR: %IMAGE% is already in Quay. Use a new tag, e.g.: deploy\build-image.bat %TAG%-2 & goto fail)
findstr /l /c:"no such manifest:" "%OUT%" >nul && goto build
type "%OUT%"
echo ERROR: cannot check whether %IMAGE% is already in Quay: fix the error above, or use --no-push.
goto fail

rem 3. Build the image.
:build
echo Building %IMAGE%
call docker build --platform linux/amd64 -t "%IMAGE%" .
if errorlevel 1 (echo ERROR: docker build failed. & goto fail)

rem 4. Check the image loads the API, the worker and the SQL Server driver (.env.example has every setting).
call docker run --rm --env-file .env.example "%IMAGE%" python -c "import pyodbc, app.main, app.worker; print('image OK')"
if errorlevel 1 (echo ERROR: the image check failed: the image does not start. & goto fail)

rem 5. Push it to Quay.
if "%PUSH%"=="0" goto done
call docker push "%IMAGE%"
if errorlevel 1 (echo ERROR: docker push failed. Run docker login first. & goto fail)

:done
echo.
echo Image:  %IMAGE%
echo Tag:    %TAG%
echo Next:   put %TAG% in deploy\deploy_threatgen.yaml and deploy\deploy_common.yaml,
echo         then follow deploy\DEPLOYMENT_GUIDE.md
popd
endlocal
exit /b 0

:fail
popd
endlocal
exit /b 1
