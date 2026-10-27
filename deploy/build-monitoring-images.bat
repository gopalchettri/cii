@echo off
rem Build the 8 monitoring images on Red Hat UBI 9, check each runs as OpenShift runs it, and push them to Quay.
rem
rem   deploy\build-monitoring-images.bat                     all 8: build, check, push
rem   deploy\build-monitoring-images.bat grafana             only this image (any of the 8 names)
rem   deploy\build-monitoring-images.bat grafana --no-push   build and check only
rem
rem The names and tags are the image: lines of deploy\deploy_common.yaml (change a version there, then run this;
rem for kube-state-metrics also set SRC_SHA256 in its Dockerfile to the new tag's source archive sha256).
rem Each image is built from deploy\images\NAME\Dockerfile. Log in first:
rem   docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
setlocal EnableExtensions DisableDelayedExpansion

set "REGISTRY=quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc"
set "YAML=deploy\deploy_common.yaml"
set "OUT=%TEMP%\build-monitoring-images.txt"
set "PUSH=1"
set "ONLY="
set "DONE="
rem The arguments that make each program print its version and exit.
set "VERSION_prometheus=--version"
set "VERSION_alertmanager=--version"
set "VERSION_loki=-version"
set "VERSION_alloy=--version"
set "VERSION_grafana=--version"
set "VERSION_redis_exporter=-version"
set "VERSION_kube-state-metrics=version"
set "VERSION_nginx=-v"
rem kube-state-metrics' version command refuses the --port flags its ENTRYPOINT adds, so it runs the bare binary.
set "ENTRY_kube-state-metrics=--entrypoint /kube-state-metrics"
rem The repo root (the folder above deploy\), saved before shift moves %%0.
set "ROOT=%~dp0.."

rem Read the arguments: --no-push, and at most one image name.
:read_args
if "%~1"=="" goto args_read
if /i "%~1"=="--no-push" (set "PUSH=0") else if defined ONLY (echo ERROR: give one image name at most. & exit /b 1) else (set "ONLY=%~1")
shift
goto read_args
:args_read

rem Work from the repo root, wherever this was started from.
pushd "%ROOT%" || (echo ERROR: cannot open the folder above deploy\. & exit /b 1)

rem 1. The images: every image: line in Quay but the app's (tsg-api), each name:tag once.
set "LIST= "
set "NAMES= "
for /f "tokens=2" %%R in ('findstr /r /c:"^ *image: " "%YAML%"') do call :add_image "%%R"
if "%LIST%"==" " (echo ERROR: no monitoring image: lines found in %YAML%. & goto fail)
echo Images in %YAML%:%LIST%

rem 2. A name given must be one of them.
if not defined ONLY goto build_all
call set "REST=%%NAMES: %ONLY% =%%"
if "%REST%"=="%NAMES%" (echo ERROR: "%ONLY%" is not --no-push or one of the images:%NAMES%& goto fail)

rem 3. Build, check and push each image in turn; stop at the first failure.
:build_all
for %%I in (%LIST%) do (
    call :one_image %%I
    if errorlevel 1 goto fail
)

echo.
if "%PUSH%"=="1" (echo Built, checked and pushed to Quay:) else (echo Built and checked, not pushed:)
for %%I in (%DONE%) do echo   %%I
if "%PUSH%"=="1" echo Next:   the next step of deploy\DEPLOYMENT_GUIDE.md
if exist "%OUT%" del "%OUT%"
popd
endlocal
exit /b 0

:fail
if exist "%OUT%" del "%OUT%"
if defined DONE if "%PUSH%"=="1" (echo Pushed before the failure:%DONE%) else (echo Built before the failure, not pushed:%DONE%)
popd
endlocal
exit /b 1

rem Add one image: line's image (%%1) to LIST, unless it is another registry's, the app's or already there.
:add_image
set "REF=%~1"
call set "NAMETAG=%%REF:%REGISTRY%/=%%"
if "%NAMETAG%"=="%REF%" exit /b 0
for /f "tokens=1,2 delims=:" %%A in ("%NAMETAG%") do (set "NAME=%%A" & set "TAG=%%B")
if /i "%NAME%"=="tsg-api" exit /b 0
call set "REST=%%LIST: %NAMETAG% =%%"
if not "%REST%"=="%LIST%" exit /b 0
set "LIST=%LIST%%NAMETAG% "
set "NAMES=%NAMES%%NAME% "
exit /b 0

rem Build one image (%%1 = name:tag), check it, push it; exit 1 on any failure.
:one_image
for /f "tokens=1,2 delims=:" %%A in ("%~1") do (set "NAME=%%A" & set "TAG=%%B")
if defined ONLY if /i not "%NAME%"=="%ONLY%" exit /b 0
set "IMAGE=%REGISTRY%/%NAME%:%TAG%"
set "BARE=%TAG%"
if /i "%BARE:~0,1%"=="v" set "BARE=%BARE:~1%"
set "VERSION_ARGS="
call set "VERSION_ARGS=%%VERSION_%NAME%%%"
if not defined VERSION_ARGS (echo ERROR: no version check for %NAME%: add VERSION_%NAME% at the top of this file. & exit /b 1)
set "ENTRY="
call set "ENTRY=%%ENTRY_%NAME%%%"
if not exist "deploy\images\%NAME%\Dockerfile" (echo ERROR: deploy\images\%NAME%\Dockerfile is missing. & exit /b 1)

rem Never overwrite a tag in Quay: the pods would keep running the old image. Only "no such manifest" means it is
rem not there; any other error (certificate, network) stops the build rather than risk an overwrite.
if "%PUSH%"=="0" goto image_build
call docker manifest inspect "%IMAGE%" >"%OUT%" 2>&1
if not errorlevel 1 (echo ERROR: %IMAGE% is already in Quay. That is fine only if it is the UBI 9 build: check it, and build the others by name, as deploy\DEPLOYMENT_GUIDE.md Part 2, step 3 shows. & exit /b 1)
findstr /l /c:"no such manifest:" "%OUT%" >nul && goto image_build
type "%OUT%"
echo ERROR: cannot check whether %IMAGE% is already in Quay: fix the error above, or use --no-push to build and check only.
exit /b 1

:image_build
echo.
echo Building %IMAGE%
call docker build --platform linux/amd64 --build-arg "TAG=%TAG%" -t "%IMAGE%" "deploy\images\%NAME%"
if errorlevel 1 (echo ERROR: docker build failed for %NAME%. & exit /b 1)

rem Check it starts as OpenShift starts it (a random user in group 0) and prints the tag's version.
call docker run --rm --user 1000870000:0 %ENTRY% "%IMAGE%" %VERSION_ARGS% >"%OUT%" 2>&1
if errorlevel 1 (type "%OUT%" & echo ERROR: %NAME% does not start as a random user in group 0, as OpenShift runs it. & exit /b 1)
type "%OUT%"
findstr /l /c:"%BARE%" "%OUT%" >nul
if errorlevel 1 (echo ERROR: %NAME% does not print version %BARE%. & exit /b 1)

rem nginx only: the proxy's own config must load (nginx -t), as the pod runs it: a random user, the file mounted
rem where deploy_common.yaml mounts it, the same arguments. Grafana's and Flower's names point at this container.
if /i not "%NAME%"=="nginx" goto image_push
call docker run --rm --user 1000870000:0 --add-host grafana.ai-common.svc.cluster.local:127.0.0.1 --add-host flower.ai-common.svc.cluster.local:127.0.0.1 -v "%CD%\observability\nginx:/etc/nginx/tsg:ro" "%IMAGE%" -t -e stderr -c /etc/nginx/tsg/nginx.conf >"%OUT%" 2>&1
if errorlevel 1 (type "%OUT%" & echo ERROR: nginx does not accept observability\nginx\nginx.conf: fix it there and in deploy\configmap.yaml. & exit /b 1)
type "%OUT%"

:image_push
rem Push it to Quay.
if "%PUSH%"=="0" goto image_done
call docker push "%IMAGE%"
if errorlevel 1 (echo ERROR: docker push failed for %NAME%. If docker login said Login Succeeded, a "denied" or "unauthorized" above means your Quay user cannot create the repository dda-desc/%NAME%, or may not write to it: the Quay admin gives you Write on it, creating it if missing, or lets you create repositories in dda-desc. See deploy\DEPLOYMENT_GUIDE.md Part 1. & exit /b 1)
:image_done
set "DONE=%DONE% %IMAGE%"
exit /b 0
