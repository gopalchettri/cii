# Deploy TSG to OpenShift

Run every step in order, in PowerShell, from the `cii-main` folder (the one with `pyproject.toml`).
Replace `<...>` with your value.

| Project | What runs there |
|---|---|
| `ai-threatgen` | API, 4 workers, beat |
| `ai-remediation` | A second copy of the 4 workers |
| `ai-common` | Monitoring (Grafana, Prometheus, Loki ...) and Flower |

## First deployment

### 1. Log in

```powershell
oc login --server=<cluster API address>
docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
```

### 2. Build and push the 7 monitoring images

```powershell
deploy\build-monitoring-images.bat
```

Takes a while the first time. Check: it ends with the list of 7 images and no `ERROR`.

### 3. Build and push the app image

```powershell
deploy\build-image.bat
```

Write down the `Tag:` it prints (e.g. `24-Oct-2026`).

### 4. Put the tag in the YAML files

```powershell
$old = (Select-String -Path deploy\deploy_threatgen.yaml -Pattern 'tsg-api:(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
$new = '<tag from step 3>'
foreach ($f in 'deploy_threatgen.yaml', 'deploy_remediation.yaml', 'deploy_common.yaml') { $p = Join-Path $PWD "deploy\$f"; [IO.File]::WriteAllText($p, [IO.File]::ReadAllText($p).Replace("tsg-api:$old", "tsg-api:$new")) }
Select-String -Path deploy\deploy_*.yaml -Pattern 'tsg-api:'
```

Check: every line shows the new tag.

### 5. Copy the image pull secret to the other two projects

```powershell
oc -n ai-threatgen extract secret/quay-pull --keys=.dockerconfigjson "--to=$env:TEMP" --confirm
oc -n ai-remediation create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
oc -n ai-common create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
Remove-Item "$env:TEMP\.dockerconfigjson"
```

### 6. Secrets

```powershell
Copy-Item deploy\secrets.example.yaml deploy\secrets.yaml
notepad deploy\secrets.yaml
```

Replace every `CHANGE_ME` with the real value. A password inside a connection string must be URL-encoded
(`@` becomes `%40`). The Grafana password needs 16 or more characters.

```powershell
Select-String -Path deploy\secrets.yaml -Pattern '^[^#]*CHANGE_ME'
oc apply -f deploy\secrets.yaml
```

Check: `Select-String` prints nothing. Keep `secrets.yaml` private.

### 7. Settings

In `configmap.yaml`, set `CII_CORS_ORIGINS` to the platform UI's https address (not `*`).

```powershell
notepad deploy\configmap.yaml
oc apply -f deploy\configmap.yaml
```

### 8. Remove the old deploy

The API is down from here until step 11. `NotFound` is fine.

```powershell
oc -n ai-threatgen scale deployment tsg-api celery-worker celery-worker-admin tsg-beat tsg-flower --replicas=0
oc -n ai-remediation scale deployment celery-worker celery-exporter mssql-exporter mongodb-exporter --replicas=0
oc -n ai-threatgen delete deployment api worker-threats worker-scenarios worker-service-mapper worker-maintenance beat --ignore-not-found
oc -n ai-remediation delete deployment worker-threats worker-scenarios worker-service-mapper worker-maintenance --ignore-not-found
oc -n ai-remediation delete deployment prometheus alertmanager loki alloy grafana redis-exporter kube-state-metrics flower --ignore-not-found
oc -n ai-remediation delete route grafana prometheus alertmanager loki flower --ignore-not-found
foreach ($p in 'ai-threatgen', 'ai-remediation', 'ai-common') { "== $p"; oc -n $p get route | findstr threatgen }
```

The last line lists the Routes on the two `threatgen` addresses. Delete any old one, except `api` in `ai-threatgen`:

```powershell
oc -n <project> delete route <name>
```

### 9. Network rules

```powershell
oc apply -f deploy\networkpolicy_threatgen.yaml -f deploy\networkpolicy_remediation.yaml
```

### 10. Workers in ai-remediation

```powershell
oc apply -f deploy\deploy_remediation.yaml
foreach ($d in 'worker-threats', 'worker-scenarios', 'worker-service-mapper', 'worker-maintenance') { oc -n ai-remediation rollout status deployment/$d --timeout=10m }
```

Check: each line ends with `successfully rolled out`.

### 11. API, workers and beat in ai-threatgen

```powershell
oc apply -f deploy\deploy_threatgen.yaml
foreach ($d in 'worker-threats', 'worker-scenarios', 'worker-service-mapper', 'worker-maintenance', 'beat', 'api') { oc -n ai-threatgen rollout status deployment/$d --timeout=10m }
```

Check: each line ends with `successfully rolled out`.

### 12. Monitoring and Flower in ai-common

```powershell
oc apply -f deploy\deploy_common.yaml
foreach ($d in 'prometheus', 'alertmanager', 'loki', 'alloy', 'grafana', 'redis-exporter', 'kube-state-metrics', 'flower') { oc -n ai-common rollout status deployment/$d --timeout=10m }
```

Check: each line ends with `successfully rolled out`.

### 13. Check

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/health
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ready
```

Check: both answer `ok` / `ready`. Grafana opens at
https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/grafana/ (log in as `admin` only to change it).

### 14. Create an API key for each calling system

The key is shown once: copy it.

```powershell
$adminKey = Read-Host 'Admin key (CII_ADMIN_API_KEY)'
Set-Content -Path client.json -Encoding ascii -Value '{"name": "<system name>", "description": "<what it is>"}'
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/api-clients -H "X-Admin-Key: $adminKey" -H "Content-Type: application/json" --data-binary "@client.json"
Remove-Item client.json
```

### 15. First import of the outside intelligence

```powershell
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh/<job_id>
```

Repeat the second line with the `job_id` from the first until `status` is `done`.

## Next release

Run steps 1, 3, 4, 10, 11, 12 and 13. Also run:

- step 2, only if a monitoring version changed (an `image:` line in `deploy\deploy_common.yaml`). Build just that
  image, e.g. `deploy\build-monitoring-images.bat grafana`. A new kube-state-metrics version also needs its
  `SRC_SHA256` in `deploy\images\kube-state-metrics\Dockerfile`.
- steps 6 and 7, only if `secrets.example.yaml` or `configmap.yaml` changed.

## Change a setting or secret later

Edit and apply the file (step 6 or 7), then restart one project at a time:

```powershell
oc -n ai-remediation rollout restart deployment -l part-of=tsg
oc -n ai-remediation rollout status deployment -l part-of=tsg --timeout=10m
oc -n ai-threatgen rollout restart deployment -l part-of=tsg
oc -n ai-threatgen rollout status deployment -l part-of=tsg --timeout=10m
oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring
oc -n ai-common rollout status deployment -l part-of=tsg-monitoring --timeout=10m
```

## If something fails

| You see | Do this |
|---|---|
| `ImagePullBackOff` | The image is not in Quay (steps 2, 3, 4) or `quay-pull` is missing (step 5). |
| `exceeded quota` | Wait 2 minutes (an old pod is still stopping). Still failing: `oc -n <project> describe quota`. |
| `CreateContainerConfigError` | Apply `secrets.yaml` and `configmap.yaml` (steps 6, 7). |
| `field is immutable` | An old Deployment is still there: step 8. |
| `/ready` answers 503 | The answer names the missing store or worker: `oc -n <project> logs deploy/<name>`. |
| `CrashLoopBackOff` | `oc -n <project> logs deploy/<name> --previous` shows why (often a setting). |
