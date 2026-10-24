# Deploy TSG to OpenShift

Run every step in order, in PowerShell, from the `cii-main` folder (the one with `pyproject.toml`).
Replace `<...>` with your value.

| Project | What runs there |
|---|---|
| `ai-threatgen` | API, 6 workers (threats, scenarios, controls, remediation, service mapper, maintenance), beat |
| `ai-remediation` | A second copy of the 6 workers |
| `ai-common` | Monitoring (Grafana, Prometheus, Loki ...) and Flower |

Each worker prefers a node its twin is not on, and the two API pods different nodes, so one node failure stops
neither a queue nor the API. Preferred only: a pod still starts when no other node fits.

## First deployment

### 1. Log in and check the quotas

```powershell
oc login --server=<cluster API address>
docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
oc -n ai-threatgen describe quota
oc -n ai-remediation describe quota
oc -n ai-threatgen get quota -o yaml | Select-String CrossNamespacePodAffinity
oc -n ai-remediation get quota -o yaml | Select-String CrossNamespacePodAffinity
```

Check: the last two print nothing (`describe` does not show a quota's scope selector). A quota with the
`CrossNamespacePodAffinity` scope counts the pods whose spreading rule names another project, which every worker's
does (to find its twin), and usually allows none: the workers are refused (`exceeded quota`). Some clusters also
refuse such pods unless a quota allows them (`insufficient quota to match these scopes`). Then either ask the
cluster admin to allow at least 6 such pods in that project, or delete the `namespaces:` line from each worker in
`deploy_threatgen.yaml` and `deploy_remediation.yaml` (and its check in `tests/test_deploy.py`): each project then
spreads only its own pods, so a worker and its twin may share a node again. Make that change in git too, or the
next release brings the line back.

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
oc -n ai-threatgen delete deployment api worker-threats worker-scenarios worker-controls worker-remediation worker-service-mapper worker-maintenance beat --ignore-not-found
oc -n ai-remediation delete deployment worker-threats worker-scenarios worker-controls worker-remediation worker-service-mapper worker-maintenance --ignore-not-found
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
oc -n ai-remediation rollout status deployment -l part-of=tsg --timeout=10m
```

Check: each line ends with `successfully rolled out`.

### 11. API, workers and beat in ai-threatgen

```powershell
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen rollout status deployment -l part-of=tsg --timeout=10m
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

- once, if the running `api` pods still have a 1 CPU limit (a release before the 750m API): before step 11, run
  `oc -n ai-threatgen set resources deployment/api --limits=cpu=750m` and wait with
  `oc -n ai-threatgen rollout status deployment/api --timeout=10m`. Otherwise the new workers and the API's
  extra update pod do not fit the 6 CPU quota together.

- step 2, only if a monitoring version changed (an `image:` line in `deploy\deploy_common.yaml`). Build just that
  image, e.g. `deploy\build-monitoring-images.bat grafana`. A new kube-state-metrics version also needs its
  `SRC_SHA256` in `deploy\images\kube-state-metrics\Dockerfile`.
- steps 6 and 7, only if `secrets.example.yaml` or `configmap.yaml` changed. After step 7, restart Prometheus so
  new alert rules load:

  ```powershell
  oc -n ai-common rollout restart deployment/prometheus
  oc -n ai-common rollout status deployment/prometheus --timeout=10m
  ```

## Roll back a release

With the previous release's deploy files, in this order:

1. Make room in ai-threatgen's quota. Its twin in ai-remediation keeps mapping controls:

   ```powershell
   oc -n ai-threatgen delete deployment worker-controls
   ```

2. Run steps 10 and 11.
3. Wait until `tsg_controls` is empty (Grafana panel "Jobs waiting in each queue"), then:

   ```powershell
   oc -n ai-remediation delete deployment worker-controls
   ```

4. Run step 12 last: the previous `deploy_common.yaml` no longer watches `tsg_controls`.

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
| `exceeded quota` | Wait up to 6 minutes (old pods still stopping, then OpenShift's retry back-off). Still failing: `oc -n <project> describe quota`; a `CrossNamespacePodAffinity` quota: step 1. |
| `insufficient quota to match these scopes` | The cluster lets a pod name another project only under a `CrossNamespacePodAffinity` quota: step 1. |
| `CreateContainerConfigError` | Apply `secrets.yaml` and `configmap.yaml` (steps 6, 7). |
| `field is immutable` | An old Deployment is still there: step 8. |
| `/ready` answers 503 | The answer names the missing store or worker: `oc -n <project> logs deploy/<name>`. |
| `CrashLoopBackOff` | `oc -n <project> logs deploy/<name> --previous` shows why (often a setting). |
