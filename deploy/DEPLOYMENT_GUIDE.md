# Deploy TSG to OpenShift

| Project | What runs there |
|---|---|
| `ai-threatgen` | API (2 copies), 4 workers, beat |
| `ai-remediation` | A second copy of the 4 workers |
| `ai-common` | Monitoring (Grafana, Prometheus, Loki ...) and Flower. Shared with the chatbot. |

Run every command in PowerShell, in the `cii` folder. Replace `<...>` with your value.

## Before you start

- `oc login --server=<cluster API address>`, with admin rights in the three projects.
- `docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local`
- The DBA has installed `scripts\sql\tsg_*.sql`, then `scripts\sql\grants.sql`.
- First deploy? Do [First time only](#first-time-only) before step 5.

## 1. Build and push the image

```powershell
deploy\build-image.bat
```

The tag is today's date, e.g. `24-Oct-2026`. A second build on the same day needs a new tag:
`deploy\build-image.bat 24-Oct-2026-2`.

Check: the last lines show `Image:` and `Tag:`.

## 2. Put the tag in the YAML

```powershell
$old = (Select-String -Path deploy\deploy_threatgen.yaml -Pattern 'tsg-api:(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
$new = '<tag from step 1>'
foreach ($f in 'deploy_threatgen.yaml', 'deploy_remediation.yaml', 'deploy_common.yaml') { $p = Join-Path $PWD "deploy\$f"; [IO.File]::WriteAllText($p, [IO.File]::ReadAllText($p).Replace("tsg-api:$old", "tsg-api:$new")) }
Select-String -Path deploy\deploy_*.yaml -Pattern 'tsg-api:'
```

Check: every line shows the new tag.

## 3. Secrets

```powershell
Copy-Item deploy\secrets.example.yaml deploy\secrets.yaml
notepad deploy\secrets.yaml
oc apply -f deploy\secrets.yaml
```

Replace every `CHANGE_ME` with the real value. A password inside a connection string must be URL-encoded
(`@` becomes `%40`). Keep `secrets.yaml` private: never share it.

Check: `Select-String -Path deploy\secrets.yaml -Pattern '^[^#]*CHANGE_ME'` prints nothing.

## 4. Settings

In `deploy\configmap.yaml`, set `CII_CORS_ORIGINS` to the platform UI's https address (`*` is not allowed).

```powershell
notepad deploy\configmap.yaml
oc apply -f deploy\configmap.yaml
```

Check: `Select-String -Path deploy\configmap.yaml -Pattern '^[^#]*CHANGE_ME'` prints nothing.

## 5. Network rules

```powershell
oc apply -f deploy\networkpolicy_threatgen.yaml -f deploy\networkpolicy_remediation.yaml
```

## 6. Workers in ai-remediation

```powershell
oc apply -f deploy\deploy_remediation.yaml
oc -n ai-remediation rollout status deployment/worker-threats --timeout=10m
oc -n ai-remediation rollout status deployment/worker-scenarios --timeout=10m
oc -n ai-remediation rollout status deployment/worker-service-mapper --timeout=10m
oc -n ai-remediation rollout status deployment/worker-maintenance --timeout=10m
```

Check: each line ends with `successfully rolled out`.

## 7. API, workers and beat in ai-threatgen

```powershell
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen rollout status deployment/worker-threats --timeout=10m
oc -n ai-threatgen rollout status deployment/worker-scenarios --timeout=10m
oc -n ai-threatgen rollout status deployment/worker-service-mapper --timeout=10m
oc -n ai-threatgen rollout status deployment/worker-maintenance --timeout=10m
oc -n ai-threatgen rollout status deployment/beat --timeout=10m
oc -n ai-threatgen rollout status deployment/api --timeout=10m
```

Check: each line ends with `successfully rolled out`.

## 8. Monitoring and Flower in ai-common

```powershell
oc apply -f deploy\deploy_common.yaml
foreach ($d in 'prometheus', 'alertmanager', 'loki', 'alloy', 'grafana', 'redis-exporter', 'kube-state-metrics', 'flower') { oc -n ai-common rollout status deployment/$d --timeout=10m }
```

Check: each line ends with `successfully rolled out`.

## 9. Check

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/health
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ready
```

Check: both answer with status `ok` / `ready`. Grafana opens at
https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/grafana/ and Flower at `.../flower/`.

---

## First time only

**a) Build and push the 7 monitoring images** (Prometheus, Alertmanager, Loki, Alloy, Grafana, redis-exporter,
kube-state-metrics). It takes a while the first time:

```powershell
deploy\build-monitoring-images.bat
```

Check: the last lines list the 7 images, and it ends without `ERROR`.

**b) Image pull secret** in the two other projects (copied from `ai-threatgen`):

```powershell
oc -n ai-threatgen extract secret/quay-pull --keys=.dockerconfigjson "--to=$env:TEMP" --confirm
oc -n ai-remediation create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
oc -n ai-common create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
Remove-Item "$env:TEMP\.dockerconfigjson"
```

**c) Remove the old deploy** (the API is down for a few minutes until step 7 finishes). "NotFound" is fine.

```powershell
oc -n ai-threatgen scale deployment tsg-api celery-worker celery-worker-admin tsg-beat tsg-flower --replicas=0
oc -n ai-remediation scale deployment celery-worker celery-exporter mssql-exporter mongodb-exporter --replicas=0
oc -n ai-threatgen delete deployment api worker-threats worker-scenarios worker-service-mapper worker-maintenance beat --ignore-not-found
oc -n ai-remediation delete deployment worker-threats worker-scenarios worker-service-mapper worker-maintenance --ignore-not-found
oc -n ai-remediation delete deployment prometheus alertmanager loki alloy grafana redis-exporter kube-state-metrics flower --ignore-not-found
oc -n ai-remediation delete route grafana prometheus alertmanager loki flower --ignore-not-found
```

Then check that no other Route uses the two addresses; delete any old one you find (keep `api` in `ai-threatgen`):

```powershell
foreach ($p in 'ai-threatgen', 'ai-remediation', 'ai-common') { "== $p"; oc -n $p get route | findstr threatgen }
```

**d) After step 9: an API key for each calling system** (shown once: copy it):

```powershell
$adminKey = Read-Host 'Admin key (CII_ADMIN_API_KEY)'
Set-Content -Path client.json -Encoding ascii -Value '{"name": "<system name>", "description": "<what it is>"}'
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/api-clients -H "X-Admin-Key: $adminKey" -H "Content-Type: application/json" --data-binary "@client.json"
Remove-Item client.json
```

**e) First import of the outside intelligence:**

```powershell
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh/<job_id>
```

Repeat the second line until `status` is `done`.

---

## Change a setting later

Apply the changed file (step 3 or 4), then restart one project at a time:

```powershell
oc -n ai-remediation rollout restart deployment -l part-of=tsg
oc -n ai-remediation rollout status deployment -l part-of=tsg --timeout=10m
oc -n ai-threatgen rollout restart deployment -l part-of=tsg
oc -n ai-threatgen rollout status deployment -l part-of=tsg --timeout=10m
oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring
oc -n ai-common rollout status deployment -l part-of=tsg-monitoring --timeout=10m
```

## New release

1. Steps 1 and 2.
2. Only if a monitoring version changed (an `image:` line in `deploy\deploy_common.yaml`): build that image, e.g.
   `deploy\build-monitoring-images.bat grafana`. A new kube-state-metrics version also needs its `SRC_SHA256` in
   `deploy\images\kube-state-metrics\Dockerfile` (the sha256 of that version's source archive).
3. Only if `secrets.example.yaml` or `configmap.yaml` changed: steps 3 and 4.
4. Steps 6, 7, 8 and 9.

## If something fails

| You see | Do this |
|---|---|
| `ImagePullBackOff` | The tag is not in Quay (step 1, 2; a monitoring image: First time only a) or `quay-pull` is missing (First time only b). |
| `exceeded quota` | Wait 2 minutes (an old pod is still stopping). Still failing: `oc -n <project> describe quota`. |
| `CreateContainerConfigError` | Apply `secrets.yaml` and `configmap.yaml` (steps 3, 4). |
| `field is immutable` | An old Deployment is still there: First time only c. |
| `/ready` answers 503 | The answer names the missing store or worker: `oc -n <project> logs deploy/<name>`. |
| `CrashLoopBackOff` | `oc -n <project> logs deploy/<name> --previous` shows why (often a setting). |
