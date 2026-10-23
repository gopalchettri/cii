# Deploying TSG to OpenShift, step by step

This guide puts TSG (the threat scenario generator) on OpenShift. UAT is production, so follow the steps in order
and check each one before you go on.

## What runs where

TSG uses three OpenShift projects. A project is a separate space on the cluster, with its own budget (quota).

| Project | What runs there | Budget (quota) |
|---|---|---|
| `ai-threatgen` | the API (2 copies), one worker per job queue (4 workers), beat (the timer) | 6 CPU, 12 Gi memory, 60 Gi disk |
| `ai-remediation` | a second copy of each of the 4 workers | 6 CPU, 12 Gi memory, 60 Gi disk |
| `ai-common` | the monitoring (Prometheus, Alertmanager, Loki, Alloy, Grafana, redis-exporter, kube-state-metrics) and Flower | 6 CPU, 16 Gi memory, 180 Gi disk, shared with the chatbot |

Everything is plain YAML in the `deploy` folder, applied with `oc apply -f`. No script makes or changes these files.

| File | What it holds |
|---|---|
| `secrets.example.yaml` | The template for `secrets.yaml`: every password, key and connection string, as `CHANGE_ME`. In git. |
| `secrets.yaml` | Your copy with the real values. Never in git (`.gitignore` keeps it out). |
| `configmap.yaml` | The app's settings (`tsg-config`, in all three projects) and the monitoring's config files. |
| `networkpolicy_threatgen.yaml` | The network rules (who may talk to the TSG pods, and where they may go) in `ai-threatgen`. |
| `networkpolicy_remediation.yaml` | The same rules in `ai-remediation`. |
| `deploy_remediation.yaml` | The 4 workers in `ai-remediation`. |
| `deploy_threatgen.yaml` | The API, the 4 workers and beat in `ai-threatgen`, and the API's public address. |
| `deploy_common.yaml` | The monitoring and Flower in `ai-common`, and their public address. |

The order always is: secrets and settings, then network rules, then `ai-remediation`, then `ai-threatgen`, then
`ai-common`. The new workers start before the new API, because the API is "ready" only when every queue has a worker.

How to read the commands:

- Run every command in **PowerShell**, in the `cii` folder (the one with `pyproject.toml`).
- `<...>` is a value you fill in. Replace the brackets too: `<robot token>` becomes `abc123`, not `<abc123>`.
- "Check" tells you what you should see. If you see something else, stop and look at
  [Common problems](#common-problems).

---

## Step 0. What you need

**What it does:** makes sure you have the tools, the rights and the inputs before you change anything.

You need:

1. **The `oc` command**, logged in to the cluster, with admin rights in `ai-threatgen`, `ai-remediation` and
   `ai-common`. (`deploy_common.yaml` also creates read-only access rules in the two app projects, so the
   monitoring can see their pods. Only a project admin may create them.)
2. **Docker** (Docker Desktop, Linux containers), logged in to the image registry (Quay).
3. **The company network**: the cluster and the registry are only reachable from there.
4. **The database procedures.** The DBA has installed every `scripts\sql\tsg_*.sql` file in the UAT database, then
   `scripts\sql\grants.sql`. Files with `copy` in their name are backups: they are not installed. Get the DBA's
   confirmation.
5. **The monitoring images in the registry mirror.** The cluster can only pull images from
   `quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc`. These must be there: `prometheus:v3.15.0`,
   `alertmanager:v0.34.1`, `loki:3.7.8`, `alloy:v1.20.1`, `grafana:12.4.12`, `redis_exporter:v1.93.0`,
   `kube-state-metrics:v2.20.0`. The exact versions are on the `image:` lines of `deploy\deploy_common.yaml`.

```powershell
oc login --server=<cluster API address>
docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
Select-String -Path deploy\deploy_common.yaml -Pattern 'image:'
docker manifest inspect quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/prometheus:v3.15.0
```

**Check:**

- `oc whoami` prints your user name.
- `oc auth can-i create role -n ai-threatgen` prints `yes`. Do the same for `ai-remediation` and `ai-common`.
- `docker login` prints `Login Succeeded`.
- `docker manifest inspect` prints a block of text (not "no such manifest") for every monitoring image. Repeat it
  for each image in the list. You can also look in the Quay web page:
  `https://quay-quay-registry.apps.dda-desc-az1-01.desccii.local/repository/dda-desc/<name>?tab=tags`.
- An image is missing? On a machine with internet access, copy it into the mirror, for example:
  `docker pull --platform linux/amd64 docker.io/prom/prometheus:v3.15.0`, then
  `docker tag docker.io/prom/prometheus:v3.15.0 quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/prometheus:v3.15.0`,
  then `docker push` that new name. Where each image comes from is in the header of `deploy\deploy_common.yaml`
  (kube-state-metrics comes from `registry.k8s.io`, the others from `docker.io`).
- No machine has both internet and the company network? After the `docker tag`, run
  `docker save -o prometheus.tar <new name>` on the internet machine. Copy the file across, then run
  `docker load -i prometheus.tar` and `docker push <new name>` on the company machine.

## Step 1. Build and push the image

**What it does:** builds the TSG image (the API, the workers, beat and Flower all run from it) from the committed
code, checks that it starts, and sends it to the registry.

```powershell
git status
.\deploy\build-image.ps1
```

- The image's tag is `v2-<commit>`: the last commit that changed the app's code or build files. A commit that only
  changes YAML or documents keeps the same tag.
- The script stops if `app\`, `pyproject.toml`, `requirements.txt`, `Dockerfile` or `.dockerignore` have changes
  that are not committed. Commit them first (or build from a clean checkout).
- No machine has both internet (for the build) and the company network (for the push)? Run
  `.\deploy\build-image.ps1 -NoPush` on the internet machine, then `docker save -o tsg-api.tar <image>`. Copy the
  file across, then run `docker load -i tsg-api.tar` and `docker push <image>` on the company machine.
- If PowerShell says "running scripts is disabled", run
  `powershell -ExecutionPolicy Bypass -File .\deploy\build-image.ps1`.

**Check:** the last lines show `Image: ...` and `Tag:   v2-...` in green. Write the tag down.

## Step 2. Put the tag in the YAML files

**What it does:** tells OpenShift which image to run. The tag is written in three files.

```powershell
$old = (Select-String -Path deploy\deploy_threatgen.yaml -Pattern 'tsg-api:(v2-[0-9a-f]+)' | Select-Object -First 1).Matches[0].Groups[1].Value
$new = '<the tag from step 1>'
foreach ($f in 'deploy_threatgen.yaml', 'deploy_remediation.yaml', 'deploy_common.yaml') { $p = Join-Path $PWD "deploy\$f"; [IO.File]::WriteAllText($p, [IO.File]::ReadAllText($p).Replace($old, $new)) }
```

- The first line reads the tag the files have now (for example `v2-f0560c76a491`).
- The last line replaces it in the three files. It keeps the files' encoding and line endings as they are.
- If the tag did not change (only YAML or documents changed since the last build), there is nothing to replace.

**Check:** the first command prints nothing (no old tag left), unless the tag did not change. The second shows every
`tsg-api` image line with the new tag.

```powershell
Select-String -Path deploy\deploy_*.yaml -SimpleMatch $old
Select-String -Path deploy\deploy_*.yaml -Pattern 'tsg-api:'
```

Commit the three changed files, so git always shows what runs.

## Step 3. The image pull secret (first time only)

**What it does:** gives the two other projects the login they need to pull images from Quay. `ai-threatgen`
already has it, as a secret named `quay-pull` (it can only read images). Copy that one; never use your own
`docker login`, which can also push.

```powershell
oc -n ai-threatgen extract secret/quay-pull --keys=.dockerconfigjson "--to=$env:TEMP" --confirm
oc -n ai-remediation create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
oc -n ai-common create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
Remove-Item "$env:TEMP\.dockerconfigjson"
```

- The first line saves the login in a file for a moment; the last line deletes that file.
- "AlreadyExists" means the secret is already there: that is fine.

**Check:** each command prints one line named `quay-pull`, of type `kubernetes.io/dockerconfigjson`.

```powershell
oc -n ai-remediation get secret quay-pull
oc -n ai-common get secret quay-pull
```

## Step 4. Secrets

**What it does:** gives the pods their passwords, keys and connection strings. OpenShift keeps them as Secrets.

```powershell
Copy-Item deploy\secrets.example.yaml deploy\secrets.yaml
notepad deploy\secrets.yaml
```

In `secrets.yaml`, replace every `CHANGE_ME` with the real value. Hosts and ports are already filled in. The values
are written once and used in all three projects.

| Key | What it is |
|---|---|
| `CII_DB_DSN` | SQL Server: the user and password of TSG's database login. |
| `CII_MONGO_URL` | MongoDB: user and password. |
| `CII_REDIS_URL` | Redis user and password (database 0: live updates and caches). |
| `CII_REDIS_CELERY_BROKER_URL` | The same Redis user and password (database 1: the job queues). |
| `CII_CHAT_API_KEY` | AI gateway key for the chat models. |
| `CII_EMBEDDING_API_KEY` | AI gateway key for the embedding model. |
| `CII_RERANK_API_KEY` | AI gateway key for the re-ranking model. |
| `CII_ADMIN_API_KEY` | The admin key (sent as `X-Admin-Key`). At least 32 characters. |
| `CII_NVD_API_KEY` | The NVD feed key. `""` means no key (slower imports). |
| `CII_PROXY_URL` | Leave it `""`. |
| `GF_SECURITY_ADMIN_PASSWORD` | Grafana's `admin` password, only to change Grafana. At least 16 characters. |

- A user name or password inside a connection string (`CII_DB_DSN`, `CII_MONGO_URL`, the Redis URLs) must be
  URL-encoded (for example `@` becomes `%40`, `+` becomes `%2B`). This prints the encoded form to paste; a `'` in the
  password is written twice: `[uri]::EscapeDataString('<password>')`.
- A value with `"` or `\` in it needs a `\` in front of that character (the values are in double quotes).
- To make a strong random key (for `CII_ADMIN_API_KEY` or the Grafana password):
  `$b = New-Object byte[] 36; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)`

Then apply it:

```powershell
oc apply -f deploy\secrets.yaml
```

**Never commit `secrets.yaml`**, and never put a real value in `secrets.example.yaml`.

**Check:**

- `git check-ignore deploy\secrets.yaml` prints the file name (git ignores it).
- `Select-String -Path deploy\secrets.yaml -Pattern '^[^#]*CHANGE_ME'` prints nothing (it skips the comments).
- These show `tsg-secrets` in each project, and `tsg-monitoring` in `ai-common`:

```powershell
oc -n ai-threatgen get secret tsg-secrets
oc -n ai-remediation get secret tsg-secrets
oc -n ai-common get secret tsg-secrets tsg-monitoring
```

## Step 5. Settings

**What it does:** gives the pods their plain (not secret) settings, and the monitoring its config files.

Open `deploy\configmap.yaml` and:

1. Set `CII_CORS_ORIGINS`: replace `CHANGE_ME_UI_ORIGIN` with the https address of the platform UI (the web page
   that calls the API), for example `https://<platform UI host>`. Several addresses: separate them with commas.
   `*` (any address) is refused: the app stops at start.
2. Read the other values (each line has a comment). In particular: `CII_ENV` is `uat`, `CII_MONGO_DB` is the right
   database, and the AI model names are the ones the gateway offers.

```powershell
notepad deploy\configmap.yaml
oc apply -f deploy\configmap.yaml
```

**Check:**

- `Select-String -Path deploy\configmap.yaml -Pattern '^[^#]*CHANGE_ME'` prints nothing.
- `oc -n ai-threatgen get configmap tsg-config` and the same for `ai-remediation` and `ai-common` show one line each.
- `oc -n ai-common get configmap` lists `prometheus-config`, `alertmanager-config`, `loki-config`, `alloy-config`,
  `grafana-provisioning` and `grafana-dashboards`.

## Step 6. Stop the old deploy (first time only)

**What it does:** removes what the old deploy left, so the new files can take over.

**This causes downtime**: the API is down from this step until step 9 finishes, usually a few minutes. Agree a time
window first. Why: the old Deployments find their pods with labels named `app.kubernetes.io/...`. A Deployment's
pod selector can never be changed after it is created, so the old Deployments must be deleted and created again.

**Do this step only once.** After step 9 the names below belong to the new Deployments, and deleting them again
would stop TSG.

6.1. See what runs now, and write down how many pods each of v1's Deployments wants. You need the counts to go back
to v1.

```powershell
oc -n ai-threatgen get deployment -L app.kubernetes.io/part-of,part-of
oc -n ai-remediation get deployment -L app.kubernetes.io/part-of,part-of
oc -n ai-common get deployment -L app.kubernetes.io/part-of,part-of
oc -n ai-threatgen get deployment tsg-api celery-worker celery-worker-admin tsg-beat tsg-flower --ignore-not-found -o 'custom-columns=NAME:.metadata.name,WANTED:.spec.replicas,BEFORE:.metadata.annotations.tsg/replicas-before-v2'
oc -n ai-remediation get deployment celery-worker celery-exporter mssql-exporter mongodb-exporter --ignore-not-found -o 'custom-columns=NAME:.metadata.name,WANTED:.spec.replicas,BEFORE:.metadata.annotations.tsg/replicas-before-v2'
```

The old TSG v2 Deployments show `tsg` or `tsg-observability` in the first label column. The new ones (after step 9)
show `tsg` or `tsg-monitoring` in the second. For each v1 Deployment, write down `WANTED`. If it is `0`, the old
deploy script already stopped v1: write down `BEFORE` instead.

6.2. If v1 still runs, stop it (scale to 0). This does not delete it: it is the way back.

```powershell
oc -n ai-threatgen scale deployment tsg-api celery-worker celery-worker-admin tsg-beat tsg-flower --replicas=0
oc -n ai-remediation scale deployment celery-worker celery-exporter mssql-exporter mongodb-exporter --replicas=0
```

"NotFound" for a name means it is not there: that is fine.

6.3. Delete the old v2 app Deployments, by name.

```powershell
oc -n ai-threatgen delete deployment api worker-threats worker-scenarios worker-service-mapper worker-maintenance beat --ignore-not-found
oc -n ai-remediation delete deployment worker-threats worker-scenarios worker-service-mapper worker-maintenance --ignore-not-found
```

6.4. Delete the old monitoring in `ai-remediation` (Deployments and Routes). A public address (host) belongs to the
first project that claims it, and `ai-common` needs `threatgen-grafana`. Their disk volumes (`prometheus-data`,
`loki-data`, `grafana-data`) are kept until the owner deletes them.

```powershell
oc -n ai-remediation delete deployment prometheus alertmanager loki alloy grafana redis-exporter kube-state-metrics flower --ignore-not-found
oc -n ai-remediation delete route grafana prometheus alertmanager loki flower --ignore-not-found
oc -n ai-common delete deployment -l app.kubernetes.io/part-of=tsg-observability
```

The last line removes an earlier test install of the monitoring in `ai-common`, if there is one. It touches only
TSG's (the label), never the chatbot's.

6.5. Free the two public addresses. List the Routes on them, one project at a time:

```powershell
foreach ($p in 'ai-threatgen', 'ai-remediation', 'ai-common') { "== $p"; oc -n $p get route | findstr threatgen }
```

Only these may stay: `ai-threatgen` route `api` on `threatgen-api...`, and the Routes in `ai-common` on
`threatgen-grafana...`. Any other Route on those two hosts must go: v1's are in `ai-threatgen` and `ai-remediation`.
Save a copy first (outside the repo), then delete it:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.tsg\v1-routes"
oc -n <project> get route <name> -o yaml | Where-Object { $_ -notmatch '^  (resourceVersion|uid|creationTimestamp):' } | Out-File -Encoding ascii "$env:USERPROFILE\.tsg\v1-routes\<project>-<name>.yaml"
oc -n <project> delete route <name>
```

The `Where-Object` part leaves out the fields OpenShift sets itself, so the copy can be applied again later.

**Check:**

- `oc -n ai-threatgen get deployment` and `oc -n ai-remediation get deployment` show no `api`, `worker-*` or `beat`.
  v1's show READY `0/0`.
- The Route list of 6.5 shows only the Routes allowed above (or none yet).
- The stopped pods are gone. A v1 worker may take up to 740 s to finish its job, and a stopping pod still uses the
  budget, so steps 8 and 9 can fail with `exceeded quota` while one is left. Repeat these every minute (up to about 15
  minutes) until the first two print `No resources found` and the last two show no pod as `Terminating`:

```powershell
oc -n ai-threatgen get pods -l app=tsg-api
oc -n ai-remediation get pods -l app=tsg-api
oc -n ai-threatgen get pods
oc -n ai-remediation get pods
```

## Step 7. Network rules

**What it does:** sets who may talk to the TSG pods (the router, the monitoring, each other) and where the pods may
connect (name lookup, the databases, Redis, the AI gateway, the internet feeds).

```powershell
oc apply -f deploy\networkpolicy_threatgen.yaml -f deploy\networkpolicy_remediation.yaml
```

**Check:** each project lists `tsg-app-ingress` and `tsg-app-egress`.

```powershell
oc -n ai-threatgen get networkpolicy
oc -n ai-remediation get networkpolicy
```

## Step 8. The workers in ai-remediation

**What it does:** starts (or updates) the second copy of the 4 workers. A worker is the program that does the
background jobs: finding threats, writing scenarios, mapping services, maintenance.

```powershell
oc apply -f deploy\deploy_remediation.yaml
oc -n ai-remediation rollout status deployment/worker-threats --timeout=10m
oc -n ai-remediation rollout status deployment/worker-scenarios --timeout=10m
oc -n ai-remediation rollout status deployment/worker-service-mapper --timeout=10m
oc -n ai-remediation rollout status deployment/worker-maintenance --timeout=10m
```

**Check:** each `rollout status` ends with `successfully rolled out` (a worker counts only once it answers a ping,
so this can take a few minutes). Then `oc -n ai-remediation get pods` shows 4 pods, each `Running` and READY `1/1`.

## Step 9. The API, the workers and beat in ai-threatgen

**What it does:** starts (or updates) the API, the first copy of the 4 workers, and beat (the timer that starts the
regular maintenance jobs). Wait for the API last: it is ready only when every queue has a worker.

```powershell
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen rollout status deployment/worker-threats --timeout=10m
oc -n ai-threatgen rollout status deployment/worker-scenarios --timeout=10m
oc -n ai-threatgen rollout status deployment/worker-service-mapper --timeout=10m
oc -n ai-threatgen rollout status deployment/worker-maintenance --timeout=10m
oc -n ai-threatgen rollout status deployment/beat --timeout=10m
oc -n ai-threatgen rollout status deployment/api --timeout=10m
```

**Check:** each `rollout status` ends with `successfully rolled out`. `oc -n ai-threatgen get pods` shows 7 pods
(2 `api`, 4 workers, 1 `beat`), each `Running` and `1/1`. `oc -n ai-threatgen get route api` shows the host
`threatgen-api.apps.dda-desc-az1-01.desccii.local`.

## Step 10. The monitoring and Flower in ai-common

**What it does:** starts (or updates) the monitoring: Prometheus (collects numbers), Alertmanager (alerts), Loki
(stores logs), Alloy (ships the pods' logs to Loki), Grafana (the dashboards), redis-exporter (queue numbers),
kube-state-metrics (pod numbers), and Flower (a view of the background jobs).

```powershell
oc apply -f deploy\deploy_common.yaml
oc -n ai-common rollout status deployment/prometheus --timeout=10m
oc -n ai-common rollout status deployment/alertmanager --timeout=10m
oc -n ai-common rollout status deployment/loki --timeout=10m
oc -n ai-common rollout status deployment/alloy --timeout=10m
oc -n ai-common rollout status deployment/grafana --timeout=10m
oc -n ai-common rollout status deployment/redis-exporter --timeout=10m
oc -n ai-common rollout status deployment/kube-state-metrics --timeout=10m
oc -n ai-common rollout status deployment/flower --timeout=10m
```

The first time, the disk volumes are created first: a pod may wait a minute or two for its volume.

**Check:** each `rollout status` ends with `successfully rolled out`. `oc -n ai-common get route` shows the host
`threatgen-grafana.apps.dda-desc-az1-01.desccii.local`.

## Step 11. Check that it all works

**What it does:** checks the API, the monitoring and the budgets. Changes nothing.

```powershell
curl.exe -sk -i https://threatgen-api.apps.dda-desc-az1-01.desccii.local/health
curl.exe -sk -i https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ready
oc -n ai-threatgen logs deploy/worker-scenarios | findstr ai.gateway_route
oc -n ai-threatgen describe quota
oc -n ai-remediation describe quota
oc -n ai-common describe quota
```

**Check:**

- `/health` answers `HTTP/1.1 200` and `{"status":"ok"}`.
- `/ready` answers `200` and `"status":"ready"`. A `503` names what is missing: a store that is `false` (MongoDB,
  Redis), or a queue with no worker. Fix that and ask again.
- The `ai.gateway_route` lines say `"route": "direct"` (the AI calls do not go through the company proxy).
- In each `describe quota`, every `Used` value is below its `Hard` value.
- Open these in a browser (`-k` above and a browser warning mean this PC does not trust the cluster's certificate):

| Address | What you see |
|---|---|
| `https://threatgen-api.apps.dda-desc-az1-01.desccii.local/docs` | The API's documentation page. |
| `https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/grafana/` | Grafana: the TSG dashboard. Start here. No login needed to look. |
| `https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/flower/` | Flower: the background jobs and the workers. |
| `https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/prometheus/` | Prometheus: open Status, then Target health. Every target is `UP`. |
| `https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/alertmanager/` | Alertmanager: the alerts that are firing now. |

## Step 12. API keys and outside intelligence (first time only)

**What it does:** creates the keys other systems use to call TSG, and imports the outside threat feeds once.

12.1. Create one API key for each system that calls TSG. The key is shown **once**: copy it and give it to that
system's owner.

```powershell
$adminKey = Read-Host 'Admin key (CII_ADMIN_API_KEY)'
Set-Content -Path client.json -Encoding ascii -Value '{"name": "<system name>", "description": "<what it is>"}'
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/api-clients -H "X-Admin-Key: $adminKey" -H "Content-Type: application/json" --data-binary "@client.json"
Remove-Item client.json
```

**Check:** the answer has `"api_key"`. The calling system sends it in the `X-API-Key` header, with `X-User-Id`,
`X-Entity-Id` and `X-Tenant-Id`.

12.2. Import the outside intelligence (when `EXTERNAL_INTELLIGENCE_ENABLED` is `"true"` in `configmap.yaml`). Until
this is done, starting a run answers `409 intel_no_data`. After this first time it runs every hour by itself.

```powershell
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh/<job_id>
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/health
```

- The first line answers with a `job_id`. Repeat the second line (with that `job_id`) every minute until `status`
  is `done`. `failed` comes with an `error` that says why.

**Check:** the third line (`/intel/health`) shows a `snapshot_id`.

---

## Change a setting or a secret later

A running pod never sees a changed setting. After the change, restart the pods, one project at a time: wait for
each project before the next. A worker restart stops its pod first, so if both copies of a worker restart together,
that queue has no worker and the API is not ready.

```powershell
notepad deploy\configmap.yaml
oc apply -f deploy\configmap.yaml
oc apply -f deploy\secrets.yaml
oc -n ai-remediation rollout restart deployment -l part-of=tsg
oc -n ai-remediation rollout status deployment -l part-of=tsg --timeout=10m
oc -n ai-threatgen rollout restart deployment -l part-of=tsg
oc -n ai-threatgen rollout status deployment -l part-of=tsg --timeout=10m
oc -n ai-common rollout restart deployment prometheus alertmanager loki alloy grafana redis-exporter kube-state-metrics flower
oc -n ai-common rollout status deployment -l part-of=tsg-monitoring --timeout=10m
```

- Apply only the file you changed (`configmap.yaml` or `secrets.yaml`).
- In `ai-common`, restart only TSG's Deployments by name: a plain `rollout restart deployment` there would also
  restart the chatbot.
- Check: each `rollout status` ends with `successfully rolled out`, then step 11.

## Release a new version

1. Step 1: build and push the image.
2. Step 2: put the new tag in the three files, and commit them.
3. Settings: `git diff <commit of the last release> HEAD -- deploy/configmap.yaml deploy/secrets.example.yaml`
   shows what changed. If anything did, apply it now: a new key in `secrets.example.yaml` goes into your
   `secrets.yaml` (step 4), then `oc apply -f deploy\secrets.yaml` and `oc apply -f deploy\configmap.yaml` (step 5).
   The new app pods of steps 8 to 10 read the new settings. A changed monitoring config file also needs the
   `ai-common` lines of "Change a setting or a secret later" after step 10.
4. Step 8: `ai-remediation`.
5. Step 9: `ai-threatgen`.
6. Step 10: `ai-common`.
7. Step 11: check.

A worker update stops the old pod first and then starts the new one (to stay within the budget). Its twin in the
other project keeps serving meanwhile, so there is no downtime. The API starts a new pod before it stops an old one.

## Roll back

To undo the last update of one Deployment:

```powershell
oc -n <project> rollout undo deployment/<name>
oc -n <project> rollout status deployment/<name> --timeout=10m
```

Do it for the same name in both app projects (workers), and for `api` last.

To go back to the files of an earlier commit (the image tag and settings in them; only a commit that already has
these files):

```powershell
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
git show <commit>:deploy/deploy_remediation.yaml | oc apply -f -
oc -n ai-remediation rollout status deployment -l part-of=tsg --timeout=10m
git show <commit>:deploy/deploy_threatgen.yaml | oc apply -f -
oc -n ai-threatgen rollout status deployment -l part-of=tsg --timeout=10m
git show <commit>:deploy/deploy_common.yaml | oc apply -f -
oc -n ai-common rollout status deployment -l part-of=tsg-monitoring --timeout=10m
```

The first line makes PowerShell pass the text to `oc` unchanged. Wait for each project (its `rollout status` line)
before the next: both copies of a worker must never be replaced at the same time.

Back to v1 after the first switch: scale the new Deployments to 0, delete the new Route, put v1's Routes back from
the copies of step 6.5, and scale v1 back up to the counts you wrote down in step 6.1.

```powershell
oc -n ai-threatgen scale deployment -l part-of=tsg --replicas=0
oc -n ai-remediation scale deployment -l part-of=tsg --replicas=0
oc -n ai-threatgen delete route api
oc apply -f "$env:USERPROFILE\.tsg\v1-routes\<project>-<name>.yaml"
oc -n <project> scale deployment <v1 name> --replicas=<count from step 6.1>
```

This does not bring back v1's monitoring in `ai-remediation`.

## Common problems

| What you see | What it means | What to do |
|---|---|---|
| A pod shows `ImagePullBackOff` or `ErrImagePull` | The cluster cannot get the image. | Check step 3 (`quay-pull` in that project) and step 2 (the tag exists in Quay; for the monitoring, step 0). `oc -n <project> describe pod <pod>` names the image. |
| `rollout status` waits and times out; events say `exceeded quota` | The project's budget is used up. A short `exceeded quota` during an update is normal: a stopping pod still counts until it exits (a worker can take up to 2 minutes), then OpenShift creates the new one. Only a timeout is a problem. | `oc -n <project> describe quota` and `oc -n <project> get events --sort-by=.lastTimestamp`. Look for pods that should not run there (for example v1's). |
| A pod shows `CreateContainerConfigError` | A Secret or ConfigMap it reads is missing. | Apply `secrets.yaml` (step 4) and `configmap.yaml` (step 5), then restart that Deployment. |
| `oc apply` says `field is immutable` or `selector does not match` | An old Deployment with the old labels is still there. | Step 6.3 or 6.4 for that name, then apply again. |
| `oc apply -f deploy\configmap.yaml` says `metadata.annotations: Too long` | The dashboard grew past what a plain apply can store. | `oc apply --server-side --force-conflicts -f deploy\configmap.yaml`. |
| `/ready` answers `503` | A store or a queue is missing. | The answer names it: a store that is `false`, or a queue with `false` (no worker). Check that worker's pods and logs: `oc -n <project> logs deploy/<name>`. |
| A pod restarts again and again (`CrashLoopBackOff`) | The program stops at start. | `oc -n <project> logs deploy/<name> --previous` shows why (often a setting: `CII_CORS_ORIGINS` with `*`, an admin key shorter than 32 characters). |
| The Route is not admitted: the address does not answer, `oc describe route` says "HostAlreadyClaimed" | Another Route holds the host. | The Route list of step 6.5 (one project at a time), then step 6.5. A Route in another project: ask the cluster admin. |
| The AI calls time out; `ai.gateway_route` says `"route": "proxy"` | The AI calls go through the company proxy. | `CII_AI_BYPASS_PROXY` must be `"true"` in `configmap.yaml`. See `docs\UAT_LLM_TIMEOUT_RUNBOOK.md`. |
