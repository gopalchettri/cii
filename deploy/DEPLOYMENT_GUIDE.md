# Deploy TSG to OpenShift

This guide has six parts.

1. **Before you start**: what you need ready.
2. **First deployment**: steps 1 to 17.
3. **Open Grafana**: see that TSG is working.
4. **Next release**: deploy a new version.
5. **If something fails**: what an error means and what to do.
6. **How TSG is laid out**: background only, not needed to deploy.

The first time, do Parts 1, 2 and 3 in order. For each later version, do Part 4 only. Not sure which? After you
log in (Part 2, step 1), run `oc -n ai-common get deployment -l part-of=tsg-monitoring`: `No resources found` means
it is the first time; a list of 8 means do Part 4.

Run every command in **PowerShell**, in the code folder: the folder that holds `pyproject.toml` (`cii-main` from the
ZIP, `cii` from git). Open PowerShell and go there first, e.g.:

```powershell
cd C:\work\cii-main
Test-Path pyproject.toml
```

**You should see:** `True`. In every new PowerShell window, run the `cd` line again.

Replace `<...>` with your value. Each step says what to **do**, what **you should see**, and what to do **if not**.

---

## Part 1. Before you start

Have all of these ready:

- [ ] A Windows PC on the network that reaches the cluster and Quay (Part 2, step 1 tests this). The image builds
      (steps 3 and 4) also download from the internet: registry.access.redhat.com, cdn-ubi.redhat.com, github.com,
      dl.grafana.com, packages.microsoft.com, pypi.org, files.pythonhosted.org and proxy.golang.org.
- [ ] The `oc` command (OpenShift CLI). Get it in the OpenShift web console: the **?** menu (top right) →
      **Command Line Tools**. Put `oc.exe` in a folder on your PATH.
- [ ] An OpenShift user with **admin** rights in `ai-threatgen`, `ai-remediation` and `ai-common` (the monitoring
      creates roles in them). Ask the cluster admin.
- [ ] A Quay user name and password that may push to `dda-desc`. Ask the cluster admin.
- [ ] Docker Desktop, started: its window says **Engine running**.
- [ ] The code: the release's ZIP from GitHub, unpacked (or a git clone). Ask the owner which branch.
- [ ] For `secrets.yaml` (step 7):
  - the SQL Server, MongoDB and Redis user names and passwords (ask the owner);
  - the AI gateway key (ask the AI gateway admin; the same key goes in `CII_CHAT_API_KEY`, `CII_EMBEDDING_API_KEY`
    and `CII_RERANK_API_KEY`);
  - the NVD key (free at https://nvd.nist.gov/developers/request-an-api-key), or none;
  - an admin key (32 or more characters) and a Grafana password (16 or more characters): you make them up in step 7.
- [ ] The platform UI's https address, e.g. `https://<ui host>` (ask the platform UI team; step 8).

---

## Part 2. First deployment

### Step 1. Log in

**Do:**

1. Open the OpenShift web console (usually https://console-openshift-console.apps.dda-desc-az1-01.desccii.local).
   Click your name (top right) → **Copy login command** → **Display Token**.
2. Copy the line that starts with `oc login --token=` and run it in PowerShell.
3. Run these. `docker login` asks for your Quay user name and password:

```powershell
docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
oc auth can-i create rolebindings -n ai-threatgen
oc auth can-i create rolebindings -n ai-remediation
oc auth can-i create rolebindings -n ai-common
```

**You should see:** `Logged into "https://..." as "<you>" using the token provided.` from the `oc login` line, then
`Login Succeeded`, then `yes` three times.

**If not:**
- `Use insecure connections? (y/n)`: the cluster uses its own certificate. Type `y`.
- `no`: ask the cluster admin for admin rights in that project.
- `error during connect`: Docker Desktop is not started. Start it and wait for **Engine running**.
- `x509: certificate signed by unknown authority`: Docker does not trust Quay's certificate. Ask the cluster admin.

The login lasts about a day. If an `oc` command later says `Unauthorized`, do this step again.

### Step 2. Check the projects' quotas

**Do:**

```powershell
oc -n ai-threatgen get quota -o yaml | Select-String CrossNamespacePodAffinity
oc -n ai-remediation get quota -o yaml | Select-String CrossNamespacePodAffinity
```

**You should see:** nothing at all.

**If a line is printed, or a later step says `insufficient quota to match these scopes`:** the cluster limits pods
whose "spread over nodes" rule looks at another project, and every worker has such a rule (it keeps away from its
twin). Send the cluster admin this: "Please allow at least 6 pods under the `CrossNamespacePodAffinity` quota scope
in `ai-threatgen` and in `ai-remediation`." Wait for the answer before step 11.

(Developers only: instead, remove the `namespaces:` line from each worker in `deploy\deploy_threatgen.yaml` and
`deploy\deploy_remediation.yaml`, and its check in `tests\test_deploy.py`, and commit it. A worker and its twin may
then share a node.)

### Step 3. Build the 7 monitoring images

**Do:**

```powershell
deploy\build-monitoring-images.bat
```

**You should see:** after a while (the first time is long), `Built, checked and pushed to Quay:` with 7 image lines
under it, and no `ERROR`.

**If it says `is already in Quay`:** that image was built before, and the script stops there without building the
rest. Build only the missing ones, by name. This line tries each image in turn: it builds the ones not in Quay, and
for the others it says `is already in Quay` (fine, nothing to do):

```powershell
foreach ($n in 'prometheus', 'alertmanager', 'loki', 'alloy', 'grafana', 'redis_exporter', 'kube-state-metrics') { deploy\build-monitoring-images.bat $n }
```

**If another `ERROR` is printed:** check step 1 (`docker login`, Docker Desktop running) and the internet sites in
Part 1, then run the step again.

### Step 4. Build the app image

**Do:**

```powershell
deploy\build-image.bat
```

**You should see:** `Tag:` followed by today's date, e.g. `Tag:    24-Oct-2026`. **Write the tag down.**

**If it says the image is already in Quay:** you built today already. Use a new tag, e.g.
`deploy\build-image.bat 24-Oct-2026-2`.

### Step 5. Put the tag in the deploy files

**Do** (put your tag from step 4 in the second line):

```powershell
$old = (Select-String -Path deploy\deploy_threatgen.yaml -Pattern 'tsg-api:(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
$new = '<tag from step 4>'
foreach ($f in 'deploy_threatgen.yaml', 'deploy_remediation.yaml', 'deploy_common.yaml') { $p = Join-Path $PWD "deploy\$f"; [IO.File]::WriteAllText($p, [IO.File]::ReadAllText($p).Replace("tsg-api:$old", "tsg-api:$new")) }
Select-String -Path deploy\deploy_*.yaml -Pattern 'tsg-api:'
```

**You should see:** 15 lines (8 from `deploy_threatgen.yaml`, 6 from `deploy_remediation.yaml`, 1 from
`deploy_common.yaml`), each with `tsg-api:<your tag>` and then a `#` note.

**If a line shows another tag:** open that file in Notepad and change the tag on that line by hand.

### Step 6. Copy the image login to the other two projects

The pods need the Quay login (`quay-pull`) in every project. It already exists in `ai-threatgen`.

**Do:**

```powershell
oc -n ai-threatgen extract secret/quay-pull --keys=.dockerconfigjson "--to=$env:TEMP" --confirm
oc -n ai-remediation create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
oc -n ai-common create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
Remove-Item "$env:TEMP\.dockerconfigjson"
```

**You should see:** `secret/quay-pull created` twice.

**If it says `already exists`:** fine, it is there.

**If the first line says `not found`:** `quay-pull` is not in `ai-threatgen` yet. Ask the cluster admin to create the
Quay pull secret `quay-pull` there, then do this step again.

### Step 7. Fill in and apply the secrets

**Do:**

```powershell
if (-not (Test-Path deploy\secrets.yaml)) { Copy-Item deploy\secrets.example.yaml deploy\secrets.yaml }
notepad deploy\secrets.yaml
```

(If `deploy\secrets.yaml` is already there, the first line keeps it.)

In Notepad, find each word that starts with `CHANGE_ME` (Ctrl+F) and replace **the whole word** with the real value:
all of `CHANGE_ME_USER` or `CHANGE_ME_PASSWORD`, not only `CHANGE_ME`. Part 1 says where each value comes from.
Save and close.
- In the connection strings (`CII_DB_DSN`, `CII_MONGO_URL`, `CII_REDIS_URL`, `CII_REDIS_CELERY_BROKER_URL`), a user
  name or password with a special character (`@ : / ? # % &`) must be URL-encoded. Run this, type the password,
  and paste what it prints: `[uri]::EscapeDataString((Read-Host 'Password'))`
- The admin key and the Grafana password are yours to make up. This makes one (64 characters):
  `-join (1..2 | ForEach-Object { [guid]::NewGuid().ToString('N') })`
- No NVD key: delete `CHANGE_ME` so the line reads `CII_NVD_API_KEY: ""`.
- **Keep the Grafana password**: you need it to sign in to Grafana.

Then:

```powershell
Select-String -Path deploy\secrets.yaml -CaseSensitive -Pattern '^[^#]*(CHANGE_ME|_USER:|_PASSWORD@|_OR_MORE_CHARACTERS)'
oc apply -f deploy\secrets.yaml
```

**You should see:** the first line prints nothing, then `secret/... created` (or `configured`) for each secret.

**If the first line prints something:** that line still has a `CHANGE_ME` word, or the end of one (e.g. `_USER`).
Replace the whole word and run the two lines again.

Keep `deploy\secrets.yaml` private. It is never committed to git.

### Step 8. Apply the settings

**Do:**

```powershell
notepad deploy\configmap.yaml
```

In Notepad, find `CHANGE_ME_UI_ORIGIN` (Ctrl+F), on the `CII_CORS_ORIGINS` line. Replace the whole word with the
platform UI's address, e.g. `https://<ui host>`: https, the host name (and `:port` if it has one), no path and no
`/` at the end. The app compares it letter for letter with the browser's address. Several addresses: separate them
with commas. Never `*`: the app refuses to start with it. Save and close Notepad, then:

```powershell
Select-String -Path deploy\configmap.yaml -Pattern 'CII_CORS_ORIGINS:'
oc apply -f deploy\configmap.yaml
```

**You should see:** first one line with `CII_CORS_ORIGINS: "https://<ui host>"` (your address), then
`configmap/... created` (or `configured`).

**If that line still has `CHANGE_ME`, a path or a `/` at the end:** fix it in Notepad and run the two lines again.

### Step 9. Remove the old deployment (first time only)

An older TSG version may run in these projects. These commands stop it and remove it. Where it is not there, you
see `NotFound`: that is fine. The API is down from here until step 12 is finished.

**Do:**

```powershell
oc -n ai-threatgen scale deployment tsg-api celery-worker celery-worker-admin tsg-beat tsg-flower --replicas=0
oc -n ai-remediation scale deployment celery-worker celery-exporter mssql-exporter mongodb-exporter --replicas=0
oc -n ai-threatgen delete deployment api worker-threats worker-scenarios worker-controls worker-remediation worker-service-mapper worker-maintenance beat --ignore-not-found
oc -n ai-remediation delete deployment worker-threats worker-scenarios worker-controls worker-remediation worker-service-mapper worker-maintenance --ignore-not-found
oc -n ai-remediation delete deployment prometheus alertmanager loki alloy grafana redis-exporter kube-state-metrics flower --ignore-not-found
oc -n ai-remediation delete route grafana prometheus alertmanager loki flower --ignore-not-found
foreach ($p in 'ai-threatgen', 'ai-remediation', 'ai-common') { "== $p"; oc -n $p get route | findstr threatgen }
```

**You should see:** `scaled`, `deleted` or `NotFound` lines (`NotFound` is fine), then, under each `== <project>`,
the Routes that use a `threatgen` address.

**If the last command lists an old Route**, delete it, or the new one cannot take its address. Old means: in
`ai-threatgen`, any Route except `api`; in `ai-remediation`, any Route listed. Keep every Route in `ai-common`:
`grafana`, `prometheus`, `alertmanager`, `loki` and `flower` there are TSG's own. Delete an old Route with:

```powershell
oc -n <project> delete route <name>
```

### Step 10. Apply the network rules

**Do:**

```powershell
oc apply -f deploy\networkpolicy_threatgen.yaml -f deploy\networkpolicy_remediation.yaml
```

**You should see:** `networkpolicy.networking.k8s.io/... created` (or `configured`) for each rule.

### Step 11. Start the workers in ai-remediation

**Do:**

```powershell
oc apply -f deploy\deploy_remediation.yaml
oc -n ai-remediation get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-remediation rollout status $_ --timeout=10m }
```

**You should see:** 6 lines ending with `successfully rolled out` (one per worker).

**If a line times out:** see Part 5, "If something fails".

### Step 12. Start the API, the workers and beat in ai-threatgen

**Do:**

```powershell
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

**You should see:** 8 lines ending with `successfully rolled out` (the API, 6 workers, beat). This can take up to
6 minutes: pods wait for room in the quota while old pods stop.

**If a line times out:** see Part 5, "If something fails".

### Step 13. Start the monitoring in ai-common

**Do:**

```powershell
oc apply -f deploy\deploy_common.yaml
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
```

**You should see:** 8 lines ending with `successfully rolled out` (Prometheus, Alertmanager, Loki, Alloy, Grafana,
redis-exporter, kube-state-metrics, Flower).

**If a line times out:** see Part 5, "If something fails".

### Step 14. Check the API

**Do:**

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/health
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ready
```

**You should see:** first `{"status":"ok"}`, then a longer answer that starts with `{"status":"ready"`.

**If the second answer starts with `{"status":"not_ready"`:** each `false` in it is a store, or a queue with no
worker, that is missing. Wait a minute and try again; still `not_ready`: Part 5.

**If nothing is printed:** this PC cannot reach the API's address. Ask the network team.

### Step 15. Check Grafana

**Do:** Part 3, steps 1 and 2 (below), then come back here for step 16.

**You should see:** the TSG dashboard with **Overall: ALL GOOD**. Give it a few minutes after step 13: until the
first data arrives, a check can still show as a problem.

**If Overall still shows a problem after 10 minutes:** the panel **What is wrong right now** names it. Fix it with
Part 5, then go on to step 16.

### Step 16. Create an API key for each system that calls TSG

**Do** (it asks for the admin key, `CII_ADMIN_API_KEY` from `secrets.yaml`):

```powershell
$adminKey = Read-Host 'Admin key (CII_ADMIN_API_KEY)'
Set-Content -Path client.json -Encoding ascii -Value '{"name": "<system name>", "description": "<what it is>"}'
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/api-clients -H "X-Admin-Key: $adminKey" -H "Content-Type: application/json" --data-binary "@client.json"
Remove-Item client.json
```

**You should see:** an answer with `"api_key": "..."`. **Copy that value now**: it is shown only once. Give it to
that system's team. Ask the owner which systems need a key (e.g. `shield-frontend`).

**If it says `The admin key is missing or wrong.`:** you typed the admin key wrong. Run the four lines again.

### Step 17. First import of the outside intelligence

**Do:**

```powershell
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh
```

**You should see:** an answer with a `job_id`.

**If the answer has `"status":409` and says `already queued or running`:** an import already runs (TSG also
imports every hour by itself). Use the `job_id` under `details` in that answer.

**Then:** put the `job_id` in this line. Run it every minute or two until `status` is `done` (it goes `queued`,
then `running`, then `done`):

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh/<job_id>
```

**If `status` is `failed`:** its `error` says why. Fix that and run the first line again.

The deployment is finished.

---

## Part 3. Open Grafana

Grafana shows whether TSG is working: jobs, queues, AI calls, errors and logs. **Looking needs no login.**

### Step 1. Open the address

On the same PC (it must be on the network that reaches the cluster), open this address in Chrome or Edge:

**https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/grafana/**

Type it exactly, with `/grafana/` at the end. Without it you get the OpenShift page "Application is not available".

**You should see:** the TSG dashboard, with no login page: a panel **How to use this page** at the top, then
**Is everything working?** with the **Overall** tile. (The top bar shows **Home** or "TSG — is everything
working?": both are right.) Bookmark the page.

**If the browser warns about the certificate** ("Your connection is not private"): it is the cluster's own
certificate. Click **Advanced**, then **Proceed to threatgen-grafana... (unsafe)** in Chrome or **Continue to
threatgen-grafana... (unsafe)** in Edge. Or ask the cluster admin for the CA certificate to install.

**If the page does not open, or shows "Application is not available":** go to step 4 below.

### Step 2. Read the dashboard

The first three panels are at the top. Scroll down for the others.

| Panel | What it tells you |
|---|---|
| **Overall** | `ALL GOOD` in green, or how many problems there are |
| **Parts of the system** | One tile per part (each worker, the stores, the AI): green is working |
| **What is wrong right now** | Each problem in plain words: "Just noticed" (still being checked) or "Confirmed" |
| **Jobs waiting in each queue** | A queue that keeps growing is missing its worker, or the AI is slow |
| **Wait for an AI request's turn (95 %), by model** | Long waits mean the AI key is the limit, not the pods |
| **AI gateway refusals (429) per minute** | Many 429s mean the gateway is refusing calls |

**Example:** a user says "my run is stuck". Copy the run's `session_id` into the box **"Find a run, request or job
id"** at the top of the page. The section **"Follow one run or request"** then shows its log lines: which stage it
is in and what it waits for.

### Step 3. Sign in (only to change Grafana itself)

Looking needs no login. To change Grafana's users or settings:

1. Click **Sign in** (top right).
2. User: `admin`. Password: the `GF_SECURITY_ADMIN_PASSWORD` you put in `deploy\secrets.yaml` (Part 2, step 7).

**Forgot the password:** set a new one (16 or more characters) in `deploy\secrets.yaml`, then:

```powershell
oc apply -f deploy\secrets.yaml
oc -n ai-common rollout restart deployment/grafana
```

Grafana takes the password from the secret each time it starts.

The TSG dashboard cannot be changed in the browser. To change it, edit `observability\grafana\dashboards\tsg.json`
and its copy in `deploy\configmap.yaml` in git, apply `configmap.yaml` (Part 2, step 8), then
`oc -n ai-common rollout restart deployment/grafana`.

### Step 4. If the address does not open

**Do** (in PowerShell, logged in as in Part 2, step 1):

```powershell
oc -n ai-common get route grafana
oc -n ai-common get pods -l app=grafana
```

**You should see:** the Route with host `threatgen-grafana.apps.dda-desc-az1-01.desccii.local` and path
`/grafana`, and the pod `Running` with `1/1`.

- **`Unauthorized`:** log in again (Part 2, step 1).
- **`NotFound`** for the Route: Grafana is not deployed. Do Part 2, step 13.
- **`HostAlreadyClaimed`** in the Route: an old Route still holds the address. Delete it (Part 2, step 9).
- **The pod is `Running` with `0/1`:** it is still starting. Wait 2 minutes and look again.
- **The pod is `Pending`, `ImagePullBackOff` or `CreateContainerConfigError`:** the last lines (Events) of
  `oc -n ai-common describe pod -l app=grafana` say why. Then see Part 5.
- **The pod is `Init:Error` or `Init:CrashLoopBackOff`:** `oc -n ai-common logs deployment/grafana -c set-admin-password`
  shows why.
- **The pod is `CrashLoopBackOff` or `Error`:** `oc -n ai-common logs deployment/grafana` shows why.
- **Both look fine but the page still does not open** (DNS or firewall): open Grafana through `oc` instead. Run
  this and keep the window open (Ctrl+C stops it):

  ```powershell
  oc -n ai-common port-forward deployment/grafana 3001:3000
  ```

  **You should see:** `Forwarding from 127.0.0.1:3001 -> 3000`. Then open **http://localhost:3001/grafana/** on the
  same PC.

### Other monitoring pages (same address)

| Page | Address | Use it to |
|---|---|---|
| Prometheus | https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/prometheus/ | see raw metrics; alert rules under **Alerts** |
| Alertmanager | https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/alertmanager/ | see firing alerts; silence one during planned work (a silence is lost when the pod restarts) |
| Flower | https://threatgen-grafana.apps.dda-desc-az1-01.desccii.local/flower/ | watch the Celery workers and their tasks live |

Logs are in the dashboard's log panels (Loki has no page of its own). Signed in as `admin`, you can also search
them under **Explore → Loki**.

To see each pod's memory (compare it with the pod's limit in Part 6, and raise the limit if it stays above 80 %):

```powershell
oc adm top pods -n ai-threatgen
oc adm top pods -n ai-remediation
```

---

## Part 4. Next release

Use this for every new version after the first deployment.

**First, get the new code.** Unpack the new release's ZIP into a new folder (with git: a new clone). Keep the old
folder: a rollback needs it. A new folder has no `deploy\secrets.yaml` and no UI address, so:

```powershell
cd <new code folder>
Copy-Item <old code folder>\deploy\secrets.yaml deploy\
Test-Path deploy\secrets.yaml
```

**You should see:** `True`. Then set `CII_CORS_ORIGINS` in the new `deploy\configmap.yaml` again: Part 2, step 8,
the Notepad part and the `Select-String` line (step 5 below applies it).

### Step 1. Log in

The same as Part 2, step 1.

### Step 2. Build the app image and write down its tag

The same as Part 2, step 4:

```powershell
deploy\build-image.bat
```

### Step 3. Put the tag in the deploy files

The same commands as Part 2, step 5.

### Step 4. Build any monitoring image that is not in Quay yet

Most releases keep the monitoring versions, so most images are in Quay already. This line tries each image by name
and builds only the missing ones.

**Do:**

```powershell
foreach ($n in 'prometheus', 'alertmanager', 'loki', 'alloy', 'grafana', 'redis_exporter', 'kube-state-metrics') { deploy\build-monitoring-images.bat $n }
```

**You should see:** for each image, `Built, checked and pushed to Quay:` or `ERROR: ... is already in Quay`. Here that
ERROR is fine: that version was built before.

**If kube-state-metrics fails with `did NOT match`:** its new version needs a new `SRC_SHA256` in
`deploy\images\kube-state-metrics\Dockerfile`. Ask the developer.

**If another `ERROR` is printed:** check step 1 (`docker login`, Docker Desktop running) and the internet sites in
Part 1, then run the step again.

### Step 5. Apply the secrets and settings (every release; no harm if nothing changed)

First check that your `deploy\secrets.yaml` has every key of the new `deploy\secrets.example.yaml`:

```powershell
$mine = Get-Content deploy\secrets.yaml -Raw
Select-String -Path deploy\secrets.example.yaml -Pattern '^\s+([A-Z_]+):' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Where-Object { $mine -notmatch "\b$_\b" }
```

**You should see:** nothing. A name printed is a new secret: copy its line from `secrets.example.yaml` into your
`secrets.yaml`, with the real value.

Then apply both, and restart the monitoring so it loads its new config files (the app pods load the new settings
in step 7):

```powershell
oc apply -f deploy\secrets.yaml
oc apply -f deploy\configmap.yaml
oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
```

**You should see:** `configured` or `unchanged` for each secret and setting, then 8 lines ending with
`successfully rolled out`.

**If a line times out:** see Part 5, "If something fails".

### Step 6. Only once: if the running API pods still have a 1 CPU limit

Check:

```powershell
oc -n ai-threatgen get deployment api -o jsonpath='{.spec.template.spec.containers[0].resources.limits.cpu}'
```

If it prints `1`, run the two lines below (otherwise the new workers and the API's extra update pod do not fit the
quota). If it prints `750m`, skip this step.

```powershell
oc -n ai-threatgen set resources deployment/api --limits=cpu=750m
oc -n ai-threatgen rollout status deployment/api --timeout=10m
```

### Step 7. Roll out, in this order

**Do:**

```powershell
oc apply -f deploy\deploy_remediation.yaml
oc -n ai-remediation get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-remediation rollout status $_ --timeout=10m }
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
oc apply -f deploy\deploy_common.yaml
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
```

**You should see:** after each `oc apply`, one `successfully rolled out` line per Deployment: 6, then 8, then 8.

**If a line times out:** see Part 5, "If something fails".

### Step 8. Check

The same as Part 2, steps 14 and 15 (the API answers `{"status":"ok"}` and `{"status":"ready"...`; Grafana shows
`ALL GOOD`).

---

## Part 5. If something fails

**First, find what is wrong.** Put the project of the step that failed in `<project>`:

```powershell
oc -n <project> get pods
oc -n <project> get events --sort-by=.lastTimestamp | Select-Object -Last 20
```

**You should see:** the pods with their `STATUS`, then the last 20 events. Find that `STATUS`, or a message from
the events, in the left column below.

| You see | Do this |
|---|---|
| `ImagePullBackOff` | The image is not in Quay (Part 2, steps 3-5) or `quay-pull` is missing (Part 2, step 6). |
| `exceeded quota` | Wait up to 6 minutes (old pods still stopping). Still failing: `oc -n <project> describe quota`, and Part 2, step 2. |
| `insufficient quota to match these scopes` | The cluster lets a pod's spreading rule look at another project only under a special quota: Part 2, step 2. |
| `CreateContainerConfigError` | A secret or setting is missing: Part 2, steps 7 and 8. |
| `field is immutable` | An older Deployment with the same name is still there. In `ai-threatgen` or `ai-remediation`: Part 2, step 9. In `ai-common` (step 9 does not clean it, and the chatbot runs there too): run `oc -n ai-common get deployment <name> --show-labels`. If it shows `part-of=tsg-monitoring` or `part-of=tsg`, it is TSG's: run `oc -n ai-common delete deployment <name>` and apply again. Otherwise it is not TSG's: do not delete it, ask its owner (the chatbot team). |
| `Pending` | The last lines (Events) of `oc -n <project> describe pod <name>` say why. `unbound ... PersistentVolumeClaims`: ask the cluster admin for storage. |
| `/ready` answers `not_ready` (503) | Each `false` in its answer is a missing store or worker. A worker: `oc -n <project> logs deployment/<that worker>` shows why. |
| `CrashLoopBackOff` | `oc -n <project> logs deployment/<name> --previous` shows why (often a setting). |
| Flower stops with `invalid literal for int() ... 'tcp://...'` | The pod still takes OpenShift's service variables (`FLOWER_PORT`): apply this release's `deploy\deploy_common.yaml` (Part 2, step 13). |

### Change a setting or secret later

Edit and apply the file (Part 2, step 7 or 8), then restart one project at a time:

```powershell
oc -n ai-remediation rollout restart deployment -l part-of=tsg
oc -n ai-remediation get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-remediation rollout status $_ --timeout=10m }
oc -n ai-threatgen rollout restart deployment -l part-of=tsg
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
```

### Roll back to the previous release

Use the previous release's code folder (the one you kept in Part 4): `cd <previous code folder>`. The previous
release has no `worker-controls` and no `worker-remediation`, so remove both, in this order, or the old pods do not
fit ai-threatgen's quota:

1. Make room in ai-threatgen's quota (their twins in ai-remediation keep working):

   ```powershell
   oc -n ai-threatgen delete deployment worker-controls worker-remediation
   ```

2. Apply the previous `deploy_remediation.yaml`, then the previous `deploy_threatgen.yaml` (Part 4, step 7, the
   first four lines). **You should see:** 6, then 6 lines ending with `successfully rolled out`.
3. Wait until the Grafana panel "Jobs waiting in each queue" shows `tsg_controls` and `tsg_remediation` empty, then:

   ```powershell
   oc -n ai-remediation delete deployment worker-controls worker-remediation
   ```

4. Last, apply the previous `deploy_common.yaml` (Part 4, step 7, the last two lines). It no longer watches
   `tsg_controls` or `tsg_remediation`.

---

## Part 6. How TSG is laid out, and why

Read this once to understand the setup. You do not need it to deploy.

### Three projects

| Project | What runs there | Why |
|---|---|---|
| `ai-threatgen` | The API (2 pods), beat (the scheduler, 1 pod) and one copy of every worker | Users and other systems call the API here. |
| `ai-remediation` | A second copy (a "twin") of every worker | While one copy restarts or its node fails, its twin keeps the same queue moving. |
| `ai-common` | Monitoring: Grafana, Prometheus, Alertmanager, Loki, Alloy, redis-exporter, kube-state-metrics, and Flower | Shared with the chatbot, so the app projects keep their quota for the app. |

Each app project has a quota of 6 CPU and 12 Gi of memory, counted on the pods' limits.

### One worker for each kind of work

Example: a user starts a run for one asset.

1. The API puts a job on the queue `tsg_threats`. **worker-threats** asks the AI which library threats apply to
   the asset (about 40 AI calls, 8 at a time).
2. The run moves on to `tsg_scenarios`. **worker-scenarios** writes the first set of 6 scenarios at once, each with
   its evidence.
3. As each scenario is saved, `tsg_controls` gets a job. **worker-controls** picks its controls (6 scenarios at
   once).
4. When the user asks for a remediation plan, `tsg_remediation` gets a job. **worker-remediation** writes it.
5. A service mapping goes to `tsg_servicemapper` and **worker-service-mapper**.
6. **worker-maintenance** (`tsg_maintenance`) repairs stuck jobs every minute, retries failed control mapping,
   rebuilds the library indexes and imports the outside intelligence.

Because every kind of work has its own worker, a long remediation plan never waits behind scenario writing, and
control mapping never waits behind a busy writer. A run's next step also goes ahead of new runs in its queue.

| Pod (in both projects unless noted) | Queue | Jobs at once | CPU request / limit | Memory request / limit |
|---|---|---|---|---|
| worker-threats | `tsg_threats` | 2 | 500m / 1 | 1Gi / 1.5Gi |
| worker-scenarios | `tsg_scenarios` | 2 | 500m / 1 | 1Gi / 2Gi |
| worker-controls | `tsg_controls` | 1 (maps 6 scenarios at once) | 100m / 250m | 640Mi / 1Gi |
| worker-remediation | `tsg_remediation` | 2 | 250m / 500m | 640Mi / 1Gi |
| worker-service-mapper | `tsg_servicemapper` | 2 | 250m / 500m | 640Mi / 1Gi |
| worker-maintenance | `tsg_maintenance` | 3 | 100m / 250m | 768Mi / 1.5Gi |
| api (ai-threatgen only, 2 pods) | - | - | 250m / 750m | 512Mi / 1Gi |
| beat (ai-threatgen only, 1 pod) | - | - | 50m / 250m | 320Mi / 512Mi |

Totals (limits): ai-threatgen 5.25 CPU and 10.5 Gi (6.0 CPU and 11.5 Gi while an API update runs, because
its new pod starts before an old one stops); ai-remediation 3.5 CPU and 8 Gi.

### Why these sizes: the AI sets the speed, not the pods

All AI models sit behind one gateway key. The main chat model, kimi-k2.5, takes 192 requests a minute; TSG sends it
at most 180 (`CII_CHAT_REQUESTS_PER_MINUTE`), which leaves room as long as nothing else uses kimi-k2.5 on this key
(still to be confirmed).

Example: a kimi call takes about 5 seconds, so 180 a minute is about 15 calls running at once for all of TSG (every
pod in both projects).

- One user alone: threat finding asks 8 questions at once. A measured run (36 questions, still 4 at once) took
  about 1.5 minutes; with 8 at once expect about a minute (not yet measured).
- 10 users start runs together: 4 runs find threats at once (2 in each worker-threats pod) and the other 6 wait
  their turn in `tsg_threats`. kimi's turns are handed out 3 a second in arrival order, so all 10 finish threat
  finding in a few minutes.
- More pods or more jobs at once would not be faster: they would only wait longer for kimi's turn. That is why the
  threats and scenarios workers run 2 jobs at a time.

Memory was measured (on a laptop): a worker uses about 220 MB. The scenarios worker keeps the evidence index
loaded: about 450 MB, and up to about 815 MB while it rebuilds the index (its limit is 2 Gi). Only the scenarios
worker keeps that index loaded (the maintenance worker builds one at each import), which keeps the other workers
small.

### The AI settings in `configmap.yaml`

| Setting | UAT value | Meaning |
|---|---|---|
| `CII_CHAT_REQUESTS_PER_MINUTE` | 180 | kimi-k2.5 requests a minute, all pods together (its own limit is 192) |
| `CII_CHAT_FALLBACK_REQUESTS_PER_MINUTE`, `CII_EMBEDDING_REQUESTS_PER_MINUTE`, `CII_RERANK_REQUESTS_PER_MINUTE` | 0 | the same for glm-5.3, the embedding model and the re-ranking model; 0 = no limit until the gateway admin gives theirs |
| `CII_MAX_CONCURRENT_FALLBACK_CALLS` | 16 | at most 16 calls to glm-5.3 at once (it takes 55-99 s a call) |
| `CII_MAX_CONCURRENT_AI_CALLS` | 0 | no overall cap: only kimi-k2.5's 180 a minute and glm-5.3's 16 at once pace the calls |

If kimi keeps refusing (HTTP 429) or timing out, a pod sends its calls to glm-5.3 first for 2 minutes (to kimi when
all 16 glm-5.3 places are busy), then tries kimi again.

### Updates and node failures

- A worker updates by stopping its old pod first (no extra pod in the quota); its twin in the other project serves
  meanwhile.
- The API starts its new pod before it stops an old one, so it never goes down during an update.
- Each worker prefers a node its twin is not on, and the two API pods different nodes, so one node failure stops
  neither a queue nor the API. Preferred only: a pod still starts when no other node fits.
- No pod takes OpenShift's automatic service variables (`<SERVICE>_PORT=tcp://...`): each finds a service by its
  DNS name. That keeps a program such as Flower from reading them as its own settings.
