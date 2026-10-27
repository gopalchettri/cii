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
it is the first time; a list (8 when all runs, fewer if an earlier deployment stopped half way) means do Part 4.

Run every command in **PowerShell**, in the code folder: the folder that holds `pyproject.toml`. From a GitHub ZIP it is named `cii-<branch>` (e.g. `cii-master`; a `/` in the branch name becomes `-`), and Windows' **Extract All** often puts it one folder deeper (e.g. `C:\work\cii-master\cii-master`). From git it is `cii`. Open PowerShell and go there first, e.g.:

```powershell
cd C:\work\cii-main
Test-Path pyproject.toml
```

**You should see:** `True`. **If `False`:** run `Get-ChildItem C:\work -Recurse -Filter pyproject.toml | Select-Object -First 1 DirectoryName` and `cd` to the folder it prints, then run `Test-Path pyproject.toml` again. In every new PowerShell window, run the `cd` line again.

Replace `<...>` with your value. Each step says what to **do**, what **you should see**, and what to do **if not**.

---

## Part 1. Before you start

Have all of these ready:

- [ ] A Windows PC on the network that reaches the cluster and Quay (Part 2, step 1 tests this). The image builds
      (steps 3 and 4) also download from the internet: registry.access.redhat.com, cdn-ubi.redhat.com, github.com,
      dl.grafana.com, packages.microsoft.com, pypi.org, files.pythonhosted.org and proxy.golang.org.
- [ ] The `oc` command (OpenShift CLI). Get it in the OpenShift web console: the **?** menu (top right) →
      **Command Line Tools** → **Download oc for Windows**. Unzip `oc.exe` into e.g. `C:\tools`, run
      `[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';C:\tools', 'User')`
      and open a new PowerShell window. Check: `oc version --client` prints `Client Version: 4...`.
- [ ] An OpenShift user with **admin** rights in `ai-threatgen`, `ai-remediation` and `ai-common` (the monitoring
      creates roles in them). Ask the cluster admin.
- [ ] A Quay user name and password that may push to `dda-desc` **and create new repositories there**: each
      monitoring image is a new repository (step 3 lists them). If your user may not create repositories, the Quay
      admin creates them first, with Write for your user. Ask the cluster admin who the Quay admin is.
- [ ] The cluster's own Quay login (the secret `quay-pull`, step 6) may **read** those new repositories. Quay makes a
      new repository private: only the user who created it can read it. Best: the Quay admin gives that login Read
      as a **default permission** of `dda-desc`, so every new repository is readable at once. Step 6 prints the
      login's name and checks it.
- [ ] Docker Desktop, started: its window says **Engine running**.
- [ ] The code: the release's ZIP from GitHub, unpacked (or a git clone). Ask the owner which branch.
- [ ] For `secrets.yaml` (step 7):
  - the SQL Server, MongoDB and Redis user names and passwords (ask the owner);
  - the AI gateway key (ask the AI gateway admin; the same key goes in `CII_CHAT_API_KEY`, `CII_EMBEDDING_API_KEY`
    and `CII_RERANK_API_KEY`);
  - the NVD key (free at https://nvd.nist.gov/developers/request-an-api-key), or none;
  - an admin key (32 or more characters) and a Grafana password (16 or more characters): you make them up in step 7.
- [ ] The platform UI's https address, e.g. `https://<ui host>` (ask the platform UI team; step 8).
- [ ] TSG's stored procedures installed by the DBA in the TSG SQL Server database: every
      `scripts\sql\tsg_*.sql` file of this release (never a file with `copy` in its name), then
      `scripts\sql\grants.sql`. Give the DBA the files from your code folder and wait for their OK. Without them
      the app cannot read its library, and the service mapper cannot read its catalog ("Could not find stored
      procedure").

---

## Part 2. First deployment

### Step 1. Log in

**Do:**

1. Open the OpenShift web console (usually https://console-openshift-console.apps.dda-desc-az1-01.desccii.local).
   Click your name (top right) → **Copy login command**. A new tab opens: log in again if it asks, then click **Display Token**.
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
twin). Send the cluster admin this: "Please allow at least 7 pods under the `CrossNamespacePodAffinity` quota scope
in `ai-threatgen` and in `ai-remediation`." Wait for the answer before step 11.

(Developers only: instead, remove the `namespaces:` line from each worker in `deploy\deploy_threatgen.yaml` and
`deploy\deploy_remediation.yaml`, and its check in `tests\test_deploy.py`, and commit it. A worker and its twin may
then share a node.)

**Then check ai-common**, where the monitoring runs (its quota is shared with the chatbot):

```powershell
oc -n ai-common describe quota
oc -n ai-common describe appliedclusterresourcequota
oc -n ai-common get limitrange
```

**You should see:** each quota with a `Used` and a `Hard` column (or `No resources found`), then `No resources found`
for the limit range. For `limits.cpu`, `limits.memory` and `requests.storage`, Hard minus Used must leave at least
2.8 CPU, 5.2Gi and 21Gi for TSG's monitoring (the `Budget:` lines at the top of `deploy\deploy_common.yaml`). What TSG
already has there is part of these numbers, not extra, so add it back first: its pods are replaced, and its claims
`prometheus-data`, `loki-data` and `grafana-data` (`oc -n ai-common get pvc` shows them) are used again.

**If there is less room:** send the cluster admin those quota lines and these three numbers, and wait for more room
(or for the chatbot team to free some) before step 13.

**If a limit range is listed:** send the developer what `oc -n ai-common get limitrange -o yaml` prints. Its limits
can refuse TSG's monitoring pods (step 13 then shows `maximum`, `minimum` or `max limit to request ratio` in the
events).

### Step 3. Build the monitoring images

**Do:**

```powershell
deploy\build-monitoring-images.bat
```

**You should see:** first `Images in deploy\deploy_common.yaml:` with the monitoring images (every `image:` line of
that file in Quay but the app's), then after a while (the first time is long) `Built, checked and pushed to Quay:`
with the same images under it, and no `ERROR`.

**If it says `is already in Quay`:** that tag was pushed before, and the script stops there without building the
rest. It is fine only if it is the UBI 9 build that this script makes: an older TSG version copied the programs' own
images to Quay under the same names and tags. Check it with your login (this reads Quay and changes nothing; put the
image from the `ERROR` line in the first line):

```powershell
$i = '<image from the ERROR line>'
docker pull $i
docker image inspect $i --format '{{.Config.Labels.name}}'
```

**You should see:** a name that starts with `ubi9`. Then build the others by name. These lines read the images from
`deploy\deploy_common.yaml` and try each in turn: they build the ones not in Quay, and for the others say `is
already in Quay` (check each of those the same way). The last line checks the monitoring proxy's config in the nginx
image, also when that image is in Quay already, pushes nothing and ends with `Built and checked, not pushed:`:

```powershell
$names = Select-String -Path deploy\deploy_common.yaml -Pattern '^\s*image: \S+/dda-desc/([\w.-]+):' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Where-Object { $_ -ne 'tsg-api' } | Select-Object -Unique
foreach ($n in $names) { deploy\build-monitoring-images.bat $n }
deploy\build-monitoring-images.bat nginx --no-push
```

**If it prints `<no value>` or another name:** that tag holds an old copy, and the pods would run it. Ask the Quay
admin to delete that tag, then run `deploy\build-monitoring-images.bat <name>`. (A node that already ran the old copy
keeps it under the same tag: if TSG's monitoring ever ran from it, ask the developer for a new version tag instead.)

**If it says `docker push failed`** and `docker login` (step 1) said `Login Succeeded`: Quay refused (`denied` or
`unauthorized` above it) because your Quay user cannot create the repository `dda-desc/<name>`, or may not write to
it if it is there. Ask the Quay admin for Write on the repositories (the names in the `Images in` line), creating the
missing ones, or to let you create repositories in `dda-desc` (Part 1). Then run the two `$names` lines above.

**If it says `nginx does not accept observability\nginx\nginx.conf`:** do not go on. Send the lines above it to the
developer.

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

**You should see:** first the file it wrote (e.g. `C:\Users\<you>\AppData\Local\Temp\.dockerconfigjson`), then `secret/quay-pull created` twice.

**If it says `already exists`:** fine, it is there.

**If the first line says `not found`:** `quay-pull` is not in `ai-threatgen` yet. Ask the cluster admin to create the
Quay pull secret `quay-pull` there, then do this step again.

**Then check that the cluster's own login can pull every image.** These lines read Quay and change nothing. They
use the login in `ai-common`'s `quay-pull`, try each image line of `deploy\deploy_common.yaml` (the app image too),
and delete the login file at the end, also when you stop them with Ctrl+C:

```powershell
oc -n ai-common extract secret/quay-pull --keys=.dockerconfigjson "--to=$env:TEMP" --confirm
$auth = "$env:TEMP\.dockerconfigjson"
try {
(Get-Content $auth -Raw | ConvertFrom-Json).auths.PSObject.Properties | ForEach-Object { $user = $_.Value.username; if (-not $user) { $user = ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.Value.auth)) -split ':')[0] }; "Pull account: $user" }
$images = Select-String -Path deploy\deploy_common.yaml -Pattern '^\s*image: (\S+/dda-desc/\S+)' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique
foreach ($i in $images) { $info = oc image info --filter-by-os=linux/amd64 -a $auth $i 2>&1 | Out-String; if ($info -match 'Digest:') { if ($info -match 'ubi9') { "OK            $i" } else { "OLD COPY      $i" } } elseif ($info -match 'unauthorized|denied') { "CANNOT READ   $i" } elseif ($info -match 'manifest unknown') { "NOT IN QUAY   $i" } else { "CANNOT CHECK  $i"; $info.Trim() } }
} finally { Remove-Item $auth -ErrorAction SilentlyContinue }
```

**You should see:** the file it wrote, `Pull account: <name>` (the user or robot the cluster pulls with; never its
password), then one line per image, each starting with `OK`. **Do not go on until every line says `OK`:** a pod
cannot start without its image. Fix each other line as below, then run the lines again:

| Line starts with | What it means | Do this |
|---|---|---|
| `CANNOT READ` | Quay refuses the pull account. Either it may not read that repository (Quay makes a new one private), or the image was never pushed: Quay answers the same for both. | Check with your own login: `docker manifest inspect <image>`. If it prints JSON, the image is there: ask the Quay admin to give the `Pull account` Read on it, best as a default permission of `dda-desc` (Part 1). If it says `no such manifest` and you pushed the images, it was never pushed: step 3 (someone else pushed them: ask the Quay admin whether it is there). |
| `NOT IN QUAY` | The repository is there, this tag is not. | Step 3, by name: `deploy\build-monitoring-images.bat <name>`. For `tsg-api`: steps 4 and 5. |
| `OLD COPY` | It is not the UBI 9 build: an older copy under the same tag. | Step 3, "If it prints `<no value>`". |
| `CANNOT CHECK` | The lines under it say why. | `x509`: this PC does not trust Quay's certificate. Ask the cluster admin, as in step 1, then run the lines again. Never turn the certificate check off here: these lines send the cluster's login. Anything else: send the lines to the developer. |

**If the first line says `not found`:** `quay-pull` is not in `ai-common`: do the first part of this step.

**If `tsg-api` says `CANNOT READ` too:** compare `ai-common`'s `quay-pull` with the one in `ai-threatgen`. These lines
print only `True` or `False`, never the login:

```powershell
$a = oc -n ai-threatgen get secret quay-pull -o 'jsonpath={.data.\.dockerconfigjson}'
$b = oc -n ai-common get secret quay-pull -o 'jsonpath={.data.\.dockerconfigjson}'
"same login: " + ([bool]$a -and ($a -ceq $b))
Remove-Variable a, b
```

- `same login: False`: `ai-common`'s `quay-pull` is not a copy of `ai-threatgen`'s. Someone else may have made it,
  maybe the chatbot team, who share this project. Do not delete it yet: ask them whether their pods use it.
  If not, run `oc -n ai-common delete secret quay-pull` and do this whole step again. If they do, ask the Quay admin
  to give the `Pull account` printed above Read on TSG's repositories in `dda-desc` (as in the table).
- `same login: True`: the pull account itself cannot read `tsg-api`, in `ai-threatgen` too (the pods there start
  from a node's own copy or from another login). A new copy changes nothing: send the `Pull account` name to the
  Quay admin and ask for Read on every image above, best as a default permission of `dda-desc` (Part 1).

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
- Redis with a password but no user name: delete `CHANGE_ME_USER` and keep the `:`, e.g. `redis://:<password>@10.228.146.4:6379/0` (in both Redis lines).
- The admin key and the Grafana password are yours to make up. This makes one (64 characters):
  `-join (1..2 | ForEach-Object { [guid]::NewGuid().ToString('N') })`
- No NVD key: delete `CHANGE_ME` so the line reads `CII_NVD_API_KEY: ""`.
- **Keep the Grafana password**: you need it to sign in to Grafana.
- Alert email (step 8 picks the sender): `SMTP_RELAY_PASSWORD` is the company mail relay's password,
  `GMAIL_APP_PASSWORD` a Google app password (Google account, Security, App passwords). For the one you do not
  use, delete `CHANGE_ME` so the line reads `""`.

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
with commas. Never `*`: the app refuses to start with it.

Alert email: in the `alertmanager.yml` part, the line `receiver:` under `route:` picks the sender, `company-smtp`
(the company mail relay) or `gmail`. In that sender's lines, replace each `CHANGE_ME_` word: the relay's
`host:port` (company-smtp only), the sender address and login, and the recipients (comma-separated). Make the same
change in `observability\alertmanager\alertmanager.yml` (the tests fail when the two differ). Mail does not go
through the proxy: the relay, or `smtp.gmail.com` port 587, must be reachable from `ai-common`.
Save and close Notepad, then:

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
oc -n ai-threatgen delete deployment api worker-threats worker-scenarios worker-controls worker-remediation worker-service-mapper worker-maintenance worker-reaper beat --ignore-not-found
oc -n ai-remediation delete deployment worker-threats worker-scenarios worker-controls worker-remediation worker-service-mapper worker-maintenance worker-reaper --ignore-not-found
oc -n ai-remediation delete deployment prometheus alertmanager loki alloy grafana redis-exporter kube-state-metrics flower --ignore-not-found
oc -n ai-remediation delete route grafana prometheus alertmanager loki flower --ignore-not-found
oc -n ai-common delete route -l part-of=tsg-monitoring
foreach ($p in 'ai-threatgen', 'ai-remediation', 'ai-common') { "== $p"; oc -n $p get route | findstr threatgen }
```

**You should see:** `scaled`, `deleted`, `NotFound` or `No resources found` lines (`NotFound` and `No resources
found` are fine), then, under each `== <project>`, the Routes that use a `threatgen` address. In ai-common, shared
with the chatbot, TSG's Routes are deleted by their label, never by name: a chatbot Route may have the same name.

**If the last command lists an old Route**, delete it, or the new one cannot take its address. Old means: in
`ai-threatgen`, any Route except `api`, `grafana` and `flower`; in `ai-remediation` and `ai-common`, any Route listed
(the `threatgen-grafana` Routes there were TSG's older ones: the new Routes live in `ai-threatgen`). Delete an old
Route with:

```powershell
oc -n <project> delete route <name>
```

**Then remove TSG's older monitoring in ai-common**, if an older TSG version left it there. First list it:

```powershell
oc -n ai-common get deployment -l app.kubernetes.io/part-of=tsg-observability
```

**You should see:** `No resources found` (then this step is done), or some of `prometheus`, `alertmanager`, `loki`,
`alloy`, `grafana`, `redis-exporter`, `kube-state-metrics` and `flower`. That label is TSG's older one, not the
chatbot's. Delete them and their Routes (their volumes, with the metrics, the logs and Grafana's database, stay):

```powershell
oc -n ai-common delete deployment,route -l app.kubernetes.io/part-of=tsg-observability
```

**If the list shows another name:** do not delete anything; ask the developer first.

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

**You should see:** 7 lines ending with `successfully rolled out` (one per worker).

**If a line times out:** see Part 5, "If something fails".

### Step 12. Start the API, the workers and beat in ai-threatgen

**Do:**

```powershell
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

**You should see:** 9 lines ending with `successfully rolled out` (the API, 7 workers, beat). This can take up to
6 minutes: pods wait for room in the quota while old pods stop.

**If a line times out:** see Part 5, "If something fails".

### Step 13. Start the monitoring in ai-common

**Do:**

```powershell
oc apply -f deploy\deploy_common.yaml
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
oc -n ai-threatgen rollout status deployment/monitoring-proxy --timeout=10m
```

**You should see:** 9 lines ending with `successfully rolled out`: 8 in ai-common (Prometheus, Alertmanager, Loki,
Alloy, Grafana, redis-exporter, kube-state-metrics, Flower), then the monitoring proxy in ai-threatgen. The proxy
is a small nginx that puts Grafana and Flower on the API's address (OpenShift lets only ai-threatgen use it).

**If a line times out:** see Part 5, "If something fails". For the proxy, see also Part 3, step 4.

### Step 14. Check the API

**Do:**

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/health
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ready
```

**You should see:** first `{"status":"ok"}`, then a longer answer that starts with `{"status":"ready"` and contains `"sql":true`. `"sql":false` does not stop `ready`, but the library pages fail: the `CII_DB_DSN` line in `secrets.yaml` is wrong. Fix it (step 7), then restart the pods (Part 5, "Change a setting or secret later").

**If the second answer starts with `{"status":"not_ready"`:** each `false` in it is a store, or a queue with no
worker, that is missing. Wait a minute and try again; still `not_ready`: Part 5.

**If nothing is printed:** this PC cannot reach the API's address. Ask the network team.

**If it prints an HTML page with `Application is not available`:** the address works, but no API pod is ready or another Route holds the address. Run `oc -n ai-threatgen get route api` (`HostAlreadyClaimed` in it: delete the old Route, Part 2, step 9) and `oc -n ai-threatgen get pods` (a pod not `1/1 Running`: Part 5).

### Step 15. Check Grafana

**Do:** first check that Grafana and Flower answer on the API's address:

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/grafana/api/health
curl.exe -sk -o NUL -w "%{http_code}\n" https://threatgen-api.apps.dda-desc-az1-01.desccii.local/flower/
```

**You should see:** first an answer with `"database": "ok"` (Grafana), then `200` (Flower).

**If not** (`Not Found`, `Application is not available`, `502` or `504`): Part 3, step 4.

Then do Part 3, steps 1 and 2 (below), and come back here for step 16.

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

(Before **Do**:) First ask the owner which systems need a key (e.g. `shield-frontend`). Do this step once for each system, with its name in place of `<system name>`.

**You should see:** an answer with `"api_key":"..."`. **Copy that value now**: it is shown only once. Give it to that system's team.

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

**If `status` is `done` but the answer has `index_error`:** the data was imported but not indexed, and runs are refused (`intel_no_data`). Its `message` says why (often the AI embedding key). Fix that and run the first line again.

**Last check:**

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/health
```

**You should see:** `"snapshot_id":"..."` with a value, not `"snapshot_id":null`.

The deployment is finished.

---

## Part 3. Open Grafana

Grafana shows whether TSG is working: jobs, queues, AI calls, errors and logs. **Looking needs no login.** That is
the owner's decision, and it means that anyone who can reach the API's address can read every log line and metric
through Grafana's query API (`/grafana/api/ds/query`), not only this dashboard.

### Step 1. Open the address

On the same PC (it must be on the network that reaches the cluster), open this address in Chrome or Edge. It is the
API's own address, with `/grafana/` at the end:

**https://threatgen-api.apps.dda-desc-az1-01.desccii.local/grafana/**

Type it exactly, with `/grafana/` at the end. Without it you get the API's own short answer, with `Not Found` in it.

**You should see:** the TSG dashboard, with no login page: a panel **How to use this page** at the top, then
**Is everything working?** with the **Overall** tile. (The top bar shows **Home** or "TSG — is everything
working?": both are right.) Bookmark the page.

**If the browser warns about the certificate** ("Your connection is not private"): it is the cluster's own
certificate. Click **Advanced**, then **Proceed to threatgen-api... (unsafe)** in Chrome or **Continue to
threatgen-api... (unsafe)** in Edge. Or ask the cluster admin for the CA certificate to install.

**If the page does not open, or shows "Application is not available", `502 Bad Gateway` or `504 Gateway Time-out`:**
go to step 4 below.

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

**You should see:** `secret/tsg-monitoring configured` (the other secrets `unchanged`), then `deployment.apps/grafana restarted`. Grafana is down for about a minute. When `oc -n ai-common get pods -l app=grafana` shows `1/1` and `Running`, sign in with the new password. Grafana takes the password from the secret each time it starts.

The TSG dashboard cannot be changed in the browser. To change it, edit `observability\grafana\dashboards\tsg.json`
and its copy in `deploy\configmap.yaml` in git, apply `configmap.yaml` (Part 2, step 8), then
`oc -n ai-common rollout restart deployment/grafana`.

### Step 4. If the address does not open

The way in: your browser → the Route `grafana` (in ai-threatgen, on the API's address) → the monitoring proxy pod
(nginx, in ai-threatgen) → Grafana's pod in ai-common. Check each in turn.

**Do** (in PowerShell, logged in as in Part 2, step 1):

```powershell
oc -n ai-threatgen get route grafana flower
oc -n ai-threatgen get pods -l app=monitoring-proxy
oc -n ai-common get pods -l app=grafana
```

**You should see:** the two Routes with host `threatgen-api.apps.dda-desc-az1-01.desccii.local` and paths
`/grafana` and `/flower`, then the proxy pod and the Grafana pod, each `Running` with `1/1`.

- **`Unauthorized`:** log in again (Part 2, step 1).
- **`NotFound`** for a Route: it is not deployed. Do Part 2, step 13.
- **`HostAlreadyClaimed`** in a Route: an old Route holds that address and path. Find it (Part 2, step 9, the last
  command) and delete it. Keep `api`, `grafana` and `flower` in ai-threatgen.
- **The proxy pod is not `Running`, or `No resources found` for it:** run
  `oc -n ai-threatgen get deployment monitoring-proxy`. `NotFound`: do Part 2, step 13. Otherwise the last lines
  (Events) of `oc -n ai-threatgen describe pod -l app=monitoring-proxy` say why (with no pod:
  `oc -n ai-threatgen get events --sort-by=.lastTimestamp | Select-Object -Last 20`):
  - `ImagePullBackOff`: the cluster cannot get the nginx image from Quay. See Part 5, `ImagePullBackOff`.
  - `exceeded quota`: ai-threatgen's quota is full, often only while other pods there stop: wait up to 6 minutes.
    Still failing: apply `deploy\deploy_threatgen.yaml` (Part 2, step 12). Its beat has a smaller CPU limit, which
    makes room for the proxy and for the API's extra pod during an update. The proxy then starts by itself.
  - `CrashLoopBackOff`: `oc -n ai-threatgen logs deployment/monitoring-proxy --previous` shows why. With
    `host not found in upstream`, Grafana's or Flower's Service is missing in ai-common: do Part 2, step 13.
- **The page shows `502 Bad Gateway`:** the proxy runs but Grafana does not answer. Check the Grafana pod (the
  bullets below). If it is `Running` with `1/1`, the proxy kept an old address of Grafana (it looks it up only when
  it starts, and Grafana's Service was deleted and created again). Restart the proxy:
  `oc -n ai-threatgen rollout restart deployment/monitoring-proxy`.
- **The page shows `504 Gateway Time-out` (after about 5 seconds):** a network rule blocks the proxy
  (`oc -n ai-threatgen logs deployment/monitoring-proxy` shows `upstream timed out` and `while connecting`). Apply
  both rule files again: `oc apply -f deploy\networkpolicy_threatgen.yaml` and `oc apply -f deploy\deploy_common.yaml`.
  Still `504`: the proxy may hold Grafana's old address. Restart it:
  `oc -n ai-threatgen rollout restart deployment/monitoring-proxy`.
- **The Grafana pod is `Running` with `0/1`, or `Init:0/1`, `PodInitializing` or `ContainerCreating`:** it is still starting. Wait 2 minutes and look again.
- **`No resources found` for the Grafana pod** (the Route is there): OpenShift could not create the pod, usually because ai-common's quota (shared with the chatbot) is full. `oc -n ai-common get events --sort-by=.lastTimestamp | Select-Object -Last 20` says why (`exceeded quota`: see Part 5).
- **The Grafana pod is `Pending`, `ImagePullBackOff` or `CreateContainerConfigError`:** the last lines (Events) of
  `oc -n ai-common describe pod -l app=grafana` say why. Then see Part 5.
- **The Grafana pod is `Init:Error` or `Init:CrashLoopBackOff`:** `oc -n ai-common logs deployment/grafana -c set-admin-password`
  shows why.
- **The Grafana pod is `CrashLoopBackOff` or `Error`:** `oc -n ai-common logs deployment/grafana` shows why.
- **All look fine but the page still does not open:** check the API's address first (Part 2, step 14). If the API
  answers but Grafana does not, open Grafana through `oc` instead. Run this and keep the window open (Ctrl+C
  stops it):

  ```powershell
  oc -n ai-common port-forward deployment/grafana 3001:3000
  ```

  **You should see:** `Forwarding from 127.0.0.1:3001 -> 3000`. Then open **http://localhost:3001/grafana/** on the
  same PC.

### Other monitoring pages

Only Grafana and Flower are on the API's address (the owner's choice). Prometheus and Alertmanager have no public
address: open them through `oc`. Run the `oc` line, keep that window open while you use the page (Ctrl+C stops
it), and open the address on the same PC.

| Page | How to open it | Use it to |
|---|---|---|
| Flower | https://threatgen-api.apps.dda-desc-az1-01.desccii.local/flower/ | watch the Celery workers and their tasks live |
| Prometheus | `oc -n ai-common port-forward deployment/prometheus 9090:9090`, then http://localhost:9090/prometheus/ | see raw metrics; alert rules under **Alerts** |
| Alertmanager | `oc -n ai-common port-forward deployment/alertmanager 9093:9093`, then http://localhost:9093/alertmanager/ | see firing alerts; silence one during planned work (a silence is lost when the pod restarts) |

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

**If any file in `scripts\sql` changed** since the release that runs now, the DBA installs the changed
`tsg_*.sql` files and `grants.sql` first, as in Part 1. Wait for their OK before step 7. The running pods keep
working meanwhile: a changed procedure keeps its name, and a new one is only called by the new release.

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

Most releases keep the monitoring versions, so most images are in Quay already. The second line tries each image by
name and builds only the missing ones. The last line checks the monitoring proxy's config
(`observability\nginx\nginx.conf`) in the nginx image, also when that image is in Quay already, and pushes nothing.

**Do:**

```powershell
$names = Select-String -Path deploy\deploy_common.yaml -Pattern '^\s*image: \S+/dda-desc/([\w.-]+):' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Where-Object { $_ -ne 'tsg-api' } | Select-Object -Unique
foreach ($n in $names) { deploy\build-monitoring-images.bat $n }
deploy\build-monitoring-images.bat nginx --no-push
```

**You should see:** for each image, `Built, checked and pushed to Quay:` or `ERROR: ... is already in Quay`. Here that
ERROR is fine: that version was built before (Part 2, step 3 says how to check it is the UBI 9 build). Last,
`Built and checked, not pushed:` with the nginx image.

**Then check that the cluster can pull every image:** Part 2, step 6, the lines after "Then check". Every line must
start with `OK` before step 5.

**If kube-state-metrics fails with `did NOT match`:** its new version needs a new `SRC_SHA256` in
`deploy\images\kube-state-metrics\Dockerfile`. Ask the developer.

**If another `ERROR` is printed:** Part 2, step 3 says what it means.

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
oc -n ai-threatgen rollout restart deployment -l app=monitoring-proxy
oc -n ai-threatgen get deployment -l app=monitoring-proxy -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

**You should see:** `configured` or `unchanged` for each secret and setting, then 9 lines ending with
`successfully rolled out`: 8 in ai-common, then the monitoring proxy. Before the proxy is first deployed (step 7
creates it), its two lines print `No resources found` instead: that is fine.

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

**First, only once: remove what an older TSG version left in ai-common.** Its monitoring there has other selectors,
which `oc apply` cannot change (`field is immutable`), and its Routes use the old address. List it:

```powershell
oc -n ai-common get deployment -l app.kubernetes.io/part-of=tsg-observability
```

**You should see:** `No resources found`, or some of `prometheus`, `alertmanager`, `loki`, `alloy`, `grafana`,
`redis-exporter`, `kube-state-metrics` and `flower`. That label is TSG's older one, not the chatbot's. **If another
name is listed:** do not delete anything; ask the developer first. Otherwise delete them with their Routes. The line
deletes by label, because ai-common is shared with the chatbot. The volumes stay, and `No resources found` is fine:

```powershell
oc -n ai-common delete deployment,route -l app.kubernetes.io/part-of=tsg-observability
```

**Then do** (every release):

```powershell
oc apply -f deploy\deploy_remediation.yaml
oc -n ai-remediation get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-remediation rollout status $_ --timeout=10m }
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
oc apply -f deploy\networkpolicy_threatgen.yaml
oc -n ai-common delete route -l part-of=tsg-monitoring
oc -n ai-common delete networkpolicy monitoring-from-router --ignore-not-found
oc apply -f deploy\deploy_common.yaml
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
oc -n ai-threatgen rollout status deployment/monitoring-proxy --timeout=10m
```

**You should see:** after each `deploy_*.yaml` file, one `successfully rolled out` line per Deployment: 7, then 9,
then 9 (8 in ai-common, then the monitoring proxy). The network rules print `created`, `configured` or
`unchanged`. The two `delete` lines print `deleted` for the previous release's Routes on `threatgen-grafana` and its
rule `monitoring-from-router` in ai-common, or `No resources found` and nothing once they are gone (a rollback brings
them back): Grafana and Flower now have their Routes in ai-threatgen, through the monitoring proxy.

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
| `ImagePullBackOff` or `ErrImagePull` (Grafana: `Init:ImagePullBackOff`) | The events say why: find their message in the next three rows. Any other `Failed to pull image` message (`x509`, `i/o timeout`, `no such host`): the node cannot reach Quay; send the message to the cluster admin. |
| `Unable to retrieve some image pull secrets (quay-pull)` | That project has no `quay-pull`: Part 2, step 6. (Another pod running from the same image proves nothing: a node can start it from its own copy.) |
| `unauthorized` in a `Failed to pull image` event | The cluster's Quay login may not read that image, or the image was never pushed: Quay answers the same for both. Run the check in Part 2, step 6 (the lines after "Then check"): its table says which, and what to do. The pods try again by themselves within 5 minutes. |
| `manifest unknown` in a `Failed to pull image` event | That tag is not in Quay. A monitoring image: Part 2, step 3, by name. `tsg-api`: Part 2, steps 4 and 5. |
| `exceeded quota` | Wait up to 6 minutes (old pods still stopping). Still failing: `oc -n <project> describe quota`, and Part 2, step 2. |
| `insufficient quota to match these scopes` | The cluster lets a pod's spreading rule look at another project only under a special quota: Part 2, step 2. |
| `CreateContainerConfigError` | A secret or setting is missing: Part 2, steps 7 and 8. |
| `field is immutable` | An older Deployment with the same name is still there. In `ai-threatgen` or `ai-remediation`: Part 2, step 9. In `ai-common` (the chatbot runs there too): run `oc -n ai-common get deployment <name> --show-labels`. If it shows `part-of=tsg-monitoring`, `part-of=tsg` or `app.kubernetes.io/part-of=tsg-observability` (TSG's older label), it is TSG's: run `oc -n ai-common delete deployment <name>` and apply again (the end of Part 2, step 9 removes all the older ones at once). Otherwise it is not TSG's: do not delete it, ask its owner (the chatbot team). |
| `Pending` | The last lines (Events) of `oc -n <project> describe pod <name>` say why. `unbound ... PersistentVolumeClaims`: run `oc -n <project> get pvc`. A claim that is `Pending` with an empty `STORAGECLASS` means the cluster has no default storage class: ask the cluster admin which one to use (the other claims there show one) and tell the developer, who names it in `deploy\deploy_common.yaml`. With that new file, delete the `Pending` claim (it holds no data yet: `oc -n <project> delete pvc <name>`) and apply again. Otherwise ask the cluster admin for storage. |
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
oc -n ai-threatgen rollout restart deployment -l app=monitoring-proxy
oc -n ai-threatgen get deployment -l app=monitoring-proxy -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

### Roll back to the previous release

Use the previous release's code folder (the one you kept in Part 4): `cd <previous code folder>`. Then, in this
order:

1. Remove the monitoring proxy and its two Routes from ai-threatgen, and worker-reaper from both projects.
   `oc apply` of the previous files never deletes them, and the previous release's pods need their room in
   ai-threatgen's quota: with the proxy still there, the API's update pod does not fit and the API never rolls
   back. The previous release has no reaper worker (its worker-maintenance does that work), and worker-reaper's
   100m would also push the API's update pod past the quota. Grafana and Flower are off the API's address from
   here on.

   ```powershell
   oc -n ai-threatgen delete deployment,service,route -l part-of=tsg-monitoring
   oc -n ai-threatgen delete deployment worker-reaper --ignore-not-found
   oc -n ai-remediation delete deployment worker-reaper --ignore-not-found
   ```

   **You should see:** `deleted` for `deployment.apps/monitoring-proxy`, `service/monitoring-proxy`,
   `route.route.openshift.io/grafana` and `route.route.openshift.io/flower`, then `deployment.apps "worker-reaper"
   deleted` twice. The API's own Route `api` stays.

2. Apply the previous settings, `deploy_remediation.yaml` and `deploy_threatgen.yaml`:

   ```powershell
   oc apply -f deploy\configmap.yaml
   oc apply -f deploy\deploy_remediation.yaml
   oc -n ai-remediation get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-remediation rollout status $_ --timeout=10m }
   oc apply -f deploy\deploy_threatgen.yaml
   oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
   ```

   **You should see:** `configured` or `unchanged` for each setting, then 6, then 8 lines ending with
   `successfully rolled out`.

3. Last, apply the previous `deploy_common.yaml` and restart the monitoring, so it loads the previous alert rules
   and dashboard:

   ```powershell
   oc apply -f deploy\deploy_common.yaml
   oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring
   oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
   ```

   **You should see:** 8 lines ending with `successfully rolled out`. Grafana is then at the previous release's
   address (its guide's Part 3).

---

## Part 6. How TSG is laid out, and why

Read this once to understand the setup. You do not need it to deploy.

### Three projects

| Project | What runs there | Why |
|---|---|---|
| `ai-threatgen` | The API (2 pods), beat (the scheduler, 1 pod), the monitoring proxy (1 pod: Grafana and Flower on the API's address) and one copy of every worker | Users and other systems call the API here. |
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
6. **worker-maintenance** (`tsg_maintenance`) rebuilds the library indexes and imports the outside intelligence
   (jobs that can run for an hour).
7. **worker-reaper** (`tsg_reaper`) repairs stuck jobs every minute and retries failed control mapping, on a queue
   of its own: a long maintenance job never holds the thread a reaper pass needs.

Because every kind of work has its own worker, a long remediation plan never waits behind scenario writing, and
control mapping never waits behind a busy writer. A run's next step also goes ahead of new runs in its queue.

| Pod (in both projects unless noted) | Queue | Jobs at once | CPU request / limit | Memory request / limit |
|---|---|---|---|---|
| worker-threats | `tsg_threats` | 2 | 500m / 1 | 1Gi / 1.5Gi |
| worker-scenarios | `tsg_scenarios` | 2 | 500m / 1 | 1Gi / 2Gi |
| worker-controls | `tsg_controls` | 1 (maps 6 scenarios at once) | 100m / 250m | 640Mi / 1Gi |
| worker-remediation | `tsg_remediation` | 2 | 250m / 500m | 640Mi / 1Gi |
| worker-service-mapper | `tsg_servicemapper` | 2 | 250m / 500m | 640Mi / 1Gi |
| worker-maintenance | `tsg_maintenance` | 3 | 100m / 150m | 768Mi / 1.5Gi |
| worker-reaper | `tsg_reaper` | 2 | 50m / 100m | 320Mi / 384Mi |
| api (ai-threatgen only, 2 pods) | - | - | 250m / 750m | 512Mi / 1Gi |
| beat (ai-threatgen only, 1 pod) | - | - | 50m / 200m | 320Mi / 512Mi |
| monitoring-proxy (ai-threatgen only, 1 pod: Grafana and Flower on the API's address) | - | - | 50m / 50m | 64Mi / 64Mi |

Totals (limits): ai-threatgen 5.25 CPU and 10.94 Gi (6.0 CPU and 11.94 Gi while an API update runs, because
its new pod starts before an old one stops); ai-remediation 3.5 CPU and 8.38 Gi.

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
| `CII_MAX_CONCURRENT_AI_CALLS` | 0 | 0 = no fixed limit on AI calls at once: TSG runs at full speed and backs off by itself only after the gateway answers 429 (see below). A number above 0 is a fixed ceiling for all pods together |

**How TSG backs off after a 429.** When the gateway answers 429 ("too many"), TSG sets one limit for all pods and all
4 models: half the calls in flight at that moment. Each answered call raises it a little, and a few minutes after the
last 429 it disappears: TSG is back to no limit. The Grafana gauge **AI capacity in use** shows the calls in flight
out of that limit (`tsg_ai_slots_cap` is the limit, 0 = none; `tsg_ai_slots_in_use` counts the calls in flight, also
at no limit): **No limit set** is the normal state.

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
