# Deploy TSG to OpenShift

## Start here

| You want to | Follow |
|---|---|
| Put a new version on UAT (TSG runs there already: the usual case) | **Part 4**, which starts with a checklist |
| Deploy TSG where it has never run | Parts 1, 2 and 3, in order |
| Fix a step that failed | Part 5 |
| Understand the setup (not needed to deploy) | `docs/CONCURRENT_USERS_SIZING.md` and the comments in the `deploy\*.yaml` files |

Not sure whether TSG runs there already? After you log in (Part 2, step 1), run
`oc -n ai-common get deployment -l part-of=tsg-monitoring`: `No resources found` means the first time; a list (8
when all runs, fewer if an earlier deployment stopped half way) means Part 4.

Each step says what to **do**, what **you should see** when all is well, and what to do **if not**. Replace
`<...>` with your value.

Run every command in **PowerShell**, in the code folder: the folder that holds `pyproject.toml`. From a GitHub ZIP it is named `cii-<branch>` (e.g. `cii-master`; a `/` in the branch name becomes `-`), and Windows' **Extract All** often puts it one folder deeper (e.g. `C:\work\cii-master\cii-master`). From git it is `cii`. Open PowerShell and go there first, e.g.:

```powershell
cd C:\work\cii-main
Test-Path pyproject.toml
```

**You should see:** `True`. **If `False`:** run `Get-ChildItem C:\work -Recurse -Filter pyproject.toml | Select-Object -First 1 DirectoryName` and `cd` to the folder it prints, then run `Test-Path pyproject.toml` again. In every new PowerShell window, run the `cd` line again.

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
- [ ] An OpenShift user with **admin** rights in `ai-threatgen` and `ai-common` (the monitoring creates roles in
      them). Ask the cluster admin.
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
  - the SQL Server, MongoDB and Redis user names and passwords (ask the owner). Redis: one login for all of TSG,
    with TLS on ("The Redis owner's part" below);
  - the AI gateway key (ask the AI gateway admin; the same key goes in each module's own
    `CII_SCENARIO_CHAT_API_KEY`, `CII_REMEDIATION_CHAT_API_KEY`, `CII_SERVICE_MAPPER_CHAT_API_KEY`, and in
    `CII_EMBEDDING_API_KEY` and `CII_RERANK_API_KEY`, unless a module gets a key of its own);
  - an admin key (32 or more characters) and a Grafana password (16 or more characters): you make them up in step 7.
- [ ] The platform UI's https address: `deploy\configmap.yaml` already holds UAT's (`CII_CORS_ORIGINS`). Ask the
      platform UI team only if it changed (step 8).
- [ ] Optional: where alert emails go (step 8). Without it, alerts show only in Grafana. Either the company mail relay (its `host:port`, a sender address, its
      login and password; ask the mail team) or a Gmail account (its address and a Google app password: the
      account needs 2-Step Verification on, then Google account, Security, App passwords). And the recipients.
      Mail does not go through the proxy: ask the network team to let `ai-common` reach the relay, or
      `smtp.gmail.com` port 587, directly.
- [ ] MongoDB (ask the DBA): TSG writes with write concern `majority` and waits at most 10 s for it. For
      failover, MongoDB must be a replica set of at least 3 data-bearing members; `CII_MONGO_URL` (step 7)
      then lists every member, with `replicaSet=<name>` and without `directConnection=true`, and each member's
      address must be open in the MongoDB rules of `deploy\networkpolicy_threatgen.yaml` and of
      `tsg-app-egress` in `deploy\deploy_common.yaml` (tell the developer). A set with an arbiter (two data
      members) works, but while a data member is down every write fails after 10 s (the API answers 503, jobs
      retry). A single server works too, with no failover. After step 14, `/ready` shows what TSG reached
      under `mongodb` (replica set, default write concern).
- [ ] TSG's stored procedures installed by the DBA in the TSG SQL Server database: every
      `scripts\sql\tsg_*.sql` file of this release (never a file with `copy` in its name), then
      `scripts\sql\grants.sql`. Give the DBA the files from your code folder and wait for their OK. Without them
      the app cannot read its library, and the service mapper cannot read its catalog ("Could not find stored
      procedure").

**The Redis owner's part.** TSG logs in to Redis with one user name and password, shared by all its parts (the
API, the workers, beat, Flower and redis-exporter). Tell the Redis owner:

- If that user has ACL rules: it reads and writes TSG's keys (all start with `tsg:`) in databases 0 and 1, runs
  TSG's Lua scripts and `INFO`, and needs **every channel** (`allchannels`): Celery subscribes to channel
  patterns, and Redis compares a pattern letter for letter with the user's channel rules, so `&tsg:*` refuses it
  and the workers stop.
- **TLS** (the URLs are `rediss://`): every TSG pod checks Redis' certificate, and that the certificate names the
  address in the URLs. Ask that it names `10.228.146.4` (an IP address entry). If it names only a host name, write
  that name in place of `10.228.146.4` in every Redis URL (step 7). TLS on another port than 6379: tell the
  developer (the network rules open 6379 only). A certificate from the company's own CA: give the CA file to the
  developer, who mounts it and points `CII_REDIS_CA_FILE` (configmap.yaml) and redis-exporter's
  `REDIS_EXPORTER_TLS_CA_CERT_FILE` at it (the deploy files mount none today). No TLS yet: step 7 says what to write.
- Redis' `maxmemory-policy` must be `noeviction`: any other policy drops keys (a queue, the AI limits) when Redis
  is full. The API and the workers log it at start-up, as an error when it is not.

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
oc auth can-i create rolebindings -n ai-common
```

**You should see:** `Logged into "https://..." as "<you>" using the token provided.` from the `oc login` line, then
`Login Succeeded`, then `yes` twice.

**If not:**
- `Use insecure connections? (y/n)`: the cluster uses its own certificate. Type `y`.
- `no`: ask the cluster admin for admin rights in that project.
- `error during connect`: Docker Desktop is not started. Start it and wait for **Engine running**.
- `x509: certificate signed by unknown authority`: Docker does not trust Quay's certificate. Ask the cluster admin.

The login lasts about a day. If an `oc` command later says `Unauthorized`, do this step again.

### Step 2. Check the projects' quotas

**Do:** check ai-threatgen, where the app runs (6 CPU, 12 Gi memory, 60 Gi storage):

```powershell
oc -n ai-threatgen describe quota
```

**You should see:** each quota with a `Used` and a `Hard` column. `limits.cpu` and `limits.memory` must have a Hard of
at least `5.5` and `10.6Gi` (6 CPU and 12 GB or 12Gi both fit): TSG's pods there need 5.5 CPU and 10.56 Gi, and
an update never adds a pod (the header of `deploy\deploy_threatgen.yaml`). TSG's own pods are part of `Used`: they are replaced, not added. Anything else
in `Used` (v1's pods) takes from the same quota.

**If Hard is lower:** send the cluster admin those quota lines and wait for more room before step 12.

**Then check ai-common**, where the monitoring runs (its quota is shared with the chatbot):

```powershell
oc -n ai-common describe quota
oc -n ai-common describe appliedclusterresourcequota
oc -n ai-common get limitrange
```

**You should see:** each quota with a `Used` and a `Hard` column (or `No resources found`), then `No resources found`
for the limit range. For `limits.cpu`, `limits.memory` and `requests.storage`, Hard minus Used must leave at least
2.95 CPU, 5.9Gi and 22Gi for TSG's monitoring and its reaper worker (the `Budget:` lines at the top of
`deploy\deploy_common.yaml`). What TSG
already has there is part of these numbers, not extra, so add it back first: its pods are replaced, and its claims
`prometheus-data`, `loki-data`, `grafana-data` and `alloy-data` (`oc -n ai-common get pvc` shows them) are used again.

**If there is less room:** send the cluster admin those quota lines and these three numbers, and wait for more room
(or for the chatbot team to free some) before step 12.

**If a limit range is listed:** send the developer what `oc -n ai-common get limitrange -o yaml` prints. Its limits
can refuse TSG's pods there (steps 12 and 13 then show `maximum`, `minimum` or `max limit to request ratio` in the
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
foreach ($f in 'deploy_threatgen.yaml', 'deploy_common.yaml') { $p = Join-Path $PWD "deploy\$f"; [IO.File]::WriteAllText($p, [IO.File]::ReadAllText($p).Replace("tsg-api:$old", "tsg-api:$new")) }
Select-String -Path deploy\deploy_*.yaml -Pattern 'tsg-api:'
```

**You should see:** 10 lines (8 from `deploy_threatgen.yaml`, 2 from `deploy_common.yaml`: Flower and the reaper
worker), each with `tsg-api:<your tag>` and then a `#` note.

**If a line shows another tag:** open that file in Notepad and change the tag on that line by hand.

### Step 6. Copy the image login to ai-common

The pods need the Quay login (`quay-pull`) in both projects. It already exists in `ai-threatgen`.

**Do:**

```powershell
oc -n ai-threatgen extract secret/quay-pull --keys=.dockerconfigjson "--to=$env:TEMP" --confirm
oc -n ai-common create secret generic quay-pull --type=kubernetes.io/dockerconfigjson "--from-file=.dockerconfigjson=$env:TEMP\.dockerconfigjson"
Remove-Item "$env:TEMP\.dockerconfigjson"
```

**You should see:** first the file it wrote (e.g. `C:\Users\<you>\AppData\Local\Temp\.dockerconfigjson`), then `secret/quay-pull created`.

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
The file holds two Secrets: `tsg-secrets` (the database and Redis logins and the keys, written once for both
projects) and `tsg-monitoring` (Grafana's password and the alert email passwords).
- In the connection strings (`CII_DB_DSN`, `CII_MONGO_URL`, `CII_REDIS_URL`, `CII_REDIS_CELERY_BROKER_URL`), a user
  name or password with a special character (`@ : / ? # % &`) must be URL-encoded. Run this, type the password,
  and paste what it prints: `[uri]::EscapeDataString((Read-Host 'Password'))`
- Redis with a password but no user name: delete `CHANGE_ME_USER` and keep the `:`, e.g.
  `rediss://:<password>@10.228.146.4:6379/0` (in both Redis lines). Keep `rediss://` (TLS); only while the Redis
  owner has not turned TLS on, write `redis://` instead, in both lines.
- The admin key and the Grafana password are yours to make up. This makes one (64 characters):
  `-join (1..2 | ForEach-Object { [guid]::NewGuid().ToString('N') })`
- **Keep the Grafana password**: you need it to sign in to Grafana.
- Alert email (step 8 picks the sender): `SMTP_RELAY_PASSWORD` is the company mail relay's password,
  `GMAIL_APP_PASSWORD` a Google app password (Google account, Security, App passwords; it needs 2-Step
  Verification on), never the Gmail account's own password. For a sender you do not use (both, when you send
  no alert email), delete `CHANGE_ME` so the line reads `""`. Keep both lines: Alertmanager does not start while either is missing.

Then:

```powershell
Select-String -Path deploy\secrets.yaml -CaseSensitive -Pattern '^[^#]*(CHANGE_ME|_USER:|_PASSWORD@|_OR_MORE_CHARACTERS|ai-remediation)'
oc apply -f deploy\secrets.yaml
```

**You should see:** the first line prints nothing, then `secret/... created` (or `configured`) for each secret.

**If the first line prints something:** that line still has a `CHANGE_ME` word, or the end of one (e.g. `_USER`).
Replace the whole word and run the two lines again. A line with `namespace: ai-remediation` comes from an earlier
release's `secrets.yaml` (TSG no longer runs there): delete that Secret's 8 lines, from the `- apiVersion: v1` above
it to the `stringData: *secrets` below it, save, and run the two lines again.

Keep `deploy\secrets.yaml` private. It is never committed to git.

### Step 8. Apply the settings

**Do:**

```powershell
notepad deploy\configmap.yaml
```

`CII_CORS_ORIGINS` already holds UAT's UI address, `https://threatgen-api.apps.dda-desc-az1-01.desccii.local`.
Change it only if the platform UI's address changes: https, the host name (and `:port` if it has one), no path
and no `/` at the end. The app compares it letter for letter with the browser's address. Several addresses:
separate them with commas. Never `*`: any web site could then call the API from a browser (the app refuses it
only when `CII_ENV` is `prod`; UAT's is `uat`).

Alert email (optional): leave the `CHANGE_ME_` words in `observability\alertmanager\alertmanager.yml` as they are,
and no email is sent; alerts still show in Grafana and at `/alertmanager`, and Alertmanager logs a failed send for
each. To send email (`notepad observability\alertmanager\alertmanager.yml`): the line `receiver:` under `route:`
picks the sender, `company-smtp`
(the company mail relay) or `gmail`. In that sender's lines, replace each `CHANGE_ME_` word: the relay's
`host:port` (company-smtp only), the sender address and login, and the recipients (comma-separated). A
relay that does not offer STARTTLS needs the line `require_tls: false` added under its `smarthost:` line.

If you set up email, check that one really arrives (after step 13, once Alertmanager runs). Send a test alert:

```text
oc -n ai-common exec deploy/alertmanager -- amtool --alertmanager.url=http://localhost:9093/alertmanager alert add TsgTestAlert severity=warning --annotation=summary="Test: TSG alert email works"
```

**You should see:** the email within a few minutes. None: read `oc -n ai-common logs deploy/alertmanager` for the
failed send (the relay's address, login or the network rule to it).
Mail does not go through the proxy: the relay, or `smtp.gmail.com` port 587, must be reachable from `ai-common` (Part 1).
Save and close Notepad, then:

```powershell
Select-String -Path deploy\configmap.yaml -Pattern 'CII_CORS_ORIGINS:'
oc apply -f deploy\configmap.yaml
oc apply -k observability
```

**You should see:** first one line with `CII_CORS_ORIGINS: "https://threatgen-api.apps.dda-desc-az1-01.desccii.local"`
(or the UI address you set), then `configmap/... created` (or `configured`) for `tsg-config` and for each of the
8 monitoring ConfigMaps, which `oc apply -k observability` makes from the files in `observability/`.

**If that line still has `CHANGE_ME`, a path or a `/` at the end:** fix it in Notepad and run the two lines again.

### Step 10. Apply the network rules

**Do:**

```powershell
oc apply -f deploy\networkpolicy_threatgen.yaml
```

**You should see:** `networkpolicy.networking.k8s.io/... created` (or `configured`) for each rule.

### Step 12. Start the reaper worker in ai-common, then the API, the workers and beat in ai-threatgen

**Do:**

```powershell
oc apply -f deploy\deploy_common.yaml -l part-of=tsg
oc -n ai-common rollout status deployment/worker-reaper --timeout=10m
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

**You should see:** `deployment.apps/worker-reaper created` (with its two network rules, `tsg-app-ingress` and
`tsg-app-egress`, and nothing else from that file yet) and its `successfully rolled out`, then 8 lines ending with
`successfully rolled out` (the API, 6 workers, beat). The reaper worker comes first: it hands back the jobs a
stopped worker held. The API is ready once MongoDB answers. This can take up to
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

**If the second answer starts with `{"status":"not_ready"`:** the API cannot reach MongoDB (`"mongo":false`); the
other stores and the workers are only reported. Wait a minute and try again; still `not_ready`: Part 5.

**If nothing is printed:** this PC cannot reach the API's address. Ask the network team.

**If it prints an HTML page with `Application is not available`:** the address works, but no API pod is ready or another Route holds the address. Run `oc -n ai-threatgen get route api` (`HostAlreadyClaimed` in it: delete the old Route, Part 3, step 4) and `oc -n ai-threatgen get pods` (a pod not `1/1 Running`: Part 5).

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

The page **TSG — AI usage** opens from the link in the home page's **AI usage** row.

**Alert email:** each alert that fires is emailed to the recipients of step 8 (and again when it clears). When
one fires and no email comes, run `oc -n ai-common logs deployment/alertmanager`: it shows why the send failed
(a wrong login, or the relay or `smtp.gmail.com` not reachable from `ai-common`).

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
imports by itself: once at beat's first check, about a minute after its first start, then on the saved schedule, weekly on Sunday
02:00 UTC until changed with `PUT /v1/tsg/intel/schedule` or on the admin page's Schedule page). Use the `job_id`
under `details` in that answer. The sources are MITRE ATT&CK Enterprise and ICS, and no other.

**Then:** put the `job_id` in this line. Run it every minute or two until `status` is `done` (it goes `queued`,
then `running`, then `done`):

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh/<job_id>
```

**If `status` is `failed`:** its `error` says why. When it names feeds that could not be imported, the other
feeds' data was imported; `GET /v1/tsg/intel/health` (the last check below) says why each named feed failed.
Fix that and run the first line again.

**If `status` is `done` but the answer has `index_error`:** the data was imported but not indexed, and runs are refused (`intel_no_data`). Its `message` says why (often the AI embedding key). Fix that and run the first line again.

**Last check:**

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/health
```

**You should see:** `"snapshot_id":"..."` with a value, not `"snapshot_id":null`.

**Then the control links.** Right after every import TSG links each MITRE ATT&CK mitigation to controls of the
control library, by itself, on `worker-maintenance` (no extra pod). The first time this is about 100 AI calls (an
estimate: one per mitigation), once; a later run asks the AI only for a mitigation that changed. Watch it:

```powershell
curl.exe -sk https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/control-links
```

**You should see:** `"not_prepared"` go down to `0` over the next minutes, and `"prepared_at"` with a time.
`POST /v1/create_session` works before that (its controls are then found by meaning alone), but it answers 409
`intel_no_data` until the import above is done.

**If `not_prepared` stays above 0:** the judging of those mitigations failed (often the AI was busy); their
earlier links, if any, are kept. Run it again by hand; it only asks for the ones still missing:

```powershell
curl.exe -sk -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/control-links/prepare
```

**The admin page.** The API pods also serve a web page for these tasks at
`https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ui/`: import now, the schedule, the control links, jobs,
search vectors, API keys, library curation, AI usage and system state. There is nothing more to deploy: no pod,
Route, Service or network rule of its own (the API's Route already serves every path). The pages Jobs, Search
vectors, API keys and Library curation ask for the admin key (`CII_ADMIN_API_KEY`): type it in the bar at the top.
It stays in that browser tab's memory only and is gone on reload. The page has no login of its own: whoever can
reach the API's address can open it and change the switch and the schedule, as they can call those routes today.

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
| **TSG — AI usage** (its own dashboard: the link in the home page's **AI usage** row) | AI calls by module, API call and part of the work; failed ones by reason; by activity and model; tokens; whether the tracking works; links to one session's or request's report. Counts only: the exact numbers come from `GET /v1/ai-usage` |

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

The dashboards cannot be changed in the browser. To change one, edit its file in `observability\grafana\dashboards`
(`tsg.json` or `ai_usage.json`) in git, run `oc apply -k observability`, then
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
- **`HostAlreadyClaimed`** in a Route: an old Route holds that address and path. Find it with
  `oc -n ai-threatgen get route | findstr threatgen` and delete it with `oc -n ai-threatgen delete route <name>`.
  Keep `api`, `grafana` and `flower` in ai-threatgen.
- **The proxy pod is not `Running`, or `No resources found` for it:** run
  `oc -n ai-threatgen get deployment monitoring-proxy`. `NotFound`: do Part 2, step 13. Otherwise the last lines
  (Events) of `oc -n ai-threatgen describe pod -l app=monitoring-proxy` say why (with no pod:
  `oc -n ai-threatgen get events --sort-by=.lastTimestamp | Select-Object -Last 20`):
  - `ImagePullBackOff`: the cluster cannot get the nginx image from Quay. See Part 5, `ImagePullBackOff`.
  - `exceeded quota`: ai-threatgen's quota is full, often only while other pods there stop: wait up to 6 minutes.
    Still failing: apply `deploy\deploy_threatgen.yaml` (Part 2, step 12). Its beat has a smaller CPU limit, which
    makes room for the proxy. The proxy then starts by itself.
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

To see each pod's memory (compare it with the pod's `limits` in `deploy\deploy_threatgen.yaml` or
`deploy\deploy_common.yaml`, and raise the limit if it stays above 80 %):

```powershell
oc adm top pods -n ai-threatgen
oc adm top pods -n ai-common -l part-of=tsg-monitoring
```

---

## Part 4. Next release

Use this for every new version after the first deployment. It takes about an hour, most of it waiting for image
builds and pods. Tick each line as you finish it; the details follow.

- [ ] Before step 1: the DBA has installed changed SQL files; the new code is in a new folder, with your `secrets.yaml`
- [ ] Step 1. Log in
- [ ] Step 2. Build the app image and write down its tag
- [ ] Step 3. Put the tag in the deploy files
- [ ] Step 4. Build any monitoring image that is not in Quay yet; check the cluster can pull every image
- [ ] Step 5. Check, then apply, the secrets and settings
- [ ] Step 6. Roll out, in this order
- [ ] Step 8. Check

### Before step 1: the SQL files and the new code folder

**If any file in `scripts\sql` changed** since the release that runs now, the DBA installs the changed
`tsg_*.sql` files and `grants.sql` first, as in Part 1. Wait for their OK before step 6. The running pods keep
working meanwhile: a changed procedure keeps its name, and a new one is only called by the new release.

**The release with `POST /v1/create_session` changes one SQL file: `scripts\sql\tsg_GetAssetContext.sql`.** It now
also returns the asset's "data handled" (`data_handled`), which both start routes tell the AI as a fact. This step
is the database team's, by hand, on each SQL Server TSG reads (UAT and production): nobody who deploys TSG has
access to the databases, and the app installs nothing there. Send them that one file from the new code folder
(`grants.sql` is unchanged by this feature) and wait for their OK. If it is not installed, nothing fails: every run
works as before, and only that one fact is missing from what the AI is told.

**Get the new code.** Unpack the new release's ZIP into a new folder (with git: a new clone). Keep the old folder:
a rollback needs it. A new folder has no `deploy\secrets.yaml`, so copy yours over:

```powershell
cd <new code folder>
Copy-Item <old code folder>\deploy\secrets.yaml deploy\
Test-Path deploy\secrets.yaml
```

**You should see:** `True`. If you send alert email, set its lines in the new `deploy\configmap.yaml` (and in
`observability\alertmanager\alertmanager.yml`) again: Part 2, step 8 (step 5 below applies it).

### Step 1. Log in

The same as Part 2, step 1.

### Step 2. Build the app image and write down its tag

The same as Part 2, step 4:

```powershell
deploy\build-image.bat
```

### Step 3. Put the tag in the deploy files

The same commands as Part 2, step 5. **You should see:** 10 lines, each with `tsg-api:<your tag>`. When the deploy
files carried that tag already, the commands change nothing and only show it.

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

First check that your `deploy\secrets.yaml` has every Secret and every key of the new
`deploy\secrets.example.yaml`:

```powershell
$mine = Get-Content deploy\secrets.yaml -Raw
Select-String -Path deploy\secrets.example.yaml -Pattern '^\s+name: (tsg-[\w-]+)', '^\s+([A-Z_]+):' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique | Where-Object { $mine -notmatch "\b$_\b" }
```

**You should see:** nothing. Each name printed is missing from your `secrets.yaml`. Fix it, then run the lines
again:
- A `tsg-...` name is a new Secret: copy its whole block (from its `- apiVersion: v1` line to the next one) from
  `secrets.example.yaml` into your `secrets.yaml`, and replace its `CHANGE_ME` words as in Part 2, step 7.
  Without it, every pod that reads it stops with `CreateContainerConfigError`.
- Any other name is a new key: copy its line into the same Secret in your `secrets.yaml`, with the real value.

Names that releases brought:

| The check prints | Do |
|---|---|
| `CII_SCENARIO_CHAT_API_KEY`, `CII_REMEDIATION_CHAT_API_KEY`, `CII_SERVICE_MAPPER_CHAT_API_KEY` (29-Oct-2026) | Add the three lines to `tsg-secrets`, each with the AI gateway key (the value `CII_CHAT_API_KEY` holds). Keep the `CII_CHAT_API_KEY` line for now: this release does not read it, and the previous release needs it if you roll back (Part 5). Go on to step 6 right after this step: the running pods still read the `CII_CHAT_` settings, which this release's `configmap.yaml` no longer has, so one of them that restarts in between does not start. |
| `SMTP_RELAY_PASSWORD`, `GMAIL_APP_PASSWORD` | Add both to `tsg-monitoring`, as in Part 2, step 7: `""` for a sender you do not use (both `""` when you send no email). Alertmanager does not start without both lines. |

Then run the check in Part 2, step 7 (the `Select-String` line before `oc apply`): a `secrets.yaml` from a release
before 28-Oct-2026 still has a Secret for `ai-remediation`, which that step says how to delete.

Redis TLS: once the Redis owner has turned TLS on (Part 1, "The Redis owner's part"), change `redis://` to
`rediss://` in both Redis lines of `tsg-secrets`; until then keep `redis://`.

Then apply both, and restart the monitoring so it loads its new config files: Prometheus its alert rules,
Grafana its dashboards, Alertmanager its senders. Flower is left out: it runs the app image, and the running one
would not start with the new settings; step 6 starts it on the new image, with the app pods.

```powershell
oc apply -f deploy\secrets.yaml
oc apply -f deploy\configmap.yaml
oc apply -k observability
oc -n ai-common rollout restart deployment -l 'part-of=tsg-monitoring,app!=flower'
oc -n ai-common get deployment -l 'part-of=tsg-monitoring,app!=flower' -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
oc -n ai-threatgen rollout restart deployment -l app=monitoring-proxy
oc -n ai-threatgen get deployment -l app=monitoring-proxy -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

**You should see:** `created` (a new Secret), `configured` or `unchanged` for each secret and setting, then 8
lines ending with `successfully rolled out`: 7 in ai-common, then the monitoring proxy. Before the proxy is first
deployed (step 6 creates it), its two lines print `No resources found` instead: that is fine.

**If a line times out:** see Part 5, "If something fails".

### Step 6. Roll out, in this order

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

**Then do** (every release). Start the reaper worker first, on its own:

```powershell
oc apply -f deploy\deploy_common.yaml -l part-of=tsg
oc -n ai-common rollout status deployment/worker-reaper --timeout=10m
```

**You should see:** `deployment.apps/worker-reaper created` (or `configured`), its two network rules, then
`deployment "worker-reaper" successfully rolled out`. **Go on only then.** If it times out (often `exceeded quota`:
ai-common is shared with the chatbot), use Part 5 before you apply anything else.

Then the app, the network rules and the monitoring:

```powershell
oc apply -f deploy\deploy_threatgen.yaml
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
oc apply -f deploy\networkpolicy_threatgen.yaml
oc -n ai-common delete route -l part-of=tsg-monitoring
oc -n ai-common delete networkpolicy monitoring-from-router --ignore-not-found
oc apply -f deploy\deploy_common.yaml
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
oc -n ai-threatgen rollout status deployment/monitoring-proxy --timeout=10m
```

**You should see:** after each `deploy_*.yaml` file, one `successfully rolled out` line per Deployment: 1, then 8,
then 9:
- 1: the reaper worker, in ai-common;
- 8: the API, the 6 workers and beat, in ai-threatgen (up to 6 minutes: each pod stops before its new one starts,
  so an update never needs room in the quota);
- 9: the 8 monitoring Deployments in ai-common, then the monitoring proxy.

The network rules print `created`, `configured` or `unchanged`. The two `delete` lines print `deleted` for the
previous release's Routes on `threatgen-grafana` and its rule `monitoring-from-router` in ai-common, or `No
resources found` and nothing once they are gone (a rollback brings them back): Grafana and Flower have their Routes
in ai-threatgen, through the monitoring proxy.

Keep this order: the reaper worker serves `tsg_reaper` before the new API and beat send to it. While a worker
restarts, its queue's jobs wait (nothing is lost) and the API stays ready. The API and every worker also build
MongoDB's indexes when they start (nothing to run).

**If a line times out:** see Part 5, "If something fails".

### Step 8. Check

The same as Part 2, steps 14 and 15 (the API answers `{"status":"ok"}` and `{"status":"ready"...`; Grafana shows
`ALL GOOD`).

After the first release with `worker-reaper`, check its memory once, in ai-common:

```powershell
oc adm top pods -n ai-common -l app=worker-reaper
```

**You should see:** one pod, well under its 768Mi limit (on a laptop the worker uses about 230Mi). If it was
restarted with `OOMKilled` (Part 5), ask the developer to raise its limit.

Then watch the first threat-scenario run: in Grafana, the panel **AI gateway refusals (429) per minute** should
stay at 0, or near it (at most 2 a click: threat scenarios wait their turn under
`CII_SCENARIO_CHAT_TOKENS_PER_MINUTE`, 1000000 at the gateway's 2,000,000, which was 25,000 until Nov 2026). If it does not: Part 5, the row "The
AI gateway answers 429".

After the first release with AI usage tracking, carry the AI call texts of the last 14 days over to the
collection that keeps them for good (the previous release expires them after 14 days; safe to run again):

```powershell
oc -n ai-threatgen exec deploy/api -- python -m app.worker.admin.ai_usage_tools copy-texts
```

**You should see:** `tsg_ai_call_texts now holds <n> AI call texts`. Five minutes later,
`GET /v1/ai-usage` answers with counts (the first ones after the first run), and the dashboard **TSG — AI usage**
shows them.

After the first release with `POST /v1/create_session`, three things happen by themselves; nothing to run, only
to check:

1. **One import, right after the roll-out.** At the new `beat` pod's first check, about a minute after it and
   `worker-maintenance` start, TSG imports MITRE ATT&CK once (Enterprise and ICS, the only sources), whatever the day. This
   import also stores the whole ATT&CK graph (MongoDB `tsg_attack`), which `POST /v1/create_session` needs. It
   first deletes what the four removed feeds (CISA KEV, FIRST EPSS, NIST NVD, CISA ICS advisories) left in
   MongoDB: their records in `tsg_intel` and their status documents; every import checks again. From then
   on the import runs on the saved schedule, no longer every hour: weekly on Sunday 02:00 UTC until someone
   changes it (`PUT /v1/tsg/intel/schedule`, or the admin page).
2. **About 100 AI calls, once.** After that import TSG links each MITRE mitigation to library controls (the task
   `tsg_link_mitigations` on `worker-maintenance`; no new pod, queue or beat entry to deploy). It asks the
   threat-scenario chat model (kimi-k2.5) once per mitigation, about 100 times in all (an estimate, not measured
   on UAT), within that model's own limits, so runs started in those minutes share them. Later imports ask only
   for a mitigation that changed.
3. **The admin page is there:** `https://threatgen-api.apps.dda-desc-az1-01.desccii.local/ui/`, served by the API
   pods (Part 2, step 17, "The admin page").

Check 1 and 2 with the two `curl.exe` lines of Part 2, step 17 (`/v1/tsg/intel/health`, then
`/v1/tsg/intel/control-links`). The graph and the links are stored in two new MongoDB collections, `tsg_attack` and
`tsg_control_links`. The app creates them itself, and `tsg_attack`'s indexes at start-up, as it does for every
collection (only while `EXTERNAL_INTELLIGENCE_ENABLED` is `true`); nothing is installed in MongoDB by hand.
`deploy\configmap.yaml` has two new lines, `CII_ANSWER_TOKENS_LINK_CONTROLS` and `CII_ANSWER_TOKENS_PICK_CONTROLS`
(the answer room of the two new AI tasks); step 5 applies them.

From the same release a source can no longer be withdrawn: `POST /v1/tsg/intel/sources/{source}/revoke` and
`.../approve` answer 404, and the admin page's Data ingestion page has no Withdraw or Approve button. Nothing to
do: both sources are always imported.

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
| `CreateContainerConfigError` | A secret or setting is missing: Part 2, steps 7 and 8. After a new release: the check in Part 4, step 5. |
| `field is immutable` | An older Deployment with the same name is still there. In `ai-threatgen`: run `oc -n ai-threatgen delete deployment <name>` and apply again (for `api`, the API is down until it rolls out). In `ai-common` (the chatbot runs there too): run `oc -n ai-common get deployment <name> --show-labels`. If it shows `part-of=tsg-monitoring`, `part-of=tsg` or `app.kubernetes.io/part-of=tsg-observability` (TSG's older label), it is TSG's: run `oc -n ai-common delete deployment <name>` and apply again (the start of Part 4, step 6 removes all the older ones at once). Otherwise it is not TSG's: do not delete it, ask its owner (the chatbot team). |
| `Pending` | The last lines (Events) of `oc -n <project> describe pod <name>` say why. `unbound ... PersistentVolumeClaims`: run `oc -n <project> get pvc`. A claim that is `Pending` with an empty `STORAGECLASS` means the cluster has no default storage class: ask the cluster admin which one to use (the other claims there show one) and tell the developer, who names it in `deploy\deploy_common.yaml`. With that new file, delete the `Pending` claim (it holds no data yet: `oc -n <project> delete pvc <name>`) and apply again. Otherwise ask the cluster admin for storage. |
| `/ready` answers `not_ready` (503) | The API cannot reach MongoDB (`"mongo":false`): `oc -n ai-threatgen logs deployment/api` shows why. Another `false` (SQL Server, Redis) or a worker count of 0 is reported but does not make it `not_ready`: that store or worker's own logs show why. |
| `POST /v1/create_session` answers 409 `intel_no_data` | TSG's copy of MITRE ATT&CK is empty, or lacks a matrix the asset needs (ICS for an OT asset, Enterprise for an IT one, both for an IT\OT or a mixed one). `GET /v1/tsg/intel/health` shows each source's state; import with the first line of Part 2, step 17, and wait for `done`. While `EXTERNAL_INTELLIGENCE_ENABLED` is `"false"` in `deploy\configmap.yaml` nothing is imported at all. |
| The AI gateway answers 429 (Grafana: **AI gateway refusals (429) per minute**, by model, above 0) | A few that stop by themselves need nothing: TSG asks again at 20, 40 and 60 s (`CII_AI_BUSY_MAX_WAIT_SECONDS` 20, `CII_AI_BUSY_TOTAL_WAIT_SECONDS` 60); a threat-scenario call still refused then waits for its job's next try. If the panel stays above 0 for 10 minutes, find the budget the gateway names: "The budget a 429 names" below. |
| `mongodb.validator_stale` (an error) in a pod's start-up log | MongoDB keeps an older rule on the collection the line names that still requires a field TSG no longer writes, and the app's MongoDB user may not replace it (`collMod`), so MongoDB refuses new records there (their API answers 500). The pod starts anyway. The line names the fields and the command to run: send it to the DBA. It applies at once, with no restart; the next start-up logs nothing. `mongodb.validator_not_applied` (a warning) means TSG could not read the rule, or could not replace one that requires no field TSG has stopped writing (expected on UAT, whose MongoDB user may not run `collMod`): nothing to do unless records are refused. |
| `CrashLoopBackOff` | `oc -n <project> logs deployment/<name> --previous` shows why (often a setting). |
| Flower stops with `invalid literal for int() ... 'tcp://...'` | The pod still takes OpenShift's service variables (`FLOWER_PORT`): apply this release's `deploy\deploy_common.yaml` (Part 2, step 13). |

**The budget a 429 names.** A call that gives up after its waits logs the budget that refused it. Search the
workers of the model the panel names (kimi-k2.5: threat scenarios; glm-5.3: remediation and the service mapper):

```powershell
foreach ($w in 'worker-threats', 'worker-scenarios', 'worker-remediation', 'worker-service-mapper') { "== $w"; oc -n ai-threatgen logs deployment/$w | findstr limit_scope }
```

**You should see:** nothing (every 429 was waited out and answered: change nothing), or lines with e.g.
`"limit_type": "tokens"` and `"limit_scope": "team", "limit": 2000000`: the team's budget of 2,000,000 tokens a
minute, shared by every model (it was 25,000 until Nov 2026). Set threat scenarios' `CII_SCENARIO_CHAT_TOKENS_PER_MINUTE`
in `deploy\configmap.yaml` so that 1.5 x it, plus about 21,000 x plans at once and 10,000 x mappings at once, stays
under the budget: `"1000000"` at 2,000,000 (UAT since 15-Nov-2026); lower it if 429s follow bursts. For
`"limit_type": "requests"`, set that module's `..._CHAT_REQUESTS_PER_MINUTE` just under the named limit (kimi-k2.5's
own is 600). Apply it and restart the app ("Change a setting or secret later"). No new image is needed.

### Change a setting or secret later

Edit and apply the file (Part 2, step 7 or 8), then restart one project at a time:

```powershell
oc -n ai-threatgen rollout restart deployment -l part-of=tsg
oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
oc -n ai-common rollout restart deployment/worker-reaper
oc -n ai-common rollout status deployment/worker-reaper --timeout=10m
oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring
oc -n ai-common get deployment -l part-of=tsg-monitoring -o name | ForEach-Object { oc -n ai-common rollout status $_ --timeout=10m }
oc -n ai-threatgen rollout restart deployment -l app=monitoring-proxy
oc -n ai-threatgen get deployment -l app=monitoring-proxy -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
```

### Back up and restore MongoDB (the DBA's)

Every run, scenario, plan, service mapping, AI usage row and the audit live only in MongoDB (`CII_MONGO_DB`, UAT
`cii_uat`); SQL Server holds the libraries and the asset data. Nothing else keeps a copy of them.

- **Back up** every day with the DBA's own tooling, for example a scheduled
  `mongodump --db cii_uat --gzip --archive=<file>` or the platform's volume snapshots, and keep the copies off the
  MongoDB server.
- **Test a restore** once a release: restore the newest copy into a scratch database
  (`mongorestore --gzip --archive=<file> --nsFrom='cii_uat.*' --nsTo='cii_uat_restore.*'`) and check that its
  `tsg_sessions` holds that day's runs.
- After a restore into the live database, restart the API and the workers. The reaper takes over any job a
  restored record shows as queued or running once its lease has run out.

### Roll back to the previous release

Use the previous release's code folder (the one you kept in Part 4): `cd <previous code folder>`. Then, in this
order:

1. Remove the monitoring proxy and its two Routes from ai-threatgen, and worker-reaper from ai-common.
   `oc apply` of the previous files never deletes them, and the previous release's pods need their room in
   ai-threatgen's quota: with the proxy still there, the API's update pod does not fit and the API never rolls
   back. The previous release has no reaper worker (its worker-maintenance does that work), so this release's
   would run beside it. Grafana and Flower are off the API's address from here on.

   ```powershell
   oc -n ai-threatgen delete deployment,service,route -l part-of=tsg-monitoring
   oc -n ai-common delete deployment worker-reaper --ignore-not-found
   ```

   **You should see:** `deleted` for `deployment.apps/monitoring-proxy`, `service/monitoring-proxy`,
   `route.route.openshift.io/grafana` and `route.route.openshift.io/flower`, then `deployment.apps "worker-reaper"
   deleted`. The API's own Route `api` stays.

2. Apply the previous settings and `deploy_threatgen.yaml`:

   ```powershell
   oc apply -f deploy\configmap.yaml
   oc apply -k observability
   oc apply -f deploy\deploy_threatgen.yaml
   oc -n ai-threatgen get deployment -l part-of=tsg -o name | ForEach-Object { oc -n ai-threatgen rollout status $_ --timeout=10m }
   ```

   **You should see:** `configured` or `unchanged` for each setting, then 8 lines ending with
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

A release before AI usage tracking records no AI usage while it runs, and writes the AI call texts to
`tsg_ai_calls` (expired after 14 days) again; the usage rows and texts already kept are never touched. Going
forward again, run its `copy-texts` once more (Part 4, step 8).

### AI usage rows not stored (alert `AiUsageNotRecorded`)

The AI calls went on; MongoDB did not take their usage rows, which were logged whole as `ai.usage_row_spilled`.
Loki keeps them 7 days: within them, export those lines (Grafana, Explore, Loki,
`{app="tsg"} |= "ai.usage_row_spilled"`, raise the line limit above the alert's count, then Download as
JSON or as text; or `logcli query --output=raw --limit=0 ...`) and replay them. Any of those files works,
UTF-8 or UTF-16:

```powershell
Get-Content spilled.json -Raw | oc -n ai-threatgen exec -i deploy/api -- python -m app.worker.admin.ai_usage_tools replay -
```

**You should see:** `<n> spilled AI usage rows stored`. A row already stored is skipped, so a second run does
no harm; it adds up every hour from the oldest replayed row to now again. It stores and adds up under the
5-minute add-up's lock, waiting up to 5 minutes for it; `Another add-up of AI usage is running` means it
stored nothing: run it again. `This add-up of AI usage ran past its lock and stopped` or `MongoDB did not
answer in time` means MongoDB was too slow: the rows it stored are kept and the next 5-minute add-up counts
them; run it again to count them now (the stored rows are skipped). `AiUsageRollupBehind` needs no
replay: the next add-up (every 5 minutes) catches up from where it stopped by itself.
