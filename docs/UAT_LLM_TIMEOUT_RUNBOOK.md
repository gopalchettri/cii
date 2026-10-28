# UAT: fixing the LLM time-outs, step by step

## What is wrong, in one paragraph

In UAT every AI call times out. The pods send all outside traffic to the company proxy
(`http://10.61.192.2:8080`), and that proxy cannot reach the AI service `llmapi.govai.ae`. The AI service is on the
internal network, so the pods must call it **directly**. They do that only when `llmapi.govai.ae` is on the pod's
"do not use the proxy" list, the `NO_PROXY` setting. The support team proved it: without `NO_PROXY` the call waits
30 seconds and fails; with `NO_PROXY=llmapi.govai.ae` it answers `200 "I'm alive!"`.

## Before you start

- You need the `oc` command, logged in to the UAT cluster (`oc login ...`).
- The commands are written for **Windows PowerShell** and also work in a Linux shell. **Copy them exactly.** The
  commands that run inside a pod have no double quotes inside their single quotes on purpose: Windows PowerShell 5.1
  breaks such quotes on their way to `oc`.
- There are two projects: **`ai-threatgen`** (the API, the workers and beat) and **`ai-remediation`** (a second set
  of workers). The workers of both projects take jobs from the same queues, so **both projects must be fixed**.
- **Part A** (steps 1 to 4) fixes UAT **today**, without new code and without downtime beyond pod restarts.
  **Part B** (steps 5 and 6) makes the fix **permanent**. It is a bigger change: read "Before step 5" first.

### Which deployments to change

UAT may run the old version (v1) or the new one (v2). Step 1 tells you which.

| Project | v1 names: change these | v2 names: change these | Never change |
|---|---|---|---|
| `ai-threatgen` | `tsg-api`, `celery-worker`, `celery-worker-admin`, `tsg-beat` | `api`, `worker-threats`, `worker-scenarios`, `worker-controls`, `worker-remediation`, `worker-service-mapper`, `worker-maintenance`, `beat` | `tsg-flower`, `flower`, and the monitoring |
| `ai-remediation` | `celery-worker` | `worker-threats`, `worker-scenarios`, `worker-controls`, `worker-remediation`, `worker-service-mapper`, `worker-maintenance` | `celery-exporter`, `mssql-exporter`, `mongodb-exporter`, `flower`, and the monitoring (Prometheus, Grafana, Loki, Alloy, Alertmanager, exporters) |

"The monitoring" means Prometheus, Grafana, Loki, Alloy, Alertmanager, kube-state-metrics and the exporters. If
step 1 shows an app deployment that is in neither list, change it too and tell us its name.

---

# Part A: unblock UAT today

## Step 1: see what UAT is running (changes nothing)

```
oc -n ai-threatgen get deploy -o custom-columns=NAME:.metadata.name,READY:.status.readyReplicas,IMAGE:.spec.template.spec.containers[0].image
oc -n ai-remediation get deploy -o custom-columns=NAME:.metadata.name,READY:.status.readyReplicas,IMAGE:.spec.template.spec.containers[0].image
```

- Write down every deployment **name**. Use the table above to pick the ones you change in step 3.
- Names like `tsg-api` and `celery-worker` mean UAT runs **v1**. Names like `api` and `worker-scenarios`, with an image
  ending in `tsg-api:v2-<commit>` or a build date such as `tsg-api:24-Oct-2026`, mean UAT runs **v2**.

## Step 2: confirm the problem, from inside each app pod (changes nothing)

Run this once for **each** deployment you will change, in its project. It takes up to a minute per deployment.

```
oc -n <project> exec deploy/<name> -- sh -c 'echo NO_PROXY=$NO_PROXY no_proxy=$no_proxy; curl -s -m 30 -o /dev/null -w default:%{http_code} https://llmapi.govai.ae/health/liveliness; echo ,exit=$?; curl -s -m 30 --noproxy llmapi.govai.ae -o /dev/null -w direct:%{http_code} https://llmapi.govai.ae/health/liveliness; echo ,exit=$?'
```

Example for the API: `<project>` = `ai-threatgen`, `<name>` = `tsg-api`.

- `default` is the route the pod's own settings choose (the one the app uses).
- `direct` skips the proxy.

| You see | Meaning |
|---|---|
| `default:000,exit=28` (or another exit) and `direct:200,exit=0` | **This is the problem.** The pod sends the call to the proxy, which cannot reach the AI service; the direct route works. Go on. |
| `default:200` | This pod already reaches the AI service. If every pod shows this, the time-outs have another cause: stop and send the output. |
| `direct:000,exit=6` (and `default` with any exit) | The pod has no hosts entry for the AI service. Cluster DNS cannot find it; through the proxy it did not need one. Add the entry (below), then run step 2 again. |
| `direct:000,exit=7` or `exit=28` | The pod finds the address but cannot connect to `10.231.255.253:443`: a network rule blocks it. Send `oc -n <project> get networkpolicy` to the network team and ask them to open that project's pods to `10.231.255.253:443`. |
| Anything else | Stop and send the output. |

To add the hosts entry to a deployment (this restarts its pods):

```
oc -n <project> patch deploy/<name> -p 'spec: {template: {spec: {hostAliases: [{ip: 10.231.255.253, hostnames: [llmapi.govai.ae]}]}}}'
oc -n <project> rollout status deploy/<name> --timeout=15m
```

## Step 3: add the AI service to NO_PROXY on every app deployment

**3.1 Record the settings as they are now.** Keep this output: you need it to undo.

```
oc -n ai-threatgen set env deploy --all --list | findstr /i "deployments proxy"
oc -n ai-remediation set env deploy --all --list | findstr /i "deployments proxy"
```

(On Linux use `grep -i -E "deployments|proxy"` instead of `findstr`.)

**3.2 Change one deployment at a time.** For each deployment from the table, in its project, run both lines, and
wait for the second to finish before you start the next deployment:

```
oc -n <project> set env deploy/<name> NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local,llmapi.govai.ae no_proxy=localhost,127.0.0.1,.svc,.cluster.local,llmapi.govai.ae
oc -n <project> rollout status deploy/<name> --timeout=15m
```

- Set **both** `NO_PROXY` and `no_proxy`: Linux tools and Python read the lowercase one first.
- `set env` restarts that deployment's pods. A worker may take up to about 12 minutes to finish its current job and
  stop, so be patient.
- The second line must end with `successfully rolled out`. If it times out, show why and send the output:
  `oc -n <project> get events --sort-by=.lastTimestamp` (often `exceeded quota`).
- Do not judge by `oc get pods -w`: the old pods also show `Running`.

**3.3 Check every deployment got both settings.** Run the two commands from 3.1 again. Under each deployment you
changed, there must be a `NO_PROXY=` line **and** a `no_proxy=` line, and both must include `llmapi.govai.ae`. If one is
missing, run 3.2 again for that deployment.

**3.4 Before step 4**, `oc -n ai-threatgen get pods` and `oc -n ai-remediation get pods` must show no pod in
`Terminating`. Otherwise the next commands may still reach an old pod.

**To undo step 3** for one deployment (only if something goes wrong): look at that deployment in the output you kept
from 3.1, and treat `NO_PROXY` and `no_proxy` separately. If a variable was not listed before, remove it (`NAME-`). If
it was listed, set it back to the value shown. Then wait with `rollout status` as in 3.2. Examples:

- **It had neither** (such as `tsg-api`):

  ```
  oc -n <project> set env deploy/<name> NO_PROXY- no_proxy-
  ```

- **It had only `NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local`:**

  ```
  oc -n <project> set env deploy/<name> NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local no_proxy-
  ```

## Step 4: check that UAT works now

1. **Run step 2 again for every deployment you changed.** Now both lines list `llmapi.govai.ae`, and you see
   `default:200,exit=0`. A deployment that still shows `default:000` was missed: do step 3 for it.
2. In the console, start one small **threat run** and request one **remediation plan**. Both must finish without
   "The AI service timed out".
   - A run or plan that already **failed** before step 3 stays failed: start a new one.
   - One that was only **retrying** carries on by itself.
3. If something still times out, collect the recent log of **every** deployment you changed, in **both** projects,
   and send the lines:

   ```
   oc -n <project> logs deploy/<name> --all-containers --since=15m | findstr /i "timed_out unreachable llmapi"
   ```

   (On Linux use `grep -i -E "timed_out|unreachable|llmapi"` instead of `findstr`.)

UAT works again here. But a later deployment would bring back the old settings, so do Part B.

---

# Part B: make the fix permanent

## Before step 5 (read all of it)

- **Since D25 the deploy is plain YAML applied with `oc`.** The scripts this runbook used before
  (`deploy-uat.ps1`, `observability.ps1`, `scripts/gen_openshift_config.py`) are gone. Step 5 now follows
  `deploy/DEPLOYMENT_GUIDE.md`, step by step; "guide step N" below is step N of that guide's Part 2.
- **Step 5 is not only the NO_PROXY fix.** If step 1 showed v1 names, step 5 is the switch from v1 to v2. It replaces
  UAT's app with everything in this repository's `main` branch:
  - the `NO_PROXY` fix (D23);
  - a plan covers every system linked to the asset (D20);
  - a control counts only on systems of its asset type (D21);
  - the D34 remediation prompt, stored as `remediation-1` (D36), and at most 5 controls per scenario (D22);
  - the plan request names supporting systems once per request (D34): the platform sends
    `supporting_systems_applicable_to_risk` and `supporting_systems_applicable_to_existing_controls`.
    `supporting_system_ids` inside an existing control is now a 422, and so is any of the old flags (the message
    names the list to send instead). Tell the platform team before the release.
- **It causes downtime.** Guide step 9 stops v1 and deletes the old v2 Deployments; UAT is down until the new API is
  running (guide step 12). Agree the release and a downtime window first.
- **The DBA goes first.** The DBA must install every `scripts\sql\tsg_*.sql` in the UAT database, then
  `grants.sql`. Leave out any file whose name has `copy` in it. This includes the new `tsg_GetAssetContext.sql` (D20)
  and must be done **before** the new app starts: runs the new app starts on the old procedure keep only their named
  systems for good, and the deploy does not check it. Get the DBA's confirmation.
- **`CII_CORS_ORIGINS` must be a real address.** In `deploy\configmap.yaml` replace `CHANGE_ME_UI_ORIGIN` with the
  real address(es) of the platform UI (guide step 8). `*` stops the app at start.
- **The monitoring images must be in Quay** (guide step 3). Step 5 also installs the monitoring in `ai-common` (D24)
  and removes the one in `ai-remediation`. Guide step 3 builds these images on Red Hat UBI 9 and pushes them to
  `quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc`: `prometheus:v3.15.0`, `alertmanager:v0.34.1`,
  `loki:3.7.8`, `alloy:v1.20.1`, `grafana:12.4.12`, `redis_exporter:v1.93.0`, `kube-state-metrics:v2.20.0`,
  `nginx:1.24.0` (the `image:` lines of `deploy\deploy_common.yaml`). Check each one in the Quay web UI
  (`/repository/dda-desc/<name>?tab=tags`). If they cannot be built yet, wait with step 5 (Part A keeps UAT
  working).
- **Tools:** run steps 5 and 6 in PowerShell, on a machine that can reach the cluster, with:
  - `git`, or the release's ZIP from GitHub;
  - Docker (Docker Desktop, Linux containers);
  - a login to the image registry;
  - the `oc` command, with admin rights in `ai-threatgen`, `ai-remediation` and `ai-common`.

## Step 5: deploy from the repository

Since D25 the deploy is plain YAML applied with `oc`: follow `deploy/DEPLOYMENT_GUIDE.md`. In short, in PowerShell,
in the `cii` folder (the one with `pyproject.toml`) of a clone of `https://github.com/gopalchettri/cii.git`:

**5.1 Get the code and build the images** (guide steps 3 and 4):

```
git checkout main
git pull
git branch --contains 0f62fd8
docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
.\deploy\build-monitoring-images.bat
.\deploy\build-image.bat
```

- `git branch --contains 0f62fd8` must print `* main`. If it prints nothing, this checkout doesn't have the fix: stop.
  The `master` branch has neither the fix nor these files.
- `build-image.bat` builds whatever is in the folder (it does not use git): build from a clean checkout of `main`
  or the release's ZIP.
- `build-monitoring-images.bat` stops at the first image that is already in Quay: guide step 3 says how to build
  only the missing ones.
- A push that fails with `denied` or `unauthorized` after `docker login` said `Login Succeeded` means your Quay
  user cannot create the repository `dda-desc/<name>`, or may not write to it: the Quay admin gives you Write on it
  (creating it if missing) or lets you create repositories in `dda-desc` (guide Part 1). Without `Login Succeeded`, log in and run it again.
- The builds download from the internet (registry.access.redhat.com, packages.microsoft.com, PyPI, GitHub); the
  push needs the company network. If no machine has both, see `--no-push` at the top of `deploy\build-image.bat`.
- At the end it prints the tag: today's date, such as `24-Oct-2026`. Write it down.
- A tag that is already in Quay is refused. For a second build on the same day, give a new tag:
  `.\deploy\build-image.bat 24-Oct-2026-2`.

**5.2 Deploy** (guide steps 5 to 13, in this order):

1. Put the tag in `deploy\deploy_threatgen.yaml`, `deploy\deploy_remediation.yaml` and `deploy\deploy_common.yaml`
   (guide step 5).
2. First time only: create the image pull secret `quay-pull` in `ai-remediation` and `ai-common` (guide step 6).
3. Copy `deploy\secrets.example.yaml` to `deploy\secrets.yaml`, fill in every `CHANGE_ME` and apply it (guide step 7).
   The file holds passwords: never commit or share it.
4. Set `CII_CORS_ORIGINS` in `deploy\configmap.yaml` and apply it (guide step 8).
5. First time only: stop v1 (scaled to 0, not deleted), delete the old v2 Deployments, the old monitoring in
   `ai-remediation`, and v1's Routes on `threatgen-api` and `threatgen-grafana` (guide step 9). Save a copy of each
   v1 Route first, for 5.4: `oc -n <project> get route <name> -o yaml > <name>-route-v1.yaml`.
   This is where the downtime starts.
6. Apply the network rules, then `deploy_remediation.yaml`, `deploy_threatgen.yaml` and `deploy_common.yaml`, waiting
   for each rollout: every worker first, the API last (guide steps 10 to 13).

**5.3 Do not delete the old (v1) deployments yet.** Guide step 9 only scaled them to 0. Going back (5.4) needs them,
and they still carry the `NO_PROXY` from step 3.
- Check with `oc -n ai-threatgen get deploy` and `oc -n ai-remediation get deploy`: the old ones show READY `0/0` or
  empty, and the new ones (`api`, `worker-*`, `beat`) show `1/1` (`api` `2/2`); `oc -n ai-common get deploy` shows
  `flower` and the monitoring.
- Delete the old ones (`oc -n <project> delete deploy/<old-name>`) only after step 6 passes **and** v2 is accepted
  in UAT.

**5.4 If step 5 fails and UAT must work again now**, go back to v1 (the guide's "Roll back" section goes back one
v2 release, not to v1): scale the new Deployments to 0 (`oc -n <project> scale deployment -l part-of=tsg
--replicas=0` in `ai-threatgen` and `ai-remediation`, and `oc -n ai-threatgen scale deployment monitoring-proxy
--replicas=0`), delete the new Routes on `threatgen-api` (`oc -n ai-threatgen delete route api grafana flower`:
a v1 copy on the same address and path would be refused while they stay), apply the copies of v1's Routes
saved in 5.2 (`oc apply -f <name>-route-v1.yaml`) and scale v1 back up to its old counts. Step 3's `NO_PROXY` is still on v1. v1's monitoring does not come back this
way: bring it back from the v1 repository.

Then do step 4 again. Once the cause is fixed, do 5.2 again (leave out its first-time-only parts already done).

## Step 6: final check

1. **Run step 2 for each new deployment**: `api`, `worker-threats`, `worker-scenarios`, `worker-controls`,
   `worker-remediation`, `worker-service-mapper`, `worker-maintenance`, `beat` in `ai-threatgen`, and the six workers
   in `ai-remediation`. Each must show
   `default:200,exit=0`. The new deployments already list the AI service on `NO_PROXY`.
2. **Each worker logs, at start-up, how it reaches the AI service.** Check one worker in each project:

   ```
   oc -n ai-threatgen logs deploy/worker-scenarios | findstr ai.gateway_route
   oc -n ai-remediation logs deploy/worker-scenarios | findstr ai.gateway_route
   ```

   - The lines are JSON, for example `{"host": "llmapi.govai.ae", "route": "direct", "event": "ai.gateway_route", ...}`.
   - Every line must contain `"route": "direct"`. A line with `"route": "proxy"` means that worker still sends AI
     calls through the proxy: send the line.
3. **One threat run and one remediation plan finish in the console.** In the console's Setup, use the API address
   `https://threatgen-api.apps.dda-desc-az1-01.desccii.local`. The first time v2 runs, two refusals can happen that have
   nothing to do with the proxy, so don't go back to step 3 for them:
   - **401 "API key invalid":** v2 has its own key store. Create a key once; the admin key is `CII_ADMIN_API_KEY`
     from `deploy\secrets.yaml` (guide step 7; creating a key is guide step 16). The new `api_key` is shown **once**: copy it into the console's
     X-API-Key field.

     ```
     curl.exe -k -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/api-clients -H "X-Admin-Key: <CII_ADMIN_API_KEY>" -H "Content-Type: application/json" -d '{\"name\":\"uat-console\",\"description\":\"uat\"}'
     ```

   - **409 `intel_no_data`:** nothing has been imported yet. Start the import once, repeat the second line until the
     job says `done`, then check that health shows a `snapshot_id`:

     ```
     curl.exe -k -X POST https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh
     curl.exe -k https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/refresh/<job_id>
     curl.exe -k https://threatgen-api.apps.dda-desc-az1-01.desccii.local/v1/tsg/intel/health
     ```

   Only "The AI service timed out", or `"route": "proxy"` in 6.2, sends you back to step 3.

   "Every AI slot stayed busy" (reason `ai_busy`) is not a proxy fault. Two limits give this message. The
   `ai.slots_busy` log line names the full one in its `limiter`:

   ```
   oc -n ai-threatgen logs deploy/worker-scenarios | findstr ai.slots_busy
   oc -n ai-remediation logs deploy/worker-scenarios | findstr ai.slots_busy
   ```

   - **`"limiter": "tsg:ai_slots"`:** the AI gateway answered 429 (too many requests), and TSG then limits its own AI
     calls on every pod until 3 minutes pass with no 429 (D30). In Grafana, "Why the AI did not answer" shows them
     as busy; the "AI no answer" tile does not count them. A pod that stopped in the middle of a call stops counting
     within a minute, so restarting pods does not help: wait, or ask the gateway admin for a higher limit on TSG's
     key.
   - **`"limiter": "tsg:ai_fallback_slots:<module>"`:** that module's fallback slots
     (`CII_<MODULE>_MAX_CONCURRENT_FALLBACK_CALLS`) stayed full, because the first model kept failing or timing out and every call went to the fallback. This is
     the timeout problem: go back to step 3.

---

## What changed in the repository (commit `0f62fd8`)

| File | Change |
|---|---|
| `deploy/deploy.yaml` | The API, the 4 workers and beat: `llmapi.govai.ae` added to `NO_PROXY`, and the same list added as `no_proxy`. |
| `deploy/deploy.ai-remediation.yaml` | The same for its 3 workers. |
| `deploy/networkpolicy.yaml` | A comment only. |
| `scripts/gen_openshift_config.py` | The pre-deploy check refuses an AI service address that is not `https` on port 443, not pinned in the pods, or not on `NO_PROXY` and `no_proxy` in every app pod. |
| `app/ai/common.py` | The app no longer hides the pod's own `NO_PROXY` entries when it adds the AI service, and at start-up it logs one `ai.gateway_route` line per AI service: `direct`, or through the proxy. |
| `app/core/constants/common.py` | The name of that new log line. |
| `tests/test_ai_proxy_bypass.py`, `tests/test_deploy.py` | Tests for all of the above. |
| `readme_to_run_uat.txt`, `docs/SOLUTION_DESIGN.md` | The same steps in short, and decision D23. |
