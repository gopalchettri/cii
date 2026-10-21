# UAT: fixing the LLM time-outs, step by step

## What is wrong, in one paragraph

In UAT every AI call times out. The pods send all outside traffic to the company proxy
(`http://10.61.192.2:8080`), and that proxy cannot reach the AI service `llmapi.govai.ae`. The AI service is on the
internal network, so the pods must call it **directly**. They do that only when `llmapi.govai.ae` is on the pod's
"do not use the proxy" list, the `NO_PROXY` setting. The support team proved it: without `NO_PROXY` the call waits
30 seconds and fails; with `NO_PROXY=llmapi.govai.ae` it answers `200 "I'm alive!"`.

## Before you start

- You need the `oc` command, logged in to the UAT cluster (`oc login ...`).
- The commands below work in PowerShell and in a Linux shell.
- There are two projects: **`ai-threatgen`** (the API, the workers and beat) and **`ai-remediation`** (a second set
  of workers).
- Steps 1 to 4 fix UAT **today** without new code. Steps 5 and 6 make the fix **permanent**.

---

## Step 1: see what UAT is running (changes nothing)

```
oc -n ai-threatgen get deploy -o custom-columns=NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image
oc -n ai-remediation get deploy -o custom-columns=NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image
```

Write down every deployment **name** and **image**. You need the names in step 3.

- The repository's deployments are called `api`, `worker-threats`, `worker-scenarios`, `worker-service-mapper`,
  `worker-maintenance` and `beat` (and in `ai-remediation`: `worker-threats`, `worker-scenarios`,
  `worker-service-mapper`).
- If UAT shows other names, such as `tsg-api`, UAT is running an older deployment than this repository. Step 5
  replaces it.

## Step 2: confirm the problem from inside the API pod (changes nothing)

Use the API's name from step 1 (below it is `tsg-api`):

```
oc -n ai-threatgen exec deploy/tsg-api -- sh -c 'echo "NO_PROXY=$NO_PROXY"; curl -s -m 30 -o /dev/null -w "via proxy: %{http_code}\n" https://llmapi.govai.ae/health/liveliness; curl -s -m 30 --noproxy llmapi.govai.ae -o /dev/null -w "direct: %{http_code}\n" https://llmapi.govai.ae/health/liveliness'
```

It takes up to a minute. What it means:

| You see | Meaning |
|---|---|
| `via proxy: 000` and `direct: 200` | **This is the problem.** The proxy cannot reach the AI service; the direct route works. Go to step 3. |
| `via proxy: 200` and `direct: 200` | The proxy can reach it now; the time-outs have another cause. Stop and send the output. |
| `direct: 000` | The pod cannot reach the AI service directly either (firewall or network rule). Ask the network team to open the pods to `10.231.255.253:443`. |

## Step 3: unblock UAT now

Run this once for **every app deployment** from step 1: the API, every worker and beat, in **both** projects.
**Skip** flower and the monitoring tools (Grafana, Prometheus, Loki, Alloy, Alertmanager).

```
oc -n ai-threatgen set env deploy/<name> NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local,llmapi.govai.ae no_proxy=localhost,127.0.0.1,.svc,.cluster.local,llmapi.govai.ae
```

For the workers in the second project, use `-n ai-remediation` instead.

- Set **both** `NO_PROXY` and `no_proxy`: Linux tools and Python read the lowercase one first.
- Each command restarts that deployment's pods by itself, one at a time.

Wait until every pod is running again (press Ctrl+C when each shows `Running` and `1/1`):

```
oc -n ai-threatgen get pods -w
oc -n ai-remediation get pods -w
```

**To undo step 3** (only if something goes wrong): `oc -n <project> set env deploy/<name> NO_PROXY- no_proxy-`

## Step 4: check that UAT works

1. Run step 2 again. Now `NO_PROXY` lists `llmapi.govai.ae`, and **both** lines say `200`.
2. In the console, start one small threat run, or request one remediation plan. It must finish without
   "The AI service timed out".
3. If something still times out, look at a worker's recent log and send the lines:

   ```
   oc -n ai-threatgen logs deploy/<worker-name> --since=15m | findstr /i "timed_out unreachable llmapi"
   ```

   (On Linux use `grep -i -E "timed_out|unreachable|llmapi"` instead of `findstr`.)

UAT works again here. But the next deployment would replace these settings with the old ones, so do steps 5 and 6.

---

## Step 5: make the fix permanent (once the fixed code is pushed)

The repository now has the fix in its deployment files (see "What changed" below).

1. Build and push the image. It prints the image name, `.../tsg-api:v2-<commit>`:

   ```
   .\deploy\build-image.ps1
   ```

2. Deploy it, with the image from step 5.1:

   ```
   .\deploy\deploy-uat.ps1 -AppImage <the image it printed>
   ```

   - It first runs the settings check. That check now **refuses** to deploy if the AI service is not on
     `NO_PROXY` in every pod.
   - **Note:** `.env.uat` currently has `*` in `CII_CORS_ORIGINS`. The check refuses that too, so first replace
     it with the real address(es) of the platform UI.
   - It then updates every worker in both projects, and the API last.

3. If step 1 showed old names (such as `tsg-api`), remove those old deployments after this deploy, so two copies
   of the app don't run side by side. Check first with `oc get deploy` in both projects, and delete only the old
   ones: `oc -n <project> delete deploy/<old-name>`.

## Step 6: final check

1. Step 2 again, on the new API deployment (`deploy/api`): both lines say `200`.
2. A worker's start-up log says how it reaches the AI service:

   ```
   oc -n ai-threatgen logs deploy/worker-scenarios | findstr ai.gateway_route
   ```

   It must show `host=llmapi.govai.ae route=direct`. If it says `route=proxy`, the AI calls still go to the proxy:
   go back to step 3.
3. One threat run and one remediation plan finish in the console.

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
