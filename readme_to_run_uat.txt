# TSG v2 (cii) - run in UAT, step by step (PowerShell).
# This file runs TSG from a laptop against the UAT stores. To deploy TSG on OpenShift, follow deploy\DEPLOYMENT_GUIDE.md.
# NOTE: run every command below from the "cii" folder (the one with pyproject.toml).
cd "C:\GopalChettri\Projects\desc-ai-modules\cii"

# Needs: Python 3.12, "ODBC Driver 17 for SQL Server", and network/VPN access to the UAT hosts:
#   SQL Server 10.228.146.2:1444, MongoDB 10.228.146.3:27018, Redis 10.228.146.4:6379, AI gateway llmapi.govai.ae
# Local MongoDB / Redis / SQL Server are NOT needed - the UAT ones are used.
# Behind a proxy? Nothing to do: CII_AI_BYPASS_PROXY=true in .env sends the AI calls direct (v1's LITELLM_BYPASS_PROXY).
# v1 must be STOPPED first (v1 and v2 share the Redis keys "tsg:*" on the same databases).
# The OpenShift v2 pods must be scaled to 0 first too: they share the Redis queues and would take this laptop's jobs:
#   oc -n ai-threatgen scale deployment -l part-of=tsg --replicas=0
#   oc -n ai-common scale deployment/worker-reaper --replicas=0
#   (back afterwards: deploy\DEPLOYMENT_GUIDE.md Part 2, step 12)
# The DBA must already have installed scripts\sql\tsg_*.sql (+ grants.sql) in EYShieldDB_Copy.

# The env MUST be named .venv (dot-prefixed).

# 1. Create the virtual environment (Python 3.12)
py -3.12 -m venv .venv

# 2. Activate it
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (CMD):
.venv\Scripts\activate.bat
# On Git Bash / WSL:
source .venv/Scripts/activate

# 3. Upgrade pip
python -m pip install --upgrade pip

# 4. Install the application with the exact tested versions.
#    UAT does NOT use ".[local]" (the reranker is the remote qwen3 model) - do not install it.
pip install -e . -c requirements.txt
#    (only if you also want to run tests/lint:  pip install -e ".[dev]" -c requirements.txt)

# 5. Verify no dependency conflicts
pip check

# 6. UAT settings. The app reads ONLY a file named ".env" in this folder (there is no switch to pick another).
#    Keep your laptop settings, then use the UAT file:
Copy-Item .env .env.dev.bak -Force
Copy-Item .env.uat .env -Force
#    BEFORE STARTING, open .env and fix:
#      CII_CORS_ORIGINS=*   is REFUSED when CII_ENV=uat -> put the real origin(s), comma-separated,
#                           e.g. https://threatgen-api.apps.dda-desc-az1-01.desccii.local  (empty = none)
#      CII_ENV              must be uat (not dev)
#      CII_CHAT_REQUESTS_PER_MINUTE  must be 180 (kimi-k2.5 takes 192 a minute)
#      CII_ADMIN_API_KEY    must be at least 32 characters (outside dev)
#    Change .env BEFORE starting any worker/beat/API; after any later change, restart all of them.
#      EVIDENCE_SIMILARITY_THRESHOLD must be set while EXTERNAL_INTELLIGENCE_ENABLED=true (it is: 50)

# 7. Check the settings and that the three stores answer (all must be True; a False names the store)
python -c "from app.core.config import get_settings; s = get_settings(); print(s.env, s.chat_model, s.mongo_db)"
#    expected: uat litellm_proxy/kimi-k2.5 cii_uat
#    The first word must be uat. If it says dev, fix CII_ENV in .env.
#    WARNING: never run pytest on this machine: it would use the UAT MongoDB and Redis.
python -c "from app.core.readiness import check_readiness; print(check_readiness()[0])"

# 8. Start in this order: workers and beat FIRST, the API LAST
#    (the API is "ready" only when every queue has a worker).
#    Open 6 PowerShell windows; in each: cd to the cii folder and activate .venv (step 2).

#   The AI calls skip the corporate proxy by themselves: .env has CII_AI_BYPASS_PROXY=true (as v1's
#   TSG_LITELLM_BYPASS_PROXY). Keep CII_LOG_LEVEL=INFO: DEBUG is for a short diagnosis only.

# Window 1 - job worker (threat finding, scenarios, controls, remediation plans).
#   --pool=threads is REQUIRED: gevent / prefork are refused at start-up on purpose.
celery -A app.worker worker --pool=threads -c 10 -Q tsg_threats,tsg_scenarios,tsg_controls,tsg_remediation -n scenarios@%h --loglevel=INFO

# Window 2 - Service Mapper worker (its own queue, 2 mappings at once; as run.ps1 does locally).
#   !! RUN BOTH LINES, in this order, in the SAME window: its own metrics port (9103), never the job worker's 9100.
#   !! After it starts, the first log line must say  "port": 9103  (if 9100, Ctrl+C and redo both lines).
$env:CII_WORKER_METRICS_PORT = "9103"
celery -A app.worker worker --pool=threads -c 2 -Q tsg_servicemapper -n mapper@%h --loglevel=INFO

# Window 3 - maintenance worker (library index builds, the intelligence refresh).
#   !! RUN BOTH LINES, in this order, in the SAME window. The CII_WORKER_METRICS_PORT line gives this
#   !! worker its own metrics port (9102). Without it the worker silently uses 9100, the job worker's port.
#   !! After it starts, the first log line must say  "port": 9102  (if 9100, Ctrl+C and redo all lines).
$env:CII_WORKER_METRICS_PORT = "9102"
celery -A app.worker worker --pool=threads -c 3 -Q tsg_maintenance -n maintenance@%h --loglevel=INFO

# Window 4 - reaper worker (the reaper that re-sends lost jobs, the controls retry sweep; alone, never behind a long job).
#   !! RUN BOTH LINES, in this order, in the SAME window: its own metrics port (9104), never the job worker's 9100.
#   !! After it starts, the first log line must say  "port": 9104  (if 9100, Ctrl+C and redo both lines).
$env:CII_WORKER_METRICS_PORT = "9104"
celery -A app.worker worker --pool=threads -c 2 -Q tsg_reaper -n reaper@%h --loglevel=INFO

# Window 5 - beat (the timer: reaper every minute, index warm-up every 30 min). Run exactly ONE.
celery -A app.worker beat --loglevel=INFO

# Window 6 - the API
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers

# 9. Check (browser)
#    http://localhost:8000/health  -> {"status": "ok"}
#    http://localhost:8000/ready   -> 200, mongo/sql/redis true, a worker for every queue
#    http://localhost:8000/docs    -> API documentation
#    503 on /ready: the body says which store or queue is missing - start that worker / fix that store.
#
#    PROBLEM: worker log shows  ai.call_unavailable / ProxyError 503 / ERR_CONNECT_FAIL 110 / ai_timed_out, or at
#             start  ai.gateway_route host=llmapi.govai.ae route=proxy  -> the AI calls go through the corporate proxy.
#    FIX 1: .env must have CII_AI_BYPASS_PROXY=true (step 6). Fix it, Ctrl+C every window, start again.
#    FIX 2: still failing? test direct access from this machine:
#             nslookup llmapi.govai.ae
#             Test-NetConnection llmapi.govai.ae -Port 443
#             curl.exe -v https://llmapi.govai.ae/health
#    FIX 3: direct access fails too -> ask the network team to open this machine -> llmapi.govai.ae:443
#           (the OpenShift pods use a hosts entry  10.231.255.253 llmapi.govai.ae  and call it directly: it is on
#           their NO_PROXY - see "OPENSHIFT: every AI call times out" below).
#    A run still retrying picks the fix up by itself; one already "failed" (5 tries) needs a new run.
#
#    OPENSHIFT: every AI call times out ("The AI service timed out") - D23, 2026-10-21
#    Why: the pods send outside calls to the corporate proxy (HTTPS_PROXY=http://10.61.192.2:8080), which cannot
#         reach the AI gateway. llmapi.govai.ae must be on the pods' NO_PROXY so the calls go to it directly.
#    1. See what runs (changes nothing):
#         oc -n ai-threatgen get deploy -o custom-columns=NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image
#    FULL STEPS, with every check and the undo: docs\UAT_LLM_TIMEOUT_RUNBOOK.md. In short:
#    2. Test from inside EACH app pod (the API and every worker, in ai-threatgen; changes nothing). Copy it exactly:
#       no double quotes inside the single quotes (Windows PowerShell 5.1 breaks them):
#         oc -n <project> exec deploy/<name> -- sh -c 'echo NO_PROXY=$NO_PROXY no_proxy=$no_proxy; curl -s -m 30 -o /dev/null -w default:%{http_code} https://llmapi.govai.ae/health/liveliness; echo ,exit=$?; curl -s -m 30 --noproxy llmapi.govai.ae -o /dev/null -w direct:%{http_code} https://llmapi.govai.ae/health/liveliness; echo ,exit=$?'
#       "default:000" and "direct:200" = this problem.
#    3. Unblock now: record the settings (oc -n <project> set env deploy --all --list), then on EVERY app
#       deployment in ai-threatgen (API, every worker, beat; not flower, not the monitoring), one at a time:
#         oc -n <project> set env deploy/<name> NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local,llmapi.govai.ae no_proxy=localhost,127.0.0.1,.svc,.cluster.local,llmapi.govai.ae
#         oc -n <project> rollout status deploy/<name> --timeout=15m
#    4. Check: step 2 again on every changed deployment (both lines list llmapi.govai.ae, "default:200,exit=0");
#       one threat run and one plan finish.
#    5. For good: deploy from this repository, step by step: deploy\DEPLOYMENT_GUIDE.md (plain YAML applied with
#       oc). From v1 this is the switch to v2 (downtime; the DBA installs scripts\sql\tsg_*.sql first): its Part 2, step 9.
#       Never delete the old v1 deployments before v2 is accepted: they are the way back (the guide's "Roll back").
#    6. Check: every worker's start-up log has  "route": "direct"  in its ai.gateway_route line:
#         oc -n <project> logs deploy/worker-scenarios | findstr ai.gateway_route

# 10. Create an API key (admin key = CII_ADMIN_API_KEY from .env). It is shown ONCE - copy it.
curl.exe -X POST http://localhost:8000/v1/tsg/api-clients -H "X-Admin-Key: <CII_ADMIN_API_KEY>" -H "Content-Type: application/json" -d "{\"name\":\"uat-test\",\"description\":\"uat\"}"
#    Business calls then send 4 headers: X-API-Key, X-User-Id, X-Entity-Id, X-Tenant-Id

# 11. External intelligence is ON in .env.uat - first time only. No key needed (no admin key, no API key).
#    Until this import finishes, each window shows ONE line, naming these calls (expected, nothing broken):
#      external_intelligence.no_data_yet  action="... POST /v1/tsg/intel/refresh ..."
#    and starting a run answers 409 intel_no_data. Both stop once health shows a snapshot_id.
#    To run without the feeds instead: curl.exe -X PUT http://localhost:8000/v1/tsg/intel/switch
#      -H "Content-Type: application/json" -d "{\"enabled\": false}"
curl.exe -X POST http://localhost:8000/v1/tsg/intel/refresh
curl.exe http://localhost:8000/v1/tsg/intel/refresh/<job_id>
#    ...repeat the line above until it says done, then:
curl.exe http://localhost:8000/v1/tsg/intel/health
#    A source "failed": its last_error ends with the reason, e.g. "(last: ConnectTimeout: ...)" or "(last: HTTP 503)".
#      ConnectTimeout / ConnectError / ProxyError = the app cannot get out (proxy, firewall): set
#      CII_PROXY_URL=http://<proxy>:<port> in .env, restart API and workers, refresh again. HTTP 5xx or 429 = the
#      source is busy, the next hourly check tries again. Details: docs/EXTERNAL_INTELLIGENCE.md section 6.
#    On OpenShift use https://threatgen-api.apps.dda-desc-az1-01.desccii.local instead of http://localhost:8000
#    (add -k if this PC does not trust the cluster certificate).
#    ...snapshot_id must be set. EVIDENCE_SIMILARITY_THRESHOLD=50 is provisional (not calibrated on the UAT reranker).

# 12. Grafana + Flower (optional monitoring). Start it AFTER the workers and the API are running.
#     Open one more window: cd to the cii folder, activate .venv (step 2), then:
python scripts/monitoring.py start
python scripts/monitoring.py status
#    status must show 7 lines, each "ready" (Grafana, Prometheus, Alertmanager, Loki, Alloy, Flower, redis_exporter).
#    Open:
#      Grafana (start here)   http://localhost:3000/grafana/
#      Flower (celery jobs)   http://localhost:5555/flower/
#      Prometheus             http://localhost:9090/prometheus/
#      Alertmanager           http://localhost:9093/alertmanager/
#    Notes:
#      - The FIRST start downloads about 500 MB (github.com, dl.grafana.com). If this machine has no internet
#        it fails: download on another machine and copy the folder to %USERPROFILE%\.tsg\monitoring-v2
#      - Ports 3000, 5555, 9090, 9093 must be free (v1's monitoring uses the same ports - stop it first).
#      - Grafana's log panels need log files: set CII_LOG_DIR=logs in .env and restart the API and workers.
#        With CII_LOG_DIR empty (as in .env.uat) only numbers and alerts show, no logs.
#      - LOGIN: Flower, Prometheus and Alertmanager need NO login. Grafana needs no login to look.
#        To change Grafana itself, log in as  admin  with the GRAFANA_ADMIN_PASSWORD line of .env; if that line is
#        empty or missing, the random password is in  %USERPROFILE%\.tsg\monitoring-v2\grafana-admin-password.txt
#      - SECURITY: anyone who can reach ports 3000, 5555, 9090, 9093 can read the numbers and logs and silence
#        alerts. Do not expose these ports beyond the people who need them.
#      - Stop it:  python scripts/monitoring.py stop

# 13. Check that every celery worker is working (new window, .venv activated):
python -c "from app.core.readiness import count_online_workers; from app.worker import ROUTED_QUEUES; print(count_online_workers(ROUTED_QUEUES))"
#    each of tsg_threats, tsg_scenarios, tsg_controls, tsg_remediation, tsg_servicemapper, tsg_maintenance, tsg_reaper must show at least 1 (wait up to 20 s after start)
celery -A app.worker inspect ping
#    must answer pong from scenarios@..., mapper@..., maintenance@... and reaper@...
celery -A app.worker inspect active_queues
#    scenarios@... serves tsg_threats + tsg_scenarios + tsg_controls + tsg_remediation; mapper@... serves tsg_servicemapper; maintenance@... serves
#    tsg_maintenance (intelligence refresh, embeddings builds); reaper@... serves tsg_reaper (the reaper, the controls retry sweep).
#    Each worker is named by its module:
#    its log file is logs/worker-<name>.log, and every job line carries module=<module> and worker=<name>@<host>.
#    Beat is not in these checks: about 1 minute after it starts, the reaper window must log tsg_reap, every minute.
#    Every job, queue and worker in one call (admin key; add &status=failed, &kind=tsg_map_services, &hours=72):
curl.exe -H "X-Admin-Key: <CII_ADMIN_API_KEY>" "http://localhost:8000/v1/admin/jobs?status=queued&status=running&status=failed"
#    One API call to its worker: take X-Request-ID from the API's answer, then
python scripts/debug_tools.py find <request id>

# 14. Stop: Ctrl+C in each window (a worker finishes its running jobs first; press twice to force).
#     Put your laptop settings back:
Copy-Item .env.dev.bak .env -Force
