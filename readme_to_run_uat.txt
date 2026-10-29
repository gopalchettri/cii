# TSG v2 (cii) - run on the UAT Windows machine, step by step.
# This runs TSG on one Windows machine against the UAT stores. To deploy TSG on OpenShift, follow deploy\DEPLOYMENT_GUIDE.md.
#
# Use "Windows PowerShell" (the prompt starts with PS). NOT CMD: there a .ps1 file opens in an editor instead of
# running. NOT PowerShell 7 (pwsh): run.ps1 needs Windows PowerShell 5.1.
# Run every command from the cii folder (the one with pyproject.toml), e.g.:
cd C:\Users\gopal.chettri\Documents\cii_tsg_rem-sm

# =====================================================================================================
# PART 1 - ONE TIME (a new machine, or a new copy of the code)
# =====================================================================================================

# 1. Check the machine
py -0
#    must list 3.12. 3.13 / 3.14 are untested and may fail to install: install Python 3.12 (64-bit) if missing.
Get-OdbcDriver -Name "ODBC Driver 17 for SQL Server" -Platform 64-bit
#    must print one driver. Nothing printed -> install "ODBC Driver 17 for SQL Server" (x64).
Test-NetConnection 10.228.146.2 -Port 1444     # SQL Server
Test-NetConnection 10.228.146.3 -Port 27018    # MongoDB
Test-NetConnection 10.228.146.4 -Port 6379     # Redis
#    each must say  TcpTestSucceeded : True.  False -> ask the network team to open this machine to that IP and port.
#    No local MongoDB, SQL Server or Redis (Memurai) is needed: TSG uses the UAT ones above.

# 2. Create the Python environment (it MUST be named .venv)
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
#    The prompt now starts with (.venv).
#    "running scripts is disabled on this system" -> run this once in this window, then activate again:
#      Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#    Made with the wrong Python earlier? Remove-Item .venv -Recurse -Force, then step 2 again.

# 3. Install the packages through the corporate proxy (straight to pypi.org times out: ConnectTimeoutError)
$env:HTTP_PROXY  = "http://10.61.192.2:8080"
$env:HTTPS_PROXY = "http://10.61.192.2:8080"
pip install -e . -c requirements.txt
#    UAT does NOT install ".[local]" (the reranker is the remote qwen3 model).
pip check
#    must say: No broken requirements found.
#    Still timing out -> this machine uses another proxy. See which one Windows uses, and put it in the two lines above:
#      Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select ProxyEnable, ProxyServer, AutoConfigURL

# 4. UAT settings. The app reads ONLY a file named ".env" in this folder - never ".env.uat". Copy it over:
Copy-Item .env.uat .env -Force
#    Then open .env and check (start-up stops with the reason if one is wrong):
#      CII_ENV=uat
#      CII_CORS_ORIGINS                        the web pages that may call the API, comma-separated, e.g.
#                                              https://threatgen-api.apps.dda-desc-az1-01.desccii.local; "*" (any) is
#                                              accepted in UAT, refused in prod
#      CII_ADMIN_API_KEY                       at least 32 characters
#      CII_SCENARIO_CHAT_REQUESTS_PER_MINUTE=180  kimi-k2.5 takes 192 a minute; only threat scenarios use kimi-k2.5,
#                                              remediation and the service mapper use glm-5.3
#      EVIDENCE_SIMILARITY_THRESHOLD=50        must be set while EXTERNAL_INTELLIGENCE_ENABLED=true
#      CII_AI_BYPASS_PROXY=true                the AI calls go straight to the AI gateway, not through the proxy
#      CII_LOG_LEVEL=INFO                      DEBUG is for a short diagnosis only
#    After any later change to .env: .\stop.ps1, then .\run.ps1 again.

# 5. Check the settings and the three UAT stores (window from step 2, .venv activated)
python -c "from app.core.config import get_settings; s = get_settings(); print(s.env, s.scenario_chat_model, s.mongo_db)"
#    expected: uat litellm_proxy/kimi-k2.5 cii_uat
#    The first word must be uat. If it says dev, .env is not the UAT file: step 4.
python -c "from app.core.readiness import check_readiness; print(check_readiness()[0])"
#    expected: mongo, sql and redis all True. A False: the warning printed above it says why
#    (network: step 1; wrong password in .env; ODBC driver missing: step 1).
#    WARNING: never run pytest on this machine: it would use the UAT MongoDB and Redis.

# =====================================================================================================
# PART 2 - EVERY TIME
# =====================================================================================================

# 6. Nothing else may use the UAT Redis queues
#    - v1 must be STOPPED (v1 and v2 share the Redis keys "tsg:*" on the same databases).
#    - The OpenShift v2 pods must be scaled to 0: they share the Redis queues and would take this machine's jobs:
#        oc -n ai-threatgen scale deployment -l part-of=tsg --replicas=0
#        oc -n ai-common scale deployment/worker-reaper --replicas=0
#      (back afterwards: deploy\DEPLOYMENT_GUIDE.md Part 2, step 12)
#    - First time only: the DBA must have installed scripts\sql\tsg_*.sql (+ grants.sql) in EYShieldDB_Copy.

# 7. Start everything - one command, from the cii folder
.\run.ps1 -NoBrowser
#    It opens 6 windows - TSG api, worker, service_mapper, maintenance, reaper, beat - starts the monitoring tools
#    (Grafana, Flower, ...), waits up to 90 s and prints the /ready answer.
#    It uses .venv\Scripts\python.exe itself: no need to activate .venv first.
#    Good:  /ready: 200 ...
#    "Not reachable: mongo, sql, redis"     -> .env is not the UAT file (step 4), or the network is closed (step 1).
#                                              (Ignore its "Start-Service Memurai" hint: that is for the laptop.)
#    "The monitoring tools did not start"   -> only Grafana / Flower are missing; the API and the workers run (step 13).
#    "The <name> program has ended"         -> read the error in the window 'TSG <name>'.
#    "Already running" / "Port ... is in use" -> .\stop.ps1 first.
#
#    The API listens on 127.0.0.1:8000: only this machine can call it. Must other machines call it? Close the
#    'TSG api' window, then in this window (.venv activated):
#      python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers
#    and Windows Firewall must allow port 8000 inbound (the server admin opens it).

# 8. Check
.\run.ps1 status
#    each of the 6 must say "running", and /ready 200 with mongo/sql/redis true and a worker for every queue.
#    503 on /ready: the body says which store or queue is missing - fix that store, or read that worker's window.
#    In a browser on this machine:
#      http://localhost:8000/health  -> {"status": "ok"}
#      http://localhost:8000/docs    -> API documentation

# 9. Stop
.\stop.ps1
#    The workers finish their running jobs first (up to 60 s), then every window and the monitoring tools close.

# =====================================================================================================
# PART 3 - FIRST USE, MONITORING AND PROBLEMS
# For the python / celery commands below: a new Windows PowerShell window, cd to the cii folder,
# .venv\Scripts\Activate.ps1
# =====================================================================================================

# 10. PROBLEM: the AI calls fail
#    worker log shows  ai.call_unavailable / ProxyError 503 / ERR_CONNECT_FAIL 110 / ai_timed_out, or at
#    start  ai.gateway_route host=llmapi.govai.ae route=proxy  -> the AI calls go through the corporate proxy.
#    FIX 1: .env must have CII_AI_BYPASS_PROXY=true (step 4). Fix it, .\stop.ps1, .\run.ps1.
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

# 11. Create an API key (admin key = CII_ADMIN_API_KEY from .env). It is shown ONCE - copy it.
curl.exe -X POST http://localhost:8000/v1/tsg/api-clients -H "X-Admin-Key: <CII_ADMIN_API_KEY>" -H "Content-Type: application/json" -d "{\"name\":\"uat-test\",\"description\":\"uat\"}"
#    Business calls then send 4 headers: X-API-Key, X-User-Id, X-Entity-Id, X-Tenant-Id

# 12. External intelligence is ON in .env.uat - first time only. No key needed (no admin key, no API key).
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
#      CII_PROXY_URL=<the proxy of step 3> in .env, .\stop.ps1, .\run.ps1, refresh again. HTTP 5xx or 429 = the
#      source is busy, the next hourly check tries again.
#    On OpenShift use https://threatgen-api.apps.dda-desc-az1-01.desccii.local instead of http://localhost:8000
#    (add -k if this PC does not trust the cluster certificate).
#    ...snapshot_id must be set. EVIDENCE_SIMILARITY_THRESHOLD=50 is provisional (not calibrated on the UAT reranker).

# 13. Grafana + Flower (monitoring). .\run.ps1 starts them (step 7) and .\stop.ps1 stops them.
#    .\run.ps1 status lists them: 7 lines, each "ready" (Grafana, Prometheus, Alertmanager, Loki, Alloy, Flower, redis_exporter).
#    Open:
#      Grafana (start here)   http://localhost:3000/grafana/
#      Flower (celery jobs)   http://localhost:5555/flower/
#      Prometheus             http://localhost:9090/prometheus/
#      Alertmanager           http://localhost:9093/alertmanager/
#    Notes:
#      - The FIRST start downloads about 500 MB (github.com, dl.grafana.com). Behind the proxy: set the two $env:
#        lines of step 3 in the window before .\run.ps1. No internet at all: download on another machine and copy the
#        folder to %USERPROFILE%\.tsg\monitoring-v2
#      - Ports 3000, 5555, 9090, 9093 must be free (v1's monitoring uses the same ports - stop it first).
#      - Grafana's log panels read the log files in logs\ (CII_LOG_DIR=logs, as in .env.uat).
#      - LOGIN: Flower, Prometheus and Alertmanager need NO login. Grafana needs no login to look.
#        To change Grafana itself, log in as  admin  with the GRAFANA_ADMIN_PASSWORD line of .env; if that line is
#        empty or missing, the random password is in  %USERPROFILE%\.tsg\monitoring-v2\grafana-admin-password.txt
#      - SECURITY: anyone who can reach ports 3000, 5555, 9090, 9093 can read the numbers and logs and silence
#        alerts. Do not expose these ports beyond the people who need them.

# 14. Check that every celery worker is working (.venv activated)
python -c "from app.core.readiness import count_online_workers; from app.worker import ROUTED_QUEUES; print(count_online_workers(ROUTED_QUEUES))"
#    each of tsg_threats, tsg_scenarios, tsg_controls, tsg_remediation, tsg_servicemapper, tsg_maintenance, tsg_reaper must show at least 1 (wait up to 20 s after start)
celery -A app.worker inspect ping
#    must answer pong from scenarios@..., mapper@..., maintenance@... and reaper@...
celery -A app.worker inspect active_queues
#    scenarios@... serves tsg_threats + tsg_scenarios + tsg_controls + tsg_remediation; mapper@... serves tsg_servicemapper; maintenance@... serves
#    tsg_maintenance (intelligence refresh, embeddings builds); reaper@... serves tsg_reaper (the reaper, the controls retry sweep).
#    Each worker is named by its module:
#    its log file is logs/worker-<name>.log, and every job line carries module=<module> and worker=<name>@<host>.
#    Beat is not in these checks: about 1 minute after it starts, the 'TSG reaper' window must log tsg_reap, every minute.
#    Every job, queue and worker in one call (admin key; add &status=failed, &kind=tsg_map_services, &hours=72):
curl.exe -H "X-Admin-Key: <CII_ADMIN_API_KEY>" "http://localhost:8000/v1/admin/jobs?status=queued&status=running&status=failed"
#    One API call to its worker: take X-Request-ID from the API's answer, then
python scripts/debug_tools.py find <request id>
