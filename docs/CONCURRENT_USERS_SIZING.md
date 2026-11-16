# Sizing TSG for the number of users

When the number of users who press Start at the same time changes, only settings change. No code changes.
N below means the number of users at the same time.

## 1. The settings that follow N

| Setting | Rule | 5 users | 10 users | 15 users | What it controls |
|---|---|---|---|---|---|
| `CII_SCENARIO_MAX_CONCURRENT_AI_CALLS` | 4 x N | 20 | 40 | 60 | threat-scenario AI calls (kimi-k2.5) at once, all users together: each Start asks about 4 threat questions at once |
| `CII_REMEDIATION_MAX_CONCURRENT_AI_CALLS` | N | 5 | 10 | 15 | remediation plans at once (one glm-5.3 call each) |
| `CII_SERVICE_MAPPER_MAX_CONCURRENT_AI_CALLS` | N | 5 | 10 | 15 | service mappings at once (one glm-5.3 call each) |
| `CII_WORKER_THREADS` (UAT server only) | 3 x N | 15 | 30 | 45 | threads of `run.ps1`'s job worker; a thread mostly waits for the AI |

**Set by the reranker, not by N.** Measure it with the owner's probe (`litellm_probe_oc.py`, which steps up the calls
sent at once):

| Setting | Rule | UAT (16 Nov 2026) | What it controls |
|---|---|---|---|
| `CII_MAX_CONCURRENT_AI_CALLS` | the reranker's best "at once", below the step that failed | 8 (best speed at 8, 10 worked, 12 dropped a connection) | every reranker and embedding call at once, all processes together; the two models share it |
| `CII_RERANKS_AT_ONCE` | half of the line above | 4 | evidence reranks at once in one worker; control searches keep the other half |

With 8 at once the reranker finishes about 6.7 calls a second. One Start's first set makes about 12-24 reranks: 6
evidence searches, 6 control searches, and gap-fill matches. So 5 users who start together share about 10-20 s of
reranker time. To go faster, ask the gateway team for more reranker capacity, then measure again.

**OpenShift only:** the worker threads (`-c`) in `deploy/deploy_threatgen.yaml`.

| Worker | Rule | 5 users | 10 users | 15 users |
|---|---|---|---|---|
| `worker-threats`, `worker-scenarios`, `worker-controls` | N each (a run has one job of each at a time) | 5 | 10 | 15 |
| `worker-remediation` | plans at once + 2 | 7 | 12 | 17 |
| `worker-service-mapper` | mappings at once | 5 | 10 | 15 |

The OpenShift files now have `worker-controls` 4 for 10 users. It works, but some users wait a few extra seconds for
controls. They also have `CII_MAX_CONCURRENT_AI_CALLS` 0 (no cap) and `CII_RERANKS_AT_ONCE` 24: set them to the
reranker's measured values (8 and 4) before OpenShift serves users.

## 2. Check the gateway's budget

The gateway allows 2,000,000 tokens a minute, shared by every model. This must hold:

    1.5 x CII_SCENARIO_CHAT_TOKENS_PER_MINUTE + 21,000 x plans at once + 10,000 x mappings at once <= 2,000,000

| Users | With `CII_SCENARIO_CHAT_TOKENS_PER_MINUTE` 1000000 | Fits? |
|---|---|---|
| 5 | 1,500,000 + 105,000 + 50,000 = 1,655,000 | yes |
| 10 | 1,500,000 + 210,000 + 100,000 = 1,810,000 | yes |
| 15 | 1,500,000 + 315,000 + 150,000 = 1,965,000 | yes, just |
| 20 | 1,500,000 + 420,000 + 200,000 = 2,120,000 | **no**: set it to (2,000,000 - 31,000 x N) / 1.5, about 900000 |

Above about 15 users the budget, not TSG, sets the pace: the last users start some seconds later. Ask the gateway team
for a bigger budget.

Requests: each Start sends kimi-k2.5 about 8 requests. `CII_SCENARIO_CHAT_REQUESTS_PER_MINUTE` 180 covers up to about
20 users. kimi-k2.5's own limit is 600, so stay at or below about 570.

## 3. Rules to keep

- `CII_THREAT_QUESTIONS_AT_ONCE` (16) is per Start, not per user. It must stay at or below
  `CII_SCENARIO_MAX_CONCURRENT_AI_CALLS`. Below 4 users, set it to 4 x N; for OpenShift, `tests/test_deploy.py`
  checks this.
- These don't change with users:
  - `CII_THREATS_PER_QUESTION`
  - every `CII_ANSWER_TOKENS_*`
  - the 429 settings `CII_AI_BUSY_*`
  - `CII_RERANK_REQUESTS_PER_MINUTE` and `CII_EMBEDDING_REQUESTS_PER_MINUTE` (0: the gateway sets no per-minute limit)
  - `CII_MAX_CONCURRENT_AI_CALLS` and `CII_RERANKS_AT_ONCE` (the reranker's capacity: measure again if the gateway
    team changes the reranker)
- Pod CPU and memory were measured for up to 10 users (D80). Above that, watch the worker pods' CPU in Grafana.

## 4. Where to set them, and apply

- **UAT server:**
  1. Edit `.env.uat` (the source, kept off GitHub) and copy it to `.env` on the server.
  2. Run `.\run.ps1 stop`, then `.\run.ps1`.
  3. `run.ps1` sizes the remediation worker (plans + 2 threads) and the mapper worker (mappings) by itself.
  4. Keep the key-free copy `.env.uat.example` the same, with keys blank.
- **OpenShift:**
  1. Set the settings above in `deploy/configmap.yaml` and the threads in `deploy/deploy_threatgen.yaml`.
  2. Follow `deploy/DEPLOYMENT_GUIDE.md`, Part 5, "Change a setting or secret later". No new image is needed.
- **To measure the need from real runs:**

      python scripts/ai_capacity_report.py --base <api> --since <time> --users N --env-file .env.uat

UAT today (16 Nov 2026): the UAT server's `.env.uat` is set for 5 users, with the reranker capped at 8 calls at once
(evidence 4). The OpenShift files are still set for 10 users (D78-D80), with no reranker cap.
