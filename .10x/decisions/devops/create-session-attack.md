# devops: create-session-attack (17 Nov 2026)

- No new pod, queue, Service, Route or network rule. `tsg_link_mitigations` is routed to `tsg_maintenance`
  (`worker-maintenance`); the write and pick calls run in the existing `worker-scenarios` and `worker-controls`. Every
  app pod already has the AI gateway's host alias, `NO_PROXY` entry and network rule.
- Beat: the intelligence entry is now a check every 60 s (expires after 180 s), only while
  `EXTERNAL_INTELLIGENCE_ENABLED` is true; the saved schedule decides whether a check imports. No change to the beat
  Deployment or its command.
- `/ui/` is served by the API pods from `app/ui` (the Dockerfile copies `app/` whole); the API's Route (`path: /`)
  already covers it.
- `deploy/configmap.yaml`: two lines added beside the other answer-token settings,
  `CII_ANSWER_TOKENS_LINK_CONTROLS: "2048"` and `CII_ANSWER_TOKENS_PICK_CONTROLS: "3072"` (the code's defaults, the
  same as the three `.env` example files). `deploy/deploy_threatgen.yaml`: the maintenance worker's heading comment
  names the control links. Nothing else in `deploy/*.yaml` changed. Deploy and settings tests after the change: 131
  passed, 1 failed (the owner's local `.env.uat` still holds `CII_NVD_API_KEY`; not from this change).
- Release steps written in `deploy/DEPLOYMENT_GUIDE.md` (Part 4): the database team installs the updated
  `scripts/sql/tsg_GetAssetContext.sql` on each SQL Server (nobody deploying TSG has that access); at beat's first
  check, about a minute after the roll-out, one import runs by itself, then the linking (about 100 AI calls once, an estimate).
- Contract pin `tests/contract/celery.json` (the new task and the 60-second entry) is the lead's to rewrite.

Left for the owner: the line `CII_NVD_API_KEY` in the git-ignored `deploy/secrets.yaml` and `.env.uat` names a feed
that is gone; the app ignores it. Not verified: a roll-out on OpenShift; CPU and memory of `worker-maintenance`
(100m/250m) and `worker-controls` (250m/500m) during a linking run or a pick call were not measured.
