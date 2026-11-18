"""Every API operation, end to end, against a running TSG (API, workers, MongoDB, SQL Server, Redis, the AI):
an API key, the library's vectors, the intel import, its schedule changed and put back, the ATT&CK
mitigations linked to library controls, a run written, reviewed, regenerated and given its next set, a
promoted threat rejected again, plans (generated and manual) reviewed, regenerated and cancelled, a service
mapping, a run the AI writes from MITRE ATT&CK (POST /v1/create_session) checked and reviewed the same way,
every job listed and an embeddings build cancelled, a second run cancelled and deleted, the key revoked.
At the end, every operation the app's own OpenAPI lists is checked off ("N of N operations called").

It keeps the main run (saved as TSG_RUN_ID in debug/.env, for scripts/scorecard.py) and rejects the threats
it promoted, so the library ends as it began; the ATT&CK run is deleted unless a check on it failed. The
intel switch and the import schedule end as they began too, also when a step fails: the switch is turned off
again if it was off, and the schedule is saved again as it was read.

From the project folder: .venv\\Scripts\\python scripts\\e2e_all_api.py [--base http://localhost:8000]"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from debug_tools import set_debug_value  # noqa: E402  (scripts/ is on the path: this script's own folder)
from e2e_client import CALLED, FAILED, Api, are_controls_settled, job_settled, run_settled, wait  # noqa: E402

from app.core.constants import Header  # noqa: E402
from app.schemas.remediation import PLAN_REQUEST_EXAMPLES  # noqa: E402

RUN = "/v1/sessions/{session_id}"
PLAN = RUN + "/scenarios/{scenario_id}/treatment-plan"
MAPPING = "/v1/service-mapper/{mapping_id}"
REFRESH = "/v1/tsg/intel/refresh/{job_id}"
JOB = "/v1/admin/jobs/{job_id}"
USAGE = "/v1/ai-usage"
SCHEDULE = "/v1/tsg/intel/schedule"
LINKS = "/v1/tsg/intel/control-links"
CREATE_SESSION = "/v1/create_session"
#: What an admin sets on the import schedule: the body of its PUT.
SCHEDULE_FIELDS = ("enabled", "frequency", "day_of_week", "time", "timezone")
TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")


def setup(api: Api) -> str:
    """Health, an API key, the vectors and the intel import. Returns the key's client id."""
    api.call("GET", "/health")
    if (ready := api.call("GET", "/ready", (200, 503))) and CALLED[("GET", "/ready")] != 200:
        raise SystemExit(f"  Not ready: {ready}. Start the API and the workers first.")
    name = {"name": f"e2e-{uuid.uuid4().hex[:6]}"}
    minted = api.call("POST", "/v1/tsg/api-clients", (201,), admin=True, body=name)
    api.key = minted["api_key"]
    api.call("GET", "/v1/tsg/api-clients", admin=True, params={"active": "true"})
    build = api.call("POST", "/v1/embeddings", (202,), admin=True)
    wait(api, "/v1/embeddings/{job_id}", job_settled, 30, admin=True, job_id=build["job_id"])
    api.intel_was_on = (api.call("GET", "/v1/tsg/intel/switch") or {}).get("runtime_enabled", True)
    api.call("PUT", "/v1/tsg/intel/switch", body={"enabled": True})
    refresh = api.call("POST", "/v1/tsg/intel/refresh", (202, 409), body={})  # 409: the switch queued one
    wait(api, REFRESH, job_settled, 60, job_id=refresh.get("job_id") or refresh["details"]["job_id"])
    health = api.call("GET", "/v1/tsg/intel/health")
    print(f"      snapshot {health.get('snapshot_id')}, no_data {health.get('no_data')}")
    return minted["client_id"]


def change_and_restore_schedule(api: Api) -> None:
    """The import schedule read, saved with a slot six days ahead (so nothing starts), read back, then saved
    again as it was read, also when a check fails."""
    before = api.call("GET", SCHEDULE) or {}
    if CALLED[("GET", SCHEDULE)] != 200:
        return
    slot = datetime.now(UTC).replace(second=0, microsecond=0) + timedelta(days=6)
    far = {"enabled": True, "frequency": "weekly", "day_of_week": slot.weekday()}
    far |= {"time": slot.strftime("%H:%M"), "timezone": "UTC"}
    try:
        api.call("PUT", SCHEDULE, body=far)
        saved = api.call("GET", SCHEDULE) or {}
        next_run = saved.get("next_run_at")
        if any(saved.get(name) != far[name] for name in far) or not next_run:
            FAILED.append(f"schedule: saved {far}, read back {saved}")
        elif datetime.fromisoformat(next_run) != slot:
            FAILED.append(f"schedule: next_run_at is {next_run}, the slot saved is {slot.isoformat()}")
    finally:
        restored = api.call("PUT", SCHEDULE, body={name: before.get(name) for name in SCHEDULE_FIELDS}) or {}
    if any(restored.get(name) != before.get(name) for name in SCHEDULE_FIELDS):
        FAILED.append(f"schedule: not restored: it was {before}, it is {restored}")
    print(
        f"      next run {before.get('next_run_at')}, changed to {slot.isoformat()}, now {restored.get('next_run_at')}"
    )


def prepare_control_links(api: Api) -> None:
    """The control links' summary, then a preparation (409: the import queued one) followed to done: its
    counts are numbers."""
    api.call("GET", LINKS)
    started = api.call("POST", LINKS + "/prepare", (202, 409)) or {}
    job_id = started.get("job_id") or (started.get("details") or {}).get("job_id")
    if not job_id:  # 409 with no job: the switch is off
        FAILED.append(f"control links: no preparation to follow: {started}")
        return
    job = wait(api, LINKS + "/{job_id}", job_settled, 60, job_id=job_id) or {}
    counts = job.get("result") or {}
    if job.get("status") != "done" or any(
        type(counts.get(name)) is not int for name in ("judged", "unchanged", "failed")
    ):
        FAILED.append(f"control links: preparation {job_id} is not done with its counts: {job}")
    print(f"      {counts}; {api.call('GET', LINKS, quiet=True)}")


def run_request(args: argparse.Namespace, systems: list[int]) -> dict[str, Any]:
    """The body both start routes take."""
    body = {"asset_id": args.asset, "supporting_system_id": systems, "service_id": args.service}
    return body | {"sector_id": args.sector, "subsector_id": args.subsector}


def start_run(api: Api, args: argparse.Namespace, systems: list[int]) -> str:
    return api.call("POST", "/v1/sessions", (202,), idempotent=True, body=run_request(args, systems))["session_id"]


def review_run(api: Api, args: argparse.Namespace) -> tuple[str, list[str]]:
    """The main run written and reviewed. Returns its id and the scenarios accepted."""
    run = start_run(api, args, args.systems)
    set_debug_value("TSG_RUN_ID", run)
    print(f"      run {run} (saved as TSG_RUN_ID)")
    api.first_event(RUN + "/events", session_id=run)
    api.call("GET", "/v1/jobs")
    wait(api, RUN, run_settled, 60, session_id=run)
    results = api.call("GET", RUN + "/results", session_id=run)
    api.call("GET", RUN + "/plan-trace", session_id=run)
    written = [item["scenario_id"] for item in results["scenarios"] if item.get("status") == "done"]
    print(f"      {len(written)} written of {len(results['scenarios'])}")
    if not written:
        raise SystemExit("  No scenario was written: nothing to review.")
    api.call("GET", RUN + "/scenarios/{scenario_id}", session_id=run, scenario_id=written[0])
    api.call("GET", "/v1/entities/{listed_entity_id}/scenarios", listed_entity_id=args.entity)
    accepted = decide_and_extend(api, run, written)
    promote_and_reject(api, run, [item for item in results["scenarios"] if item.get("status") == "done"])
    return run, accepted


def decide_and_extend(
    api: Api, run: str, written: list[str], settled: Callable[[Any], bool] = run_settled
) -> list[str]:
    """Two scenarios accepted, one rejected and written again, then the next set, each followed until
    `settled`. Returns the scenarios accepted."""
    accepted, rejected = written[:2], written[2:3] or written[-1:]
    api.call("POST", RUN + "/accept", session_id=run, body={"scenario_ids": accepted})
    api.call("POST", RUN + "/scenarios/reject", session_id=run, body={"scenario_ids": rejected})
    wait(api, RUN, settled, 30, session_id=run)  # the accepted scenarios' controls
    api.call("POST", RUN + "/regenerate/scenarios", (202,), session_id=run, body={"scenario_ids": rejected})
    wait(api, RUN, settled, 30, session_id=run)
    api.call("POST", RUN + "/scenarios/next-set", (202, 409), session_id=run)  # 409: no path left
    wait(api, RUN, settled, 60, session_id=run)
    return accepted


def review_attack_run(api: Api, args: argparse.Namespace) -> None:
    """A run the AI writes from MITRE ATT&CK (POST /v1/create_session): written, reviewed, regenerated, given
    its next set and its promoted threat rejected, as the main run; deleted unless a check on it failed."""
    failures = len(FAILED)
    body = run_request(args, args.systems)
    started = api.call("POST", CREATE_SESSION, (202, 409), idempotent=True, body=body) or {}
    if CALLED[("POST", CREATE_SESSION)] == 409:
        no_data = started.get("reason") == "intel_no_data"
        why = "import the ATT&CK data first (POST /v1/tsg/intel/refresh)" if no_data else json.dumps(started)[:300]
        FAILED.append(f"create_session: not started: {why}")
        print(f"      not started: {why}")
    if not (run := started.get("session_id")):
        return
    wait(api, RUN, are_controls_settled, 60, session_id=run)
    results = api.call("GET", RUN + "/results", session_id=run) or {}
    written = [item for item in results.get("scenarios", []) if item.get("status") == "done"]
    print(f"      run {run}: {len(written)} written of {len(results.get('scenarios', []))}")
    if written:
        api.call("GET", RUN + "/plan-trace", session_id=run)
        api.call("GET", RUN + "/scenarios/{scenario_id}", session_id=run, scenario_id=written[0]["scenario_id"])
        decide_and_extend(api, run, [item["scenario_id"] for item in written], are_controls_settled)
        promote_and_reject(api, run, written)
    check_attack_scenarios(api, run)
    if len(FAILED) == failures:
        api.call("DELETE", RUN, session_id=run)
    else:
        print(f"      run {run} is kept: a check on it failed")


def check_attack_scenarios(api: Api, run: str) -> None:
    """Every scenario the run shows now names its ATT&CK group, cites a technique and has its controls."""
    shown = api.call("GET", RUN + "/results", session_id=run, params={"include_replaced": "false"}) or {}
    written = [item for item in shown.get("scenarios", []) if item.get("status") == "done"]
    if not written:
        FAILED.append(f"create_session: run {run} shows no written scenario: {shown.get('error')}")
    for item in written:
        cited = [str(entry.get("ref")) for entry in item.get("evidence") or []]
        techniques = [ref for ref in cited if TECHNIQUE_ID.fullmatch(ref)]
        state = f"group {item.get('actor')}, techniques {techniques}, controls {item.get('controls_status')}"
        print(f"      {item['scenario_id']}: {state}, {len(item.get('controls') or [])} control(s)")
        if not (item.get("actor") and techniques and item.get("controls_status") == "done"):
            FAILED.append(f"create_session: scenario {item['scenario_id']} of run {run}: {state}")


def promote_and_reject(api: Api, run: str, written: list[dict[str, Any]]) -> None:
    """An AI-written threat proposed to the library, then rejected by the curator: the library is unchanged.
    With none in the run, a library threat is proposed, which the API refuses."""
    ai_written = [item for item in written if (item.get("threat") or {}).get("is_threat_ai_generated")]
    target = (ai_written or written)[0]["scenario_id"]
    expect = (200,) if ai_written else (200, 409, 422)
    path = RUN + "/scenarios/{scenario_id}/promote-to-library"
    promoted = api.call("POST", path, expect, session_id=run, scenario_id=target) or {}
    ids = {item.get("threat_catalogue_id") for item in promoted.get("results", [])} - {None}
    pending = api.call("GET", "/v1/tsg/library/pending", admin=True) or {}
    ours = [item["catalogue_id"] for item in pending.get("items", []) if item["catalogue_id"] in ids]
    body = {"approve": [], "reject": ours}
    api.call("POST", "/v1/tsg/library/decisions", (200,) if ours else (200, 422), admin=True, body=body)


def plan_request_example(args: argparse.Namespace, kind: int) -> dict[str, Any]:
    """A published plan request (0 generated, 1 hand-written) on this run's asset: the systems it names (no
    real asset has them) become --systems in the order the risk lists them, cycled when fewer are given."""
    body = json.loads(json.dumps(PLAN_REQUEST_EXAMPLES[kind]))
    named = body["supporting_systems_applicable_to_risk"]
    on_asset = {system: args.systems[i % len(args.systems)] for i, system in enumerate(named)}
    for field in ("supporting_systems_applicable_to_risk", "supporting_systems_applicable_to_existing_controls"):
        body[field] = [on_asset[system] for system in body[field]]
    return body


def manual_plan_request(args: argparse.Namespace) -> dict[str, Any]:
    """The published hand-written example on this run's asset, its scenario on the first --systems."""
    manual = plan_request_example(args, 1)
    scenario = manual["manual_scenario"]
    on_asset = dict(zip(scenario["supporting_system_id"], args.systems, strict=False))
    scenario |= {"asset_id": args.asset, "entity_id": args.entity}
    scenario["supporting_system_id"] = list(on_asset.values())
    del scenario["mapped_controls"]  # the example's control code is not in every library
    return manual


def plans(api: Api, args: argparse.Namespace, run: str, scenario: str) -> None:
    """A generated plan reviewed, regenerated and cancelled; a manual one requested; both registers read."""
    generated = plan_request_example(args, 0)
    ids = {"session_id": run, "scenario_id": scenario}
    api.call("POST", "/v1/remediation", (202,), idempotent=True, body=generated | ids)
    plan_settled = lambda body: body.get("progress", {}).get("overall") != "generating"  # noqa: E731
    wait(api, PLAN + "/status", plan_settled, 30, **ids)
    api.call("GET", PLAN, **ids)
    api.first_event(PLAN + "/events", **ids)
    api.call("POST", PLAN + "/review", body={"decision": "accepted", "comment": "e2e"}, **ids)
    api.call("POST", PLAN + "/regenerate", (202,), body={}, **ids)
    api.call("POST", PLAN + "/cancel", (200, 409), **ids)  # 409: version 2 finished first
    api.call("GET", RUN + "/treatment-plans", session_id=run)
    api.call("GET", "/v1/entities/{listed_entity_id}/treatment-plans", listed_entity_id=args.entity)
    api.call("POST", "/v1/remediation", (202,), idempotent=True, body=manual_plan_request(args))


def service_mapper(api: Api, args: argparse.Namespace) -> None:
    api.call("GET", "/v1/entities/{listed_entity_id}/services", listed_entity_id=args.entity)
    body = {
        # A mapping of its own each run, so its run and regenerate always start (a mapping whose last run
        # found nothing new starts no run again); the tag in brackets keeps the catalog name match.
        "service_name": f"{args.mapper_service_name} (E2E {uuid.uuid4().hex[:6]})",
        "service_description": args.mapper_service_description,
        "sector": args.mapper_sector,
        "subsector": args.mapper_subsector,
        "entity_names": [args.mapper_entity_name],
    }
    mapping = api.call("POST", "/v1/service-mapper", (202,), idempotent=True, body=body)["mapping_id"]
    api.call("GET", "/v1/service-mapper")
    api.call("GET", MAPPING + "/status", mapping_id=mapping)
    api.first_event(MAPPING + "/events", mapping_id=mapping)
    done = wait(api, MAPPING, job_settled, 20, mapping_id=mapping) or {}
    if done.get("status") != "done":
        FAILED.append("service mapper: generation did not complete")
        return
    lists = ("upstream_services", "downstream_services")
    ids = [item["dependency_id"] for name in lists for item in done.get(name, [])]
    # Every relationship in one call; with none, an unknown id comes back in `failed`.
    body = {"accept": ids or ["missing"], "reject": [""]}
    decided = api.call("POST", MAPPING + "/dependencies/decision", body=body, mapping_id=mapping) or {}
    reasons = [failure["reason"] for failure in decided.get("failed", [])]
    if reasons != ([] if ids else ["dependency_not_found"]):
        FAILED.append(f"service mapper: relationship decisions not saved: {reasons}")
    # A run that found nothing new is not run again: 200 with the mapping as it is.
    api.call("POST", MAPPING + "/regenerate", (202,) if ids else (200,), idempotent=True, mapping_id=mapping)
    wait(api, MAPPING, job_settled, 20, mapping_id=mapping)


def ai_usage(api: Api, run: str, since: str) -> None:
    """The run's AI calls per request (start, regenerate, next set, its plans), one request's activities and
    every call, each agreeing with the others; then the hourly totals (no key on any of them)."""
    listed = api.call("GET", USAGE + "/requests", params={"session_id": run}) or {}
    by_api = {item["api"]: item for item in listed.get("items", [])}
    for wanted in ("create_scenario", "create_plan"):
        if not (by_api.get(wanted) or {}).get("total_ai_calls"):
            FAILED.append(f"ai usage: no AI call counted for {wanted} in run {run}: {sorted(by_api)}")
    start = by_api.get("create_scenario") or {}
    parts = start.get("buckets", {})
    quiet = [part for part in ("threats", "scenario") if start and not parts[part]["total_ai_calls"]]
    # threat finding answers a question an earlier run asked word for word with that answer (D70): no call
    if quiet and quiet != (["threats"] if start.get("reused_answers") else []):
        FAILED.append(f"ai usage: a part of the run's start counted no call: {start['buckets']}")
    summary = listed.get("summary") or {}
    if summary.get("total_ai_calls") != sum(item["total_ai_calls"] for item in listed.get("items", [])):
        FAILED.append(f"ai usage: the session's total is not its requests' sum: {summary}")
    if not start:
        return
    detail = api.call("GET", USAGE + "/requests/{request_id}", request_id=start["request_id"]) or {}
    unnamed = [item for item in detail.get("activities", []) if not (item["activity"] and item["description"])]
    if unnamed or sum(item["total_ai_calls"] for item in detail.get("activities", [])) != start["total_ai_calls"]:
        FAILED.append(f"ai usage: the start's activities do not add up or lack a name: {unnamed}")
    calls = api.call("GET", USAGE + "/calls", params={"request_id": start["request_id"], "limit": 500}) or {}
    attempts = [call for call in calls.get("items", []) if call["outcome"] != "reused"]
    if len(attempts) != start["total_ai_calls"] or any("prompt" in call for call in calls.get("items", [])):
        FAILED.append(f"ai usage: {len(attempts)} calls listed, {start['total_ai_calls']} counted")
    totals_ready = lambda body: any(  # noqa: E731 - the hourly add-up runs every 5 minutes
        item["key"].get("api") == "create_scenario" and item["total_ai_calls"] >= start["total_ai_calls"]
        for item in body.get("items", [])
    )
    totals = wait(api, USAGE, totals_ready, 7, params={"since": since, "group_by": ["module", "api"]})
    if not totals_ready(totals or {}):
        FAILED.append("ai usage: the hourly totals never counted the run's start")


def admin_jobs(api: Api, run: str) -> None:
    """Every job listed, the main run among them; the run read by its id; an embeddings build cancelled at
    once (409: it ended first)."""
    listed = api.call("GET", "/v1/admin/jobs", admin=True, params={"module": "threat_scenarios"}) or {}
    if run not in {job["id"] for job in listed.get("jobs", [])}:
        FAILED.append(f"admin jobs: the run {run} is not listed")
    api.call("GET", JOB, admin=True, job_id=run)
    build = api.call("POST", "/v1/embeddings", (202,), admin=True)
    api.call("POST", JOB + "/cancel", (200, 409), admin=True, job_id=build["job_id"])
    wait(api, "/v1/embeddings/{job_id}", job_settled, 30, admin=True, job_id=build["job_id"])


def cancel_and_delete(api: Api, args: argparse.Namespace) -> None:
    """A second run, on one system, cancelled at once and deleted for good."""
    run = start_run(api, args, args.systems[:1])
    api.call("POST", RUN + "/cancel", session_id=run)
    wait(api, RUN, run_settled, 10, session_id=run)
    api.call("DELETE", RUN, session_id=run)


def coverage() -> int:
    """Every operation the app's OpenAPI lists, checked off; then the failures."""
    from app.main import app

    operations = {(method.upper(), path) for path, ops in app.openapi()["paths"].items() for method in ops}
    missed = sorted(operations - set(CALLED))
    print(f"\n  {len(operations) - len(missed)} of {len(operations)} operations called")
    for method, path in missed:
        print(f"    not called: {method} {path}")
    print(f"  {len(FAILED)} failure(s)")
    for failure in FAILED:
        print(f"    {failure}")
    return 0 if not missed and not FAILED else 1


def arguments() -> argparse.Namespace:
    """The run's inputs: by default the asset the earlier E2E runs used (entity 125, asset 1166)."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="http://localhost:8000")
    parser.add_argument("--user", default="e2e-tester")
    parser.add_argument("--entity", type=int, default=125)
    parser.add_argument("--tenant", default="DESC")
    parser.add_argument("--asset", type=int, default=1166)
    numbers = lambda text: [int(n) for n in text.split(",")]  # noqa: E731
    parser.add_argument("--systems", type=numbers, default=[1448, 1449, 1450, 1451])
    parser.add_argument("--service", type=int, default=1546)
    parser.add_argument("--sector", type=int, default=183)
    parser.add_argument("--subsector", type=int, default=199)
    parser.add_argument("--mapper-service-name", default="Power Generation System")
    parser.add_argument(
        "--mapper-service-description", default="Generates electricity and dispatches it to the transmission grid."
    )
    parser.add_argument("--mapper-sector", default="Energy")
    parser.add_argument("--mapper-subsector", default="Power")
    parser.add_argument("--mapper-entity-name", default="Example Utility")
    return parser.parse_args()


def main() -> int:
    args = arguments()
    identity = {Header.USER_ID: args.user, Header.ENTITY_ID: str(args.entity), Header.TENANT_ID: args.tenant}
    api = Api(args.base, identity)
    since = (datetime.now(UTC) - timedelta(hours=1)).isoformat()  # the hourly totals of this test and before
    try:
        print("Setup")
        client_id = setup(api)
        print("Intel schedule")
        change_and_restore_schedule(api)
        print("Control links")
        prepare_control_links(api)
        print("Run")
        run, accepted = review_run(api, args)
        print("Plans")
        plans(api, args, run, accepted[0])
        print("Service mapper")
        service_mapper(api, args)
        print("ATT&CK run")
        review_attack_run(api, args)
        print("AI usage")
        ai_usage(api, run, since)
        print("Admin jobs")
        admin_jobs(api, run)
        print("Cancel and delete")
        cancel_and_delete(api, args)
        print("Key")
        api.call("POST", "/v1/tsg/api-clients/{client_id}/revoke", admin=True, client_id=client_id)
        api.call("GET", "/v1/jobs", (401,))  # the revoked key no longer works
    finally:  # the switch ends as it began, also after a step that failed (these routes take no key)
        if not api.intel_was_on:
            api.call("PUT", "/v1/tsg/intel/switch", body={"enabled": False})
    return coverage()


if __name__ == "__main__":
    sys.exit(main())
