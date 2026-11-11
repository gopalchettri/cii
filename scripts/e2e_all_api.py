"""Every API operation, end to end, against a running TSG (API, workers, MongoDB, SQL Server, Redis, the AI):
an API key, the library's vectors, the intel import, a run written, reviewed, regenerated and given its next
set, a promoted threat rejected again, plans (generated and manual) reviewed, regenerated and cancelled, a
service mapping, every job listed and an embeddings build cancelled, a second run cancelled and deleted, a
source withdrawn and approved again, the key revoked.
At the end, every operation the app's own OpenAPI lists is checked off ("51 of 51 operations called").

It keeps the main run (saved as TSG_RUN_ID in debug/.env, for scripts/scorecard.py) and rejects the threats
it promoted, so the library ends as it began. The intel switch and the source end as they began too,
also when a step fails: the switch is turned off again if it was off, and a source Legal has not approved is
neither withdrawn nor approved.

From the project folder: .venv\\Scripts\\python scripts\\e2e_all_api.py [--base http://localhost:8000]"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from debug_tools import set_debug_value  # noqa: E402  (scripts/ is on the path: this script's own folder)
from e2e_client import CALLED, FAILED, Api, job_settled, run_settled, wait  # noqa: E402

from app.core.constants import Header  # noqa: E402
from app.models.remediation.requests import PLAN_REQUEST_EXAMPLES  # noqa: E402

#: Operations left out on purpose, not "not called": a source Legal has not approved is never approved here.
SKIPPED: set[tuple[str, str]] = set()
RUN = "/v1/sessions/{session_id}"
PLAN = RUN + "/scenarios/{scenario_id}/treatment-plan"
MAPPING = "/v1/service-mapper/{mapping_id}"
REFRESH = "/v1/tsg/intel/refresh/{job_id}"
SOURCE = "/v1/tsg/intel/sources/{source}"
JOB = "/v1/admin/jobs/{job_id}"
USAGE = "/v1/ai-usage"


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


def start_run(api: Api, args: argparse.Namespace, systems: list[int]) -> str:
    body = {"asset_id": args.asset, "supporting_system_id": systems, "service_id": args.service}
    body |= {"sector_id": args.sector, "subsector_id": args.subsector}
    return api.call("POST", "/v1/sessions", (202,), idempotent=True, body=body)["session_id"]


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
    accepted, rejected = written[:2], written[2:3] or written[-1:]
    api.call("POST", RUN + "/accept", session_id=run, body={"scenario_ids": accepted})
    api.call("POST", RUN + "/scenarios/reject", session_id=run, body={"scenario_ids": rejected})
    wait(api, RUN, run_settled, 30, session_id=run)  # the accepted scenarios' controls
    api.call("POST", RUN + "/regenerate/scenarios", (202,), session_id=run, body={"scenario_ids": rejected})
    wait(api, RUN, run_settled, 30, session_id=run)
    api.call("POST", RUN + "/scenarios/next-set", (202, 409), session_id=run)  # 409: no path left
    wait(api, RUN, run_settled, 60, session_id=run)
    promote_and_reject(api, run, [item for item in results["scenarios"] if item.get("status") == "done"])
    return run, accepted


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
    for field in (
        "supporting_systems_applicable_to_risk",
        "supporting_systems_applicable_to_existing_controls",
    ):
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
    unnamed = [
        item for item in detail.get("activities", []) if not (item["activity"] and item["description"])
    ]
    if (
        unnamed
        or sum(item["total_ai_calls"] for item in detail.get("activities", [])) != start["total_ai_calls"]
    ):
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


def withdraw_and_approve(api: Api, source: str) -> None:
    """Only a source Legal approved is withdrawn and approved again. The health shows no approval: an
    approved source waits for its first data (`pending_sources`) or has had some; a withdrawal blanks it."""
    health = api.call("GET", "/v1/tsg/intel/health") or {}
    had_data = any(row["source"] == source and row["last_success_at"] for row in health.get("sources", []))
    if not had_data and source not in health.get("pending_sources", []):
        SKIPPED.update({("POST", SOURCE + "/revoke"), ("POST", SOURCE + "/approve")})
        print(f"      {source} is not approved: neither withdrawn nor approved")
        return
    try:
        api.call("POST", SOURCE + "/revoke", source=source)
    finally:  # approved again also when the withdrawal's answer never came (it waits for an index rebuild)
        approved = api.call("POST", SOURCE + "/approve", source=source) or {}
    if job := approved.get("refresh_job_id"):
        wait(api, REFRESH, job_settled, 30, job_id=job)


def coverage() -> int:
    """Every operation the app's OpenAPI lists, checked off; then the failures."""
    from app.main import app

    operations = {(method.upper(), path) for path, ops in app.openapi()["paths"].items() for method in ops}
    uncalled = operations - set(CALLED)
    missed = sorted(uncalled - SKIPPED)
    print(f"\n  {len(operations - uncalled)} of {len(operations)} operations called, {len(SKIPPED)} skipped")
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
        "--mapper-service-description",
        default="Generates electricity and dispatches it to the transmission grid.",
    )
    parser.add_argument("--mapper-sector", default="Energy")
    parser.add_argument("--mapper-subsector", default="Power")
    parser.add_argument("--mapper-entity-name", default="Example Utility")
    parser.add_argument("--source", default="cisa_kev", help="the intel source withdrawn and approved again")
    return parser.parse_args()


def main() -> int:
    args = arguments()
    identity = {Header.USER_ID: args.user, Header.ENTITY_ID: str(args.entity), Header.TENANT_ID: args.tenant}
    api = Api(args.base, identity)
    since = (datetime.now(UTC) - timedelta(hours=1)).isoformat()  # the hourly totals of this test and before
    try:
        print("Setup")
        client_id = setup(api)
        print("Run")
        run, accepted = review_run(api, args)
        print("Plans")
        plans(api, args, run, accepted[0])
        print("Service mapper")
        service_mapper(api, args)
        print("AI usage")
        ai_usage(api, run, since)
        print("Admin jobs")
        admin_jobs(api, run)
        print("Cancel and delete")
        cancel_and_delete(api, args)
        print("Intel source")
        withdraw_and_approve(api, args.source)
        print("Key")
        api.call("POST", "/v1/tsg/api-clients/{client_id}/revoke", admin=True, client_id=client_id)
        api.call("GET", "/v1/jobs", (401,))  # the revoked key no longer works
    finally:  # the switch ends as it began, also after a step that failed (these routes take no key)
        if not api.intel_was_on:
            api.call("PUT", "/v1/tsg/intel/switch", body={"enabled": False})
    return coverage()


if __name__ == "__main__":
    sys.exit(main())
