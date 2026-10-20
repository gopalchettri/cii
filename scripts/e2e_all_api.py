"""Every API operation, end to end, against a running TSG (API, workers, MongoDB, SQL Server, Redis, the AI):
an API key, the library's vectors, the intel import, a run written, reviewed, regenerated and given its next
set, a promoted threat rejected again, plans (generated and manual) reviewed, regenerated and cancelled, a
service mapping, a second run cancelled and deleted, a source withdrawn and approved again, the key revoked.
At the end, every operation the app's own OpenAPI lists is checked off ("45 of 45 operations called").

It keeps the main run (saved as TSG_RUN_ID in debug/.env, for scripts/scorecard.py) and rejects the threats
it promoted, so the library ends as it began. The intel switch and the source end as they began too,
also when a step fails: the switch is turned off again if it was off, and a source Legal has not approved is
neither withdrawn nor approved.

From the project folder: .venv\\Scripts\\python scripts\\e2e_all_api.py [--base http://localhost:8000]"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from debug_tools import set_debug_value  # noqa: E402  (scripts/ is on the path: this script's own folder)
from e2e_client import CALLED, FAILED, Api  # noqa: E402

from app.core.constants import Header  # noqa: E402
from app.models.remediation.examples import PLAN_REQUEST_EXAMPLES  # noqa: E402

#: Operations left out on purpose, not "not called": a source Legal has not approved is never approved here.
SKIPPED: set[tuple[str, str]] = set()
RUN = "/v1/sessions/{session_id}"
PLAN = RUN + "/scenarios/{scenario_id}/treatment-plan"
MAPPING = "/v1/service-mapper/{mapping_id}"
REFRESH = "/v1/tsg/intel/refresh/{job_id}"
SOURCE = "/v1/tsg/intel/sources/{source}"


def wait(api: Api, template: str, settled: Callable[[Any], bool], minutes: int, **given: Any) -> Any:
    """Reads `template` every 10 s, printing each new state, until `settled`; a timeout is a failure, and an
    unexpected status stops the wait (already a failure)."""
    deadline, last, body = time.monotonic() + minutes * 60, None, None
    while time.monotonic() < deadline:
        body = api.call("GET", template, quiet=True, **given)
        if CALLED[("GET", template)] != 200:
            return body
        if (state := json.dumps(_state(body), default=str)) != last:
            print(f"      {next(part for part in reversed(template.split('/')) if '{' not in part)}: {state}")
            last = state
        if settled(body):
            return body
        time.sleep(10)
    FAILED.append(f"GET {template}: not settled in {minutes} min")
    return body


def _state(body: dict[str, Any]) -> dict[str, Any]:
    progress = body.get("progress")
    if isinstance(progress, dict):
        keys = ("threats", "scenarios", "controls", "overall", "generation")
        return {key: progress[key] for key in keys if progress.get(key) is not None}
    return {key: body[key] for key in ("status", "latest_status") if key in body}


def run_settled(body: dict[str, Any]) -> bool:
    return body.get("progress", {}).get("overall") not in ("pending", "in_progress")


def job_settled(body: dict[str, Any]) -> bool:
    return body.get("status") in ("done", "failed", "cancelled")


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


def plans(api: Api, args: argparse.Namespace, run: str, scenario: str) -> None:
    """A generated plan reviewed, regenerated and cancelled; a manual one requested; both registers read."""
    generated, manual = (json.loads(json.dumps(example)) for example in PLAN_REQUEST_EXAMPLES)
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
    systems = args.systems[:2]
    manual["manual_scenario"] |= {"asset_id": args.asset, "entity_id": args.entity}
    manual["manual_scenario"]["supporting_system_id"] = systems
    del manual["manual_scenario"]["mapped_controls"]  # the example's control code is not in every library
    api.call("POST", "/v1/remediation", (202,), idempotent=True, body=manual)


def service_mapper(api: Api, args: argparse.Namespace) -> None:
    api.call("GET", "/v1/entities/{listed_entity_id}/services", listed_entity_id=args.entity)
    body = {
        "service_name": args.mapper_service_name,
        "service_description": args.mapper_service_description,
        "sector": args.mapper_sector,
        "subsector": args.mapper_subsector,
        "entity_names": [args.mapper_entity_name],
    }
    mapping = api.call("POST", "/v1/service-mapper", (202,), idempotent=True, body=body)["mapping_id"]
    api.call("GET", "/v1/service-mapper")
    api.first_event(MAPPING + "/events", mapping_id=mapping)
    done = wait(api, MAPPING, job_settled, 20, mapping_id=mapping) or {}
    if done.get("status") != "done":
        FAILED.append("service mapper: generation did not complete")
        return
    directions = (("upstream_services", ("upstream",)), ("downstream_services", ("downstream",)))
    directions += (("bidirectional_services", ("upstream", "downstream")),)
    relationships = [(i["dependency_id"], d) for f, ds in directions for i in done.get(f, []) for d in ds]
    if relationships:  # the mapping is accepted only once every relationship has its own decision
        api.call("POST", MAPPING + "/decision", (409,), body={"action": "accept"}, mapping_id=mapping)
    for dependency_id, direction in relationships or [("missing", "upstream")]:
        api.call(
            "POST",
            MAPPING + "/dependencies/{dependency_id}/decision",
            (200,) if relationships else (404,),
            body={"direction": direction, "action": "accept"},
            mapping_id=mapping,
            dependency_id=dependency_id,
        )
    api.call("POST", MAPPING + "/decision", body={"action": "accept"}, mapping_id=mapping)
    api.call("POST", MAPPING + "/regenerate", (202,), idempotent=True, mapping_id=mapping)
    wait(api, MAPPING, job_settled, 20, mapping_id=mapping)


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
    try:
        print("Setup")
        client_id = setup(api)
        print("Run")
        run, accepted = review_run(api, args)
        print("Plans")
        plans(api, args, run, accepted[0])
        print("Service mapper")
        service_mapper(api, args)
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
