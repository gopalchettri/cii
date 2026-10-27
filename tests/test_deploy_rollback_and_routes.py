"""The guide's commands that delete or roll back: a rollback first removes the monitoring proxy (oc apply of
the previous files never deletes it, and the API's update pod needs its room in ai-threatgen's quota), TSG's
Routes in the shared ai-common are deleted by label only, the pull check never leaves the cluster's login in
%TEMP%, and no setting reaches Flower as one of its own options."""

import re

from tests.test_deploy import COMMON_FILE, CONFIG_FILE, PROXY, SECRETS_FILE, YAML_FILES, _objects, _shared
from tests.test_deploy_monitoring_images import GUIDE

#: Every object a rollback must remove before it applies the previous release, and only those.
PROXY_DELETE = "oc -n ai-threatgen delete deployment,service,route -l part-of=tsg-monitoring"
#: The workers the previous release does not have: `oc apply` of its files leaves them running in the quota.
NEW_WORKER_DELETES = [
    "oc -n ai-threatgen delete deployment worker-reaper --ignore-not-found",
    "oc -n ai-remediation delete deployment worker-reaper --ignore-not-found",
]


def _section(start: str, end: str) -> str:
    """The guide's text from the heading `start` up to the heading `end`."""
    guide = GUIDE.read_text(encoding="utf-8")
    return guide[guide.index(start) : guide.index(end)]


def test_a_rollback_removes_the_monitoring_proxy_before_it_applies_the_previous_release() -> None:
    """A rollback frees the quota of the proxy and of the workers the previous release lacks, then loads the
    previous settings, app and monitoring rules."""
    rollback = _section("### Roll back to the previous release", "## Part 6.")
    removed = rollback.index(PROXY_DELETE)
    assert removed < rollback.index("Apply the previous") and removed < rollback.index("oc apply -f")
    worker_deletes = [line.strip() for line in rollback.splitlines() if "delete deployment worker" in line]
    assert worker_deletes == NEW_WORKER_DELETES
    assert max(rollback.index(line) for line in NEW_WORKER_DELETES) < rollback.index("oc apply -f")
    settings = rollback.index("oc apply -f deploy\\configmap.yaml")
    assert settings < rollback.index("oc apply -f deploy\\deploy_threatgen.yaml")
    restarted = rollback.index("oc -n ai-common rollout restart deployment -l part-of=tsg-monitoring")
    assert rollback.index("oc apply -f deploy\\deploy_common.yaml") < restarted  # rules load at start


def test_the_rollback_label_selects_the_proxy_its_service_and_its_two_routes_only() -> None:
    """In ai-threatgen, part-of=tsg-monitoring selects the proxy, its Service and its two Routes only."""
    kinds = {"Deployment", "Service", "Route"}
    selected = {
        (o["kind"], o["metadata"]["name"])
        for o in _objects(*YAML_FILES)
        if o["kind"] in kinds
        and o["metadata"]["namespace"] == "ai-threatgen"
        and o["metadata"].get("labels", {}).get("part-of") == "tsg-monitoring"
    }
    assert selected == {("Deployment", PROXY), ("Service", PROXY), ("Route", "grafana"), ("Route", "flower")}


def test_tsg_s_routes_in_the_shared_ai_common_are_deleted_by_label_never_by_name() -> None:
    """Every ai-common Route delete selects TSG's label, and Part 4 deletes each of TSG's two labels once."""
    for text in (GUIDE.read_text(encoding="utf-8"), COMMON_FILE.read_text(encoding="utf-8")):
        deletes = re.findall(r"oc -n ai-common delete \S*route\b.*", text)
        assert deletes and [line for line in deletes if " -l " not in line] == []
    part_4 = _section("## Part 4.", "## Part 5.")
    assert len(re.findall(r"oc -n ai-common delete \S*route\b", part_4)) == 2  # the older label, the previous


def test_step_9_keeps_every_route_this_release_puts_in_ai_threatgen() -> None:
    """Step 9's kept Routes in ai-threatgen are exactly the Routes the deploy files create there."""
    step_9 = _section("### Step 9.", "### Step 10.")
    [kept] = re.findall(r"in\s+`ai-threatgen`, any Route except ([^;]+);", step_9)
    routes = {o["metadata"]["name"] for o in _objects(*YAML_FILES, kind="Route")}
    assert set(re.findall(r"`([\w-]+)`", kept)) == routes == {"api", "grafana", "flower"}


def test_the_pull_check_deletes_the_cluster_s_login_file_even_when_stopped() -> None:
    """The pull check removes the cluster's login file in finally, so Ctrl+C cannot leave it in %TEMP%."""
    step_6 = _section("### Step 6.", "### Step 7.")
    check = step_6[step_6.index("Then check") :]
    assert re.search(r"\ntry \{\n(?:.*\n)*?.*oc image info.*\n\} finally \{ Remove-Item \$auth\b", check)
    assert not re.search(r"^Remove-Item \$auth", check, re.MULTILINE)


def test_no_setting_reaches_flower_as_one_of_its_own_options() -> None:
    """No tsg-config or tsg-secrets key starts with FLOWER_, which Flower would read as its own option."""
    keys = {key for copy in _shared(CONFIG_FILE, "tsg-config").values() for key in copy}
    keys |= {key for copy in _shared(SECRETS_FILE, "tsg-secrets").values() for key in copy}
    assert keys and [key for key in keys if key.upper().startswith("FLOWER_")] == []
