"""The monitoring programs reach their pods: the guide reads the images from deploy_common.yaml and checks
that the cluster's own Quay login can pull each one, a refused push names the Quay right it lacks, both the
first deployment and the next release remove TSG's older monitoring in ai-common, and every ai-common pod that
writes a volume runs as its own ServiceAccount. Every explanation of the AI call limit says what 0 means."""

import re

from tests.test_deploy import COMMON_FILE, CONFIG_FILE, DEPLOY, MIRROR, MONITORING_NAMESPACE, REPO, _objects

GUIDE = DEPLOY / "DEPLOYMENT_GUIDE.md"
BUILD_SCRIPT = DEPLOY / "build-monitoring-images.bat"
RUNBOOK = REPO / "docs" / "UAT_LLM_TIMEOUT_RUNBOOK.md"
RULES = REPO / "observability" / "prometheus" / "rules.yml"
DASHBOARD = REPO / "observability" / "grafana" / "dashboards" / "tsg.json"
APP_IMAGE_NAME = "tsg-api"
#: The label on TSG's older monitoring copies in ai-common: TSG's, not the chatbot's.
OLD_MONITORING_LABEL = "app.kubernetes.io/part-of=tsg-observability"
#: The Routes the previous release put on the threatgen-grafana host in ai-common, deleted by label: a chatbot
#: Route there may have the same name.
OLD_COMMON_ROUTES = "oc -n ai-common delete route -l part-of=tsg-monitoring"
#: TSG's older monitoring copies and their Routes in ai-common.
OLD_MONITORING_DELETE = f"oc -n ai-common delete deployment,route -l {OLD_MONITORING_LABEL}"


def _quay_images() -> list[str]:
    """Every Quay image: line of deploy_common.yaml, each once, as build-monitoring-images.bat reads them."""
    found = re.findall(rf"^ *image: ({re.escape(MIRROR)}/\S+)", COMMON_FILE.read_text(encoding="utf-8"), re.M)
    return list(dict.fromkeys(found))


def _image_name(image: str) -> str:
    """The repository name of an image (or of a bare name:tag)."""
    return image.rpartition("/")[2].partition(":")[0]


def test_every_guide_command_that_lists_the_images_reads_them_all_from_deploy_common_yaml() -> None:
    """A list typed into the guide misses the next image: each pattern that reads deploy_common.yaml's image
    lines finds every monitoring image (the pull check the app image too), and no command quotes a name."""
    guide = GUIDE.read_text(encoding="utf-8")
    patterns = re.findall(r"-Pattern '([^']*dda-desc[^']*)'", guide)
    assert patterns
    lines = COMMON_FILE.read_text(encoding="utf-8").splitlines()
    monitoring = {_image_name(image) for image in _quay_images()} - {APP_IMAGE_NAME}
    found_by_pattern = []
    for pattern in patterns:
        # Select-String: the first match on each line, case ignored.
        found = {match[1] for line in lines if (match := re.search(pattern, line, re.IGNORECASE))}
        assert {_image_name(image) for image in found} >= monitoring, pattern
        found_by_pattern.append(found)
    assert set(_quay_images()) in found_by_pattern  # the pull check tries every image in full, the app's too
    assert [name for name in monitoring if f"'{name}'" in guide] == []


def test_a_refused_push_names_the_quay_right_it_lacks_not_the_login() -> None:
    """After a good docker login, Quay refuses ("denied" or "unauthorized") a push to a repository the user
    may not create, or may not write to: the script, the guide and the runbook said to log in again."""
    for path in (BUILD_SCRIPT, GUIDE, RUNBOOK):
        paragraphs = re.split(r"\n\s*\n", path.read_text(encoding="utf-8"))
        about_a_refused_push = [p for p in paragraphs if re.search(r"push (failed|that fails)", p)]
        assert about_a_refused_push, path.name
        assert all("cannot create" in p and "write to" in p for p in about_a_refused_push), path.name


def test_the_pull_check_neither_deletes_a_shared_login_unchecked_nor_turns_tls_off() -> None:
    """ai-common's quay-pull may be the chatbot's: step 6 compares it with ai-threatgen's (base64, so case
    counts) before it says to delete it, and never sends the cluster's login with TLS checks off."""
    guide = GUIDE.read_text(encoding="utf-8")
    step_6 = guide[guide.index("### Step 6.") : guide.index("### Step 7.")]
    compared = step_6.index(f"$b = oc -n {MONITORING_NAMESPACE} get secret quay-pull")
    assert "-ceq" in step_6[compared:]
    assert compared < step_6.index(f"oc -n {MONITORING_NAMESPACE} delete secret quay-pull")
    assert "--insecure" not in step_6


def test_the_first_time_cleanup_removes_tsg_s_older_monitoring_in_ai_common() -> None:
    """An older release left TSG's monitoring in ai-common with other selectors, which "oc apply" cannot
    change, and Routes on the old address. Step 9 lists those copies, then deletes them and the old Routes;
    Part 5 names the old label as TSG's, not the chatbot's."""
    guide = GUIDE.read_text(encoding="utf-8")
    listed = guide.index(f"oc -n {MONITORING_NAMESPACE} get deployment -l {OLD_MONITORING_LABEL}")
    assert listed < guide.index(OLD_MONITORING_DELETE)
    assert OLD_COMMON_ROUTES in guide
    assert OLD_COMMON_ROUTES in COMMON_FILE.read_text(encoding="utf-8")  # its first-time header
    [immutable] = [line for line in guide.splitlines() if line.startswith("| `field is immutable`")]
    assert OLD_MONITORING_LABEL in immutable


def test_the_next_release_also_removes_tsg_s_older_monitoring_before_it_applies_deploy_common_yaml() -> None:
    """UAT is past its first deployment, so it takes Part 4: without the same cleanup there, its apply of
    deploy_common.yaml stops at "field is immutable" and the old Routes stay."""
    guide = GUIDE.read_text(encoding="utf-8")
    part_4 = guide[guide.index("## Part 4.") : guide.index("## Part 5.")]
    listed = part_4.index(f"oc -n {MONITORING_NAMESPACE} get deployment -l {OLD_MONITORING_LABEL}")
    deleted = part_4.index(OLD_MONITORING_DELETE)
    applied = part_4.index("oc apply -f deploy\\deploy_common.yaml")
    assert listed < deleted < applied
    every_release = part_4.index("**Then do** (every release)")  # a rollback brings the previous Routes back
    assert every_release < part_4.index(OLD_COMMON_ROUTES) < applied


def test_every_ai_common_pod_that_writes_a_volume_runs_as_its_own_service_account() -> None:
    """ai-common's default ServiceAccount is shared with the chatbot, whose team may give it another SCC
    (such as anyuid): OpenShift then sets no fsGroup, and Loki or Grafana cannot write its volume."""
    accounts = {
        account["metadata"]["name"]
        for account in _objects(COMMON_FILE, kind="ServiceAccount")
        if account["metadata"]["namespace"] == MONITORING_NAMESPACE
    }
    writers = []
    for deployment in _objects(COMMON_FILE, kind="Deployment"):
        name, pod = deployment["metadata"]["name"], deployment["spec"]["template"]["spec"]
        claims = [volume for volume in pod.get("volumes", []) if "persistentVolumeClaim" in volume]
        if deployment["metadata"]["namespace"] == MONITORING_NAMESPACE and claims:
            assert pod.get("serviceAccountName") == name, name
            assert name in accounts, name
            writers.append(name)
    assert {"prometheus", "loki", "grafana"} <= set(writers)


def test_an_ai_common_identity_without_rights_mounts_no_api_token() -> None:
    """A pod that never calls the OpenShift API carries no token for it (as Flower and the app pods)."""
    bound = {
        subject["name"]
        for binding in _objects(COMMON_FILE, kind="RoleBinding")
        for subject in binding["subjects"]
    }
    without_rights = {
        account["metadata"]["name"]: account.get("automountServiceAccountToken")
        for account in _objects(COMMON_FILE, kind="ServiceAccount")
        if account["metadata"]["name"] not in bound
    }
    assert set(without_rights) >= {"loki", "grafana"}
    assert [name for name, mounts in without_rights.items() if mounts is not False] == []


def test_every_explanation_of_the_ai_call_limit_says_tsg_backs_off_after_a_gateway_429() -> None:
    """At CII_MAX_CONCURRENT_AI_CALLS 0 there is no fixed limit, but TSG sets a shared one itself after a
    gateway 429, and tsg_ai_slots_cap shows it: a line saying "0 = no limit" sent the reader the wrong way."""
    for path in (CONFIG_FILE, RULES, DASHBOARD, GUIDE):
        lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if "CII_MAX_CONCURRENT_AI_CALLS" in line
        ]
        assert lines, path.name
        assert [line.strip()[:80] for line in lines if "429" not in line] == [], path.name
