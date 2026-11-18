"""Every ai-common pod that writes a volume runs as its own ServiceAccount, and an identity without rights
mounts no API token."""

from tests.test_deploy import COMMON_FILE, MONITORING_NAMESPACE, _objects


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
        subject["name"] for binding in _objects(COMMON_FILE, kind="RoleBinding") for subject in binding["subjects"]
    }
    without_rights = {
        account["metadata"]["name"]: account.get("automountServiceAccountToken")
        for account in _objects(COMMON_FILE, kind="ServiceAccount")
        if account["metadata"]["name"] not in bound
    }
    assert set(without_rights) >= {"loki", "grafana"}
    assert [name for name, mounts in without_rights.items() if mounts is not False] == []
