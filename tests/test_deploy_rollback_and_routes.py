"""The rollback's label selects the monitoring proxy, its Service and its two Routes only, and no setting
reaches Flower as one of its own options."""

from tests.test_deploy import CONFIG_FILE, PROXY, SECRETS_FILE, YAML_FILES, _objects, _shared


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


def test_no_setting_reaches_flower_as_one_of_its_own_options() -> None:
    """No tsg-config or tsg-secrets key starts with FLOWER_, which Flower would read as its own option."""
    keys = {key for copy in _shared(CONFIG_FILE, "tsg-config").values() for key in copy}
    keys |= {key for copy in _shared(SECRETS_FILE, "tsg-secrets").values() for key in copy}
    assert keys and [key for key in keys if key.upper().startswith("FLOWER_")] == []
