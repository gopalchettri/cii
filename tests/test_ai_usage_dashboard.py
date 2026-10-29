"""The "TSG — AI usage" dashboard (observability/grafana/dashboards/ai_usage.json): counts only, the reports'
own plain words, each API call tied to the route that starts it, and its links to the home page and to the
reports open what they name. Expected values come from the Python catalogues and the app, never typed in."""

import ast
import inspect
import json
import re
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml
from fastapi.routing import iter_route_contexts

from app.api.routers.ai_usage import router as reports_router
from app.core.constants import (
    ACTIVITY_INFO,
    API_INFO,
    BUCKET_INFO,
    AiApi,
    AiOutage,
    AiUsageOutcome,
    AiUsageReason,
    Module,
)
from tests.test_observability import DASHBOARD, OBS, _panels, _promtool

AI_DASHBOARD = OBS / "grafana" / "dashboards" / "ai_usage.json"
SERVICES = OBS.parent / "app" / "services"
#: The module whose API calls each service folder holds (app/services/<folder>).
SERVICE_FOLDER_MODULES = {
    "scenario": Module.THREAT_SCENARIOS,
    "remediation": Module.REMEDIATION,
    "service_mapper": Module.SERVICE_MAPPER,
}


def _dashboard(path: Path = AI_DASHBOARD) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _openapi() -> dict:
    from app.main import create_app

    return create_app().openapi()


def _column_settings(panel: dict) -> dict[str, dict]:
    """A table's per-column settings: raw column name -> {property id: value}, from its by-name overrides."""
    return {
        override["matcher"]["options"]: {prop["id"]: prop["value"] for prop in override["properties"]}
        for override in panel["fieldConfig"]["overrides"]
        if override["matcher"]["id"] == "byName"
    }


def _shown(mappings: list[dict]) -> dict[str, str]:
    """Value mappings as {value: shown text}."""
    return {
        value: shown["text"]
        for mapping in mappings
        if mapping["type"] == "value"
        for value, shown in mapping["options"].items()
    }


def _organize(panel: dict, option: str) -> dict:
    """One option of a table's organize step (excludeByName, renameByName...)."""
    return {
        name: value
        for step in panel.get("transformations", [])
        if step["id"] == "organize"
        for name, value in step["options"].get(option, {}).items()
    }


def _label_columns(panel: dict) -> set[str]:
    """The label columns a table shows: those its queries sum by or label_join into, less those it hides."""
    exprs = " ".join(target["expr"] for target in panel["targets"])
    labels = {
        label.strip() for group in re.findall(r"\bby \(([\w, ]+)\)", exprs) for label in group.split(",")
    }
    labels |= set(re.findall(r'"(\w+)", "/"', exprs))  # label_join(..., "<new label>", "/", ...)
    return labels - {name for name, hidden in _organize(panel, "excludeByName").items() if hidden}


def _called_names(function: object) -> set[str]:
    """The method names a function calls (x.name(...))."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def _origin_methods() -> dict[str, tuple[str | None, str]]:
    """Each service method that starts AI work: its name -> (module, api), from @origin_of_its_jobs."""
    found = {}
    for path in SERVICES.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for api, name in re.findall(r"@origin_of_its_jobs\(AiApi\.(\w+)\)\s+def (\w+)\(", source):
            found[name] = (SERVICE_FOLDER_MODULES.get(path.parent.name), AiApi[api].value)
    return found


def _links_to(source: Path, target: Path) -> list[str]:
    """Every address in dashboard `source` that opens dashboard `target`."""
    uid = re.escape(_dashboard(target)["uid"])
    return re.findall(rf'/grafana/d/{uid}/[^"\\\s)\]]*', json.dumps(_dashboard(source), ensure_ascii=False))


def test_the_page_shows_counts_only() -> None:
    """Catches a chart on the page (timeseries, bar chart...), a range query, or a per-second rate standing in
    for a count; only the write-time quantile reads rate(), as a histogram quantile must."""
    panels = _panels(AI_DASHBOARD)
    assert {panel["type"] for panel in panels} <= {"row", "text", "stat", "table"}
    for panel in panels:
        for target in panel.get("targets", []):
            where, expr = (panel["id"], target["refId"]), target["expr"]
            assert target.get("instant") is True and not target.get("range"), where
            rates = re.findall(r"\b(rate|irate|deriv)\(", expr)
            assert rates == [] or (rates == ["rate"] and expr.startswith("histogram_quantile(")), where


def test_every_count_takes_a_series_new_in_the_chosen_time_whole() -> None:
    """Review 2026-10-29: a counter appears at its first step, which increase() never sees, so each new
    series (a route's first API call, a model's first call, every series of a restarted pod) lost one: a live
    run showed 127 AI calls and 2 API calls for 204 and 9. Every count, here and on the home page's AI usage
    row, has all three parts: the exact rise, increase() for a series that existed before, and the highest
    value of one born in the chosen time. Mutation: count one query with increase() alone."""
    plain_counts = []
    for panel in [*_panels(AI_DASHBOARD), *_home_ai_row()]:
        for target in panel.get("targets", []):
            for selector in re.findall(r"increase\(([^\[]+)\[\$__range\]\)", target.get("expr", "")):
                existed = f"last_over_time({selector}[1h] offset $__range)"
                parts = (
                    f"({selector} - {selector} offset $__range) and resets({selector}[$__range]) == 0",
                    f"max_over_time({selector}[$__range]) unless {existed}",
                )
                if not all(part in target["expr"] for part in parts):
                    plain_counts.append((panel["id"], selector))
    assert plain_counts == []


#: Synthetic counters, one per case, every minute from 0 to 120: (values, its count in (60m, 120m]). A born
#: counter's first scrape already holds several calls, as live: one call a scrape would let increase()'s
#: extrapolation towards zero land on the right count by rounding.
COUNTER_CASES = {
    "steady": ("5+1x120", 60),
    "born in the range": ("_x70 4+4x50", 204),
    "born and gone in the range (a pod replaced)": ("_x70 5+5x10 stale", 55),
    "a failed scrape at the range's start": ("10+1x59 stale 71+1x59", 60),
    "a restart in the range": ("100+1x90 1+1x29", 60),
}


def _home_ai_row() -> list[dict]:
    return [panel for panel in _panels(DASHBOARD) if 66 <= panel["id"] <= 73]


@pytest.mark.parametrize("panel_id", [104, 66], ids=["ai usage page: AI calls", "home page: AI calls"])
def test_an_ai_calls_tile_counts_exactly_whatever_a_series_does_in_the_chosen_time(
    panel_id: int, tmp_path: Path
) -> None:
    """Review 2026-10-29: counting a series by its value at the range's two ends missed a pod born and gone
    within it (a rollout) and counted a series' whole life after one failed scrape at the start. The tile's
    real query runs in promtool over one synthetic counter per case (1h range at 120m). Mutations: count with
    increase() alone (a born counter loses its first call); look series up at the two ends only."""
    promtool = _promtool()
    if promtool is None:
        pytest.skip("promtool is not installed (python scripts/monitoring.py install)")
    [panel] = [panel for panel in [*_panels(AI_DASHBOARD), *_home_ai_row()] if panel["id"] == panel_id]
    [target] = panel["targets"]
    expr = target["expr"].replace("$__range", "1h").replace("$module", ".*").replace("$api", ".*")
    series = 'tsg_ai_usage_calls_total{module="threat_scenarios", api="create_scenario", outcome="ok"}'
    tests = [
        {
            "interval": "1m",
            "input_series": [{"series": series, "values": values}],
            "promql_expr_test": [
                {"expr": expr, "eval_time": "120m", "exp_samples": [{"labels": "{}", "value": count}]}
            ],
        }
        for values, count in COUNTER_CASES.values()
    ]
    file = tmp_path / "counts.test.yml"
    file.write_text(
        yaml.safe_dump({"rule_files": [], "evaluation_interval": "1m", "tests": tests}), encoding="utf-8"
    )
    command = [promtool, "test", "rules", str(file)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_query_reads_the_provisioned_prometheus() -> None:
    """Catches a panel, a query or a query variable left on Grafana's default data source (or another uid):
    it shows nothing in UAT, where the only Prometheus is the provisioned one."""
    for panel in _panels(AI_DASHBOARD):
        if panel["type"] in {"row", "text"}:
            continue
        assert panel["targets"], panel["id"]
        uids = {panel["datasource"]["uid"]} | {target["datasource"]["uid"] for target in panel["targets"]}
        assert uids == {"prometheus"}, panel["id"]
    for variable in _dashboard()["templating"]["list"]:
        if variable["type"] == "query":
            assert variable["datasource"]["uid"] == "prometheus", variable["name"]


def test_the_plain_words_are_the_reports_own() -> None:
    """Catches a table column showing raw labels (no display name or no mapping), or a mapping drifting from
    the catalogues the API's reports use: an API call, part, activity, outcome or reason renamed, added or
    dropped in app/core/constants and not here, a module with no 'no API call' line, or an API call's
    description missing from the page."""
    calls = {f"{module}/{api}": label for (module, api), (label, _) in API_INFO.items()}
    unrecorded = {f"{module}/none" for module in Module} | {"none/none"}
    expected = {
        "bucket": {bucket: label for bucket, (label, _) in BUCKET_INFO.items()},
        "activity": {f"{bucket}/{task}": name for (bucket, task), (name, _) in ACTIVITY_INFO.items()},
        "about": {f"{bucket}/{task}": about for (bucket, task), (_, about) in ACTIVITY_INFO.items()},
    }
    expected_values = {
        "outcome": {outcome.value for outcome in AiUsageOutcome},
        "reason": {reason.value for reason in [*AiOutage, *AiUsageReason]} | {"none"},
    }
    mapped_columns = set()
    for panel in _panels(AI_DASHBOARD):
        if panel["type"] != "table":
            continue
        settings = _column_settings(panel)
        for column in _label_columns(panel):
            assert {"displayName", "mappings"} <= set(settings.get(column, {})), (panel["id"], column)
        for column, properties in settings.items():
            if "mappings" not in properties:
                continue
            shown, where = _shown(properties["mappings"]), (panel["id"], column)
            mapped_columns.add(column)
            if column == "call":
                assert set(shown) == set(calls) | unrecorded and shown.items() >= calls.items(), where
            elif column in expected:
                assert shown == expected[column], where
            elif column in expected_values:
                assert set(shown) == expected_values[column], where
    assert mapped_columns >= {"call", *expected, *expected_values}
    descriptions = " ".join(panel.get("description", "") for panel in _panels(AI_DASHBOARD))
    for label, description in API_INFO.values():
        assert f"{label}: {description}." in descriptions, label


def test_the_per_part_columns_are_the_reports_parts_in_order() -> None:
    """Catches a per-part column renamed away from its part's report label, two parts' queries swapped under
    each other's names, or a part missing or out of the reports' order."""
    parts = []
    for panel in _panels(AI_DASHBOARD):
        renames = _organize(panel, "renameByName")
        for target in panel.get("targets", []):
            # A count names its part thrice (counted(): its increase, its offset and its new series)
            for bucket in dict.fromkeys(re.findall(r'bucket="(\w+)"', target["expr"])):
                parts.append(bucket)
                assert renames[f"Value #{target['refId']}"] == BUCKET_INFO[bucket][0], (panel["id"], bucket)
    assert parts == list(BUCKET_INFO)


def test_each_api_call_is_named_by_the_route_that_starts_it() -> None:
    """Catches a route regex that matches no route or two (a path renamed, a [^/]+ dropped), a call paired
    with another module's route (the three regenerates), a status or method that no AI route answers, the
    page's copies of the API call set differing, or an API call added to API_INFO or to a service with
    @origin_of_its_jobs and no route rule here."""
    exprs = [
        target["expr"]
        for panel in _panels(AI_DASHBOARD)
        for target in panel.get("targets", [])
        if "tsg_http_requests_total" in target["expr"]
    ]
    [pairs] = {tuple(re.findall(r'"call", "([^"]+)", "route", "([^"]+)"', expr)) for expr in exprs}
    [method] = {re.search(r'method="(\w+)"', expr)[1] for expr in exprs}
    [status] = {int(re.search(r'status="(\d+)"', expr)[1]) for expr in exprs}
    from app.main import create_app

    starting = [
        route
        for route in iter_route_contexts(create_app().routes)
        if method in (route.methods or ()) and route.status_code == status
    ]
    calls = sorted(f"{module}/{api}" for module, api in API_INFO)
    origins = _origin_methods()
    assert sorted(call for call, _ in pairs) == calls
    assert sorted(f"{module}/{api}" for module, api in origins.values()) == calls
    for call, route_regex in pairs:
        matched = [route for route in starting if re.fullmatch(route_regex, route.path)]
        assert len(matched) == 1, (call, route_regex, [route.path for route in matched])
        called = _called_names(matched[0].endpoint)
        made = {f"{module}/{api}" for name, (module, api) in origins.items() if name in called}
        assert made == {call}, (call, matched[0].path, made)


def test_the_reports_variable_reads_each_environment_s_ui_url() -> None:
    """Catches the hidden reports variable reading another job or label, the laptop's api target without its
    ui_url (or one not ending at the reports' path), or UAT's relabel rule missing, set on another job, or
    placed before the rule that sets the job."""
    [variable] = [v for v in _dashboard()["templating"]["list"] if v["name"] == "reports"]
    assert (variable["definition"], variable["hide"], variable["multi"]) == (
        'label_values(up{job="api"}, ui_url)',
        2,
        False,
    )
    job = re.search(r'job="(\w+)"', variable["definition"])[1]

    laptop = yaml.safe_load((OBS / "prometheus" / "prometheus.local.yml").read_text(encoding="utf-8"))
    [api_job] = [scrape for scrape in laptop["scrape_configs"] if scrape["job_name"] == job]
    [(targets, labels)] = [(group["targets"], group.get("labels", {})) for group in api_job["static_configs"]]
    assert len(targets) == 1 and labels.get("ui_url") == f"http://{targets[0]}{reports_router.prefix}"

    uat = yaml.safe_load((OBS / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))
    [pods] = [scrape for scrape in uat["scrape_configs"] if scrape["job_name"] == "pods"]
    rules = pods["relabel_configs"]
    [api_rule] = [rule for rule in rules if rule.get("target_label") == "ui_url" and rule["regex"] == job]
    job_rule = next(rule for rule in rules if rule.get("target_label") == "job")
    assert api_rule["source_labels"] == ["job"] and rules.index(api_rule) > rules.index(job_rule)
    assert api_rule["replacement"] == reports_router.prefix  # relative: UAT's Grafana is on the API's host


def test_the_report_links_open_real_reports() -> None:
    """Catches a link to a report path the API does not have (/request, /call), a query parameter the report
    does not take (sessionId), or a link without target="_blank" (Grafana's router swallows a relative
    /v1 link opened in its own tab)."""
    paths = {
        path: operations["get"] for path, operations in _openapi()["paths"].items() if "get" in operations
    }
    content = " ".join(
        panel["options"]["content"] for panel in _panels(AI_DASHBOARD) if panel["type"] == "text"
    )
    links = re.findall(r'<a href="\$\{reports\}([^"]*)"([^>]*)>', content)
    assert links
    for link, attributes in links:
        assert 'target="_blank"' in attributes, link
        address, _, query = link.partition("?")
        address = re.sub(r"\$\{[^}]+\}", "x", reports_router.prefix + address)
        [operation] = [
            op for path, op in paths.items() if re.fullmatch(re.sub(r"\{\w+\}", "[^/]+", path), address)
        ]
        taken = {param["name"] for param in operation.get("parameters", []) if param["in"] == "query"}
        assert set(re.findall(r"(?:^|&)(\w+)=", query)) <= taken, link


def test_the_home_page_and_the_ai_usage_page_link_both_ways() -> None:
    """Catches a home AI calls tile with no link to this page, this page with no link home, a link to a wrong
    uid (either page renamed), or a link naming a variable or a panel the other page does not have
    (var-session, viewPanel=panel-114; var-id, viewPanel=panel-60)."""
    ai_uid, home_uid = _dashboard()["uid"], _dashboard(DASHBOARD)["uid"]
    tiles = [
        panel
        for panel in _panels(DASHBOARD)
        if panel["type"] == "stat"
        and any("tsg_ai_usage_calls_total" in target["expr"] for target in panel.get("targets", []))
    ]
    assert tiles
    for tile in tiles:
        urls = [link["url"] for link in tile["fieldConfig"]["defaults"].get("links", [])]
        assert any(url.startswith(f"/grafana/d/{ai_uid}/") for url in urls), tile["id"]
    assert any(link["url"].startswith(f"/grafana/d/{home_uid}/") for link in _dashboard()["links"])
    for source, target in [(DASHBOARD, AI_DASHBOARD), (AI_DASHBOARD, DASHBOARD)]:
        variables = {variable["name"] for variable in _dashboard(target)["templating"]["list"]}
        panel_ids = {panel["id"] for panel in _panels(target)}
        for url in _links_to(source, target):
            assert set(re.findall(r"var-(\w+)=", url)) <= variables, url
            assert {int(n) for n in re.findall(r"viewPanel=panel-(\d+)", url)} <= panel_ids, url
