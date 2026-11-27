// The treatment plan register: every plan of the signed-in entity, newest first, filtered and paged, with the way
// to each plan and to the run that holds its scenario.

import { DECISION_WORDS, STATUS_WORDS } from "./plan.js";
import { run_address } from "./runs.js";

const PAGE_SIZE = 25;
const REFRESH_SECONDS = 15;
const STATUS_CHOICES = [
  { value: "", label: "Any" },
  { value: "queued", label: "Waiting to start" },
  { value: "running", label: "Being written" },
  { value: "done", label: "Written" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Stopped" },
];
const DECISION_CHOICES = [
  { value: "", label: "Any" },
  { value: "pending", label: "Awaiting decision" },
  { value: "accepted", label: "Accepted" },
  { value: "rejected", label: "Rejected" },
];
const LEVEL_CHOICES = [{ value: "", label: "Any" }, "Critical", "High", "Medium", "Low"];

export async function show(container, tools) {
  const entity_id = tools.identity().entity_id;
  const filters = { status: "", decision: "", risk_level: "" };
  let offset = 0;
  let shown = null;
  tools.set_subtitle(`Every treatment plan of entity ${entity_id}, newest first.`);
  tools.set_actions(tools.build_link("Write a scenario by hand", "#/manual_plan", { class: "button" }));

  const select_of = (name, choices) => {
    const select = tools.build_select(choices, filters[name]);
    select.addEventListener("change", () => {
      filters[name] = select.value;
      offset = 0;
      load();
    });
    return select;
  };
  const filter_bar = tools.build_element(
    "div",
    { class: "toolbar" },
    tools.build_field("Plan status", select_of("status", STATUS_CHOICES)),
    tools.build_field("Decision", select_of("decision", DECISION_CHOICES)),
    tools.build_field("Risk level", select_of("risk_level", LEVEL_CHOICES)),
  );
  const place = tools.build_element("div", { class: "stack" });
  container.append(tools.build_section({ title: "Filters" }, filter_bar), place);

  const read = () =>
    tools.call("GET", tools.with_query(`/v1/entities/${encodeURIComponent(entity_id)}/treatment-plans`, { ...filters, offset, limit: PAGE_SIZE }));

  function build(answer) {
    shown = answer;
    if (answer.total === 0) return build_nothing(filters, tools, clear_filters);
    if (answer.items.length === 0 && offset > 0) {
      offset = 0; // the page emptied (plans deleted meanwhile): back to the first
      load();
      return tools.build_loading();
    }
    const turn_page = (next) => {
      offset = next;
      load(false);
    };
    const paging = tools.build_pager({ offset, limit: PAGE_SIZE, total: answer.total, on_change: turn_page });
    return [build_kpis(answer, tools), tools.build_section({ title: "Plans" }, build_rows(answer.items, tools), paging)];
  }

  function clear_filters() {
    Object.keys(filters).forEach((name) => (filters[name] = ""));
    filter_bar.querySelectorAll("select").forEach((select) => (select.value = ""));
    offset = 0;
    load(false);
  }

  const load = (quiet = true) => tools.load_into(place, read, build, { quiet });
  tools.every(REFRESH_SECONDS, () => {
    if (shown?.items.some((item) => item.latest_status === "queued" || item.latest_status === "running")) load();
  });
  await load(false);
}

function build_kpis(answer, tools) {
  const count = (test) => answer.items.filter(test).length;
  const hint = answer.total > answer.items.length ? "On this page" : null;
  return tools.build_kpis([
    { label: "Plans", value: answer.total, hint: "Matching the filters" },
    { label: "Awaiting decision", value: count((item) => item.latest_status === "done" && item.decision === "pending"), hint, tone: "warn" },
    { label: "Accepted", value: count((item) => item.decision === "accepted"), hint, tone: "good" },
    { label: "Failed", value: count((item) => item.latest_status === "failed"), hint, tone: "bad" },
  ]);
}

function build_rows(items, tools) {
  const plan_link = (item) => `#/plan/${encodeURIComponent(item.session_id)}/${encodeURIComponent(item.scenario_id)}`;
  // ponytail: a list item does not say which kind of run holds it: a hand-written one is a standard run, else the
  // kind this tab remembers, else the standard run page. Exact needs a pipeline field on RemediationSummary.
  const run_link = (item) => run_address(tools, item.session_id, item.source === "manual" ? "tsg" : undefined);
  const columns = [
    {
      title: "Scenario",
      show: (item) => [tools.build_link(item.title || "Untitled scenario", plan_link(item)), tools.build_element("p", { class: "muted mono", text: item.scenario_id })],
    },
    { title: "Asset", show: (item) => item.asset_id, numeric: true },
    { title: "Source", show: (item) => tools.build_tag(item.source === "manual" ? "Written by hand" : "Generated") },
    {
      title: "Plan",
      show: (item) =>
        tools.build_element(
          "span",
          { class: "tags" },
          tools.build_badge(item.latest_status, `Version ${item.latest_version}: ${STATUS_WORDS[item.latest_status] ?? tools.humanise(item.latest_status)}`),
          tools.build_badge(item.decision, DECISION_WORDS[item.decision]),
        ),
    },
    { title: "Risk level", show: (item) => (item.risk_level ? tools.build_tag(item.risk_level) : null) },
    { title: "Updated", show: (item) => tools.format_date(item.updated_at), nowrap: true },
    {
      title: "Open",
      show: (item) =>
        tools.build_actions(
          tools.build_link("View plan", plan_link(item), { class: "button small primary" }),
          tools.build_link("Open run", run_link(item), { class: "button small" }),
        ),
    },
  ];
  return tools.build_table(items, columns, { caption: "Treatment plans" });
}

function build_nothing(filters, tools, clear_filters) {
  if (Object.values(filters).some(Boolean)) {
    return tools.build_empty("No plan matches these filters.", tools.build_button("Clear the filters", clear_filters));
  }
  return tools.build_empty(
    "No treatment plan yet. Accept a scenario in a run and create its plan, or write a scenario by hand.",
    tools.build_actions(tools.build_link("Open the runs", "#/runs", { class: "button primary" }), tools.build_link("Write a scenario by hand", "#/manual_plan", { class: "button" })),
  );
}
