// Home: who is signed in, quick actions, the work in progress, the runs opened in this tab, the plans that wait for
// a decision and whether the service is ready.

import { address, build_recent_runs, build_work_list, read_jobs } from "./runs.js";

const REFRESH_SECONDS = 15;
const PLANS_SHOWN = 5;
const RECENT_SHOWN = 5;

export async function show(container, tools) {
  const { build_element, build_section } = tools;
  const who = tools.identity();
  const status_place = build_element("div", { class: "muted", "aria-live": "polite" });
  const work_place = build_element("div", { class: "columns" });
  const plans_place = build_element("div", { class: "columns" });

  const load_work = (quiet) => tools.load_into(work_place, () => read_jobs(tools), (answer) => build_work_list(tools, answer), { quiet });
  const load_plans = (quiet) => tools.load_into(plans_place, () => read_waiting_plans(tools, who.entity_id), (answer) => build_waiting_plans(tools, answer), { quiet });
  const load_status = () => tools.load_into(status_place, () => read_service_state(tools), (state) => build_service_state(tools, state), { quiet: true });

  const welcome = build_section(
    { title: `Welcome, ${who.user_id}`, subtitle: `You are assessing the assets of entity ${who.entity_id}.` },
    build_element(
      "div",
      { class: "actions" },
      tools.build_link("New run", address("new_run"), { class: "button primary" }),
      tools.build_link("Treatment plans", address("plans"), { class: "button" }),
      tools.build_link("Service mapper", address("service_mapper"), { class: "button" }),
    ),
    status_place,
  );
  container.append(
    welcome,
    build_section({ title: "Work in progress", subtitle: `Runs, plans and service maps being written. Checked every ${REFRESH_SECONDS} seconds.` }, work_place),
    build_element(
      "div",
      { class: "grid-2" },
      build_section({ title: "Recently opened runs", actions: [tools.build_link("All runs", address("runs"), { class: "button small" })] }, build_recent_runs(tools, RECENT_SHOWN)),
      build_section({ title: "Plans awaiting a decision", actions: [tools.build_link("Open the register", address("plans"), { class: "button small" })] }, plans_place),
    ),
  );
  tools.every(REFRESH_SECONDS, () => {
    load_work(true);
    load_plans(true);
  });
  await Promise.all([load_work(false), load_plans(false), load_status()]);
}

/** The newest finished plans no one has accepted or rejected yet. */
function read_waiting_plans(tools, entity_id) {
  const path = `/v1/entities/${encodeURIComponent(entity_id)}/treatment-plans`;
  return tools.call("GET", tools.with_query(path, { status: "done", decision: "pending", limit: PLANS_SHOWN }));
}

function build_waiting_plans(tools, answer) {
  const plans = answer?.items ?? [];
  if (!plans.length) {
    return tools.build_empty("No plan waits for a decision. Accept scenarios in a run, then ask for their treatment plans.", tools.build_link("Open your runs", address("runs"), { class: "button" }));
  }
  const columns = [
    { title: "Plan", show: (plan) => tools.build_link(plan.title || "Untitled plan", address("plan", plan.session_id, plan.scenario_id)) },
    { title: "Risk", show: (plan) => (plan.risk_level ? tools.humanise(plan.risk_level) : null) },
    { title: "Written", nowrap: true, show: (plan) => tools.format_date(plan.updated_at) },
  ];
  const caption = answer.total > plans.length ? `The newest ${plans.length} of ${answer.total}.` : "Newest first.";
  return tools.build_table(plans, columns, { caption });
}

/** Ready, or degraded: the main database does not answer (503) or another store or a queue's workers are missing. */
async function read_service_state(tools) {
  let report;
  try {
    report = await tools.request("GET", "/ready");
  } catch (error) {
    if (error.status !== 503) throw error;
    return { ready: false };
  }
  const stores_up = Object.values(report?.dependencies ?? {}).every(Boolean);
  const workers_up = Object.values(report?.workers ?? {}).every((online) => Number(online) > 0);
  return { ready: report?.status === "ready" && stores_up && workers_up };
}

function build_service_state(tools, { ready }) {
  if (ready) return ["Service: ", tools.build_badge("ready", "Ready")];
  return ["Service: ", tools.build_badge("degraded", "Degraded"), " Some work may wait or not start. If it lasts, tell your administrator."];
}
