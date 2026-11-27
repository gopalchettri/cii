// Runs: open a run by its id, the runs opened in this tab, the work queued or running, and the entity's earlier
// runs (found from its scenarios) with Cancel and Delete. Also exports the run helpers the home page shows.

const REFRESH_SECONDS = 15;
const SCENARIOS_PER_PAGE = 200; // the newest scenarios read at once; their runs are the rows of one page
/** The two kinds of run: the word session.js keeps, its page and its name on screen. */
export const RUN_KINDS = {
  mitre: { page: "mitre_run", label: "MITRE ATT&CK" },
  tsg: { page: "run", label: "Standard" },
};
const WORK_WORDS = {
  threats: "Finding threats",
  scenarios: "Writing scenarios",
  controls: "Matching controls",
  remediation: "Writing a treatment plan",
  service_mapping: "Mapping services",
};
const RUN_WORK = ["threats", "scenarios", "controls"];

/** "#/run/abc" for ("run", "abc"). */
export const address = (page, ...parts) => `#/${[page, ...parts.map((part) => encodeURIComponent(String(part)))].join("/")}`;

/** The kind of a run this tab knows ("mitre" or "tsg"), else `fallback`. */
export function known_kind(tools, session_id, fallback = "tsg") {
  return tools.recent_runs().find((run) => run.id === session_id)?.kind ?? fallback;
}

/** The address of a run's page. */
export function run_address(tools, session_id, kind) {
  return address(RUN_KINDS[kind ?? known_kind(tools, session_id)]?.page ?? "run", session_id);
}

/** GET the signed-in entity's queued or running work. */
export function read_jobs(tools) {
  return tools.call("GET", "/v1/jobs");
}

/**
 * The work queued or running as a table, each row with a link to its page.
 * @param {(job: object) => Node | null} [action_of] a button per row (runs: Cancel)
 */
export function build_work_list(tools, answer, action_of = () => null) {
  const jobs = answer?.jobs ?? [];
  if (!jobs.length) {
    return tools.build_empty(
      "Nothing is queued or running. Start a new run, or ask for a treatment plan from a run's scenarios.",
      tools.build_link("Start a new run", address("new_run"), { class: "button primary" }),
    );
  }
  const columns = [
    { title: "Work", show: (job) => tools.build_link(WORK_WORDS[job.kind] ?? tools.humanise(job.kind), work_address(tools, job)) },
    { title: "Asset", show: (job) => job.asset_name || (job.asset_id ? `Asset ${job.asset_id}` : null) },
    { title: "Status", show: (job) => build_work_status(tools, job) },
    { title: "Progress", show: (job) => describe_progress(job) },
    { title: "Started", nowrap: true, show: (job) => tools.format_date(job.created_at) },
    { title: "Actions", show: (job) => action_of(job) },
  ];
  const caption = answer.total > jobs.length ? `${jobs.length} of ${answer.total} shown, oldest first.` : "Oldest first.";
  return tools.build_table(jobs, columns, { caption });
}

function work_address(tools, job) {
  if (job.kind === "service_mapping" && job.mapping_id) return address("service_mapper", job.mapping_id);
  // ponytail: a plan's job names its run, not its scenario, so it opens the run (its plans are under its scenarios).
  if (job.session_id) return run_address(tools, job.session_id);
  return address("plans");
}

function build_work_status(tools, job) {
  if (!job.retrying) return tools.build_badge(job.status);
  return tools.build_element("span", { class: "stack" }, tools.build_badge("retrying", "Waiting to try again"), tools.build_element("small", { class: "muted", text: job.retrying.message }));
}

function describe_progress(job) {
  const progress = job.progress;
  if (!progress || !progress.planned) return null;
  const waiting = progress.controls_waiting ? `, controls being matched for ${progress.controls_waiting}` : "";
  return `${progress.written} of ${progress.planned} scenarios written${waiting}`;
}

export async function show(container, tools) {
  const { build_element, build_section } = tools;
  tools.set_subtitle("Find a run you started earlier, follow the work in progress, or tidy up old runs.");
  tools.set_actions(tools.build_link("New run", address("new_run"), { class: "button primary" }));
  const work_place = build_element("div", { class: "columns" });
  const earlier_place = build_element("div", { class: "columns" });
  let offset = 0;

  const load_work = (quiet) => tools.load_into(work_place, () => read_jobs(tools), (answer) => build_work_list(tools, answer, build_cancel_button), { quiet });
  const load_earlier = (quiet) => tools.load_into(earlier_place, () => read_earlier_runs(tools, offset), (answer) => build_earlier_runs(answer), { quiet });
  const refresh = () => Promise.all([load_work(true), load_earlier(true)]);

  function build_cancel_button(job) {
    if (!RUN_WORK.includes(job.kind) || !job.session_id) return null;
    return build_cancel(job.session_id);
  }

  function build_cancel(session_id) {
    const question = "Stop this run? The scenarios already written stay readable; the rest are not written.";
    return tools.build_button("Cancel run", () => cancel_run(session_id), { kind: "danger", small: true, confirm: question });
  }

  async function cancel_run(session_id) {
    await tools.call("POST", `/v1/sessions/${encodeURIComponent(session_id)}/cancel`);
    tools.show_toast("The run is cancelled. What was already written stays readable.", "good");
    await refresh();
  }

  async function delete_run(session_id) {
    const gone = await tools.call("DELETE", `/v1/sessions/${encodeURIComponent(session_id)}`);
    const plans = gone?.remediation_plans ? ` and ${gone.remediation_plans} treatment plan(s)` : "";
    tools.show_toast(`The run is deleted, with its ${gone?.scenarios ?? 0} scenario(s)${plans}.`, "good");
    await refresh();
  }

  function build_run_actions(run) {
    if (run.board?.session_status === "active") return build_cancel(run.session_id);
    // Not a count: a run's scenarios can fall across two pages of this list.
    const question = "Delete this run, all its scenarios and their treatment plans? This cannot be undone.";
    return tools.build_button("Delete", () => delete_run(run.session_id), { kind: "danger", small: true, confirm: question });
  }

  function build_earlier_runs({ runs, total }) {
    if (!runs.length && offset === 0) {
      return tools.build_empty("No scenario has been written for your organisation yet. Start a run to see it here.", tools.build_link("Start a new run", address("new_run"), { class: "button primary" }));
    }
    const columns = [
      { title: "Run", show: (run) => tools.build_link(run.board?.asset_name || `Asset ${run.board?.asset_id ?? "unknown"}`, run_address(tools, run.session_id, run.kind)) },
      { title: "Kind", show: (run) => (run.is_manual ? "Manual scenario" : (RUN_KINDS[run.kind]?.label ?? RUN_KINDS.tsg.label)) },
      { title: "Scenarios", numeric: true, show: (run) => tools.format_count(run.scenarios.length) },
      { title: "Decisions", show: (run) => build_decisions(tools, run.scenarios) },
      { title: "State", show: (run) => (run.board ? tools.build_badge(run.board.session_status) : tools.build_badge("unknown", "Not read")) },
      { title: "Last written", nowrap: true, show: (run) => tools.format_date(run.last_written) },
      { title: "Actions", show: build_run_actions },
    ];
    const pager = tools.build_pager({
      offset,
      limit: SCENARIOS_PER_PAGE,
      total,
      on_change: (next) => {
        offset = next;
        load_earlier(false);
      },
    });
    const note = "Runs are listed by their newest scenarios. A run with no scenario yet shows under Work in progress.";
    const table = tools.build_table(runs, columns, { caption: note, empty: "No run on this page: go to the previous page." });
    return [table, total > SCENARIOS_PER_PAGE || offset > 0 ? pager : null];
  }

  const open_id = build_element("input", { type: "text", class: "mono", required: true, maxlength: 64, autocomplete: "off", spellcheck: "false" });
  const open_kind = tools.build_select(Object.entries(RUN_KINDS).map(([value, kind]) => ({ value, label: kind.label })), "mitre");
  const open_form = tools.build_form(
    [tools.build_row(tools.build_field("Run id", open_id, { hint: "The id shown on the run's page, or given when it started." }), tools.build_field("Kind of run", open_kind))],
    "Open run",
    () => {
      const id = open_id.value.trim();
      if (!id) throw new Error("Type the run's id.");
      tools.go(RUN_KINDS[open_kind.value].page, id);
    },
  );

  container.append(
    build_element(
      "div",
      { class: "grid-2" },
      build_section({ title: "Open a run", subtitle: "Go straight to a run you know the id of." }, open_form),
      build_section({ title: "Opened in this tab", subtitle: "Forgotten when you sign out or close the tab." }, build_recent_runs(tools)),
    ),
    build_section({ title: "Work in progress", subtitle: `Runs, plans and service maps being written. Checked every ${REFRESH_SECONDS} seconds.`, actions: [tools.build_button("Refresh", () => load_work(true), { kind: "quiet" })] }, work_place),
    build_section({ title: "Earlier runs", subtitle: "Every run of your organisation that has scenarios, newest first." }, earlier_place),
  );
  tools.every(REFRESH_SECONDS, () => load_work(true));
  await Promise.all([load_work(false), load_earlier(false)]);
}

/** The runs opened in this tab, newest first. */
export function build_recent_runs(tools, most = Infinity) {
  const runs = tools.recent_runs().slice(0, most);
  if (!runs.length) {
    return tools.build_empty("No run opened in this tab yet. Start a new run, or open one by its id.", tools.build_link("Start a new run", address("new_run"), { class: "button" }));
  }
  const columns = [
    { title: "Run", show: (run) => tools.build_link(run.label || run.id, run_address(tools, run.id, run.kind)) },
    { title: "Kind", show: (run) => RUN_KINDS[run.kind]?.label ?? tools.humanise(run.kind) },
    { title: "Opened", nowrap: true, show: (run) => tools.format_date(run.at) },
  ];
  return tools.build_table(runs, columns, { caption: "Newest first." });
}

/** The entity's newest scenarios grouped by run, each run with its status board (asset, state). */
async function read_earlier_runs(tools, offset) {
  const entity_id = tools.identity().entity_id;
  const path = `/v1/entities/${encodeURIComponent(entity_id)}/scenarios`;
  const answer = await tools.call("GET", tools.with_query(path, { offset, limit: SCENARIOS_PER_PAGE }));
  const runs = group_by_run(tools, answer.scenarios ?? []);
  // ponytail: one cheap read per run for its asset and state (no AI); a list-of-runs route would make it one call.
  const boards = await Promise.allSettled(runs.map((run) => tools.call("GET", `/v1/sessions/${encodeURIComponent(run.session_id)}`)));
  boards.forEach((board, index) => (runs[index].board = board.status === "fulfilled" ? board.value : null));
  return { runs, total: answer.total ?? 0 };
}

function group_by_run(tools, scenarios) {
  const runs = new Map();
  for (const scenario of scenarios) {
    const run = runs.get(scenario.session_id) ?? { session_id: scenario.session_id, scenarios: [], last_written: null, is_manual: false, has_techniques: false };
    run.scenarios.push(scenario);
    if (!run.last_written || scenario.created_at > run.last_written) run.last_written = scenario.created_at;
    run.is_manual ||= scenario.scenario_source === "manual";
    run.has_techniques ||= (scenario.attack_techniques ?? []).length > 0;
    runs.set(scenario.session_id, run);
  }
  // ponytail: the answer does not say which kind made a run; ATT&CK techniques on its scenarios mark a MITRE one.
  return [...runs.values()].map((run) => ({ ...run, kind: known_kind(tools, run.session_id, run.has_techniques ? "mitre" : "tsg") }));
}

function build_decisions(tools, scenarios) {
  const count = { accepted: 0, rejected: 0, pending: 0, failed: 0 };
  for (const scenario of scenarios) {
    if (scenario.accepted) count.accepted += 1;
    else if (scenario.rejected_at || scenario.rejected_by) count.rejected += 1;
    else if (scenario.status === "failed") count.failed += 1; // a failure card cannot be decided
    else count.pending += 1;
  }
  return tools.build_element(
    "span",
    { class: "tags" },
    tools.build_badge("accepted", `${count.accepted} accepted`),
    tools.build_badge("rejected", `${count.rejected} rejected`),
    tools.build_badge("pending", `${count.pending} to decide`),
    count.failed ? tools.build_badge("failed", `${count.failed} not written`) : null,
  );
}
