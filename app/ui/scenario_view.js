// A run's scenarios as both run pages show them (a standard run, pages/run.js, and a MITRE ATT&CK run,
// pages/mitre_run.js): the page's state and quiet refresh, the seven-step progress, the review meter and filter,
// the scenario card, the details drawer and the Word export. A page hands in its own API paths and its header;
// everything is built with the tools (dom.js), never from markup.

/** One page of scenarios and plans. ponytail: a run past 500 scenarios would need paging through the results. */
export const RESULTS_LIMIT = 500;
const CONTROLS_ON_CARD = 6;
const REGENERATE_GRACE_MS = 5000; // a regenerate's mark outlives the status read that may predate the click

const DECISIONS = {
  pending: { badge: "to_review", words: "To review", tone: null },
  accepted: { badge: "accepted", words: "Accepted", tone: "accepted" },
  rejected: { badge: "rejected", words: "Rejected", tone: "rejected" },
  failed: { badge: "failed", words: "Could not be written", tone: "failed" },
};
const MATCH_WORDS = { EXACT: "exact", NEAREST: "nearest", GIVEN: "named by the author" };
const OVERALL = {
  pending: ["queued", "Waiting to start"],
  in_progress: ["running", "Working"],
  awaiting_review: ["to_review", "Ready for review"],
  awaiting_next_set: ["waiting", "Ready for the next set"],
  complete: ["complete", "Complete"],
  error: ["failed", "Failed"],
  cancelled: ["cancelled", "Stopped"],
};
const STAGE_STATES = { PENDING: "idle", RUNNING: "running", COMPLETE: "done", ERROR: "error", CANCELLED: "idle" };
/** Why one scenario of a review call was skipped or refused, in plain words. */
const SKIP_WORDS = {
  unknown: "it is not part of this run",
  failure_scenario: "it could not be written",
  already_rejected: "it was already rejected",
  already_accepted: "it was already accepted",
  duplicate_version: "another version of it is already accepted",
  library_inactive: "its library threat has been retired",
  version_not_current: "a newer version has replaced it",
  changed_concurrently: "someone else decided it at the same moment",
  hand_written: "it was written by a person, so it cannot be rewritten",
};
/** A refusal of the whole call, in plain words. */
const REFUSAL_WORDS = {
  generation_in_progress: "The run is still writing scenarios. Try again when it has finished.",
  run_failed: "This run failed before any scenario was written.",
  run_cancelled: "This run was stopped before its scenarios were planned. Start a new run for this asset.",
  nothing_left: "Every planned scenario of this run is already written.",
  target_reached: "This run already has the number of scenarios it was set to write.",
  scenarios_abandoned: "The scenarios left to write could not be written.",
  duplicate_version: "Another version of this scenario is already accepted.",
  scenarios_not_decidable: "This scenario cannot be decided now.",
  scenarios_not_regenerable: "This scenario cannot be written again.",
  nothing_to_accept: "This run has no written scenario to accept.",
  scenario_not_accepted: "Accept the scenario before sending its threat to the library.",
  nothing_to_promote: "This scenario's threat is already a library threat: there is nothing to send.",
  run_being_deleted: "This run is being deleted.",
  deleting: "This run is being deleted.",
};
const PROMOTION_WORDS = {
  inserted: "sent to the library curators for approval",
  existing: "already in the library",
  curator_rejected: "a curator declined this wording before, so it was not sent again",
};
const PLAN_LOOKS = {
  queued: ["queued", "Plan queued"],
  running: ["running", "Plan being written"],
  failed: ["failed", "Plan failed"],
  cancelled: ["cancelled", "Plan stopped"],
};

/** "pending", "accepted", "rejected" or "failed" (a card that could not be written has no decision). */
export function decision_of(scenario) {
  if (scenario.status === "failed") return "failed";
  if (scenario.accepted) return "accepted";
  return scenario.rejected_at || scenario.rejected_by ? "rejected" : "pending";
}

export function title_of(scenario) {
  if (scenario.status === "failed") return "Scenario could not be written";
  return scenario.scenario?.scenario_title || "Untitled scenario";
}

/** An API refusal in plain words (no reason codes on the page); anything else as it is. */
export function plain_error(error) {
  const lead = REFUSAL_WORDS[error?.reason];
  // The API's own detail can name a field or a route: it is never shown when the refusal is known.
  const reasons = [...new Set((error?.body?.errors ?? []).map((item) => SKIP_WORDS[item.reason]).filter(Boolean))];
  if (!lead && !reasons.length) return error;
  const why = reasons.length && error.reason !== "duplicate_version" ? ` Why: ${reasons.join("; ")}.` : "";
  return new Error(`${lead ?? "This could not be done."}${why}`);
}

/** The run's overall state as a badge. */
export function build_overall_badge(tools, board) {
  const [word, label] = OVERALL[board.progress?.overall] ?? ["unknown", "Unknown"];
  return tools.build_badge(word, label);
}

/**
 * Opens a run page: reads the run, its scenarios and its plans, shows them, and refreshes quietly (only when
 * something changed, keeping the reader's place). `setup`:
 *   kind: "tsg" | "mitre"; session_id; paths: {board, results, plans, accept, reject, regenerate, promote?(id)};
 *   build_header(state) -> nodes; next_set(state) -> promise; next_set_blocked(state) -> "" or why not;
 *   live?: a node shown with the page's buttons (the live-updates badge).
 * @returns {Promise<{refresh: () => Promise<void>, state: object, is_working: () => boolean, end: (text: string) => void}>}
 */
export async function open_run_page(container, tools, setup) {
  const state = { board: null, results: null, plans: [], filter: "all", gone: false };
  const regenerating = new Map(); // scenario id -> when its regenerate was asked
  const opened = new Set(); // the long texts the reader opened, kept across rebuilds
  const note = tools.build_element("div");
  const body = tools.build_element("div", { class: "stack" });
  container.append(note, body);
  let last_answer = "";
  let in_flight = null;
  let again = false;
  let remembered = false;

  async function read() {
    const [board, results, plans] = await Promise.all([
      tools.call("GET", setup.paths.board),
      tools.call("GET", setup.paths.results),
      tools.call("GET", setup.paths.plans).catch(() => null), // a plan list that fails leaves only the plan badges out
    ]);
    return { board, results, plans: plans?.items ?? [] };
  }

  function build(answer) {
    Object.assign(state, answer);
    last_answer = JSON.stringify(answer);
    if (!remembered) {
      remembered = true;
      tools.remember_run({ kind: setup.kind, id: setup.session_id, label: answer.board.asset_name || `Asset ${answer.board.asset_id}` });
      tools.set_subtitle(answer.board.asset_name || `Asset ${answer.board.asset_id}`);
    }
    return build_page(tools, state, context(), setup);
  }

  function context() {
    const scenarios = current_scenarios(state.results);
    forget_finished(regenerating, scenarios, state.board);
    return {
      tools,
      kind: setup.kind,
      session_id: setup.session_id,
      paths: setup.paths,
      busy: state.board.session_status === "active",
      regenerating,
      opened,
      plan_of: (scenario_id) => state.plans.find((plan) => plan.scenario_id === scenario_id) ?? null,
      refresh: () => {
        last_answer = ""; // rebuild even when the answer reads the same (a regenerate mark changed)
        return refresh();
      },
    };
  }

  async function refresh() {
    if (state.gone) return;
    if (in_flight) {
      again = true;
      return in_flight;
    }
    in_flight = (async () => {
      try {
        const answer = await read();
        const seen = JSON.stringify(answer, (key, value) => (key === "elapsed_seconds" ? undefined : value)); // a running clock is no change
        if (!state.gone && seen !== last_answer) await tools.load_into(body, async () => answer, build, { quiet: true });
        tools.replace_content(note);
      } catch (error) {
        if (error.status === 404) end("This run no longer exists, so there is nothing more to show.");
        else if (error.status === 403) end(`You cannot open this run: ${error.message}`);
        else if (error.status >= 400 && error.status < 500 && ![408, 429].includes(error.status)) end(error.message);
        else tools.replace_content(note, tools.build_callout(`Could not refresh: ${error.message} It is tried again shortly.`, "warn"));
      }
    })();
    await in_flight;
    in_flight = null;
    if (again) {
      again = false;
      await refresh();
    }
  }

  function is_working() {
    if (!state.board) return false;
    const cards = current_scenarios(state.results);
    const mapping = cards.some((card) => card.controls_status === "queued" || card.controls_status === "running");
    return state.board.session_status === "active" || state.board.progress?.overall === "in_progress" || mapping || regenerating.size > 0;
  }

  function end(text) {
    state.gone = true;
    tools.set_actions();
    tools.replace_content(note);
    tools.replace_content(body, tools.build_empty(text, tools.build_link("Open the list of runs", "#/runs")));
  }

  await tools.load_into(body, read, build);
  return { refresh, state, is_working, end };
}

function current_scenarios(results) {
  return (results?.scenarios ?? []).filter((scenario) => !scenario.replaced_by);
}

/** A regenerate's mark ends when its card is replaced, or once the run stopped working (after a short grace). */
function forget_finished(regenerating, scenarios, board) {
  const now = Date.now();
  for (const [id, asked_at] of regenerating) {
    const card = scenarios.find((scenario) => scenario.scenario_id === id);
    const idle = board.session_status !== "active" && now - asked_at > REGENERATE_GRACE_MS;
    if (!card || idle) regenerating.delete(id);
  }
}

function build_page(tools, state, ctx, setup) {
  const scenarios = current_scenarios(state.results);
  tools.set_actions(...build_page_actions(tools, state, ctx, setup, scenarios), setup.live ?? null);
  const cards_place = tools.build_element("div");
  const show_cards = () => tools.replace_content(cards_place, build_cards(shown_scenarios(scenarios, state.filter), ctx, scenarios.length));
  show_cards();
  const on_filter = (value) => {
    state.filter = value;
    show_cards();
  };
  const progress = tools.build_section({ title: "Progress" }, build_run_steps(tools, state.board, scenarios, state.plans, ctx.kind));
  const review = tools.build_section(
    { title: "Scenarios", subtitle: review_subtitle(state.board, scenarios) },
    build_run_notes(tools, state.board),
    state.results.total > (state.results.scenarios ?? []).length &&
      tools.build_callout(`Only the first ${RESULTS_LIMIT} scenarios of this run are shown.`, "warn"),
    build_review_summary(tools, scenarios, state.filter, on_filter),
    cards_place,
  );
  return [setup.build_header(state), progress, review];
}

function review_subtitle(board, scenarios) {
  if (board.session_status === "active") return "Scenarios are being written. New cards appear here as each one is ready.";
  if (!scenarios.length) return "No scenario has been written yet.";
  return "Accept or reject each scenario. Accepted scenarios can get a treatment plan.";
}

function build_page_actions(tools, state, ctx, setup, scenarios) {
  const pending = scenarios.filter((scenario) => decision_of(scenario) === "pending").length;
  const next_blocked = ctx.busy ? "Wait until the run has finished writing." : setup.next_set_blocked(state);
  const accept_all = tools.build_button("Accept all", () => accept_all_scenarios(ctx), {
    kind: "primary",
    confirm: `Accept all ${pending} scenario(s) waiting for review? A scenario whose other version is already accepted is skipped.`,
    disabled: !pending || ctx.busy,
    title: !pending ? "Nothing is waiting for review." : ctx.busy ? "Wait until the run has finished writing." : null,
  });
  const next_set = tools.build_button("Generate next set", () => setup.next_set(state), { disabled: Boolean(next_blocked), title: next_blocked || null });
  const written = (list) => list.filter((scenario) => decision_of(scenario) !== "failed");
  const has_written = written(scenarios).length > 0;
  // The filter can change after this button is built: what it exports is read on the click.
  const word = tools.build_button("Export to Word", () => export_scenarios(tools, setup.kind, state.board, written(shown_scenarios(scenarios, state.filter))), {
    kind: "quiet",
    disabled: !has_written,
    title: has_written ? "Saves the scenarios shown below as a Word document." : "No written scenario yet.",
  });
  return [accept_all, next_set, word, tools.build_button("Print", () => tools.print_page(), { kind: "quiet" })];
}

async function accept_all_scenarios(ctx) {
  let answer;
  try {
    answer = await ctx.tools.call("POST", ctx.paths.accept, { mode: "all" });
  } catch (error) {
    throw plain_error(error);
  }
  const skipped = answer.skipped.length ? ` ${answer.skipped.length} could not be accepted.` : "";
  ctx.tools.show_toast(`${answer.accepted.length} scenario(s) accepted.${skipped}`, answer.skipped.length ? "warn" : "good");
  await ctx.refresh();
}

// ---------- progress, notes, meter and filter ----------

/** The seven steps of a run, read from its status, its scenarios and its plans. */
export function build_run_steps(tools, board, scenarios, plans, kind) {
  const progress = board.progress ?? {};
  const count = progress.scenario_count ?? {};
  const stage = (key, label, idle, detail) => stage_step(tools, progress, key, label, idle, detail);
  const waiting = scenarios.filter((scenario) => ["queued", "running"].includes(scenario.controls_status)).length;
  const mapped = scenarios.filter((scenario) => scenario.controls_status === "done").length;
  return tools.build_stepper([
    { label: "Start", state: "done", detail: board.asset_name || `Asset ${board.asset_id}` },
    stage("threats", "Threats & plan", "Waiting to start", count.total != null ? `${count.total} scenario(s) planned` : "Finding threats"),
    stage("scenarios", "Write scenarios", "After the plan", `${count.served ?? 0} written${count.remaining != null ? ` · ${count.remaining} to write` : ""}`),
    kind === "mitre" // owner 2026-11-27: a MITRE card's controls are identified by its remediation plan
      ? { label: "Controls", state: "idle", detail: "In each remediation plan" }
      : stage("controls", "Map controls", "After scenarios are written", `${waiting ? `${waiting} waiting · ` : ""}${mapped} mapped`),
    review_step(progress, count),
    ...plan_steps(plans, count),
  ]);
}

function stage_step(tools, progress, key, label, idle, detail) {
  const state = progress[key] ?? "PENDING";
  if (progress.retrying?.stage === key) return { label, state: "waiting", detail: "Waiting to try again" };
  if (state === "PENDING") return { label, state: "idle", detail: idle };
  if (state === "ERROR") return { label, state: "error", detail: progress.error_message?.[key] || "Needs attention" };
  if (state === "CANCELLED") return { label, state: "idle", detail: "Stopped" };
  const took = progress.timings?.[key];
  const timing = state === "COMPLETE" && typeof took === "number" ? ` · took ${tools.format_seconds(took)}` : "";
  return { label, state: STAGE_STATES[state] ?? "idle", detail: `${detail}${timing}` };
}

function review_step(progress, count) {
  const label = "Review";
  const accepted = count.accepted ?? 0;
  const rejected = count.rejected ?? 0;
  if ((count.served ?? 0) + accepted + rejected === 0) return { label, state: "idle", detail: "After scenarios are written" };
  if (count.pending_review) return { label, state: "waiting", detail: `${count.pending_review} to review · ${accepted} accepted` };
  const next = progress.overall === "awaiting_next_set" ? " · ask for the next set" : "";
  return { label, state: "done", detail: `${accepted} accepted · ${rejected} rejected${next}` };
}

function plan_steps(plans, count) {
  const write = { label: "Treatment plans", state: "idle", detail: "After you accept scenarios" };
  const decide = { label: "Decide plans", state: "idle", detail: "After a plan is ready" };
  if (!plans.length) {
    if (count.accepted) write.detail = `${count.accepted} accepted scenario(s) without a plan`;
    return [write, decide];
  }
  const writing = plans.filter((plan) => ["queued", "running"].includes(plan.latest_status)).length;
  const failed = plans.filter((plan) => plan.latest_status === "failed").length;
  const ready = plans.filter((plan) => plan.latest_status === "done");
  if (writing) Object.assign(write, { state: "running", detail: `${writing} being written · ${ready.length} ready` });
  else if (failed) Object.assign(write, { state: "error", detail: `${failed} failed · open the plan to try again` });
  else Object.assign(write, { state: "done", detail: `${ready.length} plan(s) ready` });
  const open = ready.filter((plan) => plan.decision === "pending").length;
  const accepted = plans.filter((plan) => plan.decision === "accepted").length;
  const rejected = plans.filter((plan) => plan.decision === "rejected").length;
  if (open) Object.assign(decide, { state: "waiting", detail: `${open} waiting for a decision · ${accepted} accepted` });
  else if (accepted || rejected) Object.assign(decide, { state: "done", detail: `${accepted} accepted · ${rejected} rejected` });
  return [write, decide];
}

/** What the run says the reader should know: a failure, a retry after an outage, its own notes. */
function build_run_notes(tools, board) {
  const progress = board.progress ?? {};
  const notes = [];
  if (board.session_status === "failed") notes.push(tools.build_callout(`This run could not finish. ${board.error?.message ?? ""}`.trim(), "bad"));
  if (progress.retrying) {
    const when = tools.format_date(progress.retrying.retry_at);
    notes.push(tools.build_callout(`${progress.retrying.message} It is tried again automatically at ${when}.`, "warn"));
  }
  const words = Object.values(progress.error_message ?? {}).filter(Boolean);
  if (board.session_status !== "failed" && words.length) notes.push(tools.build_callout(`Notes from the run: ${words.join(" ")}`, "info"));
  return notes;
}

function build_review_summary(tools, scenarios, filter, on_filter) {
  const counts = { pending: 0, accepted: 0, rejected: 0, failed: 0 };
  scenarios.forEach((scenario) => (counts[decision_of(scenario)] += 1));
  const parts = [
    { label: "Accepted", value: counts.accepted, tone: "good" },
    { label: "Rejected", value: counts.rejected, tone: counts.rejected ? "bad" : null }, // red only when some are
    { label: "To review", value: counts.pending, tone: "wait" },
  ];
  if (counts.failed) parts.push({ label: "Could not be written", value: counts.failed, tone: "warn" });
  const choices = [
    { value: "all", label: "All", count: scenarios.length },
    { value: "pending", label: "To review", count: counts.pending + counts.failed },
    { value: "accepted", label: "Accepted", count: counts.accepted },
    { value: "rejected", label: "Rejected", count: counts.rejected },
  ];
  return [tools.build_meter(parts, scenarios.length), tools.build_chips(choices, filter, on_filter, "Show scenarios")];
}

/** The cards a filter shows; "To review" also shows the cards that could not be written. */
function shown_scenarios(scenarios, filter) {
  if (filter === "all") return scenarios;
  return scenarios.filter((scenario) => {
    const decision = decision_of(scenario);
    return decision === filter || (filter === "pending" && decision === "failed");
  });
}

function build_cards(list, ctx, total) {
  const { tools } = ctx;
  if (list.length) return tools.build_element("div", { class: "cards" }, list.map((scenario) => build_scenario_card(scenario, ctx)));
  if (total) return tools.build_empty("No scenario in this view. Choose All to see every scenario.");
  if (ctx.busy) return tools.build_empty("The first scenarios are being written. They appear here as each one is ready.");
  return tools.build_empty("This run has no scenario yet. Use Generate next set to write some.");
}

// ---------- the card ----------

/** One scenario's card: its text, its threat and actors, its controls, its state and what can be done with it. */
export function build_scenario_card(scenario, ctx) {
  const { tools } = ctx;
  const decision = decision_of(scenario);
  const is_regenerating = ctx.regenerating.has(scenario.scenario_id);
  const badges = [tools.build_badge(DECISIONS[decision].badge, DECISIONS[decision].words)];
  if (is_regenerating) badges.push(tools.build_badge("running", "Regenerating"));
  if (scenario.version > 1) badges.push(tools.build_badge("none", `Version ${scenario.version}`, "idle"));
  const plan = decision === "accepted" ? ctx.plan_of(scenario.scenario_id) : null;
  if (plan) badges.push(build_plan_badge(tools, plan));
  return tools.build_card({
    title: title_of(scenario),
    subtitle: card_subtitle(scenario, ctx.kind),
    badges,
    tone: is_regenerating ? "busy" : DECISIONS[decision].tone,
    body: decision === "failed" ? build_failure(tools, scenario) : build_card_body(scenario, ctx),
    footer: build_card_actions(scenario, decision, ctx),
  });
}

function card_subtitle(scenario, kind) {
  if (kind === "mitre" || scenario.status === "failed") return null;
  return [scenario.scenario?.threat_category, scenario.threat?.threat_type].filter(Boolean).join(" · ") || null;
}

function build_failure(tools, scenario) {
  const outage = Boolean(scenario.failure?.reason);
  const text = outage
    ? "The AI service did not answer while this scenario was being written. Regenerate to write it again."
    : "This scenario could not be written and cannot be written again.";
  const threat = scenario.threat?.threat_name;
  return [threat && labelled(tools, "Threat", tools.build_element("p", { text: threat })), tools.build_callout(text, "warn")];
}

function build_card_body(scenario, ctx) {
  const { tools } = ctx;
  const text = scenario.scenario ?? {};
  const long = (key, value) => remembered_text(ctx, `${scenario.scenario_id}:${key}`, value);
  const shared_start = build_version_notes(tools, scenario, ctx.kind);
  const controls = labelled(tools, "Controls", build_control_tags(scenario, ctx));
  if (ctx.kind === "mitre") {
    return [
      ...shared_start,
      labelled(tools, "Threat scenario description", tools.build_element("p", { text: text.threat_scenario_description || "—" })),
      labelled(tools, "Threat scenario", long("scenario", text.scenario_statement)),
      labelled(tools, "Risk statement", long("risk", text.risk_statement)),
      labelled(tools, "Relevant groups", build_group_tags(tools, scenario)),
      labelled(tools, "Attack techniques", build_technique_tags(tools, scenario)),
      controls,
    ];
  }
  return [
    ...shared_start,
    labelled(tools, "Threat", tools.build_element("p", { text: scenario.threat?.threat_name || "—" })),
    labelled(tools, "Threat scenario", long("scenario", text.scenario_statement)),
    labelled(tools, "Risk statement", long("risk", text.risk_statement)),
    labelled(tools, "Threat actor", build_actor_line(tools, scenario)),
    labelled(tools, "Supporting systems", build_system_tags(tools, text.supporting_systems_involved ?? [])),
    controls,
  ];
}

function labelled(tools, label, content) {
  return tools.build_element("div", {}, tools.build_element("p", { class: "label", text: label }), content);
}

/** A long text whose "Show more" stays open across a refresh. */
function remembered_text(ctx, key, text) {
  const block = ctx.tools.build_long_text(text, 4);
  const toggle = block.querySelector("button");
  if (!toggle) return block;
  if (ctx.opened.has(key)) toggle.click();
  toggle.addEventListener("click", () => (ctx.opened.has(key) ? ctx.opened.delete(key) : ctx.opened.add(key)));
  return block;
}

function build_version_notes(tools, scenario, kind) {
  const notes = [];
  const previous = scenario.replaced_scenarios?.[0];
  if (scenario.replaces_accepted_version) {
    notes.push(tools.build_callout(`Version ${scenario.version}. The accepted version stays in place until you accept this one as its replacement.`, "info"));
  } else if (previous) {
    notes.push(tools.build_callout(`Version ${scenario.version}: it replaces version ${previous.version}.`, "info"));
  }
  if (scenario.regenerate_error) {
    const why = kind === "mitre" ? "the new version did not pass the MITRE ATT&CK checks" : "the new version could not be written";
    notes.push(tools.build_callout(`The last rewrite did not succeed (${why}), so this version was kept. You can try again.`, "warn"));
  }
  return notes;
}

function build_actor_line(tools, scenario) {
  const named = (scenario.actors ?? []).filter((actor) => actor.actor_name);
  if (!named.length) return tools.build_element("p", { class: "muted", text: "None linked" });
  const acting = named.filter((actor) => actor.role === "acting").map((actor) => actor.actor_name);
  const others = named.filter((actor) => actor.role !== "acting").map((actor) => actor.actor_name);
  const lead = acting.length ? acting : others;
  const also = acting.length && others.length ? ` · also capable: ${others.join(", ")}` : null;
  return tools.build_element("p", {}, tools.build_element("strong", { text: lead.join(", ") }), also);
}

function build_system_tags(tools, systems) {
  const affected = systems.filter((system) => system.is_applicable !== false);
  if (!affected.length) return tools.build_element("p", { class: "muted", text: "None listed" });
  const tags = affected.map((system) =>
    tools.build_tag(`${system.supporting_system}${system.is_entry_point ? " · entry point" : ""}`, null, system.justification || null),
  );
  return tools.build_element("div", { class: "tags" }, tags);
}

function build_group_tags(tools, scenario) {
  const groups = (scenario.actors ?? []).filter((actor) => actor.actor_name);
  if (!groups.length) return tools.build_element("p", { class: "muted", text: "None named" });
  const tags = groups.map((group) => tools.build_tag(group_name(group), group.url || null, group.relevance || null));
  return tools.build_element("div", { class: "tags" }, tags);
}

function build_technique_tags(tools, scenario) {
  const techniques = scenario.attack_techniques ?? [];
  if (!techniques.length) return tools.build_element("p", { class: "muted", text: "None named" });
  const tags = techniques.map((technique) => tools.build_tag(`${technique.mitre_id} ${technique.name}`, technique.url || null));
  return tools.build_element("div", { class: "tags" }, tags);
}

function group_name(actor) {
  return [actor.mitre_id, actor.actor_name].filter(Boolean).join(" ");
}

/** What stands in for the controls while they are not there; "" when they are. */
function control_state_text(scenario) {
  const status = scenario.controls_status;
  if (!status && (scenario.attack_techniques ?? []).length) return "Controls are identified in the remediation plan."; // a MITRE card (owner 2026-11-27)
  if (!status) return "No controls: this card is not a written scenario.";
  if (status === "queued" && scenario.controls_error) return "Matching controls is waiting to be tried again.";
  if (status === "queued" || status === "running") return "Controls are being matched…";
  if (status === "failed") return "Matching controls did not finish. Regenerate the scenario to try again.";
  if (status === "cancelled") return "Matching controls was stopped.";
  return (scenario.controls ?? []).length ? "" : "No library control matches this scenario.";
}

function control_label(control) {
  return [control.control_code, control.control_name].filter(Boolean).join(" ") || `Control ${control.control_id}`;
}

function build_control_tags(scenario, ctx) {
  const { tools } = ctx;
  const waiting = control_state_text(scenario);
  if (waiting) return tools.build_element("p", { class: "muted", text: waiting });
  const controls = scenario.controls;
  const tags = controls.slice(0, CONTROLS_ON_CARD).map((control) => {
    const match = MATCH_WORDS[control.match_type] ?? String(control.match_type || "").toLowerCase();
    const tag = tools.build_tag(`${control_label(control)} · ${match}`, null, control.match_reason || null);
    const kind = String(control.match_type || "").toLowerCase();
    if (kind === "exact" || kind === "nearest") tag.classList.add(`tag-${kind}`); // the two look different, not by colour alone: the word is in the tag
    return tag;
  });
  const hidden = controls.length - CONTROLS_ON_CARD;
  const more = hidden > 0 && tools.build_button(`${hidden} more`, () => open_scenario_details(scenario, ctx), { kind: "ghost", small: true, title: "Show every control" });
  return tools.build_element("div", { class: "tags" }, tags, more);
}

function build_plan_badge(tools, plan) {
  if (PLAN_LOOKS[plan.latest_status]) return tools.build_badge(...PLAN_LOOKS[plan.latest_status]);
  if (plan.decision === "accepted") return tools.build_badge("accepted", "Plan accepted");
  if (plan.decision === "rejected") return tools.build_badge("rejected", "Plan rejected");
  return tools.build_badge("pending", "Plan ready to decide");
}

function build_card_actions(scenario, decision, ctx) {
  const { tools } = ctx;
  const id = scenario.scenario_id;
  const locked = ctx.busy || ctx.regenerating.has(id);
  const why_locked = ctx.busy ? "Wait until the run has finished writing." : locked ? "A new version is being written." : null;
  const small = (label, action, options = {}) => tools.build_button(label, action, { small: true, disabled: locked, title: why_locked, ...options });
  const can_regenerate = scenario.scenario_source !== "manual" && (decision !== "failed" || Boolean(scenario.failure?.reason));
  const regenerate = can_regenerate && small("Regenerate", () => regenerate_scenario(scenario, ctx), { kind: "quiet" });
  const details = tools.build_button("Details", () => open_scenario_details(scenario, ctx), { kind: "ghost", small: true });
  if (decision === "failed" || decision === "rejected") return name_for_card([regenerate, details], scenario);
  if (decision === "accepted") {
    const promote = ctx.paths.promote && tools.build_button("Promote to library", () => promote_scenario(scenario, ctx), {
      kind: "quiet",
      small: true,
      confirm: `Send the threat of "${title_of(scenario)}" to the library curators for approval?`,
    });
    return name_for_card([build_plan_link(scenario, ctx), promote, regenerate, details], scenario);
  }
  const replaces = Boolean(scenario.replaces_accepted_version);
  const accept = small(replaces ? "Accept as replacement" : "Accept", () => accept_scenario(scenario, ctx, replaces), { kind: "primary" });
  const reject = small("Reject", () => reject_scenario(scenario, ctx), {
    kind: "danger",
    confirm: `Reject "${title_of(scenario)}"? A decision is final; you can regenerate it afterwards for a new version.`,
  });
  return name_for_card([accept, reject, regenerate, details], scenario);
}

/** Each control says which card it belongs to (screen readers; a refresh puts the focus back on the same one). */
function name_for_card(controls, scenario) {
  const title = title_of(scenario);
  for (const control of controls.filter(Boolean)) {
    if (control.tagName === "BUTTON" && !control.hasAttribute("aria-label")) control.setAttribute("aria-label", `${control.textContent}: ${title}`);
  }
  return controls.filter(Boolean);
}

function build_plan_link(scenario, ctx) {
  const plan = ctx.plan_of(scenario.scenario_id);
  const href = `#/plan/${encodeURIComponent(ctx.session_id)}/${encodeURIComponent(scenario.scenario_id)}`;
  const label = plan ? "View treatment plan" : "Create treatment plan";
  return ctx.tools.build_link(label, href, { class: `button small${plan ? "" : " primary"}` });
}

// ---------- the card's actions ----------

async function accept_scenario(scenario, ctx, replace) {
  const { tools } = ctx;
  const body = { mode: "subset", scenario_ids: [scenario.scenario_id], replace_accepted: replace || undefined };
  let answer;
  try {
    answer = await tools.call("POST", ctx.paths.accept, body);
  } catch (error) {
    if (error.reason !== "duplicate_version" || replace) throw plain_error(error);
    const question = "Another version of this scenario is already accepted. Accept this version in its place? The other one goes back to review.";
    if (await tools.ask_to_confirm(question, { confirm_label: "Accept as replacement", danger: false })) await accept_scenario(scenario, ctx, true);
    return;
  }
  if (answer.skipped.length) {
    tools.show_toast(`"${title_of(scenario)}" was not accepted: ${skip_words(answer.skipped)}.`, "warn");
  } else {
    const replaced = answer.replaced.length ? " The version accepted before went back to review." : "";
    const mapping = answer.controls_pending.length ? " Its controls are still being matched." : "";
    tools.show_toast(`Accepted "${title_of(scenario)}".${replaced}${mapping}`, "good");
  }
  await ctx.refresh();
}

async function reject_scenario(scenario, ctx) {
  let answer;
  try {
    answer = await ctx.tools.call("POST", ctx.paths.reject, { scenario_ids: [scenario.scenario_id] });
  } catch (error) {
    throw plain_error(error);
  }
  if (answer.skipped.length) ctx.tools.show_toast(`"${title_of(scenario)}" was not rejected: ${skip_words(answer.skipped)}.`, "warn");
  else ctx.tools.show_toast(`Rejected "${title_of(scenario)}".`, "good");
  await ctx.refresh();
}

async function regenerate_scenario(scenario, ctx) {
  try {
    await ctx.tools.call("POST", ctx.paths.regenerate, { scenario_ids: [scenario.scenario_id] }, { idempotent: true });
  } catch (error) {
    throw plain_error(error);
  }
  ctx.regenerating.set(scenario.scenario_id, Date.now());
  const words = scenario.status === "failed"
    ? "This scenario is being written again in its place."
    : "A new version is being written. It appears here as its own card when it is ready.";
  ctx.tools.show_toast(words, "info");
  await ctx.refresh();
}

async function promote_scenario(scenario, ctx) {
  const { tools } = ctx;
  let answer;
  try {
    answer = await tools.call("POST", ctx.paths.promote(scenario.scenario_id));
  } catch (error) {
    throw plain_error(error);
  }
  const lines = answer.results.map((result) => {
    const kind = [result.threat_type, result.asset_type].filter(Boolean).join(", ");
    return `${result.threat}${kind ? ` (${kind})` : ""}: ${PROMOTION_WORDS[result.outcome] ?? tools.humanise(result.outcome)}`;
  });
  tools.show_toast(lines.length ? `Threat library: ${lines.join(" · ")}.` : "Nothing was sent to the library.", "good");
}

function skip_words(skipped) {
  return [...new Set(skipped.map((item) => SKIP_WORDS[item.reason] ?? "it cannot be decided now"))].join("; ");
}

// ---------- the details drawer ----------

/** Everything about one scenario, in a drawer. */
export function open_scenario_details(scenario, ctx) {
  const { tools } = ctx;
  const decision = decision_of(scenario);
  const parts = decision === "failed" ? build_failure(tools, scenario) : ctx.kind === "mitre" ? mitre_details(tools, scenario) : tsg_details(tools, scenario);
  tools.open_drawer(title_of(scenario), build_decision_facts(tools, scenario, decision), parts, build_history(tools, scenario));
}

function part(tools, title, ...content) {
  return tools.build_element("section", { class: "stack" }, tools.build_element("h3", { text: title }), content);
}

function paragraph(tools, text) {
  return tools.build_element("p", { class: "clamp clamp-open", text: text || "—" });
}

function build_decision_facts(tools, scenario, decision) {
  const facts = [
    ["Status", tools.build_badge(DECISIONS[decision].badge, DECISIONS[decision].words)],
    ["Version", scenario.version],
    ["Written", tools.format_date(scenario.created_at)],
  ];
  if (decision === "accepted") facts.push(["Accepted", decided_words(tools, scenario.accepted_by, scenario.accepted_at)]);
  if (decision === "rejected") facts.push(["Rejected", decided_words(tools, scenario.rejected_by, scenario.rejected_at)]);
  return tools.build_facts(facts);
}

function decided_words(tools, by, at) {
  return [by && `by ${by}`, at && `on ${tools.format_date(at)}`].filter(Boolean).join(" ") || "Yes";
}

function tsg_details(tools, scenario) {
  const text = scenario.scenario ?? {};
  const threat = scenario.threat ?? {};
  const origin = threat.is_threat_ai_generated ? "Proposed by the AI" : threat.threat_catalogue_id != null ? "Threat library" : null;
  const also = (text.contributing_categories ?? []).length ? ` (also ${text.contributing_categories.join(", ")})` : "";
  return [
    text.threat_scenario_description && part(tools, "Description", paragraph(tools, text.threat_scenario_description)),
    part(tools, "Scenario", paragraph(tools, text.scenario_statement)),
    part(tools, "Risk", paragraph(tools, text.risk_statement)),
    part(tools, "Threat", tools.build_facts([
      ["Category", text.threat_category ? `${text.threat_category}${also}` : null],
      ["Type", threat.threat_type],
      ["Name", threat.threat_name],
      ["Origin", origin],
    ])),
    part(tools, "Threat actor", build_actor_line(tools, scenario)),
    part(tools, "Supporting systems", build_systems_table(tools, text.supporting_systems_involved ?? [])),
    part(tools, "Controls", build_controls_table(tools, scenario)),
    (scenario.evidence ?? []).length > 0 && part(tools, "Evidence", build_evidence(tools, scenario.evidence)),
    (text.assumptions ?? []).length > 0 && part(tools, "Assumptions", tools.build_element("ul", {}, text.assumptions.map((item) => tools.build_element("li", { text: item })))),
  ];
}

function mitre_details(tools, scenario) {
  const text = scenario.scenario ?? {};
  const groups = (scenario.actors ?? []).filter((actor) => actor.actor_name);
  const techniques = scenario.attack_techniques ?? [];
  return [
    part(tools, "Description", paragraph(tools, text.threat_scenario_description)),
    part(tools, "Scenario", paragraph(tools, text.scenario_statement)),
    part(tools, "Risk", paragraph(tools, text.risk_statement)),
    part(tools, "Relevant groups", tools.build_table(groups, [
      { title: "Group", show: (group) => (group.url ? tools.build_link(group_name(group), group.url) : group_name(group)) },
      { title: "Why it is listed", key: "relevance" },
    ], { caption: "Relevant groups", empty: "No group named." })),
    part(tools, "Attack techniques", tools.build_table(techniques, [
      { title: "Technique", nowrap: true, show: (technique) => (technique.url ? tools.build_link(technique.mitre_id, technique.url) : technique.mitre_id) },
      { title: "Name", key: "name" },
    ], { caption: "Attack techniques", empty: "No technique named." })),
    part(tools, "Controls", build_controls_table(tools, scenario)),
  ];
}

function build_systems_table(tools, systems) {
  return tools.build_table(systems, [
    { title: "System", key: "supporting_system" },
    { title: "Affected", show: (system) => system.is_applicable !== false },
    { title: "Entry point", show: (system) => system.is_entry_point },
    { title: "Why", key: "justification" },
  ], { caption: "Supporting systems", empty: "No supporting system listed." });
}

function build_controls_table(tools, scenario) {
  const waiting = control_state_text(scenario);
  if (waiting) return tools.build_element("p", { class: "muted", text: waiting });
  return tools.build_table(scenario.controls, [
    { title: "Code", nowrap: true, show: (control) => tools.build_element("span", { class: "mono", text: control.control_code || "—" }) },
    { title: "Control", show: (control) => tools.build_element("span", { title: control.control_description || null, text: control.control_name || "—" }) },
    { title: "Domain", key: "domain" },
    { title: "Match", nowrap: true, show: (control) => build_match_badge(tools, control.match_type) },
    { title: "Why", key: "match_reason" },
  ], { caption: "Controls" });
}

function build_match_badge(tools, match_type) {
  const word = MATCH_WORDS[match_type];
  if (match_type === "EXACT") return tools.build_badge("exact", "Exact");
  if (match_type === "NEAREST") return tools.build_badge("nearest", "Nearest");
  return tools.build_badge("none", word ? tools.humanise(word) : "—", "idle");
}

function build_evidence(tools, evidence) {
  const items = evidence.map((entry) =>
    tools.build_element(
      "li",
      {},
      tools.build_element("strong", { text: `[${entry.n}] ${entry.title || entry.ref || "Source"}` }),
      tools.build_element("p", { class: "muted", text: [entry.source, entry.kind].filter(Boolean).join(" · ") }),
      entry.url && tools.build_link(entry.url, entry.url),
      (entry.facts ?? []).length > 0 && tools.build_element("ul", {}, entry.facts.map((fact) => tools.build_element("li", { text: fact }))),
    ),
  );
  return [tools.build_element("p", { class: "muted", text: "A number in brackets in the text, such as [1], points to the source with that number." }), tools.build_element("ol", { class: "stack" }, items)];
}

/** Every version of the scenario, oldest first, then this one. */
function build_history(tools, scenario) {
  const older = [...(scenario.replaced_scenarios ?? [])].reverse();
  if (!older.length) return null;
  const rows = [...older.map((version) => ({ version, current: false })), { version: scenario, current: true }];
  const state_of = (row) => {
    if (row.current) return "Current";
    const decision = decision_of(row.version);
    return decision === "pending" ? "Replaced" : `${DECISIONS[decision].words}, replaced`;
  };
  return part(tools, "Version history", tools.build_table(rows, [
    { title: "Version", nowrap: true, show: (row) => `Version ${row.version.version}` },
    { title: "Title", show: (row) => title_of(row.version) },
    { title: "State", show: state_of },
    { title: "Written", nowrap: true, show: (row) => tools.format_date(row.version.created_at) },
  ], { caption: "Version history" }));
}

// ---------- the Word export ----------

/** Saves `scenarios` (the written ones the page shows) as a Word document. */
export function export_scenarios(tools, kind, board, scenarios) {
  if (!scenarios.length) throw new Error("There is no written scenario to export in this view.");
  const asset = board.asset_name || `Asset ${board.asset_id}`;
  const actor_column = kind === "mitre" ? "MITRE groups" : "Threat actor";
  const blocks = [
    { paragraph: `${scenarios.length} scenario(s) for ${asset}, written with AI assistance. Check that each one is realistic for your organisation.` },
    { heading: "Summary", level: 1 },
    { table: { columns: ["No.", "Scenario", actor_column, "Status"], rows: scenarios.map((scenario, index) => [String(index + 1), title_of(scenario), actors_text(scenario, kind), DECISIONS[decision_of(scenario)].words]) } },
    ...scenarios.flatMap((scenario, index) => scenario_blocks(scenario, index, kind)),
  ];
  const day = new Date().toISOString().slice(0, 10);
  tools.download_word(`Threat scenarios - ${asset} - ${day}`, `Threat scenarios: ${asset}`, blocks);
  tools.show_toast(`Word document saved with ${scenarios.length} scenario(s).`, "good");
}

function actors_text(scenario, kind) {
  const named = (scenario.actors ?? []).filter((actor) => actor.actor_name);
  if (kind === "mitre") return named.map(group_name).join(", ") || "None named";
  const acting = named.filter((actor) => actor.role === "acting");
  return (acting.length ? acting : named).map((actor) => actor.actor_name).join(", ") || "None linked";
}

function scenario_blocks(scenario, index, kind) {
  const text = scenario.scenario ?? {};
  const facts = [["Status", DECISIONS[decision_of(scenario)].words], ["Version", String(scenario.version)]];
  if (kind === "mitre") facts.push(["Relevant groups", actors_text(scenario, kind)]);
  else facts.push(["Threat", scenario.threat?.threat_name || "—"], ["Threat actor", actors_text(scenario, kind)]);
  const blocks = [{ heading: `${index + 1}. ${title_of(scenario)}`, level: 1 }, { facts }];
  if (kind === "mitre") blocks.push({ heading: "Threat scenario description", level: 2 }, { paragraph: text.threat_scenario_description });
  blocks.push({ heading: "Threat scenario", level: 2 }, { paragraph: text.scenario_statement }, { heading: "Risk statement", level: 2 }, { paragraph: text.risk_statement });
  if (kind === "mitre") {
    const rows = (scenario.attack_techniques ?? []).map((technique) => [technique.mitre_id, technique.name]);
    blocks.push({ heading: "Attack techniques", level: 2 }, rows.length ? { table: { columns: ["Technique", "Name"], rows } } : { paragraph: "None named" });
  } else {
    blocks.push(...system_blocks(text.supporting_systems_involved ?? []), ...evidence_blocks(scenario.evidence ?? []));
  }
  return [...blocks, ...control_blocks(scenario)];
}

function system_blocks(systems) {
  const rows = systems.map((system) => [system.supporting_system, system.is_entry_point ? "Yes" : "", system.is_applicable === false ? "No" : "Yes", system.justification || ""]);
  return [{ heading: "Supporting systems", level: 2 }, rows.length ? { table: { columns: ["System", "Entry point", "Affected", "Why"], rows } } : { paragraph: "None listed" }];
}

function evidence_blocks(evidence) {
  if (!evidence.length) return [];
  const list = evidence.map((entry) => [`[${entry.n}] ${entry.title || entry.ref || "Source"}`, entry.source, entry.url].filter(Boolean).join(" · "));
  return [{ heading: "Evidence", level: 2 }, { list }];
}

function control_blocks(scenario) {
  const waiting = control_state_text(scenario);
  if (waiting) return [{ heading: "Controls", level: 2 }, { paragraph: waiting }];
  const rows = scenario.controls.map((control) => [control.control_code || "", control.control_name || "", MATCH_WORDS[control.match_type] ?? "", control.match_reason || ""]);
  return [{ heading: "Controls", level: 2 }, { table: { columns: ["Code", "Control", "Match", "Why"], rows } }];
}
