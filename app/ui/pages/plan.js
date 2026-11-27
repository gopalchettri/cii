// One scenario's treatment plan (#/plan/<session_id>/<scenario_id>): the form that requests it when there is none
// yet, else the plan itself with its versions, the review of each, regenerate, cancel, Word export and print.
// It also exports the register's fields and the plan status words, which the manual scenario page and the register share.

import { run_address } from "./runs.js";

const LEVELS = ["Critical", "High", "Medium", "Low"];
const NAME_MAX = 200; // PlanRequest: risk owner, business division, risk level
const JUSTIFICATION_MAX = 1000;
const CONTROLS_MAX = 50; // existing controls one request names
const COMMENT_MAX = 2000; // a review comment
const BACKSTOP_SECONDS = 15;
const RATING = /^\d+(\.\d{1,4})?$/; // 0 or more, at most 4 decimals
const WRITING = new Set(["queued", "running"]);
const OVERALL_WORDS = {
  generating: "Being written",
  awaiting_review: "Ready for review",
  accepted: "Accepted",
  rejected: "Rejected",
  failed: "Failed",
  cancelled: "Stopped",
  read_only: "Read only",
};
/** A plan version's status and a decision in plain words (the register shows them too). */
export const STATUS_WORDS = { queued: "Waiting to start", running: "Being written", done: "Written", failed: "Failed", cancelled: "Stopped" };
export const DECISION_WORDS = { pending: "Awaiting decision", accepted: "Accepted", rejected: "Rejected" };
const IMPLEMENTATION_WORDS = {
  implemented: ["implemented", "Implemented"],
  partially_implemented: ["partially_implemented", "Partly implemented"],
  not_implemented: ["not_implemented", "Not implemented"],
  unverified: ["warning", "Not verified"],
};
const CHECK_WORDS = { retained: "Kept", replaced: "Replaced", flagged_for_review: "Flagged for review" };
const MATCH_WORDS = { exact: "Exact match", nearest: "Nearest match", given: "Named by the author", alternative: "Library alternative" };
const GAP_WORDS = {
  flagged_control: "Control flagged for review",
  no_validated_control: "No control confirmed for this risk",
  uncovered_risk: "Part of the risk no control covers",
};

export async function show(container, tools) {
  const [session_id, scenario_id] = tools.params;
  if (!session_id || !scenario_id) {
    container.append(tools.build_empty("Choose a plan from the treatment plan register.", tools.build_link("Open the register", "#/plans", { class: "button primary" })));
    return;
  }
  const paths = plan_paths(session_id, scenario_id);
  const live_note = tools.build_element("p", { class: "muted", role: "status" });
  const place = tools.build_element("div", { class: "stack" });
  container.append(live_note, place);
  let current = null; // the last answer shown: {plan} or {scenario} when there is no plan yet
  let stop_live = null;

  async function read() {
    try {
      return { plan: await tools.call("GET", paths.result) };
    } catch (error) {
      if (error.status !== 404) throw error;
      // No plan yet (or no such scenario: then this read fails too, and the error state says so).
      return { scenario: await tools.call("GET", paths.scenario) };
    }
  }

  function build(answer) {
    current = answer;
    if (answer.plan) {
      follow_live();
      return build_viewer(answer.plan, tools, actions);
    }
    tools.set_actions();
    return build_create(answer.scenario, tools, create);
  }

  const refresh = (quiet = true) => tools.load_into(place, read, build, { quiet });

  function follow_live() {
    if (stop_live) return;
    stop_live = tools.follow_stream(paths.events, {
      on_event: (type, data) => {
        if (type === "remediation.deleted") {
          tools.show_notice("This plan was deleted with its run.", "warn");
          refresh();
        } else if (type === "remediation.updated" && is_news(data, current?.plan)) refresh();
      },
      on_state: (state) => {
        const words = { live: "Live: this page updates by itself.", retrying: "Reconnecting for live updates…", ended: "Live updates stopped. Reload the page to see changes." };
        live_note.textContent = words[state] ?? "";
      },
    });
  }

  const start_key = tools.start_key(); // the same request sent again asks for one plan

  async function create(register) {
    const body = { is_manual: false, session_id, scenario_id, ...register };
    try {
      const started = await tools.call("POST", "/v1/remediation", body, { idempotent: start_key.for_content("plan", body) });
      tools.show_toast(`Treatment plan requested: version ${started.version} is being written now.`, "good");
    } catch (error) {
      if (error.reason !== "plan_already_exists") throw error;
      tools.show_toast("This scenario already has a treatment plan: it is shown now.", "info");
    }
    await refresh(false);
  }

  const actions = {
    async review(version, decision) {
      const body = { decision, version };
      if (decision === "rejected") {
        const answer = await tools.ask_to_confirm(`Reject version ${version} of this plan?`, {
          confirm_label: "Reject",
          danger: true,
          input: { label: "Why it is rejected (kept with the decision)" },
        });
        if (!answer.ok) return;
        if (answer.text.length > COMMENT_MAX) throw new Error(`Keep the comment to ${COMMENT_MAX} characters.`);
        if (answer.text) body.comment = answer.text;
      }
      await tools.call("POST", paths.review, body);
      tools.show_toast(decision === "accepted" ? `Version ${version} is now the accepted plan.` : `Version ${version} was rejected.`, "good");
      await refresh();
    },
    async regenerate() {
      const started = await tools.call("POST", paths.regenerate, {}, { idempotent: true });
      tools.show_toast(`Writing version ${started.version} of the plan. Earlier versions are kept.`, "good");
      await refresh();
    },
    async cancel() {
      await tools.call("POST", paths.cancel);
      tools.show_toast("Stopped writing the plan. Regenerate to write it again.", "good");
      await refresh();
    },
    export_word: () => export_word(current.plan, tools),
    print: () => tools.print_page(),
  };

  tools.every(BACKSTOP_SECONDS, () => {
    if (current?.plan && WRITING.has(current.plan.latest_status)) refresh();
  });
  await refresh(false);
}

/** Every address of one scenario's plan, each written out whole. */
function plan_paths(session_id, scenario_id) {
  const s = encodeURIComponent(session_id);
  const c = encodeURIComponent(scenario_id);
  return {
    result: `/v1/sessions/${s}/scenarios/${c}/treatment-plan?include_history=true`,
    review: `/v1/sessions/${s}/scenarios/${c}/treatment-plan/review`,
    regenerate: `/v1/sessions/${s}/scenarios/${c}/treatment-plan/regenerate`,
    cancel: `/v1/sessions/${s}/scenarios/${c}/treatment-plan/cancel`,
    events: `/v1/sessions/${s}/scenarios/${c}/treatment-plan/events`,
    scenario: `/v1/sessions/${s}/scenarios/${c}`,
  };
}

/** True when a live status says something the page does not show yet. */
function is_news(status, shown) {
  if (!shown || !status) return true;
  return status.updated_at !== shown.updated_at || status.latest_status !== shown.latest_status || status.decision !== shown.decision;
}

// ---------- the request form ----------

function build_create(scenario, tools, create) {
  const text = scenario.scenario ?? {};
  const title = text.scenario_title || "Untitled scenario";
  tools.set_subtitle(title);
  const summary = tools.build_section(
    { title: "Scenario", subtitle: title },
    tools.build_long_text(text.scenario_statement, 4),
    tools.build_facts([
      ["Risk statement", text.risk_statement],
      ["Threat", text.threat_name],
      ["Threat type", text.threat_type],
    ]),
  );
  // A MITRE card lists its ATT&CK techniques; otherwise the run's kind is what this tab remembers (else a standard run).
  const run_link = tools.build_link("Open the run", run_address(tools, scenario.session_id, scenario.attack_techniques?.length ? "mitre" : undefined), { class: "button" });
  if (!scenario.accepted || scenario.status !== "done") {
    const why = tools.build_callout("This scenario is not accepted. Accept it in its run first: only an accepted scenario gets a treatment plan.", "info");
    return [summary, tools.build_section({ title: "No treatment plan yet" }, why, tools.build_actions(run_link))];
  }
  const register = build_register_fields(tools, text.supporting_systems_involved ?? []);
  const form = tools.build_form(register.nodes, "Create treatment plan", () => create(register.read()), { extra: [run_link] });
  form.classList.add("form-wide");
  const intro = "Every field is optional. The register's data is kept with the plan; the risk owner's name is never sent to the AI.";
  return [summary, tools.build_section({ title: "Create treatment plan", subtitle: intro }, form)];
}

/**
 * The register's fields of a plan request (PlanRequest), every one optional, and their reading into the body.
 * `systems`: the asset's supporting systems ({supporting_system_id, supporting_system, is_applicable}) to tick;
 * none: the ids are typed as a comma list. read() throws a plain-words Error when a field is wrong.
 * @returns {{nodes: Node[], read: () => object}}
 */
export function build_register_fields(tools, systems = []) {
  const { build_element: element, build_field: field, build_row: row } = tools;
  const number = () => element("input", { type: "number", min: "0", step: "any", inputmode: "decimal" });
  const text = () => element("input", { type: "text", maxlength: NAME_MAX, autocomplete: "off" });
  const inputs = {
    likelihood_rating: number(),
    impact_rating: number(),
    final_risk_rating: number(),
    risk_level: tools.build_select([{ value: "", label: "Not set" }, ...LEVELS], ""),
    risk_owner: text(),
    impacted_business_division: text(),
    risk_identification_date: element("input", { type: "date" }),
    mitigation_start_date: element("input", { type: "date" }),
    mitigation_end_date: element("input", { type: "date" }),
    existing_controls: element("textarea", { rows: 4 }),
    existing_controls_all_subsystems_justification: element("textarea", { rows: 3, maxlength: JUSTIFICATION_MAX }),
  };
  fill_final_rating(inputs);
  const risk_systems = build_system_choice(tools, "The risk applies to", systems, (system) => system.is_applicable !== false, "Blank: the risk is on the asset itself.");
  const control_systems = build_system_choice(tools, "The existing controls are on", systems, () => false, "Blank: on none of them. Only systems the risk applies to count.");
  const optional = (hint) => ({ optional: true, hint });
  const nodes = [
    element("h3", { text: "Risk rating" }),
    row(
      field("Likelihood", inputs.likelihood_rating, optional()),
      field("Impact", inputs.impact_rating, optional()),
      field("Final risk rating", inputs.final_risk_rating, optional("Likelihood × impact until you type your own; kept as given.")),
      field("Risk level", inputs.risk_level, optional()),
    ),
    element("h3", { text: "Ownership" }),
    row(
      field("Risk owner", inputs.risk_owner, optional()),
      field("Impacted business division", inputs.impacted_business_division, optional()),
      field("Risk identification date", inputs.risk_identification_date, optional()),
    ),
    element("h3", { text: "Supporting systems" }),
    risk_systems.node,
    control_systems.node,
    element("h3", { text: "Existing controls" }),
    field("Controls already in place", inputs.existing_controls, { ...optional(`One per line: a control code or its name. Up to ${CONTROLS_MAX}.`), wide: true }),
    field("Justification", inputs.existing_controls_all_subsystems_justification, { ...optional("Why the existing controls are not on every system."), wide: true }),
    element("h3", { text: "Mitigation window" }),
    row(
      field("Start date", inputs.mitigation_start_date, optional("Sets the dates of the action plan.")),
      field("End date", inputs.mitigation_end_date, optional("Needs a start date, and is on or after it.")),
    ),
  ];
  function read() {
    const problems = [];
    const body = {
      supporting_systems_applicable_to_risk: risk_systems.read(problems),
      supporting_systems_applicable_to_existing_controls: control_systems.read(problems),
    };
    for (const [name, label] of [["likelihood_rating", "Likelihood"], ["impact_rating", "Impact"], ["final_risk_rating", "Final risk rating"]]) {
      const input = inputs[name];
      const value = input.value.trim();
      if (input.validity.badInput || (value && !RATING.test(value))) problems.push(`${label} is a number of 0 or more, with at most 4 decimals.`);
      else if (value) body[name] = Number(value);
    }
    for (const name of ["risk_level", "risk_owner", "impacted_business_division", "existing_controls_all_subsystems_justification"]) {
      const value = inputs[name].value.trim();
      if (value) body[name] = value;
    }
    if (inputs.risk_identification_date.value) body.risk_identification_date = `${inputs.risk_identification_date.value}T00:00:00Z`;
    const start = inputs.mitigation_start_date.value;
    const end = inputs.mitigation_end_date.value;
    if (end && !start) problems.push("Give the mitigation start date with its end date.");
    else if (end && end < start) problems.push("The mitigation end date is before its start date.");
    else if (start) Object.assign(body, { mitigation_start_date: start }, end ? { mitigation_end_date: end } : {});
    const controls = read_lines(inputs.existing_controls.value);
    if (controls.length > CONTROLS_MAX) problems.push(`Name at most ${CONTROLS_MAX} existing controls (there are ${controls.length}).`);
    else if (controls.length) body.existing_controls = controls;
    if (problems.length) throw new Error(problems.join(" "));
    return body;
  }
  return { nodes, read };
}

/** Fills the final rating as likelihood × impact until the person types one. */
function fill_final_rating(inputs) {
  let typed = false;
  inputs.final_risk_rating.addEventListener("input", () => (typed = inputs.final_risk_rating.value !== ""));
  const fill = () => {
    if (typed) return;
    const likelihood = inputs.likelihood_rating.value;
    const impact = inputs.impact_rating.value;
    inputs.final_risk_rating.value = likelihood && impact ? String(Math.round(Number(likelihood) * Number(impact) * 10000) / 10000) : "";
  };
  inputs.likelihood_rating.addEventListener("input", fill);
  inputs.impact_rating.addEventListener("input", fill);
}

/** Ticks of the asset's systems, or a comma list of ids when they are not known. read(problems) gives the ids. */
function build_system_choice(tools, label, systems, ticked, hint) {
  if (!systems.length) {
    const input = tools.build_element("input", { type: "text", inputmode: "numeric", autocomplete: "off", placeholder: "e.g. 214, 215" });
    const node = tools.build_field(`${label} (supporting system ids)`, input, { optional: true, hint: `Comma separated. ${hint}` });
    return { node, read: (problems) => read_ids(input.value, label, problems) };
  }
  const boxes = systems.map((system) => ({
    id: system.supporting_system_id,
    box: tools.build_element("input", { type: "checkbox", checked: ticked(system) }),
    name: system.supporting_system,
  }));
  // The hint sits inside the legend, so a screen reader reads it with the group's name.
  const legend = tools.build_element("legend", {}, label, " ", tools.build_element("small", { class: "hint", text: hint }));
  const node = tools.build_element(
    "fieldset",
    { class: "stack" },
    legend,
    boxes.map(({ box, name, id }) => tools.build_field(`${name} (${id})`, box)),
  );
  return { node, read: () => boxes.filter(({ box }) => box.checked).map(({ id }) => id) };
}

/**
 * Whole ids of a comma list ("214, 215"); a wrong one adds a problem. Exported for the manual scenario page.
 * @param {string} text @param {string} label @param {string[]} problems
 * @returns {number[]}
 */
export function read_ids(text, label, problems) {
  const parts = String(text ?? "").split(/[\s,]+/).filter(Boolean);
  if (parts.some((part) => !/^[1-9]\d{0,9}$/.test(part) || Number(part) > 2147483647)) {
    problems.push(`${label}: give whole ids of 1 or more, separated by commas.`);
    return [];
  }
  return [...new Set(parts.map(Number))];
}

/** The filled lines of a text box. Exported for the manual scenario page. */
export function read_lines(text) {
  return String(text ?? "").split("\n").map((line) => line.trim()).filter(Boolean);
}

// ---------- the plan viewer ----------

function build_viewer(result, tools, actions) {
  const scenario = result.scenario ?? {};
  tools.set_subtitle(scenario.title || result.plan?.title || "");
  tools.set_actions(
    tools.build_button("Export to Word", actions.export_word, { kind: "quiet", disabled: !result.plan }),
    tools.build_button("Print", actions.print, { kind: "quiet" }),
    tools.build_link("Open the run", run_address(tools, result.session_id), { class: "button" }),
  );
  return [
    build_status(result, tools, actions),
    ...result.warnings.map((warning) => tools.build_callout(sentence(warning), "warn")),
    build_scenario(scenario, tools),
    result.plan ? build_plan(result.plan, tools) : null,
    build_versions(result, tools, actions),
    build_register(result.register_data ?? {}, tools),
  ];
}

function build_status(result, tools, actions) {
  const overall = result.progress.overall;
  const writing = WRITING.has(result.latest_status);
  const can_change = overall !== "read_only";
  const buttons = [];
  if (writing) buttons.push(tools.build_button("Cancel", actions.cancel, { kind: "danger", confirm: "Stop writing this version of the plan? You can regenerate it later." }));
  else if (can_change) {
    buttons.push(tools.build_button("Regenerate", actions.regenerate, { confirm: "Write a new version of this plan from the same register data? Earlier versions are kept." }));
  }
  const notes = [];
  if (writing) notes.push(tools.build_callout(`Version ${result.latest_version} is being written. This page updates by itself.`, "info"));
  if (result.progress.retrying) notes.push(tools.build_callout(result.progress.retrying.message, "warn"));
  if (result.latest_status === "failed") notes.push(tools.build_callout(`Version ${result.latest_version} failed. ${result.error?.message ?? ""} Regenerate to try again.`, "bad"));
  if (result.latest_status === "cancelled") notes.push(tools.build_callout("Writing was stopped. Regenerate to write this version again.", "warn"));
  if (overall === "read_only") notes.push(tools.build_callout("The scenario is no longer accepted, so this plan can be read but not reviewed or regenerated.", "info"));
  return tools.build_section(
    { title: "Plan status", actions: buttons },
    tools.build_element(
      "div",
      { class: "tags" },
      tools.build_badge(overall, OVERALL_WORDS[overall]),
      tools.build_badge(result.decision, DECISION_WORDS[result.decision]),
    ),
    notes,
    tools.build_facts([
      ["Version shown", result.shown_version ? `Version ${result.shown_version}` : "None written yet"],
      ["Latest version", `Version ${result.latest_version}: ${STATUS_WORDS[result.latest_status] ?? tools.humanise(result.latest_status)}`],
      ["Accepted version", result.accepted_version ? `Version ${result.accepted_version}` : "None"],
      ["Updated", tools.format_date(result.updated_at)],
      ["Plan reference", tools.build_id(result.remediation_id)],
    ]),
  );
}

function build_scenario(scenario, tools) {
  const threat = scenario.threat ?? {};
  const actors = (scenario.actors ?? []).map((actor) => tools.build_tag(actor.name ?? actor.actor_name ?? "Unnamed", actor.url || null, actor.relevance || null));
  const controls = tools.build_table(
    scenario.controls ?? [],
    [
      { title: "Code", show: (control) => control.control_code, nowrap: true },
      { title: "Control", show: (control) => control.control_name },
      { title: "Match", show: (control) => build_match(String(control.match_type ?? "").toLowerCase(), tools) },
      { title: "Why", show: (control) => control.match_reason || control.rationale },
    ],
    // owner 2026-11-27: a MITRE scenario (its actors are MITRE groups) carries no controls: the plan identifies them.
    { caption: "The scenario's controls", empty: (scenario.actors ?? []).some((actor) => actor.mitre_id) ? "Controls are identified in the remediation plan." : "The scenario lists no controls." },
  );
  return tools.build_section(
    { title: "Scenario", subtitle: scenario.title || "Untitled scenario" },
    tools.build_long_text(scenario.statement, 4),
    tools.build_facts([
      ["Risk statement", scenario.risk_statement],
      ["Category", scenario.category],
      ["Threat", threat.name ?? threat.threat],
      ["Threat type", threat.type ?? threat.threat_type],
      ["Attackers", actors.length ? tools.build_element("span", { class: "tags" }, actors) : null],
    ]),
    controls,
  );
}

function build_plan(plan, tools) {
  const coverage = plan.control_coverage === "covered" ? tools.build_badge("done", "Covered by existing controls") : tools.build_badge("gaps", "Gaps to close");
  return tools.build_section(
    { title: "Treatment plan", subtitle: plan.title },
    tools.build_element("div", { class: "tags" }, tools.build_tag(`Strategy: ${plan.treatment_strategy}`), coverage),
    tools.build_long_text(plan.action_plan, 6),
    tools.build_facts([
      ["Mitigation owner", plan.mitigation_owner],
      ["Risk owner", plan.risk_owner],
      ["Impacted business division", plan.impacted_business_division],
      ["Applies to every supporting system", plan.applicable_to_all_subsystems],
    ]),
    tools.build_element("h3", { text: "Controls to implement" }),
    build_controls(plan, tools),
    plan.control_assessment.length ? [tools.build_element("h3", { text: "How each control was checked" }), build_assessment(plan.control_assessment, tools)] : null,
    plan.unresolved_gaps.length ? [tools.build_element("h3", { text: "Risks not covered" }), build_gaps(plan.unresolved_gaps, tools)] : null,
    tools.build_element("h3", { text: "Action plan" }),
    build_actions_table(plan.actions, tools),
    tools.build_element("h3", { text: "Schedule" }),
    tools.build_facts([
      ["Total duration", plan.mitigation_timeline_days != null ? `${tools.format_count(plan.mitigation_timeline_days)} days` : plan.mitigation_timeline],
      ["Planned end", format_day(plan.mitigation_end_date_planned)],
      ["Critical path", plan.critical_path.length ? plan.critical_path.join(" → ") : null],
    ]),
  );
}

function build_controls(plan, tools) {
  const columns = [
    { title: "Code", key: "control_code", nowrap: true },
    { title: "Control", show: (control) => [control.control_name, control.domain && tools.build_element("small", { class: "muted", text: ` ${control.domain}` })] },
    { title: "Type", show: (control) => tools.humanise(control.control_type) },
    { title: "Priority", show: (control) => tools.build_tag(control.priority) },
    { title: "Where it stands", show: (control) => build_implementation(control.implementation_status, tools) },
    { title: "Still needed on", show: (control) => system_names(control.required_systems) },
    { title: "Description", show: (control) => tools.build_long_text(control.description, 2) },
  ];
  const empty = plan.control_coverage === "covered" ? "No new control is needed: the existing controls cover the risk." : "The plan lists no control to implement.";
  return tools.build_table(plan.controls_to_be_implemented, columns, { caption: "Controls to implement", empty });
}

export function build_assessment(assessed, tools) {
  const check = (control) => [
    control.validation ? tools.build_badge(control.validation, CHECK_WORDS[control.validation]) : null,
    control.replaced_by ? ` by ${control.replaced_by}` : null,
    control.replaces.length ? `Replaces ${control.replaces.join(", ")}` : null,
    control.match === "alternative" && !control.replaces.length ? "Added" : null, // owner 2026-11-27: added, replacing nothing
    control.validation_reason ? tools.build_element("p", { class: "muted", text: control.validation_reason }) : null,
  ];
  const columns = [
    { title: "Code", key: "control_code", nowrap: true },
    { title: "Control", key: "control_name" },
    { title: "Match", show: (control) => build_match(control.match, tools) },
    { title: "Check", show: check },
    { title: "Where it stands", show: (control) => build_implementation(control.implementation_status, tools) },
    { title: "Already on", show: (control) => system_names(control.protected_systems) },
    { title: "Still needed on", show: (control) => system_names(control.required_systems) },
    { title: "In this plan", show: (control) => (control.recommended ? tools.build_badge("done", "Recommended") : tools.build_badge("off", "Not recommended")) },
  ];
  return tools.build_table(assessed, columns, { caption: "Controls checked against the risk and the register" });
}

function build_gaps(gaps, tools) {
  const columns = [
    { title: "Gap", show: (gap) => tools.build_badge("warning", GAP_WORDS[gap.kind] ?? tools.humanise(gap.kind)) },
    { title: "Control", key: "control_code", nowrap: true },
    { title: "Detail", key: "detail" },
  ];
  return tools.build_table(gaps, columns, { caption: "Risks not covered" });
}

function build_actions_table(actions, tools) {
  const columns = [
    { title: "Id", key: "action_id", nowrap: true },
    { title: "Action", show: (action) => [action.action, action.implements_controls.length ? tools.build_element("small", { class: "muted", text: ` Implements ${action.implements_controls.join(", ")}` }) : null] },
    { title: "Owner", key: "owner" },
    { title: "Priority", show: (action) => tools.build_tag(action.priority) },
    { title: "Depends on", show: (action) => action.depends_on.join(", ") || action.dependencies },
    { title: "Duration", show: (action) => `${tools.format_count(action.duration_days)} days`, numeric: true, nowrap: true },
    { title: "Start", show: (action) => format_day(action.start_date), nowrap: true },
    { title: "End", show: (action) => format_day(action.end_date), nowrap: true },
    { title: "Success criteria", key: "success_criteria" },
  ];
  return tools.build_table(actions, columns, { caption: "Action plan", empty: "The plan lists no action." });
}

function build_versions(result, tools, actions) {
  const can_review = result.progress.overall !== "read_only";
  const decide = (version) => {
    if (version.status !== "done" || !can_review) return null;
    return tools.build_actions(
      tools.build_button("Accept", () => actions.review(version.version, "accepted"), { small: true, kind: "primary", disabled: version.decision === "accepted" }),
      tools.build_button("Reject", () => actions.review(version.version, "rejected"), { small: true, kind: "danger", disabled: version.decision === "rejected" }),
    );
  };
  const columns = [
    { title: "Version", show: (version) => [`Version ${version.version}`, version.version === result.shown_version ? tools.build_element("small", { class: "muted", text: " (shown)" }) : null], nowrap: true },
    { title: "Status", show: (version) => [tools.build_badge(version.status, STATUS_WORDS[version.status]), version.error ? tools.build_element("p", { class: "muted", text: version.error.message }) : null] },
    {
      title: "Decision",
      show: (version) => [
        tools.build_badge(version.decision, DECISION_WORDS[version.decision]),
        version.decided_by ? tools.build_element("p", { class: "muted", text: `By ${version.decided_by}, ${tools.format_date(version.decided_at)}` }) : null,
        version.review_comment ? tools.build_element("p", { text: version.review_comment }) : null,
      ],
    },
    { title: "Requested", show: (version) => [tools.format_date(version.requested_at), version.requested_by ? ` by ${version.requested_by}` : null] },
    { title: "Finished", show: (version) => tools.format_date(version.completed_at), nowrap: true },
    { title: "Warnings", show: (version) => version.warnings.length, numeric: true },
    { title: "Review", show: decide },
  ];
  const versions = [...(result.versions ?? [])].reverse();
  return tools.build_section(
    { title: "Versions", subtitle: "Accepting a version makes it the plan; an earlier accepted version goes back to awaiting a decision." },
    tools.build_table(versions, columns, { caption: "Versions of this plan", empty: "No version yet." }),
  );
}

function build_register(register, tools) {
  return tools.build_section({ title: "Register data" }, tools.build_facts(register_facts(register, tools)));
}

function register_facts(register, tools) {
  const end = register.mitigation_end_date ? format_day(register.mitigation_end_date) : "no end date";
  const span = register.mitigation_start_date ? `${format_day(register.mitigation_start_date)} to ${end}` : null;
  return [
    ["Likelihood", register.likelihood_rating],
    ["Impact", register.impact_rating],
    ["Final risk rating", register.final_risk_rating],
    ["Risk level", register.risk_level],
    ["Risk owner", register.risk_owner],
    ["Impacted business division", register.impacted_business_division],
    ["Risk identified", format_day(register.risk_identification_date)],
    ["Mitigation window", span],
    ["Risk applies to systems", (register.supporting_systems_applicable_to_risk ?? []).join(", ") || "The asset itself"],
    ["Existing controls are on systems", (register.supporting_systems_applicable_to_existing_controls ?? []).join(", ") || "None"],
    ["Existing controls", (register.existing_controls ?? []).map((control) => control.control_code || control.control_name || control.control_id).join(", ")],
    ["Justification", register.existing_controls_all_subsystems_justification],
  ];
}

function build_implementation(status, tools) {
  const [word, label] = IMPLEMENTATION_WORDS[status] ?? [status, tools.humanise(status)];
  return tools.build_badge(word, label);
}

function build_match(match, tools) {
  if (!match) return null;
  return tools.build_badge(match, MATCH_WORDS[match] ?? tools.humanise(match), match === "exact" ? "good" : match === "nearest" ? "warn" : "idle");
}

function system_names(systems) {
  return (systems ?? []).map((system) => system.name).join(", ");
}

/** A calendar day ("2026-11-01" or a date-time) in the reader's language, without a time; a dash when missing. */
function format_day(value) {
  if (!value) return "—";
  const date = new Date(String(value).length === 10 ? `${value}T00:00:00Z` : value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" }).format(date);
}

/** A warning as a sentence: its first letter in capitals and a full stop. */
function sentence(text) {
  const words = String(text ?? "").trim();
  return words ? `${words[0].toUpperCase()}${words.slice(1)}${/[.!?]$/.test(words) ? "" : "."}` : "";
}

// ---------- Word export ----------

function export_word(result, tools) {
  const plan = result.plan;
  const scenario = result.scenario ?? {};
  const title = scenario.title || plan.title || "Treatment plan";
  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const blocks = [
    { heading: "Scenario", level: 1 },
    { paragraph: text(scenario.statement) },
    { facts: [["Risk statement", text(scenario.risk_statement)], ["Category", text(scenario.category)]] },
    { heading: "Plan", level: 1 },
    {
      facts: [
        ["Title", plan.title],
        ["Strategy", plan.treatment_strategy],
        ["Coverage", plan.control_coverage === "covered" ? "Covered by existing controls" : "Gaps to close"],
        ["Decision", `${DECISION_WORDS[result.decision]}${result.accepted_version ? ` (version ${result.accepted_version})` : ""}`],
        ["Version shown", text(result.shown_version)],
        ["Mitigation owner", plan.mitigation_owner],
        ["Total duration", plan.mitigation_timeline_days != null ? `${plan.mitigation_timeline_days} days` : text(plan.mitigation_timeline)],
        ["Critical path", plan.critical_path.join(" → ")],
      ],
    },
    { paragraph: plan.action_plan },
    { heading: "Controls to implement", level: 2 },
    {
      table: {
        columns: ["Code", "Control", "Type", "Priority", "Where it stands", "Still needed on"],
        rows: plan.controls_to_be_implemented.map((control) => [
          control.control_code,
          control.control_name,
          tools.humanise(control.control_type),
          control.priority,
          (IMPLEMENTATION_WORDS[control.implementation_status] ?? [null, control.implementation_status])[1],
          system_names(control.required_systems),
        ]),
      },
    },
    { heading: "Action plan", level: 2 },
    {
      table: {
        columns: ["Id", "Action", "Owner", "Priority", "Depends on", "Days", "Start", "End", "Success criteria"],
        rows: plan.actions.map((action) => [
          action.action_id,
          action.action,
          action.owner,
          action.priority,
          action.depends_on.join(", ") || action.dependencies,
          action.duration_days,
          format_day(action.start_date),
          format_day(action.end_date),
          action.success_criteria,
        ]),
      },
    },
  ];
  if (plan.unresolved_gaps.length) {
    blocks.push({ heading: "Risks not covered", level: 2 }, { list: plan.unresolved_gaps.map((gap) => `${GAP_WORDS[gap.kind] ?? gap.kind}: ${gap.detail}`) });
  }
  if (result.warnings.length) blocks.push({ heading: "Warnings", level: 2 }, { list: result.warnings.map(sentence) });
  blocks.push({ heading: "Register data", level: 1 }, { facts: register_facts(result.register_data ?? {}, tools).map(([label, value]) => [label, text(value)]) });
  tools.download_word(`Treatment plan - ${title}`, title, blocks);
  tools.show_toast("The plan was saved as a Word document.", "good");
}
