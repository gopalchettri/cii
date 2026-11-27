// A scenario written by hand, planned at once: the asset and its systems, the threat by library name or id, the two
// statements and the register's data. The service saves the scenario, accepts it and writes its treatment plan.

import { STATUS_WORDS, build_register_fields, read_ids, read_lines } from "./plan.js";

const STATEMENT_MAX = 4000; // ManualScenario's statements
const NAME_MAX = 500; // a threat name; a type name takes 300, a category 200
const CONTROLS_MAX = 50;
const LIBRARY_ID = /^[1-9]\d{0,9}$/;

export async function show(container, tools) {
  const { build_element: element, build_field: field, build_row: row } = tools;
  const entity_id = Number(tools.identity().entity_id);
  const id_input = (required) => element("input", { type: "number", min: "1", max: "2147483647", step: "1", inputmode: "numeric", required });
  const text = (max, required) => element("input", { type: "text", maxlength: max, required, autocomplete: "off" });
  const box = (required) => element("textarea", { rows: 4, maxlength: STATEMENT_MAX, required });
  const inputs = {
    asset_id: id_input(true),
    supporting_system_id: element("input", { type: "text", inputmode: "numeric", required: true, autocomplete: "off", placeholder: "e.g. 214, 215" }),
    service_id: id_input(false),
    sector_id: id_input(false),
    subsector_id: id_input(false),
    threat_category: text(200, false),
    threat_type: text(300, true),
    threat: text(NAME_MAX, true),
    threat_scenario: box(true),
    risk_statement: box(true),
    mapped_controls: element("textarea", { rows: 3 }),
  };
  const by_name_or_id = "Its name in the threat library, or its library id (a number).";
  const register = build_register_fields(tools);
  const fields = [
    element("h3", { text: "Asset" }),
    row(
      field("Asset id", inputs.asset_id),
      field("Supporting system ids", inputs.supporting_system_id, { hint: "The asset's systems this scenario involves, comma separated." }),
    ),
    row(field("Service id", inputs.service_id, { optional: true }), field("Sector id", inputs.sector_id, { optional: true }), field("Subsector id", inputs.subsector_id, { optional: true })),
    element("h3", { text: "Threat" }),
    row(
      field("Threat type", inputs.threat_type, { hint: by_name_or_id }),
      field("Threat", inputs.threat, { hint: by_name_or_id }),
      field("Threat category", inputs.threat_category, { optional: true, hint: "Left empty: the threat's own category." }),
    ),
    field("Threat scenario", inputs.threat_scenario, { wide: true, hint: "How the attack happens, step by step." }),
    field("Risk statement", inputs.risk_statement, { wide: true, hint: "What the business loses if it happens." }),
    field("Controls of the scenario", inputs.mapped_controls, {
      optional: true,
      wide: true,
      hint: `One per line: a control code or its name, up to ${CONTROLS_MAX}. Left empty: the service finds them in the control library.`,
    }),
    ...register.nodes,
  ];
  const result_place = element("div", { class: "stack", "aria-live": "polite" });

  function read_scenario() {
    const problems = [];
    const scenario = {
      entity_id,
      asset_id: Number(inputs.asset_id.value),
      supporting_system_id: read_ids(inputs.supporting_system_id.value, "Supporting system ids", problems),
      threat_scenario: inputs.threat_scenario.value.trim(),
      risk_statement: inputs.risk_statement.value.trim(),
    };
    if (!problems.length && scenario.supporting_system_id.length === 0) problems.push("Give at least one supporting system id.");
    for (const name of ["service_id", "sector_id", "subsector_id"]) {
      if (inputs[name].value) scenario[name] = Number(inputs[name].value);
    }
    // Each of them named by its library id (a number) or its name: ManualScenario takes either.
    for (const name of ["threat_category", "threat_type", "threat"]) {
      const value = inputs[name].value.trim();
      if (LIBRARY_ID.test(value)) scenario[`${name}_id`] = Number(value);
      else if (value) scenario[`${name}_name`] = value;
    }
    const controls = read_lines(inputs.mapped_controls.value);
    if (controls.length > CONTROLS_MAX) problems.push(`Name at most ${CONTROLS_MAX} controls of the scenario (there are ${controls.length}).`);
    else if (controls.length) scenario.mapped_controls = controls;
    if (!scenario.threat_scenario || !scenario.risk_statement) problems.push("Write the threat scenario and the risk statement.");
    if (problems.length) throw new Error(problems.join(" "));
    return scenario;
  }

  const start_key = tools.start_key(); // the same scenario sent again is saved once

  async function submit() {
    // Every wrong field at once: the scenario's and the register's.
    const problems = [];
    const manual_scenario = read_part(read_scenario, problems);
    const register_body = read_part(register.read, problems);
    if (manual_scenario && register_body) check_listed_systems(manual_scenario.supporting_system_id, register_body, problems);
    if (problems.length) throw new Error(problems.join(" "));
    const body = { is_manual: true, manual_scenario, ...register_body };
    const started = await tools.call("POST", "/v1/remediation", body, { idempotent: start_key.for_content("manual", body) });
    tools.remember_run({ kind: "tsg", id: started.session_id, label: "Scenario written by hand" });
    tools.show_toast(started.replayed ? "This scenario was already saved: nothing new was saved." : "Scenario saved. Its treatment plan is being written now.", "good");
    tools.replace_content(result_place, build_result(started, tools, write_another));
    result_place.scrollIntoView({ block: "nearest" });
  }

  function write_another() {
    form.reset();
    tools.replace_content(result_place);
    inputs.asset_id.focus();
  }

  const form = tools.build_form(fields, "Save scenario and create plan", submit);
  form.classList.add("form-wide");
  const intro = "The service saves the scenario as accepted, finds its controls and attacker if you name none, then writes its plan.";
  container.append(tools.build_section({ title: "Scenario written by hand", subtitle: intro }, form), result_place);
}

/** read()'s answer, or null with its message added to `problems`. */
function read_part(read, problems) {
  try {
    return read();
  } catch (error) {
    problems.push(error.message);
    return null;
  }
}

/** The register's two system lists may name only the scenario's own supporting systems (else the service refuses it). */
function check_listed_systems(scenario_systems, register_body, problems) {
  const lists = [
    ["supporting_systems_applicable_to_risk", "The risk applies to"],
    ["supporting_systems_applicable_to_existing_controls", "The existing controls are on"],
  ];
  for (const [name, label] of lists) {
    const others = (register_body[name] ?? []).filter((id) => !scenario_systems.includes(id));
    if (others.length) problems.push(`${label}: ${others.join(", ")} is not among the supporting system ids of the scenario.`);
  }
}

function build_result(started, tools, reset) {
  const plan = `#/plan/${encodeURIComponent(started.session_id)}/${encodeURIComponent(started.scenario_id)}`;
  const run = `#/run/${encodeURIComponent(started.session_id)}`;
  return tools.build_section(
    { title: "Saved", subtitle: started.replayed ? "This scenario had been saved before." : `Version ${started.version} of its plan is being written.` },
    tools.build_facts([
      ["Plan reference", tools.build_id(started.remediation_id)],
      ["Run", tools.build_id(started.session_id)],
      ["Scenario", tools.build_id(started.scenario_id)],
      ["Plan", tools.build_badge(started.status, `Version ${started.version}: ${STATUS_WORDS[started.status] ?? tools.humanise(started.status)}`)],
    ]),
    tools.build_actions(
      tools.build_link("View plan", plan, { class: "button primary" }),
      tools.build_link("Open run", run, { class: "button" }),
      tools.build_button("Write another", reset, { kind: "quiet" }),
    ),
  );
}
