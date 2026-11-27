// New run: choose the kind of run, the asset and its supporting systems (and, if wanted, its service, sector and
// subsector), check them, start the run once and open its page.

import { RUN_KINDS } from "./runs.js";

const KIND_HINTS = {
  mitre: "Scenarios built from the MITRE ATT&CK groups and techniques that fit the asset, each one checked against MITRE.",
  tsg: "Scenarios built from your threat library and the threat intelligence imported for the asset.",
};
const MAX_ID = 2147483647; // the largest id the service stores
const ANOTHER_SERVICE = "another";
const FIELD_NAMES = {
  asset_id: "Asset id",
  supporting_system_id: "Supporting systems",
  supporting_system_ids: "Supporting systems",
  service_id: "Service",
  sector_id: "Sector id",
  subsector_id: "Subsector id",
};

/** A whole number from 1 to MAX_ID, else null. @param {string} text */
function read_id(text) {
  const value = String(text ?? "").trim();
  return /^\d+$/.test(value) && Number(value) >= 1 && Number(value) <= MAX_ID ? Number(value) : null;
}

export async function show(container, tools) {
  const { build_element, build_field } = tools;
  tools.set_subtitle("Choose the kind of run and the asset to assess. The scenarios are written in the background; you follow them on the run's page.");
  const number_input = (props = {}) => build_element("input", { type: "text", inputmode: "numeric", autocomplete: "off", spellcheck: "false", ...props });

  const kind_inputs = Object.keys(RUN_KINDS).map((value, index) => build_element("input", { type: "radio", name: "run-kind", value, checked: index === 0 }));
  const kind_choice = build_element(
    "div",
    { class: "grid-2", role: "radiogroup", "aria-label": "Kind of run" },
    kind_inputs.map((input) => build_field(RUN_KINDS[input.value].label, input, { hint: KIND_HINTS[input.value] })),
  );

  const asset = number_input({ required: true });
  const systems = new Set();
  const systems_input = number_input();
  const systems_tags = build_element("div", { class: "tags", "aria-live": "polite" });
  const systems_note = build_element("p", { class: "form-error", role: "alert", hidden: true });

  const service = tools.build_select([{ value: "", label: "No service" }, { value: ANOTHER_SERVICE, label: "Another service: type its id" }]);
  const service_id = number_input();
  const service_id_field = build_field("Service id", service_id, { hint: "The id of a service not in the list." });
  service_id_field.hidden = true;
  service.addEventListener("change", () => (service_id_field.hidden = service.value !== ANOTHER_SERVICE));
  const services_note = build_element("small", { class: "hint", text: "Reading your organisation's services…" });
  const sector = number_input();
  const subsector = number_input();

  function show_systems() {
    const remove = (id) => () => {
      systems.delete(id);
      show_systems();
      systems_input.focus();
    };
    tools.replace_content(
      systems_tags,
      [...systems].map((id) => build_element("button", { type: "button", class: "tag", "aria-label": `Remove supporting system ${id}`, on: { click: remove(id) } }, `${id} ✕`)),
    );
  }

  /** Moves the typed ids into the tags; the ones that are not ids stay typed, with a note. */
  function take_typed_systems() {
    const words = systems_input.value.split(/[\s,;]+/).filter(Boolean);
    const problems = [];
    const left = [];
    for (const word of words) {
      const id = read_id(word);
      if (id === null) problems.push(`"${word}" is not a system id: use whole numbers, 1 or more.`);
      else if (systems.has(id)) problems.push(`System ${id} is already in the list.`);
      else systems.add(id);
      if (id === null) left.push(word);
    }
    systems_input.value = left.join(" ");
    systems_note.textContent = problems.join(" ");
    systems_note.hidden = problems.length === 0;
    show_systems();
    return left; // a repeat is only noted: it is in the list already
  }
  systems_input.addEventListener("keydown", (event) => {
    if (![",", " ", "Enter"].includes(event.key) || !systems_input.value.trim()) return;
    event.preventDefault(); // Enter adds the typed ids instead of sending the form
    take_typed_systems();
  });
  systems_input.addEventListener("change", take_typed_systems);

  function read_optional(input, name, problems) {
    if (!input.value.trim()) return null;
    const id = read_id(input.value);
    if (id === null) problems.push(`${name} must be a whole number, 1 or more.`);
    return id;
  }

  /** The StartRunRequest body, or an error that names every problem. */
  function read_body() {
    const problems = take_typed_systems().length ? ["Fix the supporting system ids."] : [];
    const asset_id = read_id(asset.value);
    if (asset_id === null) problems.push("Asset id must be a whole number, 1 or more.");
    if (!systems.size) problems.push("Add at least one supporting system id.");
    const chosen_service = service.value === ANOTHER_SERVICE ? read_optional(service_id, "Service id", problems) : read_id(service.value);
    if (service.value === ANOTHER_SERVICE && !service_id.value.trim()) problems.push("Type the service id, or choose No service.");
    const body = {
      asset_id,
      supporting_system_id: [...systems],
      service_id: chosen_service,
      sector_id: read_optional(sector, "Sector id", problems),
      subsector_id: read_optional(subsector, "Subsector id", problems),
    };
    if (problems.length) throw new Error(problems.join(" "));
    return Object.fromEntries(Object.entries(body).filter(([, value]) => value !== null));
  }

  const start_key = tools.start_key();

  async function start_run() {
    const body = read_body();
    const kind = kind_inputs.find((input) => input.checked).value;
    let answer;
    try {
      // The same form sent again (a retry after a lost answer, a double click) carries the same key: the API
      // answers 200 with the run it already started, never a second paid run.
      answer = kind === "mitre"
        ? await tools.call("POST", "/v1/mitre_create_session", body, { idempotent: start_key.for_content("mitre", body), with_status: true })
        : await tools.call("POST", "/v1/sessions", body, { idempotent: start_key.for_content("tsg", body), with_status: true });
    } catch (error) {
      throw explain_refusal(error);
    }
    const board = answer.body;
    const existed = answer.status === 200;
    tools.remember_run({ kind, id: board.session_id, label: board.asset_name || `Asset ${board.asset_id}` });
    tools.show_toast(existed ? "This run already exists: it is opened." : "The run has started: its page shows the scenarios as they are written.", existed ? "info" : "good");
    tools.go(RUN_KINDS[kind].page, board.session_id);
  }

  const form = tools.build_form(
    [
      build_element("p", { class: "label", text: "Kind of run" }),
      kind_choice,
      build_field("Asset id", asset, { hint: "The asset the scenarios are about, as numbered in your asset register." }),
      build_field("Supporting system ids", systems_input, { hint: "One or more systems the asset relies on. Separate ids with commas or spaces; press Enter to add them." }),
      systems_tags,
      systems_note,
      tools.build_row(build_element("div", {}, build_field("Service", service, { optional: true }), services_note), service_id_field),
      tools.build_row(build_field("Sector id", sector, { optional: true }), build_field("Subsector id", subsector, { optional: true })),
    ],
    "Start run",
    start_run,
  );
  container.append(tools.build_section({ title: "Start a run", subtitle: "Starting a run uses paid AI calls: check the ids first." }, form));
  asset.focus();
  await fill_services(tools, service, services_note);
}

/** Adds the entity's services to the select; when they cannot be read, the select keeps "Another service". */
async function fill_services(tools, select, note) {
  const entity_id = tools.identity().entity_id;
  try {
    const answer = await tools.call("GET", `/v1/entities/${encodeURIComponent(entity_id)}/services`);
    const services = answer?.services ?? [];
    const options = services.map((item) =>
      tools.build_element("option", { value: String(item.service_id), text: [`${item.name} (ID ${item.service_id})`, item.sector, item.sub_sector].filter(Boolean).join(" · ") }),
    );
    select.lastElementChild.before(...options);
    note.textContent = services.length ? "Optional: the service the asset supports." : "No service is listed for your organisation: type an id, or leave it out.";
  } catch {
    note.textContent = "The list of services could not be read: choose Another service to type its id.";
  }
}

/** The API's field errors in the form's own words. */
function explain_refusal(error) {
  const fields = Array.isArray(error?.body?.errors) ? error.body.errors : [];
  if (!fields.length) return error;
  const lines = fields.map((item) => {
    const name = String(item.field ?? "").replace(/^body\./, "").split(".")[0];
    return `${FIELD_NAMES[name] ?? name}: ${item.message}`;
  });
  const reference = error.request_id ? ` Reference ${error.request_id}.` : "";
  return new Error(`The run was not started. ${lines.join(" ")}${reference}`);
}
