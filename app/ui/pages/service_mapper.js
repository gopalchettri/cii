// Service mapper: describe a service, follow its run, then accept or reject each service it depends on (upstream)
// and each service that depends on it (downstream). Calls the client API with this page's own caller headers.

import { is_job_over } from "../poll.js";

// The form's starting values: catalog service 1546 (Transport / Land) of entity 125, Roads and Transport Authority.
const START = {
  "X-API-Key": "",
  "X-User-Id": "gopal",
  "X-Entity-Id": "125",
  "X-Tenant-Id": "69",
  service_name: "Traffic Management & Control",
  service_description:
    "Traffic Management & Control Service is responsible for monitoring, managing, and optimizing road traffic " +
    "flow to ensure safe and efficient transportation. It uses traffic signals, surveillance systems, sensors, and " +
    "intelligent transportation technologies to manage congestion, detect incidents, coordinate emergency " +
    "responses, and improve road network efficiency.",
  sector: "Transport",
  subsector: "Land",
  entity_names: "Roads and Transport Authority",
};
const NAME_MAX = 255; // CreateMappingRequest's own limits
const DESCRIPTION_MAX = 4000;
const RECENT = 20;
const NO_NEW_RUN = "No new run: the last run found nothing new, and nothing has changed since.";

export async function show(container, tools) {
  const { build_element, build_field, build_panel } = tools;
  const text = (name, props = {}) =>
    build_element("input", { type: "text", value: START[name], required: true, autocomplete: "off", spellcheck: "false", ...props });
  const caller = {
    "X-API-Key": text("X-API-Key", { type: "password" }),
    "X-User-Id": text("X-User-Id"),
    "X-Entity-Id": text("X-Entity-Id", { inputmode: "numeric" }),
    "X-Tenant-Id": text("X-Tenant-Id"),
  };
  const service = {
    service_name: text("service_name", { maxlength: NAME_MAX }),
    service_description: build_element("textarea", { required: true, maxlength: DESCRIPTION_MAX, rows: 5, value: START.service_description }),
    sector: text("sector", { maxlength: NAME_MAX }),
    subsector: text("subsector", { maxlength: NAME_MAX, required: false }),
    entity_names: text("entity_names"),
  };
  const recent_place = build_element("div", { class: "columns" });
  const mapping_place = build_element("div", { class: "page" });
  let stop_following = null;

  // Every call carries the caller fields as they are now.
  const call = (method, path, body) =>
    tools.request(method, path, body, Object.fromEntries(Object.entries(caller).map(([name, field]) => [name, field.value])));
  const actions_of = (mapping_id) => ({
    regenerate: () => regenerate(mapping_id),
    decide: (dependency, accept) => decide(mapping_id, dependency, accept),
  });

  async function generate() {
    const body = Object.fromEntries(Object.entries(service).map(([name, field]) => [name, field.value.trim()]));
    body.entity_names = body.entity_names.split(",").map((name) => name.trim()).filter(Boolean);
    follow((await call("POST", "/v1/service-mapper", body)).mapping_id);
  }

  async function regenerate(mapping_id) {
    const accepted = await call("POST", `/v1/service-mapper/${encodeURIComponent(mapping_id)}/regenerate`);
    if (accepted.status === "done") tools.show_notice(NO_NEW_RUN);
    follow(accepted.mapping_id);
  }

  async function decide(mapping_id, dependency, accept) {
    const body = { [accept ? "accept" : "reject"]: [dependency.dependency_id] };
    const decided = await call("POST", `/v1/service-mapper/${encodeURIComponent(mapping_id)}/dependencies/decision`, body);
    for (const failure of decided.failed) tools.show_notice(failure.message, "bad");
    tools.replace_content(mapping_place, build_mapping(decided, tools, actions_of(mapping_id)));
  }

  /** Shows the run's state on every change; once it is over, the mapping itself. */
  function follow(mapping_id) {
    stop_following?.();
    tools.replace_content(mapping_place, tools.build_loading("Following the run…"));
    const read = () => call("GET", `/v1/service-mapper/${encodeURIComponent(mapping_id)}/status`);
    stop_following = tools.follow_job(read, (status, error) => {
      if (error) tools.replace_content(mapping_place, tools.build_error(error, () => follow(mapping_id)));
      else if (!is_job_over(status)) tools.replace_content(mapping_place, build_progress(status, tools));
      else open_mapping(mapping_id);
    });
  }

  function open_mapping(mapping_id) {
    const read = () => call("GET", `/v1/service-mapper/${encodeURIComponent(mapping_id)}`);
    return tools.load_into(mapping_place, read, (mapping) => build_mapping(mapping, tools, actions_of(mapping_id)));
  }

  function show_recent() {
    const read = () => call("GET", tools.with_query("/v1/service-mapper", { limit: RECENT }));
    return tools.load_into(recent_place, read, (list) => build_recent(list.items, tools, follow));
  }

  const caller_fields = build_element(
    "div",
    { class: "toolbar" },
    build_field("X-API-Key", caller["X-API-Key"], { hint: "Your client key. Kept on this page only: gone when you leave it." }),
    build_field("X-User-Id", caller["X-User-Id"]),
    build_field("X-Entity-Id", caller["X-Entity-Id"]),
    build_field("X-Tenant-Id", caller["X-Tenant-Id"]),
  );
  const service_fields = [
    build_field("Service name", service.service_name),
    build_field("Service description", service.service_description, { hint: "What the service does: the AI works from this." }),
    build_element(
      "div",
      { class: "toolbar" },
      build_field("Sector", service.sector),
      build_field("Subsector (optional)", service.subsector, { hint: "Left empty: found in the catalog by name and sector." }),
    ),
    build_field("Entity names", service.entity_names, { hint: "Comma separated, 1 to 20." }),
  ];
  container.append(
    build_panel("Who is calling", caller_fields),
    build_panel("Describe the service", tools.build_form(service_fields, "Generate dependencies", generate)),
    build_panel("Mappings", tools.build_actions(tools.build_button("Recent mappings", show_recent)), recent_place),
    mapping_place,
  );
}

function build_progress(status, tools) {
  const facts = [
    ["Mapping id", tools.build_element("span", { class: "mono", text: status.mapping_id })],
    ["Status", tools.build_badge(status.status)],
    ["Run", of_limit(status.generation, status.max_generations)],
    ...(status.retrying ? [["Waiting", status.retrying.message]] : []),
  ];
  return tools.build_panel("Run in progress", tools.build_facts(facts), tools.build_loading("Reading again every 3 seconds…"));
}

function build_mapping(mapping, tools, actions) {
  const summary = mapping.summary;
  const at_limit = mapping.max_generations > 0 && mapping.generations_done >= mapping.max_generations;
  const regenerate = tools.build_button("Regenerate", actions.regenerate, {
    disabled: !is_job_over(mapping) || at_limit,
    title: at_limit ? "This mapping has had all its runs." : "Run it again: only services it does not hold yet are added.",
  });
  const facts = tools.build_facts([
    ["Mapping id", tools.build_element("span", { class: "mono", text: mapping.mapping_id })],
    ["Status", tools.build_badge(mapping.status)],
    ...(mapping.error ? [["Error", mapping.error.message]] : []),
    ["Runs done", of_limit(mapping.generations_done, mapping.max_generations)],
    ["Services", tools.format_count(summary.unique_services)],
    ["Upstream", `${summary.upstream_count} (up to ${summary.max_upstream} new per run)`],
    ["Downstream", `${summary.downstream_count} (up to ${summary.max_downstream} new per run)`],
    ["Updated", tools.format_date(mapping.updated_at)],
  ]);
  return [
    tools.build_panel("Mapping", facts, tools.build_actions(regenerate)),
    tools.build_panel("Upstream: services it depends on", build_services(mapping.upstream_services, tools, actions)),
    tools.build_panel("Downstream: services that depend on it", build_services(mapping.downstream_services, tools, actions)),
  ];
}

function build_services(services, tools, actions) {
  const decision = (service) => {
    if (service.isAccepted === null || service.isAccepted === undefined) return tools.build_badge("pending", "Waiting for a decision");
    return service.isAccepted ? tools.build_badge("approved", "Accepted") : tools.build_badge("rejected", "Rejected");
  };
  const decide = (service) =>
    tools.build_actions(
      tools.build_button("Accept", () => actions.decide(service, true), { disabled: service.isAccepted === true }),
      tools.build_button("Reject", () => actions.decide(service, false), { disabled: service.isAccepted === false }),
    );
  const columns = [
    { title: "Service", key: "service_name" },
    { title: "Sector / subsector", show: (service) => [service.sector, service.subsector].filter(Boolean).join(" / ") },
    { title: "Source", show: (service) => (service.ai_suggested ? "New, named by the AI" : `Catalog, id ${service.service_id}`) },
    { title: "Reason", key: "dependency_reason" },
    { title: "Decision", show: decision },
    { title: "Decide", show: decide },
  ];
  return tools.build_table(services, columns, { empty: "No service on this side yet." });
}

function build_recent(items, tools, open) {
  const columns = [
    { title: "Service", show: (mapping) => mapping.selected_service.service_name },
    { title: "Sector / subsector", show: (mapping) => [mapping.selected_service.sector, mapping.selected_service.subsector].filter(Boolean).join(" / ") },
    { title: "In the catalog", show: (mapping) => (mapping.selected_service.service_id ? `Yes, id ${mapping.selected_service.service_id}` : "No") },
    { title: "Status", show: (mapping) => tools.build_badge(mapping.status) },
    { title: "Runs done", show: (mapping) => of_limit(mapping.generations_done, mapping.max_generations), nowrap: true },
    { title: "Updated", show: (mapping) => tools.format_date(mapping.updated_at), nowrap: true },
    { title: "Open", show: (mapping) => tools.build_button("Open", () => open(mapping.mapping_id)) },
  ];
  return tools.build_table(items, columns, { caption: "Recent mappings of this entity", empty: "This entity has no mapping yet." });
}

/** "4 of 10", or "4" when there is no limit (0). */
function of_limit(count, limit) {
  return limit ? `${count} of ${limit}` : String(count);
}
