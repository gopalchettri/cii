// Service mapper. Without a param: describe a service (or pick it from the catalogue) and list this entity's
// mappings. With #/service_mapper/<mapping_id>: one mapping, followed live while its run goes on, with the
// services it depends on (upstream) and the services that depend on it (downstream) to accept or reject.

const NAME_MAX = 255; // CreateMappingRequest's own limits
const DESCRIPTION_MAX = 4000;
const ENTITIES_MAX = 20;
const DECISION_IDS_PER_CALL = 200; // DependencyDecisionRequest's own limit
const PAGE_SIZE = 20;
const BACKSTOP_SECONDS = 10; // the live stream is the main channel; this read catches what it missed
const NO_NEW_RUN = "No new run: the last run found nothing new, and nothing has changed since.";
/** A refused Generate that names its mapping: what to say before opening it (the API's own text names a setting). */
const OPENS_THE_MAPPING = {
  generation_in_progress: "This service is being mapped already: here is its mapping. Send new details once its run ends.",
  generation_limit_reached: "This service's mapping has had all its runs: here it is. Every service and decision stays.",
};
const LIMIT_REACHED = "This mapping has had all its runs. Every service and decision stays.";
const STATUS_WORDS = { queued: "Waiting to start", running: "Finding services", done: "Done", failed: "Failed", cancelled: "Cancelled" };
const SIDES = [
  { key: "upstream_services", title: "Upstream: services it depends on", word: "upstream" },
  { key: "downstream_services", title: "Downstream: services that depend on it", word: "downstream" },
];
const LIVE_WORDS = {
  connecting: "Connecting to live updates…",
  live: "Live updates on.",
  retrying: `Live updates paused: reconnecting. The page also checks every ${BACKSTOP_SECONDS} seconds.`,
  ended: `Live updates stopped. The page still checks every ${BACKSTOP_SECONDS} seconds.`,
};

export async function show(container, tools) {
  const [mapping_id] = tools.params;
  if (mapping_id) show_mapping(container, tools, mapping_id);
  else show_start(container, tools);
}

// ---------------- the start page: describe a service, and the entity's mappings ----------------

function show_start(container, tools) {
  tools.set_subtitle("Describe one of your services: the AI finds the services it depends on and the services that depend on it, for you to accept or reject.");
  const list_place = tools.build_element("div");
  let offset = 0;
  let has_running = false;
  const read = () => tools.call("GET", tools.with_query("/v1/service-mapper", { offset, limit: PAGE_SIZE }));
  const build = (list) => {
    has_running = list.items.some(is_running);
    return build_mapping_list(list, offset, tools, (next) => {
      offset = next;
      load_list(false);
    });
  };
  const load_list = (quiet) => tools.load_into(list_place, read, build, { quiet });
  const refresh = tools.build_button("Refresh", () => load_list(true), { kind: "quiet", small: true });
  container.append(
    build_describe_form(tools),
    tools.build_section({ title: "Your mappings", subtitle: "Every service your organisation has mapped.", actions: [refresh] }, list_place),
  );
  tools.every(BACKSTOP_SECONDS, () => has_running && load_list(true));
  load_list(false);
}

function build_describe_form(tools) {
  const { build_element, build_field, build_row, format_count } = tools;
  const text_input = (props = {}) => build_element("input", { type: "text", maxlength: NAME_MAX, autocomplete: "off", ...props });
  const name = text_input({ required: true });
  const sector = text_input({ required: true });
  const subsector = text_input();
  const description = build_element("textarea", { required: true, maxlength: DESCRIPTION_MAX, rows: 6 });
  const counter_text = (count) =>
    `What the service does, in plain words: the AI works from this. ${format_count(count)} of ${format_count(DESCRIPTION_MAX)} characters.`;
  const description_field = build_field("Service description", description, { hint: counter_text(0), wide: true });
  const counter = description_field.querySelector(".hint");
  description.addEventListener("input", () => (counter.textContent = counter_text(description.value.length)));
  const entities = build_entity_tags(tools);
  const catalogue_place = build_element("div");
  load_catalogue(catalogue_place, tools, (service) => {
    name.value = service.name;
    sector.value = service.sector ?? "";
    subsector.value = service.sub_sector ?? "";
  });

  const start_key = tools.start_key(); // the same service sent again is mapped once

  async function start_mapping() {
    const body = {
      service_name: name.value.trim(),
      service_description: description.value.trim(),
      sector: sector.value.trim(),
      subsector: subsector.value.trim(),
      entity_names: entities.read(),
    };
    let started;
    let replayed = false;
    try {
      const answer = await tools.call("POST", "/v1/service-mapper", body, { idempotent: start_key.for_content("map", body), with_status: true });
      started = answer.body;
      replayed = answer.status === 200;
    } catch (error) {
      const said = OPENS_THE_MAPPING[error.reason];
      if (!said || !error.details?.mapping_id) throw error;
      tools.show_toast(said, "info");
      tools.go("service_mapper", error.details.mapping_id);
      return;
    }
    if (started.status === "done") tools.show_toast(NO_NEW_RUN, "warn");
    else if (replayed) tools.show_toast("This service was already sent: its mapping is opened.", "info");
    else tools.show_toast(`Mapping started for ${body.service_name}. Its services appear as soon as the run ends.`, "good");
    tools.go("service_mapper", started.mapping_id);
  }

  const fields = [
    catalogue_place,
    build_row(build_field("Service name", name), build_field("Sector", sector)),
    build_row(build_field("Subsector", subsector, { optional: true, hint: "Left empty: the service is found in the catalogue by its name and sector." })),
    description_field,
    entities.element,
  ];
  return tools.build_section(
    { title: "Describe a service", subtitle: "Mapping the same service again (same name, sector and subsector) adds to its mapping: nothing found before is lost." },
    tools.build_form(fields, "Map its dependencies", start_mapping),
  );
}

/** The catalogue select: picking a service fills in its name, sector and subsector. */
function load_catalogue(place, tools, fill) {
  const entity_id = tools.identity()?.entity_id;
  const read = () => tools.call("GET", `/v1/entities/${encodeURIComponent(entity_id)}/services`);
  return tools.load_into(place, read, (answer) => {
    const services = answer?.services ?? [];
    if (!services.length) return tools.build_callout("Your catalogue has no services yet: type the service's details below.", "info");
    const label_of = (service) => [service.name, sector_text(service.sector, service.sub_sector)].filter(Boolean).join(" — ");
    const choices = [{ value: "", label: "Type the details yourself" }, ...services.map((service, index) => ({ value: String(index), label: label_of(service) }))];
    const select = tools.build_select(choices, "");
    select.addEventListener("change", () => select.value && fill(services[Number(select.value)]));
    return tools.build_field("Pick from your catalogue", select, { optional: true, hint: "Fills in the name, sector and subsector. Then describe what the service does." });
  });
}

/** Entity names as removable tags: Enter or Add puts the typed name (or several, comma separated) in the list. */
function build_entity_tags(tools) {
  const { build_element } = tools;
  const names = [];
  const input = build_element("input", { type: "text", maxlength: NAME_MAX, autocomplete: "off" });
  const list = build_element("div", { class: "tags", role: "list", "aria-label": "Entity names added" });

  function remove(index) {
    names.splice(index, 1);
    draw();
    input.focus();
  }

  function draw() {
    const tag_of = (name, index) =>
      build_element(
        "span",
        { class: "tag", role: "listitem" },
        name,
        build_element("button", { type: "button", class: "link-button", text: "✕", "aria-label": `Remove ${name}`, on: { click: () => remove(index) } }),
      );
    tools.replace_content(list, names.map(tag_of));
  }

  /** Adds the typed names; throws a plain message when one cannot be added. */
  function add_typed() {
    const typed = input.value.split(",").map((part) => part.split(/\s+/).filter(Boolean).join(" ")).filter(Boolean);
    const next = [...names]; // all or none: a refused name leaves the list and the box as they were
    for (const name of typed) {
      if (next.some((kept) => kept.toLowerCase() === name.toLowerCase())) throw new Error(`"${name}" is in the list already.`);
      if (next.length >= ENTITIES_MAX) throw new Error(`At most ${ENTITIES_MAX} entity names.`);
      next.push(name);
    }
    names.splice(0, names.length, ...next);
    input.value = "";
    draw();
  }

  const add_or_warn = () => {
    try {
      add_typed();
    } catch (error) {
      tools.show_toast(error.message, "warn");
    }
  };
  input.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault(); // Enter adds the name; it does not send the form
    add_or_warn();
  });
  const field = tools.build_field("Entity names", input, {
    hint: `The organisations that run or use the service, 1 to ${ENTITIES_MAX}. Press Enter or Add after each name.`,
  });
  const element = build_element(
    "div",
    { class: "stack" },
    build_element("div", { class: "toolbar" }, field, tools.build_button("Add", add_or_warn, { kind: "quiet", small: true })),
    list,
  );
  return {
    element,
    read() {
      add_typed(); // a name typed but not added yet still counts
      if (!names.length) throw new Error("Add at least one entity name.");
      return [...names];
    },
  };
}

function build_mapping_list(list, offset, tools, on_page) {
  const service_of = (item) => item.selected_service;
  const columns = [
    { title: "Service", show: (item) => tools.build_element("strong", { text: service_of(item).service_name }) },
    { title: "Sector / subsector", show: (item) => sector_text(service_of(item).sector, service_of(item).subsector) },
    { title: "Status", show: (item) => tools.build_badge(item.status, STATUS_WORDS[item.status]) },
    { title: "Runs done", show: (item) => of_limit(item.generations_done, item.max_generations), nowrap: true },
    { title: "Updated", show: (item) => tools.format_date(item.updated_at), nowrap: true },
    {
      title: "Open",
      show: (item) =>
        tools.build_link("Open", `#/service_mapper/${encodeURIComponent(item.mapping_id)}`, {
          class: "button small",
          "aria-label": `Open the mapping of ${service_of(item).service_name}`,
        }),
    },
  ];
  const table = tools.build_table(list.items, columns, {
    caption: "Your mappings",
    empty: "You have no mappings yet. Describe a service above to map its dependencies.",
  });
  if (!list.total) return table;
  return [table, tools.build_pager({ offset, limit: PAGE_SIZE, total: list.total, on_change: on_page })];
}

// ---------------- one mapping ----------------

function show_mapping(container, tools, mapping_id) {
  const id = encodeURIComponent(mapping_id);
  tools.set_subtitle("Accept or reject each service the mapping found. The review is complete when nothing is pending.");
  tools.set_actions(tools.build_link("All mappings", "#/service_mapper", { class: "button small" }));
  const progress_place = tools.build_element("div");
  const view_place = tools.build_element("div", { class: "stack" });
  container.append(progress_place, view_place);
  /** What the page knows: the mapping view, the latest status (live), the live stream's state. */
  const page = { mapping: null, status: null, live: "connecting" };

  const read_view = () => tools.call("GET", `/v1/service-mapper/${id}`);
  const read_status = () => tools.call("GET", `/v1/service-mapper/${id}/status`);
  const draw = (mapping) => {
    page.mapping = mapping;
    draw_progress();
    return build_mapping_view(mapping, page.status, tools, actions);
  };
  const load_view = () => tools.load_into(view_place, read_view, draw, { quiet: true });

  function draw_progress() {
    const latest = page.status ?? page.mapping;
    tools.replace_content(progress_place, is_running(latest) ? build_progress(latest, page.live, tools) : null);
  }

  /** A new status: redraw the progress; when the run or the decisions moved, read the mapping again. */
  function apply_status(status) {
    const seen = (known) => known && JSON.stringify([known.status, known.generation, known.progress?.relationships]);
    const moved = seen(page.status) !== seen(status);
    page.status = status;
    draw_progress();
    if (moved && page.mapping) load_view();
  }

  const actions = {
    async regenerate() {
      let started;
      try {
        started = await tools.call("POST", `/v1/service-mapper/${id}/regenerate`, undefined, { idempotent: true });
      } catch (error) {
        if (error.reason !== "generation_limit_reached") throw error;
        load_view();
        throw new Error(LIMIT_REACHED);
      }
      if (started.status === "done") {
        tools.show_toast(NO_NEW_RUN, "warn");
        return;
      }
      tools.show_toast("A new run started: it only adds services the mapping does not hold yet.", "good");
      apply_status(await read_status());
    },
    async decide(ids, accept, said) {
      let answer = null;
      const failed = [];
      for (let start = 0; start < ids.length; start += DECISION_IDS_PER_CALL) {
        const chunk = ids.slice(start, start + DECISION_IDS_PER_CALL);
        answer = await tools.call("POST", `/v1/service-mapper/${id}/dependencies/decision`, { [accept ? "accept" : "reject"]: chunk });
        failed.push(...(answer.failed ?? []));
      }
      await tools.load_into(view_place, async () => answer, draw, { quiet: true });
      for (const failure of failed) tools.show_toast(`Not saved: ${failure.message}`, "warn");
      if (ids.length > failed.length) tools.show_toast(said(ids.length - failed.length), "good");
    },
  };

  const read_first = async () => {
    const [mapping, status] = await Promise.all([read_view(), read_status()]);
    page.status = status;
    return mapping;
  };
  tools.load_into(view_place, read_first, draw);
  tools.follow_stream(`/v1/service-mapper/${id}/events`, {
    on_event: (type, data) => type === "mapping.updated" && data && typeof data === "object" && apply_status(data),
    on_state: (state) => {
      page.live = state;
      draw_progress();
    },
  });
  tools.every(BACKSTOP_SECONDS, () => {
    if (is_running(page.status ?? page.mapping)) read_status().then(apply_status, () => {}); // the next tick tries again
  });
}

function build_progress(status, live, tools) {
  const retrying = status.retrying;
  const head = tools.build_element(
    "div",
    { class: "toolbar" },
    tools.build_badge(status.status, STATUS_WORDS[status.status]),
    `Run ${of_limit(status.generations_done + 1, status.max_generations)}`, // a failed run does not count
  );
  return tools.build_section(
    { title: "Run in progress", subtitle: "Services found by earlier runs can be decided meanwhile." },
    tools.build_element(
      "div",
      { class: "stack" },
      head,
      retrying && tools.build_callout(`${retrying.message} Trying again ${tools.format_date(retrying.retry_at)}.`, "warn"),
      tools.build_loading("Finding the services it depends on and the services that depend on it…"),
      tools.build_element("p", { class: "muted", text: LIVE_WORDS[live] ?? "" }),
    ),
  );
}

function build_mapping_view(mapping, status, tools, actions) {
  return [build_summary(mapping, status, tools, actions), ...SIDES.map((side) => build_side(side, mapping, tools, actions))];
}

function build_summary(mapping, status, tools, actions) {
  const summary = mapping.summary;
  const all = SIDES.flatMap((side) => mapping[side.key]);
  const counts = {
    accepted: all.filter((service) => service.isAccepted === true).length,
    rejected: all.filter((service) => service.isAccepted === false).length,
    pending: all.filter(is_pending).length,
  };
  const at_limit = mapping.max_generations > 0 && mapping.generations_done >= mapping.max_generations;
  const running = is_running(mapping);
  const timings = status?.progress?.timings;
  const took = !running && timings?.services != null ? (timings.catalog ?? 0) + timings.services : null;
  const kpis = tools.build_kpis([
    { label: "Services", value: summary.unique_services },
    { label: "Upstream", value: summary.upstream_count, hint: `Up to ${summary.max_upstream} new per run` },
    { label: "Downstream", value: summary.downstream_count, hint: `Up to ${summary.max_downstream} new per run` },
    {
      label: "Runs done",
      value: of_limit(mapping.generations_done, mapping.max_generations),
      hint: mapping.max_generations ? null : "No limit",
      tone: at_limit ? "warn" : null,
    },
    { label: "Waiting for a decision", value: counts.pending, tone: counts.pending ? "warn" : "good" },
  ]);
  const meter_parts = [
    { label: "Accepted", value: counts.accepted, tone: "good" },
    { label: "Rejected", value: counts.rejected, tone: "bad" },
    { label: "Pending", value: counts.pending, tone: "wait" },
  ];
  const facts = tools.build_facts([
    ["Status", tools.build_badge(mapping.status, STATUS_WORDS[mapping.status])],
    ["Mapping id", tools.build_id(mapping.mapping_id)],
    ["Created", tools.format_date(mapping.created_at)],
    ["Updated", tools.format_date(mapping.updated_at)],
    ...(took === null ? [] : [["Last run took", tools.format_seconds(took)]]),
  ]);
  const failed_text = `The last run failed: ${mapping.error?.message ?? "no reason was given."} Nothing the mapping held is lost, and a failed run does not count toward the limit. Regenerate to try again.`;
  return tools.build_section(
    { title: "Summary", actions: build_summary_actions(mapping, running, at_limit, tools, actions) },
    tools.build_element(
      "div",
      { class: "stack" },
      mapping.status === "failed" && tools.build_callout(failed_text, "bad"),
      at_limit && tools.build_callout(`This mapping has had all its ${mapping.max_generations} runs. Every service and decision stays.`, "info"),
      kpis,
      all.length > 0 && tools.build_meter(meter_parts, all.length),
      facts,
    ),
  );
}

function build_summary_actions(mapping, running, at_limit, tools, actions) {
  const why_not = running ? "Wait for this run to finish." : at_limit ? `This mapping has had all its ${mapping.max_generations} runs.` : null;
  const next_run = of_limit(mapping.generations_done + 1, mapping.max_generations); // a failed run does not count
  const regenerate = tools.build_button("Regenerate", actions.regenerate, {
    kind: "primary",
    disabled: Boolean(why_not),
    title: why_not ?? "Look for more services: only services it does not hold yet are added; every decision stays.",
    confirm: `Look for more services? This starts run ${next_run}. It only adds services the mapping does not hold yet; every service and decision stays.`,
  });
  const export_word = () => {
    save_word(mapping, tools);
    tools.show_toast("The Word document is in your downloads.", "good");
  };
  return [
    regenerate,
    tools.build_button("Export to Word", export_word, { kind: "quiet" }),
    tools.build_button("Print", tools.print_page, { kind: "quiet" }),
  ];
}

function build_side(side, mapping, tools, actions) {
  const services = mapping[side.key];
  const pending_ids = services.filter(is_pending).map((service) => service.dependency_id);
  const done_word = (accept) => (accept ? "Accepted" : "Rejected");
  const bulk = (accept) => {
    const verb = accept ? "Accept" : "Reject";
    const said = (saved) => `${done_word(accept)} ${count_of(saved, side.word)}.`;
    return tools.build_button(`${verb} all pending (${pending_ids.length})`, () => actions.decide(pending_ids, accept, said), {
      kind: "quiet",
      small: true,
      disabled: pending_ids.length === 0,
      confirm: `${verb} all ${count_of(pending_ids.length, side.word)} waiting for a decision? You can change each decision later.`,
    });
  };
  const decide_one = (service, accept) => {
    const verb = accept ? "Accept" : "Reject";
    const said = () => `${done_word(accept)} ${service.service_name}.`;
    const button = tools.build_button(verb, () => actions.decide([service.dependency_id], accept, said), {
      kind: accept ? "primary" : "quiet",
      small: true,
      disabled: service.isAccepted === accept,
    });
    button.setAttribute("aria-label", `${verb} ${service.service_name}`);
    return button;
  };
  const is_new = (service) => mapping.generation > 1 && service.generation === mapping.generation;
  const columns = [
    {
      title: "Service",
      show: (service) => [
        tools.build_element("strong", { text: service.service_name }),
        is_new(service) && tools.build_element("div", {}, tools.build_tag("New in the latest run")),
      ],
    },
    { title: "Sector / subsector", show: (service) => sector_text(service.sector, service.subsector) },
    { title: "Source", show: (service) => tools.build_tag(source_text(service)) },
    {
      title: "Reason",
      show: (service) => [
        tools.build_long_text(service.dependency_reason, 3),
        service.applicability && tools.build_element("p", { class: "muted", text: `Applies: ${service.applicability}` }),
      ],
    },
    { title: "Decision", show: (service) => build_decision(service, tools) },
    { title: "Decide", show: (service) => tools.build_actions(decide_one(service, true), decide_one(service, false)) },
  ];
  const empty = is_running(mapping)
    ? "The run is still looking for services: they appear here when it ends."
    : `No ${side.word} service yet. Regenerate to look again.`;
  return tools.build_section(
    { title: `${side.title} (${services.length})`, actions: [bulk(true), bulk(false)] },
    tools.build_table(services, columns, { caption: side.title, empty }),
  );
}

function build_decision(service, tools) {
  if (service.isAccepted === false) return tools.build_badge("rejected", "Rejected");
  if (service.isAccepted !== true) return tools.build_badge("pending", "Pending");
  const by = service.accepted_by && `by ${service.accepted_by}`;
  const when = service.accepted_datetime && tools.format_date(service.accepted_datetime);
  const who = [by, when].filter(Boolean).join(", ");
  return [tools.build_badge("accepted", "Accepted"), who && tools.build_element("small", { class: "muted", text: ` ${who}` })];
}

/** The mapping and both directions as a Word document. */
function save_word(mapping, tools) {
  const columns = ["No.", "Service", "Sector / subsector", "Reason", "Source", "Decision"];
  const decision_word = (service) => (service.isAccepted === true ? "Accepted" : service.isAccepted === false ? "Rejected" : "Pending");
  const row_of = (service, index) => [
    String(index + 1),
    service.service_name,
    sector_text(service.sector, service.subsector),
    [service.dependency_reason, service.applicability && `Applies: ${service.applicability}`].filter(Boolean).join(" "),
    source_text(service),
    decision_word(service),
  ];
  const facts = [
    ["Mapping id", mapping.mapping_id],
    ["Status", STATUS_WORDS[mapping.status] ?? mapping.status],
    ["Runs done", of_limit(mapping.generations_done, mapping.max_generations)],
    ["Services", tools.format_count(mapping.summary.unique_services)],
    ["Created", tools.format_date(mapping.created_at)],
    ["Updated", tools.format_date(mapping.updated_at)],
  ];
  const sides = SIDES.flatMap((side) => {
    const services = mapping[side.key];
    return [
      { heading: `${side.title} (${services.length})`, level: 1 },
      services.length ? { table: { columns, rows: services.map(row_of) } } : { paragraph: "None." },
    ];
  });
  const date = new Date().toISOString().slice(0, 10);
  tools.download_word(`Service map ${mapping.mapping_id} ${date}`, "Service map", [{ heading: "Mapping", level: 1 }, { facts }, ...sides]);
}

// ---------------- small words ----------------

function is_running(item) {
  return item?.status === "queued" || item?.status === "running";
}

function is_pending(service) {
  return service.isAccepted !== true && service.isAccepted !== false;
}

function source_text(service) {
  return service.ai_suggested ? "New, suggested by AI" : "From your catalogue";
}

function sector_text(sector, subsector) {
  return [sector, subsector].filter(Boolean).join(" / ");
}

/** "4 of 10", or "4" when there is no limit (0). */
function of_limit(count, limit) {
  return limit ? `${count} of ${limit}` : String(count);
}

/** "1 upstream service", "3 upstream services". */
function count_of(count, word) {
  return `${count} ${word} service${count === 1 ? "" : "s"}`;
}
