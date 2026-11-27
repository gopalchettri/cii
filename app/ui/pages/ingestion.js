// Data ingestion: the on/off switch, each source's health and an import now.
// One read (the health answer holds the switch too) builds the page; every change reads it again.

import { is_job_over } from "../poll.js";

const TURN_OFF_QUESTION =
  "Turn external intelligence off? Imports stop and new scenarios are written without it. Nothing is deleted.";
const NO_DATA = "No source has data yet. Press Import now: a run that cites MITRE ATT&CK needs it.";
const NO_IMPORT_FOLLOWED = "No import is followed yet. Press Import now above; one that already runs is followed instead.";
const NOT_RECORDED = "Not since this was recorded";
const ENV_OFF =
  "It is turned off in the service's settings file (EXTERNAL_INTELLIGENCE_ENABLED). Only a change there and a restart turn it on.";

export async function show(container, tools) {
  const { request, build_element, build_section, build_facts, build_badge, build_button, format_date } = tools;
  tools.set_subtitle("The outside threat data, such as MITRE ATT&CK, that runs cite: turn it on or off, check each source, import now.");
  // The followed import outlives a reload of the rest of the page, so its section is built once.
  const job_place = build_element("div", { class: "stack", role: "status" }, tools.build_empty(NO_IMPORT_FOLLOWED));
  const import_section = build_section({ title: "Import", subtitle: "The import started here, followed until it ends." }, job_place);
  let is_importing = false;
  let stop_following = null;

  // quiet: a reload keeps the page on screen until the new answer is ready (the first load still shows "Loading").
  const load = () =>
    tools.load_into(
      container,
      () => request("GET", "/v1/tsg/intel/health"),
      (health) => [build_overview(health), build_switch(health.switch), build_sources(health), import_section],
      { quiet: true },
    );

  function build_overview(health) {
    const with_data = health.sources.filter((row) => row.last_success_at).length;
    const records = health.sources.reduce((sum, row) => sum + (Number(row.records) || 0), 0);
    const failing = health.sources.filter((row) => row.last_error).length;
    return tools.build_kpis([
      { label: "External intelligence", value: health.switch.effective ? "On" : "Off", tone: health.switch.effective ? "good" : "warn" },
      { label: "Sources with data", value: `${with_data} of ${health.sources.length}`, tone: with_data === health.sources.length ? "good" : "warn" },
      { label: "Records", value: records },
      { label: "Sources with an error", value: failing, tone: failing ? "bad" : "good" },
    ]);
  }

  function build_switch(state) {
    const turn = state.runtime_enabled
      ? build_button("Turn off", () => change_switch(false), { kind: "danger", confirm: TURN_OFF_QUESTION, disabled: !state.env_enabled })
      : build_button("Turn on", () => change_switch(true), { kind: "primary", disabled: !state.env_enabled });
    const facts = [
      ["State", build_badge(state.effective ? "on" : "off")],
      ["Admin switch", build_badge(state.runtime_enabled ? "on" : "off")],
      ["Settings file", build_badge(state.env_enabled ? "enabled" : "disabled")],
      ["Last changed", state.changed_at && `${format_date(state.changed_at)} by ${state.changed_by ?? "unknown"}`],
    ];
    const subtitle = "While it is on, imports run and new scenarios cite this data.";
    return build_section({ title: "External intelligence", subtitle, actions: [turn] }, !state.env_enabled && tools.build_callout(ENV_OFF, "warn"), build_facts(facts));
  }

  function build_sources(health) {
    const is_on = health.switch.effective;
    const why_not = !is_on ? "External intelligence is off" : is_importing ? "An import is running" : undefined;
    const columns = [
      { title: "Source", show: (row) => build_element("span", { class: "mono", text: row.source }), nowrap: true },
      { title: "State", show: build_source_badge },
      { title: "Version", key: "source_version", nowrap: true },
      { title: "Records", show: (row) => tools.format_count(row.records), numeric: true },
      { title: "Last checked", show: (row) => format_date(row.last_success_at), nowrap: true },
      { title: "Last new data", show: (row) => (row.last_new_data_at ? format_date(row.last_new_data_at) : NOT_RECORDED), nowrap: true },
      { title: "Last attempt", show: (row) => format_date(row.last_attempt_at), nowrap: true },
      { title: "Error", key: "last_error" },
      { title: "Actions", show: (row) => build_source_action(row.source, why_not) },
    ];
    const facts = [
      ["Data in use", health.snapshot_id && tools.build_id(health.snapshot_id)],
      ["Waiting for first data", health.pending_sources.join(", ") || "None"],
    ];
    const import_all = build_button("Import now", () => start_import(), { kind: "primary", disabled: Boolean(why_not), title: why_not });
    return build_section(
      { title: "Sources", subtitle: why_not ? `${why_not}: imports cannot start now.` : "Import every source, or one on its row.", actions: [import_all] },
      health.no_data && tools.build_callout(NO_DATA, "warn"),
      build_facts(facts),
      tools.build_table(health.sources, columns, { caption: "Each source and its last import", empty: "No source is registered." }),
    );
  }

  function build_source_badge(row) {
    // A claim is not proof of a running import (a worker that died leaves its claim): the last status stays shown.
    const claim = row.claimed_at && build_element("span", { class: "muted", text: ` claimed for import ${format_date(row.claimed_at)}` });
    return [build_badge(row.status), claim];
  }

  function build_source_action(source, why_not) {
    const button = build_button("Import", () => start_import(source), { small: true, disabled: Boolean(why_not), title: why_not });
    // Each row has the same button word, so a screen reader is told which source the button acts on.
    button.setAttribute("aria-label", `Import ${source}`);
    return tools.build_actions(button);
  }

  function build_job(job) {
    const optional = [
      ["Source", job.result?.source],
      ["Error", job.error?.message],
      ["Evidence index not rebuilt", job.result?.index_error?.message],
    ];
    const outcomes = (job.result?.sources ?? []).map((item) => [item.source, describe_outcome(item)]);
    return [
      job.status === "failed" && tools.build_callout(`The import failed${job.error?.message ? `: ${job.error.message}` : "."}`, "bad"),
      build_facts([
        ["Status", build_badge(job.status)],
        ...outcomes,
        ...optional.filter(([, value]) => value),
        ["Requested by", job.requested_by],
        ["Queued", format_date(job.created_at)],
        ["Started", format_date(job.started_at)],
        ["Finished", format_date(job.finished_at)],
        ["Job id", tools.build_id(job.job_id)],
      ]),
    ];
  }

  /** One source's outcome in plain words: whether anything new arrived. */
  function describe_outcome(item) {
    if (item.outcome === "failed") return "Failed: see the Error column in Sources above";
    if (item.outcome === "skipped" || item.outcome === "claim_lost") return "Skipped: another import had it";
    if (!item.new_data) return "Up to date: nothing new";
    return `New data: ${tools.format_count(item.new_versions)} records new or changed, ${tools.format_count(item.retired)} retired`;
  }

  /** Shows the import's state on every change; when it ends the sources are read again. */
  function follow_import(job_id) {
    stop_following?.();
    is_importing = true;
    tools.replace_content(job_place, tools.build_loading("Following the import…"));
    const read = () => request("GET", `/v1/tsg/intel/refresh/${encodeURIComponent(job_id)}`);
    stop_following = tools.follow_job(read, (job, error) => {
      const follow_again = () => {
        follow_import(job_id);
        return load();
      };
      tools.replace_content(job_place, error ? tools.build_error(error, follow_again) : build_job(job));
      if (!error && !is_job_over(job)) return;
      is_importing = false;
      load();
    });
  }

  async function start_import(source) {
    let job_id;
    try {
      job_id = (await request("POST", "/v1/tsg/intel/refresh", source ? { source } : undefined)).job_id;
      tools.show_notice(source ? `An import of ${source} has started.` : "An import of every source has started.", "good");
    } catch (error) {
      if (!error.details?.job_id) throw error;
      job_id = error.details.job_id; // an import already runs: that one is followed
      tools.show_notice("An import is already running. It is followed below.");
    }
    follow_import(job_id);
    await load();
  }

  /** Turning it on may queue an import: follows it, reads the page again, says what happened. */
  async function change_switch(enabled) {
    const state = await request("PUT", "/v1/tsg/intel/switch", { enabled });
    const text = `External intelligence was turned ${enabled ? "on" : "off"}.`;
    if (state.refresh_job_id) follow_import(state.refresh_job_id);
    await load();
    if (state.refresh_not_queued) tools.show_notice(`${text} No import was queued: ${state.refresh_not_queued}`, "bad");
    else tools.show_notice(state.refresh_job_id ? `${text} An import has started.` : text, "good");
  }

  await load();
}
