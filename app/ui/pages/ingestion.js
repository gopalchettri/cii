// Data ingestion: the on/off switch, each source's health and an import now.
// One read (the health answer holds the switch too) builds the page; every change reads it again.

import { is_job_over } from "../poll.js";

const TURN_OFF_QUESTION =
  "Turn external intelligence off? Imports stop and new scenarios are written without it. Nothing is deleted.";
const NO_DATA = "No source has data yet. Press Import now: a run that cites MITRE ATT&CK needs it.";
const NO_IMPORT_FOLLOWED = "No import is followed yet. Start one above; one that already runs is followed instead.";
const ENV_OFF = "EXTERNAL_INTELLIGENCE_ENABLED is false in the env file: only the env file and a restart turn it on.";

export async function show(container, tools) {
  const { request, build_element, build_panel, build_facts, build_badge, build_button, build_actions, format_date } = tools;
  // The followed import outlives a reload of the rest of the page, so its panel is built once.
  const job_place = build_element("div", { role: "status" }, tools.build_empty(NO_IMPORT_FOLLOWED));
  const import_panel = build_panel("Import", job_place);
  let is_importing = false;
  let stop_following = null;

  const load = () =>
    tools.load_into(
      container,
      () => request("GET", "/v1/tsg/intel/health"),
      (health) => [build_switch(health.switch), build_sources(health), import_panel],
    );

  function build_switch(state) {
    const turn = state.runtime_enabled
      ? build_button("Turn off", () => change_switch(false), { kind: "danger", confirm: TURN_OFF_QUESTION, disabled: !state.env_enabled })
      : build_button("Turn on", () => change_switch(true), { kind: "primary", disabled: !state.env_enabled });
    const facts = [
      ["State", build_badge(state.effective ? "on" : "off")],
      ["Admin switch", build_badge(state.runtime_enabled ? "on" : "off")],
      ["Env file setting", build_badge(state.env_enabled ? "enabled" : "disabled")],
      ["Last changed", state.changed_at && `${format_date(state.changed_at)} by ${state.changed_by ?? "unknown"}`],
    ];
    const env_note = !state.env_enabled && build_element("p", { class: "muted", text: ENV_OFF });
    return build_panel("External intelligence", build_facts(facts), env_note, build_actions(turn));
  }

  function build_sources(health) {
    const is_on = health.switch.effective;
    const why_not = !is_on ? "External intelligence is off" : is_importing ? "An import is running" : undefined;
    const columns = [
      { title: "Source", show: (row) => build_element("span", { class: "mono", text: row.source }), nowrap: true },
      { title: "State", show: build_source_badge },
      { title: "Version", key: "source_version", nowrap: true },
      { title: "Records", show: (row) => tools.format_count(row.records), numeric: true },
      { title: "Last success", show: (row) => format_date(row.last_success_at), nowrap: true },
      { title: "Last attempt", show: (row) => format_date(row.last_attempt_at), nowrap: true },
      { title: "Error", key: "last_error" },
      { title: "Actions", show: (row) => build_source_action(row.source, why_not) },
    ];
    const facts = [
      ["Active snapshot", health.snapshot_id && build_element("span", { class: "mono", text: health.snapshot_id })],
      ["Waiting for first data", health.pending_sources.join(", ") || "None"],
    ];
    const import_all = build_button("Import now", () => start_import(), { kind: "primary", disabled: Boolean(why_not), title: why_not });
    return build_panel(
      "Sources",
      health.no_data && tools.build_empty(NO_DATA),
      build_facts(facts),
      build_actions(import_all),
      tools.build_table(health.sources, columns, { caption: "Each source and its last import", empty: "No source is registered." }),
    );
  }

  function build_source_badge(row) {
    // A claim is not proof of a running import (a worker that died leaves its claim): the last status stays shown.
    const claim = row.claimed_at && build_element("span", { class: "muted", text: ` claimed for import ${format_date(row.claimed_at)}` });
    return [build_badge(row.status), claim];
  }

  function build_source_action(source, why_not) {
    const button = build_button("Import", () => start_import(source), { disabled: Boolean(why_not), title: why_not });
    // Each row has the same button word, so a screen reader is told which source the button acts on.
    button.setAttribute("aria-label", `Import ${source}`);
    return build_actions(button);
  }

  function build_job(job) {
    const optional = [
      ["Source", job.result?.source],
      ["Error", job.error?.message],
      ["Evidence index not rebuilt", job.result?.index_error?.message],
    ];
    return build_facts([
      ["Status", build_badge(job.status)],
      ...optional.filter(([, value]) => value),
      ["Requested by", job.requested_by],
      ["Queued", format_date(job.created_at)],
      ["Started", format_date(job.started_at)],
      ["Finished", format_date(job.finished_at)],
      ["Job id", build_element("span", { class: "mono", text: job.job_id })],
    ]);
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
