// A MITRE ATT&CK run (#/mitre_run/<session_id>): its stage, counts and timings, the attack paths and attacker
// groups it found, and its scenarios to review, each on its way to a treatment plan. Live: a MITRE run is followed
// on the run event stream every run shares (/v1/sessions/{id}/events, owner 2026-11-26): each event says the run
// changed, and the page reads the MITRE status again; a re-read every 15 s is the backstop for a dropped stream.

import { build_overall_badge, open_run_page, plain_error, RESULTS_LIMIT } from "../scenario_view.js";

const BACKSTOP_SECONDS = 15;
const LIVE_LOOKS = {
  connecting: ["connecting", "Connecting…"],
  live: ["live", "Live updates"],
  retrying: ["retrying", "Reconnecting…"],
  ended: ["off", "Live updates off"],
};
const STAGES = {
  queued: "Waiting to start",
  selecting_actors: "Choosing attacker groups",
  planning: "Planning attack paths",
  writing: "Writing scenarios",
  complete: "Complete",
};
/** A setting's name (TOTAL_SCENARIO_COUNT): an answer naming one is told in the page's own words instead. */
const SETTING_NAME = /\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b/;

export async function show(container, tools) {
  const [session_id] = tools.params;
  if (!session_id) {
    container.append(tools.build_empty("No run was chosen.", tools.build_link("Open the list of runs", "#/runs")));
    return;
  }
  const id = encodeURIComponent(session_id);
  const live = tools.build_element("span", { role: "status" }, tools.build_badge(...LIVE_LOOKS.connecting));
  const paths = {
    board: `/v1/mitre_sessions/${id}`,
    results: tools.with_query(`/v1/mitre_sessions/${id}/results`, { include_replaced: true, limit: RESULTS_LIMIT }),
    plans: tools.with_query(`/v1/sessions/${id}/treatment-plans`, { limit: RESULTS_LIMIT }),
    accept: `/v1/mitre_sessions/${id}/accept`,
    reject: `/v1/mitre_sessions/${id}/scenarios/reject`,
    regenerate: `/v1/mitre_sessions/${id}/regenerate/scenarios`,
    promote: (scenario_id) => `/v1/mitre_sessions/${id}/scenarios/${encodeURIComponent(scenario_id)}/promote-to-library`,
  };
  let page = null;

  async function next_set() {
    let answer;
    try {
      answer = await tools.call("POST", `/v1/mitre_sessions/${id}/scenarios/next-set`, undefined, { idempotent: true });
    } catch (error) {
      throw plain_error(error);
    }
    tools.show_toast(next_set_words(answer), answer.status === "generating" ? "good" : "warn");
    await page.refresh();
  }

  page = await open_run_page(container, tools, {
    kind: "mitre",
    session_id,
    paths,
    live,
    build_header: (state) => build_header(tools, state.board, session_id),
    next_set,
    next_set_blocked: () => "",
  });
  // The event's body is the run's board, not the MITRE detail: it only says "changed", and the page reads its own.
  const stop_stream = tools.follow_stream(`/v1/sessions/${id}/events`, {
    on_event: (type) => {
      if (type === "session.deleted") {
        stop_stream();
        page.end("This run was deleted, so there is nothing more to show.");
      } else if (type === "session.updated") page.refresh();
    },
    on_state: (state) => tools.replace_content(live, tools.build_badge(...(LIVE_LOOKS[state] ?? LIVE_LOOKS.ended))),
  });
  tools.every(BACKSTOP_SECONDS, () => page.refresh());
}

/** The next set's answer in plain words: its own message unless it names a setting. */
function next_set_words(answer) {
  if (answer.message && !SETTING_NAME.test(answer.message)) return answer.message;
  if (answer.status === "generating") return `The next set is being written (${answer.written} written so far).`;
  if (answer.status === "target_reached") return `This run already has the number of scenarios it was set to write: ${answer.written} written.`;
  return `Nothing is left to write: ${answer.written} scenarios written, ${answer.dropped} set aside by the MITRE ATT&CK checks.`;
}

function build_header(tools, board, session_id) {
  const mitre = board.mitre ?? {};
  const count = board.progress?.scenario_count ?? {};
  const meta = mitre.result?.metadata;
  return tools.build_section(
    { title: "Run" },
    tools.build_facts([
      ["Asset", board.asset_name || `Asset ${board.asset_id}`],
      ["Requested by", board.user_id],
      ["Stage", build_stage_badge(tools, board)],
      ["Status", build_overall_badge(tools, board)],
      ["Last change", tools.format_date(board.updated_at)],
      ["Run id", tools.build_id(session_id)],
    ]),
    tools.build_kpis([
      { label: "Written", value: mitre.written ?? 0 },
      { label: "Planned", value: mitre.run_target ?? 0 },
      { label: "Left to write", value: mitre.scenarios_left ?? 0 },
      { label: "To review", value: count.pending_review ?? 0, tone: count.pending_review ? "warn" : null },
      { label: "Accepted", value: count.accepted ?? 0, tone: "good" },
      { label: "Rejected", value: count.rejected ?? 0, tone: count.rejected ? "bad" : null }, // red only when some are
    ]),
    tools.build_element("div", { class: "grid-2" }, build_timings(tools, board), meta && build_paths_and_groups(tools, meta)),
  );
}

function build_stage_badge(tools, board) {
  if (board.session_status === "failed") return tools.build_badge("failed", "Failed");
  if (board.session_status === "cancelled") return tools.build_badge("cancelled", "Stopped");
  const stage = board.mitre?.stage || "queued";
  const look = stage === "complete" ? "complete" : board.session_status === "active" ? "running" : "queued";
  return tools.build_badge(look, STAGES[stage] ?? tools.humanise(stage));
}

function build_timings(tools, board) {
  const timings = board.progress?.timings ?? {};
  return tools.build_element(
    "div",
    { class: "stack" },
    tools.build_element("h3", { text: "Time taken" }),
    tools.build_facts([
      ["Finding attackers and attack paths", tools.format_seconds(timings.threats)],
      ["Writing scenarios", tools.format_seconds(timings.scenarios)],
      ["Whole run so far", tools.format_seconds(board.mitre?.elapsed_seconds)],
    ]),
  );
}

function build_paths_and_groups(tools, meta) {
  const set_aside = Object.values(meta.invalid_paths ?? {}).reduce((sum, value) => sum + (Number(value) || 0), 0);
  const crossing = !meta.it_ot_crossing_required ? "Not needed" : meta.it_ot_crossing_met ? "Needed and covered" : "Needed, not covered";
  const groups = (meta.relevant_actors ?? []).map((actor) =>
    tools.build_tag([actor.mitre_id, actor.name].filter(Boolean).join(" "), actor.url || null, actor.relevance || null),
  );
  return tools.build_element(
    "div",
    { class: "stack" },
    tools.build_element("h3", { text: "Attack paths and groups" }),
    tools.build_facts([
      ["Attack paths found", meta.valid_paths_found],
      ["Set aside by the MITRE ATT&CK checks", set_aside],
      ["Attacker groups chosen", meta.relevant_actors_selected],
      ["Groups named on the scenarios", meta.distinct_relevant_groups],
      ["Attack across IT and OT", crossing],
    ]),
    groups.length ? tools.build_element("div", { class: "tags" }, groups) : null,
  );
}
