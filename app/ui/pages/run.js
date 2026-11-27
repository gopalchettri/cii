// A threat scenario run (#/run/<session_id>): the run, its seven steps and its scenarios to review, each on its way
// to a treatment plan. Live: the run's event stream; a re-read every 15 s is the backstop for a dropped stream.

import { build_overall_badge, open_run_page, plain_error, RESULTS_LIMIT } from "../scenario_view.js";

const BACKSTOP_SECONDS = 15;
/** A next set refused because nothing is left: told as news, not as an error. */
const NOTHING_TO_WRITE = new Set(["nothing_left", "target_reached", "scenarios_abandoned"]);
const LIVE_LOOKS = {
  connecting: ["connecting", "Connecting…"],
  live: ["live", "Live updates"],
  retrying: ["retrying", "Reconnecting…"],
  ended: ["off", "Live updates off"],
};

export async function show(container, tools) {
  const [session_id] = tools.params;
  if (!session_id) {
    container.append(tools.build_empty("No run was chosen.", tools.build_link("Open the list of runs", "#/runs")));
    return;
  }
  const id = encodeURIComponent(session_id);
  const live = tools.build_element("span", { role: "status" }, tools.build_badge(...LIVE_LOOKS.connecting));
  const paths = {
    board: `/v1/sessions/${id}`,
    results: tools.with_query(`/v1/sessions/${id}/results`, { include_replaced: true, limit: RESULTS_LIMIT }),
    plans: tools.with_query(`/v1/sessions/${id}/treatment-plans`, { limit: RESULTS_LIMIT }),
    accept: `/v1/sessions/${id}/accept`,
    reject: `/v1/sessions/${id}/scenarios/reject`,
    regenerate: `/v1/sessions/${id}/regenerate/scenarios`,
  };
  let page = null;

  async function next_set() {
    let answer;
    try {
      answer = await tools.call("POST", `/v1/sessions/${id}/scenarios/next-set`, undefined, { idempotent: true });
    } catch (error) {
      if (error.status !== 409 || !NOTHING_TO_WRITE.has(error.reason)) throw plain_error(error);
      tools.show_toast(plain_error(error).message, "warn");
      return;
    }
    const words = answer?.status === "mapping_controls"
      ? "Nothing is left to write, so the stopped control matching was started again."
      : "The next set of scenarios is being written. New cards appear here as each one is ready.";
    tools.show_toast(words, "good");
    await page.refresh();
  }

  page = await open_run_page(container, tools, {
    kind: "tsg",
    session_id,
    paths,
    live,
    build_header: (state) => build_header(tools, state.board, session_id),
    next_set,
    next_set_blocked: (state) => next_set_blocked(state),
  });
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

function build_header(tools, board, session_id) {
  return tools.build_section(
    { title: "Run" },
    tools.build_facts([
      ["Asset", board.asset_name || `Asset ${board.asset_id}`],
      ["Requested by", board.user_id],
      ["Status", build_overall_badge(tools, board)],
      ["Last change", tools.format_date(board.updated_at)],
      ["Run id", tools.build_id(session_id)],
    ]),
  );
}

/**
 * Why "Generate next set" would be refused now ("" when it may be asked); the API has the last word. With nothing
 * left to write, a next set still resumes control matching that was stopped, so it stays open then.
 */
function next_set_blocked({ board, results }) {
  const progress = board.progress ?? {};
  const stopped_controls = (results?.scenarios ?? []).some((scenario) => scenario.controls_status === "cancelled");
  if (progress.threats === "ERROR") return "The run failed while finding threats.";
  if (progress.scenario_count?.remaining === 0 && !stopped_controls) return "Every planned scenario is already written.";
  return "";
}
