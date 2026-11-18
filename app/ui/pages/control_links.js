// Control links: how many MITRE ATT&CK mitigations are linked to library controls, and "Prepare now".

import { is_job_over } from "../poll.js";

const NOTHING_PREPARED =
  "No mitigation is prepared yet. Import the MITRE ATT&CK data first (Data ingestion), then press Prepare now.";
const NO_PREPARATION_FOLLOWED = "No preparation is followed yet. Press Prepare now; one that already runs is followed instead.";
const WHAT_IT_DOES =
  "The AI judges which library controls do what each mitigation says. A mitigation that did not change costs no AI call. " +
  "It also runs by itself after every import.";

export async function show(container, tools) {
  const { request, build_element, build_panel, build_facts, build_badge, format_count, format_date } = tools;
  // The followed preparation outlives a reload of the summary, so its panel is built once.
  const job_place = build_element("div", { role: "status" }, tools.build_empty(NO_PREPARATION_FOLLOWED));
  const job_panel = build_panel("Preparation", job_place);
  let is_preparing = false;
  let stop_following = null;

  const load = () =>
    tools.load_into(
      container,
      () => request("GET", "/v1/tsg/intel/control-links"),
      (summary) => [build_summary(summary), job_panel],
    );

  function build_summary(summary) {
    const why_not = is_preparing ? "A preparation is running" : undefined;
    const prepare = tools.build_button("Prepare now", start_preparation, { kind: "primary", disabled: is_preparing, title: why_not });
    const facts = [
      ["Mitigations prepared", format_count(summary.mitigations)],
      ["With at least one library control", format_count(summary.linked)],
      ["With no library control", format_count(summary.without_links)],
      ["Last prepared", summary.prepared_at ? format_date(summary.prepared_at) : "Never"],
    ];
    return build_panel(
      "Mitigations and their controls",
      summary.mitigations === 0 && tools.build_empty(NOTHING_PREPARED),
      build_facts(facts),
      build_element("p", { class: "muted", text: WHAT_IT_DOES }),
      tools.build_actions(prepare),
    );
  }

  function build_job(job) {
    return build_facts([
      ["Status", build_badge(job.status)],
      ...(job.error?.message ? [["Error", job.error.message]] : []),
      ["Judged by the AI", format_count(job.result?.judged)],
      ["Unchanged (no AI call)", format_count(job.result?.unchanged)],
      ["Failed (earlier links kept)", format_count(job.result?.failed)],
      ["Requested by", job.requested_by],
      ["Queued", format_date(job.created_at)],
      ["Started", format_date(job.started_at)],
      ["Finished", format_date(job.finished_at)],
      ["Job id", build_element("span", { class: "mono", text: job.job_id })],
    ]);
  }

  /** Shows the preparation's state on every change; when it ends the summary is read again. */
  function follow_preparation(job_id) {
    stop_following?.();
    is_preparing = true;
    tools.replace_content(job_place, tools.build_loading("Following the preparation…"));
    const read = () => request("GET", `/v1/tsg/intel/control-links/${encodeURIComponent(job_id)}`);
    stop_following = tools.follow_job(read, (job, error) => {
      const follow_again = () => {
        follow_preparation(job_id);
        return load();
      };
      tools.replace_content(job_place, error ? tools.build_error(error, follow_again) : build_job(job));
      if (!error && !is_job_over(job)) return;
      is_preparing = false;
      load();
    });
  }

  async function start_preparation() {
    let job_id;
    try {
      job_id = (await request("POST", "/v1/tsg/intel/control-links/prepare")).job_id;
    } catch (error) {
      if (!error.details?.job_id) throw error;
      job_id = error.details.job_id; // a preparation already runs: that one is followed
      tools.show_notice("A preparation is already running. It is followed below.");
    }
    follow_preparation(job_id);
    await load();
  }

  await load();
}
