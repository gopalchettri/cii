// Control links: how many MITRE ATT&CK mitigations are linked to library controls, and "Prepare now".

import { is_job_over } from "../poll.js";

const NOTHING_PREPARED =
  "No mitigation is prepared yet. Import the MITRE ATT&CK data first on the Data ingestion page, then press Prepare now.";
const NO_PREPARATION_FOLLOWED = "No preparation is followed yet. Press Prepare now; one that already runs is followed instead.";
const WHAT_IT_DOES =
  "The AI judges which library controls do what each mitigation says. A mitigation that did not change costs no AI call. " +
  "It also runs by itself after every import.";

export async function show(container, tools) {
  const { request, build_element, build_section, build_facts, build_badge, format_count, format_date } = tools;
  tools.set_subtitle("Which library controls carry out each MITRE ATT&CK mitigation, so scenarios can name real controls.");
  // The followed preparation outlives a reload of the summary, so its section is built once.
  const job_place = build_element("div", { class: "stack", role: "status" }, tools.build_empty(NO_PREPARATION_FOLLOWED));
  const job_section = build_section({ title: "Preparation", subtitle: "The preparation started here, followed until it ends." }, job_place);
  let is_preparing = false;
  let stop_following = null;

  const load = () =>
    tools.load_into(
      container,
      () => request("GET", "/v1/tsg/intel/control-links"),
      (summary) => [build_summary(summary), job_section],
      { quiet: true },
    );

  function build_summary(summary) {
    const why_not = is_preparing ? "A preparation is running" : undefined;
    const prepare = tools.build_button("Prepare now", start_preparation, { kind: "primary", disabled: is_preparing, title: why_not });
    const kpis = tools.build_kpis([
      { label: "Mitigations prepared", value: summary.mitigations },
      { label: "With a library control", value: summary.linked, tone: summary.linked ? "good" : null },
      { label: "With no library control", value: summary.without_links, tone: summary.without_links ? "warn" : null },
      { label: "Not prepared yet", value: summary.not_prepared ?? 0, tone: summary.not_prepared ? "warn" : null },
      { label: "Last prepared", value: summary.prepared_at ? format_date(summary.prepared_at) : "Never" },
    ]);
    // Data imported but never judged: Prepare now is the next step, not another import.
    const waiting = summary.not_prepared > 0 && `${format_count(summary.not_prepared)} mitigations are waiting to be prepared. Press Prepare now.`;
    const empty = waiting ? tools.build_empty(waiting) : tools.build_empty(NOTHING_PREPARED, tools.build_link("Open Data ingestion", "#/ingestion"));
    return build_section(
      { title: "Mitigations and their controls", subtitle: WHAT_IT_DOES, actions: [prepare] },
      summary.mitigations === 0 ? empty : kpis,
      summary.mitigations > 0 &&
        summary.without_links > 0 &&
        tools.build_callout(`${format_count(summary.without_links)} of ${format_count(summary.mitigations)} mitigations have no library control yet.`, "warn"),
    );
  }

  function build_job(job) {
    return [
      job.error?.message && tools.build_callout(`The preparation failed: ${job.error.message}`, "bad"),
      build_facts([
        ["Status", build_badge(job.status)],
        ["Judged by the AI", format_count(job.result?.judged)],
        ["Unchanged (no AI call)", format_count(job.result?.unchanged)],
        ["Failed (earlier links kept)", format_count(job.result?.failed)],
        ["Requested by", job.requested_by],
        ["Queued", format_date(job.created_at)],
        ["Started", format_date(job.started_at)],
        ["Finished", format_date(job.finished_at)],
        ["Job id", tools.build_id(job.job_id)],
      ]),
    ];
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
      tools.show_notice("The preparation has started. Its progress is shown below.", "good");
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
