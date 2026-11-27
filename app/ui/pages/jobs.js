// Jobs (admin key): every job, queue and worker; one job by its id, followed until it ends; stopping an
// import, a build or a linking run.

const NEWEST = 100; // jobs asked for at once
const REFRESH_SECONDS = 20; // the list is read again quietly while the page is shown
const ADMIN_JOBS = "tsg_admin_jobs"; // where imports, builds and linking runs are kept: the only jobs the cancel route takes
const ACTIVE = ["queued", "running"];
const STATUSES = [...ACTIVE, "done", "failed", "cancelled"];
const MODULES = ["threat_scenarios", "remediation", "service_mapper", "external_intelligence", "library_embeddings", "maintenance"];
const PERIODS = [
  { value: 1, label: "Last hour" },
  { value: 24, label: "Last 24 hours" },
  { value: 168, label: "Last 7 days" },
  { value: 720, label: "Last 30 days" },
  { value: 2160, label: "Last 90 days" },
];
const STOP_QUESTION =
  "A queued job never starts; a running one stops at its next safe point. It will show as cancelled and cannot be resumed, but a new one can be started at once.";

const list_choices = (tools, first, words) => [{ value: "", label: first }, ...words.map((word) => ({ value: word, label: tools.humanise(word) }))];

export async function show(container, tools) {
  const { build_element, build_field, replace_content, request } = tools;
  tools.set_subtitle("Every background job and the workers that run them. Open one to follow it, or stop an import, build or linking run.");
  const reload = { on: { change: () => list_jobs() } };
  const status = tools.build_select([...list_choices(tools, "Any status", STATUSES), { value: ACTIVE.join(","), label: "Queued or running" }], "", reload);
  const module_name = tools.build_select(list_choices(tools, "Any area", MODULES), "", reload);
  const hours = tools.build_select(PERIODS, 24, reload);
  const queues_place = build_element("div", { class: "stack" });
  const jobs_place = build_element("div", { class: "stack" });
  const job_place = build_element("div", { class: "stack", "aria-live": "polite" }, tools.build_empty("Press Details on a job, or open one by its id above."));
  const job_id = build_element("input", { type: "text", class: "mono", required: true, maxlength: 64, autocomplete: "off", spellcheck: "false" });
  let lists_asked = 0;
  let stop_following = () => {};

  /** Reads the jobs and the queues in one call; `quiet`: the old lists stay until the new ones are ready. */
  function list_jobs(quiet = false) {
    const asked = (lists_asked += 1);
    const filters = { status: status.value.split(","), module: module_name.value, hours: hours.value, limit: NEWEST };
    const is_latest = () => asked === lists_asked; // a later choice of filters is being read
    const read = async () => {
      try {
        return await request("GET", tools.with_query("/v1/admin/jobs", filters));
      } catch (error) {
        if (is_latest()) replace_content(queues_place, tools.build_empty("Not read: see the error under Jobs."));
        throw error;
      }
    };
    if (!quiet) replace_content(queues_place, tools.build_loading());
    const build = (answer) => {
      if (is_latest()) replace_content(queues_place, build_queues(tools, answer.queues));
      return build_jobs(answer.jobs);
    };
    return tools.load_into(jobs_place, read, build, { quiet });
  }

  function build_jobs(jobs) {
    const columns = [
      { title: "Status", show: (job) => tools.build_badge(job.status || "unknown") },
      { title: "Area", show: (job) => tools.humanise(job.module) },
      { title: "Kind", show: (job) => name_kind(tools, job.kind) },
      { title: "Job id", nowrap: true, show: (job) => tools.build_id(job.id) },
      { title: "Started", nowrap: true, show: (job) => tools.format_date(job.started_at) },
      { title: "Finished", nowrap: true, show: (job) => tools.format_date(job.finished_at) },
      { title: "Problem", show: (job) => describe_problem(tools, job) },
      { title: "Actions", show: (job) => tools.build_actions(build_details_button(job), build_stop_button(job)) },
    ];
    const caption = jobs.length < NEWEST ? `Newest first: ${jobs.length} shown.` : `The newest ${NEWEST} jobs. Narrow the filters to see others.`;
    return [build_job_counts(tools, jobs), tools.build_table(jobs, columns, { caption, empty: "No job matches these filters in this period. Widen the period or clear a filter." })];
  }

  function build_details_button(job) {
    const button = tools.build_button("Details", () => follow_one_job(job.id), { kind: "quiet", small: true });
    button.setAttribute("aria-label", `Details of job ${job.id}`);
    return button;
  }

  function build_stop_button(job) {
    if (job.collection !== ADMIN_JOBS || !ACTIVE.includes(job.status)) return null;
    const question = `Stop the ${name_kind(tools, job.kind).toLowerCase()} job ${job.id}? ${STOP_QUESTION}`;
    return tools.build_button("Stop job", () => stop_job(job), { kind: "danger", small: true, confirm: question });
  }

  async function stop_job(job) {
    try {
      await request("POST", `/v1/admin/jobs/${encodeURIComponent(job.id)}/cancel`);
      tools.show_notice(`Job ${job.id} is cancelled.`, "good");
    } finally {
      // Taken or refused (409: it had ended), the job is read again; once the key is gone nothing is read.
      if (tools.has_admin_key()) {
        follow_one_job(job.id);
        list_jobs(true);
      }
    }
  }

  function follow_one_job(id) {
    stop_following();
    replace_content(job_place, tools.build_loading("Reading the job…"));
    stop_following = tools.follow_job(
      () => request("GET", `/v1/admin/jobs/${encodeURIComponent(id)}`),
      (job, error) => replace_content(job_place, error ? tools.build_error(error, () => follow_one_job(id)) : build_job(tools, job, build_stop_button(job))),
    );
    job_section.scrollIntoView({ block: "nearest" });
  }

  const filters = build_element("div", { class: "toolbar" }, build_field("Status", status), build_field("Area", module_name), build_field("Active in", hours));
  const open_form = tools.build_form([build_field("Job id", job_id, { hint: "An import's, build's or linking run's job id, or a run's, plan's or mapping's id." })], "Open", () => {
    if (!job_id.value.trim()) throw new Error("Type a job id.");
    follow_one_job(job_id.value.trim());
  });
  const job_section = tools.build_section({ title: "One job", subtitle: "Followed until it ends; its details are read again every few seconds." }, open_form, job_place);
  tools.set_actions(tools.build_button("Refresh", () => list_jobs(true), { kind: "quiet" }));
  tools.every(REFRESH_SECONDS, () => list_jobs(true));
  container.append(
    tools.build_section({ title: "Queues and workers", subtitle: "How much work waits on each queue, and how many workers take it." }, queues_place),
    tools.build_section({ title: "Jobs", subtitle: `Read again every ${REFRESH_SECONDS} seconds.` }, filters, jobs_place),
    job_section,
  );
  await list_jobs();
}

function build_job_counts(tools, jobs) {
  const count = (status) => jobs.filter((job) => job.status === status).length;
  return tools.build_kpis([
    { label: "Running", value: count("running"), tone: count("running") ? "busy" : null },
    { label: "Queued", value: count("queued") },
    { label: "Failed", value: count("failed"), tone: count("failed") ? "bad" : null },
    { label: "Done", value: count("done"), tone: count("done") ? "good" : null },
  ]);
}

function build_queues(tools, queues) {
  const rows = Object.entries(queues ?? {}).map(([queue, state]) => ({ queue, ...state }));
  const columns = [
    { title: "Queue", show: (row) => tools.humanise(row.queue) },
    { title: "Waiting", numeric: true, show: (row) => tools.format_count(row.waiting) },
    { title: "Workers online", numeric: true, show: (row) => tools.format_count(row.workers_online) },
    { title: "Workers", show: (row) => build_worker_state(tools, row.workers_online) },
  ];
  return tools.build_table(rows, columns, { caption: "Each queue. A dash: the count could not be read.", empty: "No queue is reported." });
}

function build_worker_state(tools, online) {
  if (typeof online !== "number") return tools.build_badge("unknown");
  return online > 0 ? tools.build_badge("ready", "Online") : tools.build_badge("down", "No worker");
}

/** "tsg_map_services" -> "Map services": the service's own prefix says nothing to the reader. */
function name_kind(tools, kind) {
  return tools.humanise(String(kind ?? "").replace(/^tsg_/, ""));
}

function describe_problem(tools, job) {
  if (job.retrying) {
    const { message, attempt, max_attempts, retry_at } = job.retrying;
    return `${message} Try ${attempt} of ${max_attempts} failed; the next starts ${tools.format_date(retry_at)}.`;
  }
  return job.error ? job.error.message || "The job failed." : null;
}

function build_job(tools, job, stop_button) {
  const facts = [
    ["Status", tools.build_badge(job.status || "unknown")],
    ["Job id", tools.build_id(job.id)],
    ["Area", tools.humanise(job.module)],
    ["Kind", name_kind(tools, job.kind)],
    ["Entity", job.entity_id],
    ["Created", tools.format_date(job.created_at)],
    ["Started", tools.format_date(job.started_at)],
    ["Finished", tools.format_date(job.finished_at)],
    ["Problem", describe_problem(tools, job)],
    ["Why (for support)", job.error?.reason && tools.humanise(job.error.reason)],
    ["Error code (for support)", job.error?.code],
    ["Tries", job.attempts],
    ["Sent again after a stalled worker", job.resends],
    ["Worker", job.worker && tools.build_element("span", { class: "mono", text: job.worker })],
    ["Worker holds it until", tools.format_date(job.lease_until)],
    ["Kept in", job.collection && tools.build_element("span", { class: "mono", text: job.collection })],
    ["Task id", job.task_id && tools.build_id(job.task_id)],
    ["Request id", job.request_id && tools.build_id(job.request_id)],
  ];
  return [stop_button && tools.build_callout("This job can still be stopped.", "info", tools.build_actions(stop_button)), tools.build_facts(facts)];
}
