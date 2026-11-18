// Jobs (admin key): every job, queue and worker; one job by its id, followed until it ends; stopping an
// import, a build or a linking run.

const NEWEST = 100; // jobs asked for at once
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
  "A queued job never starts; a running one stops at its next safe point. It will read cancelled and cannot be resumed, but a new one can be started at once.";

const say_plainly = (word) => String(word ?? "").replaceAll("_", " ");
const list_choices = (first, words) => [{ value: "", label: first }, ...words.map((word) => ({ value: word, label: say_plainly(word) }))];

export async function show(container, tools) {
  const { build_element, build_field, build_panel, replace_content, request } = tools;
  const reload = { on: { change: () => list_jobs() } };
  const status = tools.build_select([...list_choices("Any status", STATUSES), { value: ACTIVE.join(","), label: "Queued or running" }], "", reload);
  const module_name = tools.build_select(list_choices("Any module", MODULES), "", reload);
  const hours = tools.build_select(PERIODS, 24, reload);
  // "columns": a plain block inside a panel grows as wide as its table and the page then scrolls sideways.
  const queues_place = build_element("div", { class: "columns" });
  const jobs_place = build_element("div", { class: "columns" });
  const job_place = build_element("div", { class: "columns", "aria-live": "polite" }, tools.build_empty("Press Details on a job, or open one by its id."));
  const job_id = build_element("input", { type: "text", class: "mono", required: true, maxlength: 64, autocomplete: "off", spellcheck: "false" });
  let lists_asked = 0;
  let stop_following = () => {};

  async function list_jobs() {
    const asked = (lists_asked += 1);
    replace_content(queues_place, tools.build_loading());
    replace_content(jobs_place, tools.build_loading());
    const filters = { status: status.value.split(","), module: module_name.value, hours: hours.value, limit: NEWEST };
    try {
      const answer = await request("GET", tools.with_query("/v1/admin/jobs", filters));
      if (asked !== lists_asked) return; // a later choice of filters is being read
      replace_content(queues_place, build_queues(tools, answer.queues));
      replace_content(jobs_place, build_jobs(answer.jobs));
    } catch (error) {
      if (asked !== lists_asked) return;
      replace_content(queues_place, tools.build_empty("Not read: see the error under Jobs."));
      replace_content(jobs_place, tools.build_error(error, list_jobs));
    }
  }

  function build_jobs(jobs) {
    const columns = [
      { title: "Status", show: (job) => tools.build_badge(job.status || "unknown") },
      { title: "Module", show: (job) => say_plainly(job.module) },
      { title: "Kind", nowrap: true, show: (job) => write_mono(tools, job.kind) },
      { title: "Job id", nowrap: true, show: (job) => write_mono(tools, job.id) },
      { title: "Started", nowrap: true, show: (job) => tools.format_date(job.started_at) },
      { title: "Finished", nowrap: true, show: (job) => tools.format_date(job.finished_at) },
      { title: "Problem", show: (job) => describe_problem(tools, job) },
      { title: "Actions", show: (job) => tools.build_actions(tools.build_button("Details", () => follow_one_job(job.id), { kind: "quiet" }), build_stop_button(job)) },
    ];
    const count = jobs.length < NEWEST ? `Newest first: ${jobs.length} shown.` : `The newest ${NEWEST} jobs. Narrow the filters to see others.`;
    return tools.build_table(jobs, columns, { caption: count, empty: "No job matches these filters in this period." });
  }

  function build_stop_button(job) {
    if (job.collection !== ADMIN_JOBS || !ACTIVE.includes(job.status)) return null;
    const question = `Stop the ${say_plainly(job.kind)} job ${job.id}? ${STOP_QUESTION}`;
    return tools.build_button("Stop job", () => stop_job(job), { kind: "danger", confirm: question });
  }

  async function stop_job(job) {
    try {
      await request("POST", `/v1/admin/jobs/${encodeURIComponent(job.id)}/cancel`);
      tools.show_notice(`Job ${job.id} is cancelled.`, "good");
    } finally {
      // Taken or refused (409: it had ended), the job is read again; once the key is gone nothing is read.
      if (tools.has_admin_key()) {
        follow_one_job(job.id);
        list_jobs();
      }
    }
  }

  function follow_one_job(id) {
    stop_following();
    replace_content(job_place, tools.build_loading());
    stop_following = tools.follow_job(
      () => request("GET", `/v1/admin/jobs/${encodeURIComponent(id)}`),
      (job, error) => replace_content(job_place, error ? tools.build_error(error, () => follow_one_job(id)) : build_job(tools, job, build_stop_button(job))),
    );
    job_panel.scrollIntoView({ block: "nearest" });
  }

  const filters = build_element("div", { class: "toolbar" }, build_field("Status", status), build_field("Module", module_name), build_field("Active in", hours));
  const open_form = tools.build_form([build_field("Job id", job_id, { hint: "An import's, build's or linking run's job id, or a run's, plan's or mapping's id." })], "Open", () => {
    if (!job_id.value.trim()) throw new Error("Type a job id.");
    follow_one_job(job_id.value.trim());
  });
  const job_panel = build_panel("One job", open_form, job_place);
  container.append(
    build_panel("Queues and workers", queues_place),
    build_panel("Jobs", filters, tools.build_actions(tools.build_button("Refresh", list_jobs)), jobs_place),
    job_panel,
  );
  await list_jobs();
}

function write_mono(tools, value) {
  return value ? tools.build_element("span", { class: "mono", text: value }) : null;
}

function build_queues(tools, queues) {
  const rows = Object.entries(queues ?? {}).map(([queue, state]) => ({ queue, ...state }));
  const columns = [
    { title: "Queue", nowrap: true, show: (row) => write_mono(tools, row.queue) },
    { title: "Waiting", numeric: true, show: (row) => tools.format_count(row.waiting) },
    { title: "Workers online", numeric: true, show: (row) => tools.format_count(row.workers_online) },
    { title: "Workers", show: (row) => build_worker_state(tools, row.workers_online) },
  ];
  return tools.build_table(rows, columns, { caption: "A dash: the count could not be read.", empty: "No queue is reported." });
}

function build_worker_state(tools, online) {
  if (typeof online !== "number") return tools.build_badge("unknown");
  return online > 0 ? tools.build_badge("ready", "Online") : tools.build_badge("down", "No worker");
}

function describe_problem(tools, job) {
  if (job.retrying) {
    const { message, attempt, max_attempts, retry_at } = job.retrying;
    return `${message} Try ${attempt} of ${max_attempts} failed; the next starts ${tools.format_date(retry_at)}.`;
  }
  if (!job.error) return null;
  return [job.error.message || job.error.code, job.error.reason && ` (${say_plainly(job.error.reason)})`].filter(Boolean).join("");
}

function build_job(tools, job, stop_button) {
  const facts = [
    ["Status", tools.build_badge(job.status || "unknown")],
    ["Job id", write_mono(tools, job.id)],
    ["Module", say_plainly(job.module)],
    ["Kind", write_mono(tools, job.kind)],
    ["Kept in", write_mono(tools, job.collection)],
    ["Entity", job.entity_id],
    ["Created", tools.format_date(job.created_at)],
    ["Started", tools.format_date(job.started_at)],
    ["Finished", tools.format_date(job.finished_at)],
    ["Problem", describe_problem(tools, job)],
    ["Error code", job.error?.code],
    ["Tries", job.attempts],
    ["Re-sent by the reaper", job.resends],
    ["Worker", write_mono(tools, job.worker)],
    ["Lease until", tools.format_date(job.lease_until)],
    ["Task id", write_mono(tools, job.task_id)],
    ["Request id", write_mono(tools, job.request_id)],
  ];
  if (stop_button) facts.push(["Stop", stop_button]);
  return tools.build_facts(facts);
}
