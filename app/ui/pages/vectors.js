// Search vectors (admin key): the library's search vectors built now, and the build followed until it ends.

const BUILD_KIND = "embeddings_build"; // the job kind of a build, as the jobs list names it
const LOOK_BACK_HOURS = 2160; // the latest build is looked for in the last 90 days, the most the jobs list reads
const ENDED = ["done", "failed", "cancelled"];
const ALREADY_RUNNING = "job_in_progress"; // the 409 reason of a second build; its details name the running job

export async function show(container, tools) {
  const { build_element, replace_content, request } = tools;
  const place = build_element("div", { "aria-live": "polite" });
  const start = tools.build_button("Build now", start_build, { kind: "primary", disabled: true });
  let turn = 0; // what the place shows was chosen by the latest turn; an older turn's late answer is dropped
  let stop_following = () => {};

  /** Shows the build and keeps it up to date; resolves when it ends or another build is followed. */
  function follow_build(job_id) {
    stop_following();
    return new Promise((resolve) => {
      const stop_reading = tools.follow_job(
        () => request("GET", `/v1/embeddings/${encodeURIComponent(job_id)}`),
        (job, error) => {
          replace_content(place, error ? tools.build_error(error, () => follow_build(job_id)) : build_build(tools, job));
          if (error || ENDED.includes(job.status)) resolve();
        },
      );
      stop_following = () => {
        stop_reading();
        resolve();
      };
    });
  }

  async function start_build() {
    let job_id;
    try {
      job_id = (await request("POST", "/v1/embeddings")).job_id;
      tools.show_notice("The build is queued.", "good");
    } catch (error) {
      if (error.reason !== ALREADY_RUNNING || !error.details?.job_id) throw error;
      job_id = error.details.job_id;
      tools.show_notice("A build is already queued or running: following that one.", "info");
    }
    turn += 1;
    await follow_build(job_id); // the button stays disabled until the build ends
  }

  async function show_latest_build() {
    const mine = (turn += 1);
    start.disabled = true;
    replace_content(place, tools.build_loading());
    try {
      const answer = await request("GET", tools.with_query("/v1/admin/jobs", { kind: BUILD_KIND, hours: LOOK_BACK_HOURS, limit: 1 }));
      if (mine !== turn) return;
      if (answer.jobs.length) follow_build(answer.jobs[0].id);
      else replace_content(place, tools.build_empty("No build was started in the last 90 days."));
    } catch (error) {
      if (mine === turn) replace_content(place, tools.build_error(error, show_latest_build));
    } finally {
      start.disabled = false;
    }
  }

  const about = "Makes the search vector of every library row. Needed once after the library is loaded; later builds run by themselves. One build runs at a time.";
  const jobs_link = build_element("p", { class: "muted" }, "A queued or running build can be stopped on the ", build_element("a", { href: "#/jobs", text: "Jobs" }), " page.");
  container.append(
    tools.build_panel("Build the library's search vectors", build_element("p", { text: about }), tools.build_actions(start), jobs_link),
    tools.build_panel("Latest build", place),
  );
  await show_latest_build();
}

function build_build(tools, job) {
  const write_mono = (value) => value && tools.build_element("span", { class: "mono", text: value });
  const facts = tools.build_facts([
    ["Status", tools.build_badge(job.status)],
    ["Job id", write_mono(job.job_id)],
    ["Started by", job.requested_by],
    ["Queued", tools.format_date(job.created_at)],
    ["Started", tools.format_date(job.started_at)],
    ["Finished", tools.format_date(job.finished_at)],
    ["Error", job.error && [job.error.message, job.error.code && ` (${job.error.code})`].filter(Boolean).join("")],
  ]);
  return tools.build_element("div", { class: "columns" }, facts, job.result && build_result(tools, job.result));
}

function build_result(tools, result) {
  const counts = result.counts ?? {};
  const made = result.newly_embedded ?? {};
  const rows = [...new Set([...Object.keys(counts), ...Object.keys(made)])].map((library) => ({ library, held: counts[library], made: made[library] }));
  const columns = [
    { title: "Library", show: (row) => row.library.replaceAll("_", " ") },
    { title: "Rows with a vector", numeric: true, show: (row) => tools.format_count(row.held) },
    { title: "Vectors this build made", numeric: true, show: (row) => tools.format_count(row.made) },
  ];
  return tools.build_table(rows, columns, { caption: "What the build left", empty: "The build named no library." });
}
