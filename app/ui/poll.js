// The one way every page follows a background job (an import, a build, a linking run).

export const POLL_SECONDS = 3;
/** A job in one of these is over: nothing more to read. */
export const ENDED_STATUSES = new Set(["done", "failed", "cancelled"]);
const FAILED_READS_ALLOWED = 3; // in a row; a short outage does not end the following

/** @param {{status?: string} | null} job @returns {boolean} */
export function is_job_over(job) {
  return ENDED_STATUSES.has(job?.status);
}

/**
 * Reads a job now and then every POLL_SECONDS until it is done, failed or cancelled. Paused while the tab is
 * hidden; reads at once when it shows again. `on_change(job, null)` on the first read and on every change;
 * `on_change(null, error)` once when the following gives up: the API refused the read (4xx), or
 * FAILED_READS_ALLOWED reads in a row failed.
 * @param {() => Promise<{status: string}>} read e.g. () => request("GET", `/v1/tsg/intel/refresh/${job_id}`)
 * @param {(job: object | null, error: Error | null) => void} on_change
 * @returns {() => void} stops the following (the shell also stops it when the page is left)
 */
export function follow_job(read, on_change) {
  let timer = null;
  let reading = false;
  let stopped = false;
  let last_seen = "";
  let failed_reads = 0;

  function stop() {
    stopped = true;
    clearTimeout(timer);
    document.removeEventListener("visibilitychange", read_when_shown);
  }

  function read_when_shown() {
    if (!document.hidden) read_once();
  }

  async function read_once() {
    clearTimeout(timer);
    if (stopped || reading || document.hidden) return;
    reading = true;
    let job = null;
    let error = null;
    try {
      job = await read();
    } catch (caught) {
      error = caught;
    }
    reading = false;
    if (stopped) return;
    if (error) {
      failed_reads += 1;
      const refused = error.status >= 400 && error.status < 500;
      if (refused || failed_reads >= FAILED_READS_ALLOWED) {
        stop();
        on_change(null, error);
        return;
      }
    } else {
      failed_reads = 0;
      const seen = JSON.stringify(job);
      if (seen !== last_seen) {
        last_seen = seen;
        on_change(job, null);
      }
      if (stopped) return; // on_change stopped it
      if (is_job_over(job)) {
        stop();
        return;
      }
    }
    timer = setTimeout(read_once, POLL_SECONDS * 1000);
  }

  document.addEventListener("visibilitychange", read_when_shown);
  read_once();
  return stop;
}
