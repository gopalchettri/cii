// Run by tests/test_admin_ui.py with node: the admin UI's request helper and job follower, with a fake
// fetch, document and timer. Exits non-zero on the first failed check.
import assert from "node:assert/strict";

const real_timeout = globalThis.setTimeout;
const tick = (ms = 250) => new Promise((resolve) => real_timeout(resolve, ms));
globalThis.setTimeout = (run) => real_timeout(run, 0); // the 3 s between reads, without the wait

let calls = [];
let answers = [];
globalThis.fetch = async (path, options) => {
  calls.push({ path, ...options });
  const answer = answers.shift() ?? { status: 200, body: {} };
  if (answer.unreachable) throw new TypeError("fetch failed");
  return {
    ok: answer.status >= 200 && answer.status < 300,
    status: answer.status,
    headers: new Map(Object.entries(answer.headers ?? {})),
    text: async () => (typeof answer.body === "string" ? answer.body : JSON.stringify(answer.body)),
  };
};

globalThis.location = { origin: "https://cii.example" };
const page = { hidden: false, shown: new Set() };
globalThis.document = {
  get hidden() {
    return page.hidden;
  },
  addEventListener: (_name, listener) => page.shown.add(listener),
  removeEventListener: (_name, listener) => page.shown.delete(listener),
};

const api = await import("../app/ui/api.js");
const { follow_job, is_job_over } = await import("../app/ui/poll.js");

// request: who is calling, the key only when set, JSON both ways
answers = [{ status: 200, body: { ok: 1 } }];
assert.deepEqual(await api.request("GET", "/v1/tsg/intel/health"), { ok: 1 });
assert.equal(calls[0].headers["X-User-Id"], "admin-ui");
assert.equal("X-Admin-Key" in calls[0].headers, false);
assert.equal(calls[0].body, undefined);
assert.equal(calls[0].cache, "no-store");

assert.equal(api.set_admin_key("  "), false);
assert.equal(api.set_admin_key("line\nbreak"), false);
assert.equal(api.has_admin_key(), false);
assert.equal(api.set_admin_key(" secret "), true);
assert.equal(api.set_user_id("Zoë"), false); // not sendable as a header: the earlier name stays
assert.equal(api.set_user_id(" analyst@desc "), true);
answers = [{ status: 202, body: { job_id: "j1" } }];
await api.request("POST", "/v1/tsg/intel/refresh", { source: null });
assert.equal(calls[1].headers["X-Admin-Key"], "secret");
assert.equal(calls[1].headers["X-User-Id"], "analyst@desc");
assert.equal(calls[1].headers["Content-Type"], "application/json");
assert.equal(calls[1].body, '{"source":null}');

answers = [{ status: 200, body: "" }];
assert.equal(await api.request("GET", "/health"), null);

// a refusal: one readable message, the facts beside it, and the key kept (not a 401 or 403)
const problem = {
  status: 409,
  title: "Conflict",
  detail: "An import is already running.",
  code: "conflict",
  reason: "job_in_progress",
  request_id: "req-9",
  details: { job_id: "j0" },
};
answers = [{ status: 409, body: problem }];
const conflict = await api.request("POST", "/v1/tsg/intel/refresh").catch((error) => error);
assert.ok(conflict instanceof api.ApiError);
assert.equal(conflict.message, "An import is already running. Request id req-9.");
assert.deepEqual([conflict.status, conflict.code, conflict.reason, conflict.details], [409, "conflict", "job_in_progress", { job_id: "j0" }]);
assert.equal(api.has_admin_key(), true);

answers = [{ status: 422, body: { detail: "Some fields are invalid.", errors: [{ field: "body.time", message: "bad" }] }, headers: { "X-Request-Id": "req-h" } }];
const invalid = await api.request("PUT", "/v1/tsg/intel/schedule", {}).catch((error) => error);
assert.equal(invalid.message, "Some fields are invalid. (body.time: bad) Request id req-h.");

answers = [{ status: 503, body: { status: "not_ready", dependencies: { mongo: false } } }];
const not_ready = await api.request("GET", "/ready").catch((error) => error);
assert.deepEqual([not_ready.status, not_ready.body.dependencies], [503, { mongo: false }]);

answers = [{ status: 502, body: "<html>Bad gateway</html>" }];
assert.equal((await api.request("GET", "/health").catch((error) => error)).message, "The API answered 502.");

answers = [{ unreachable: true }];
const unreachable = await api.request("GET", "/health").catch((error) => error);
assert.deepEqual([unreachable instanceof api.ApiError, unreachable.status], [true, 0]);

// 401 and 403 clear the key and tell the watchers why, in the API's own words; a set or a clear has no why
for (const [status, detail] of [[401, "The admin key is missing or wrong."], [403, "Admin endpoints are disabled on this deployment."]]) {
  const told = [];
  const stop_watching = api.watch_admin_key((has_key, refusal) => told.push([has_key, refusal]));
  api.set_admin_key("secret");
  answers = [{ status, body: { detail } }];
  await api.request("GET", "/v1/admin/jobs").catch(() => null);
  assert.deepEqual(told, [[true, null], [false, detail]]);
  assert.equal(api.has_admin_key(), false);
  stop_watching();
}

// never another origin: no call is made ("/\host" and a "/" before a tab are read by a browser as "//host")
const sent = calls.length;
for (const path of ["https://example.org/v1", "//example.org/v1", "/\\example.org/v1", "/\t/example.org/v1", "\\\\example.org/v1", "v1/x"]) {
  assert.equal(api.is_own_path(path), false, path);
  assert.ok((await api.request("GET", path).catch((error) => error)) instanceof api.ApiError, path);
}
assert.equal(calls.length, sent);
assert.deepEqual(["/health", "/v1/admin/jobs?hours=24", "/v1/tsg/intel/refresh/a%2Fb"].map(api.is_own_path), [true, true, true]);

assert.equal(api.with_query("/v1/admin/jobs", { status: ["queued", "running"], kind: "", hours: 24, module: null }), "/v1/admin/jobs?status=queued&status=running&hours=24");
assert.equal(api.with_query("/v1/ai-usage", {}), "/v1/ai-usage");

// follow_job: reads until the job is over; tells only changes
assert.deepEqual(["done", "failed", "cancelled", "running", undefined].map((status) => is_job_over({ status })), [true, true, true, false, false]);
let statuses = ["queued", "running", "running", "done", "done"];
let reads = 0;
let seen = [];
follow_job(async () => ({ status: statuses[reads++] }), (job, error) => seen.push(error ? "error" : job.status));
await tick();
assert.deepEqual([reads, seen], [4, ["queued", "running", "done"]]);
assert.equal(page.shown.size, 0); // it stopped listening for the tab

// paused while the tab is hidden; reads at once when it shows again
page.hidden = true;
reads = 0;
seen = [];
statuses = ["done"];
follow_job(async () => ({ status: statuses[reads++] }), (job) => seen.push(job.status));
await tick();
assert.equal(reads, 0);
page.hidden = false;
[...page.shown].forEach((listener) => listener());
await tick();
assert.deepEqual([reads, seen], [1, ["done"]]);

// a refused read ends it at once; an outage ends it after three reads in a row
reads = 0;
seen = [];
follow_job(async () => {
  reads += 1;
  throw new api.ApiError("No such job.", { status: 404 });
}, (job, error) => seen.push(error.message));
await tick();
assert.deepEqual([reads, seen], [1, ["No such job."]]);

reads = 0;
seen = [];
follow_job(async () => {
  reads += 1;
  throw new api.ApiError("The API did not answer.");
}, (job, error) => seen.push(error.message));
await tick();
assert.deepEqual([reads, seen], [3, ["The API did not answer."]]);

// one failed read between good ones does not end it
reads = 0;
seen = [];
follow_job(async () => {
  reads += 1;
  if (reads === 2) throw new api.ApiError("The API did not answer.");
  return { status: reads < 4 ? "running" : "done" };
}, (job, error) => seen.push(error ? "error" : job.status));
await tick();
assert.deepEqual([reads, seen], [4, ["running", "done"]]);

// stop() ends it
reads = 0;
const stop = follow_job(async () => ({ status: "running", reads: ++reads }), () => {});
stop();
await tick();
assert.ok(reads <= 1);
assert.equal(page.shown.size, 0);

console.log("admin ui checks passed");
