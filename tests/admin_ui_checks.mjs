// Run by tests/test_admin_ui.py with node: the UI's request helper (api.js), sign-in session (session.js), event
// stream reader (stream.js) and job follower (poll.js), with a fake fetch, document, storage and timer.
// Exits non-zero on the first failed check.
import assert from "node:assert/strict";

const real_timeout = globalThis.setTimeout;
const tick = (ms = 250) => new Promise((resolve) => real_timeout(resolve, ms));
globalThis.setTimeout = (run) => real_timeout(run, 0); // the waits between reads and reconnects, without the wait

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
    body: answer.stream ?? null,
    text: async () => (typeof answer.body === "string" ? answer.body : JSON.stringify(answer.body)),
  };
};

const stored = new Map();
globalThis.window = {
  sessionStorage: {
    getItem: (key) => (stored.has(key) ? stored.get(key) : null),
    setItem: (key, value) => stored.set(key, String(value)),
    removeItem: (key) => stored.delete(key),
  },
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

const session = await import("../app/ui/session.js");
const api = await import("../app/ui/api.js");
const { follow_job, is_job_over } = await import("../app/ui/poll.js");
const stream = await import("../app/ui/stream.js");

// ---------- an admin or open call: the admin key only when set, the person's name for the audit
answers = [{ status: 200, body: { ok: 1 } }];
assert.deepEqual(await api.request("GET", "/v1/tsg/intel/health"), { ok: 1 });
assert.equal(calls[0].headers["X-User-Id"], "admin-ui");
assert.equal("X-Admin-Key" in calls[0].headers, false);
assert.equal("X-API-Key" in calls[0].headers, false);
assert.equal(calls[0].body, undefined);
assert.equal(calls[0].cache, "no-store");

assert.equal(api.set_admin_key("  "), false);
assert.equal(api.set_admin_key("line\nbreak"), false);
assert.equal(api.has_admin_key(), false);
assert.equal(api.set_admin_key(" secret "), true);
answers = [{ status: 202, body: { job_id: "j1" } }];
await api.request("POST", "/v1/tsg/intel/refresh", { source: null });
assert.equal(calls[1].headers["X-Admin-Key"], "secret");
assert.equal(calls[1].headers["Content-Type"], "application/json");
assert.equal(calls[1].body, '{"source":null}');
assert.equal("Idempotency-Key" in calls[1].headers, false);

answers = [{ status: 200, body: "" }];
assert.equal(await api.request("GET", "/health"), null);

// ---------- a refusal: one readable message, the facts beside it, the key kept (not a 401 or 403)
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
assert.equal(conflict.message, "An import is already running. Reference req-9.");
assert.deepEqual([conflict.status, conflict.code, conflict.reason, conflict.details], [409, "conflict", "job_in_progress", { job_id: "j0" }]);
assert.equal(api.has_admin_key(), true);

answers = [{ status: 422, body: { detail: "Some fields are invalid.", errors: [{ field: "body.asset_id", message: "bad" }] }, headers: { "X-Request-Id": "req-h" } }];
const invalid = await api.request("PUT", "/v1/tsg/intel/schedule", {}).catch((error) => error);
assert.equal(invalid.message, "Some fields are invalid. (asset_id: bad) Reference req-h.");

answers = [{ status: 503, body: { status: "not_ready", dependencies: { mongo: false } } }];
const not_ready = await api.request("GET", "/ready").catch((error) => error);
assert.deepEqual([not_ready.status, not_ready.body.dependencies], [503, { mongo: false }]);

answers = [{ status: 502, body: "<html>Bad gateway</html>" }];
assert.equal((await api.request("GET", "/health").catch((error) => error)).message, "The service answered 502.");

answers = [{ unreachable: true }];
const unreachable = await api.request("GET", "/health").catch((error) => error);
assert.deepEqual([unreachable instanceof api.ApiError, unreachable.status], [true, 0]);

// 401 and 403 of an admin call clear the key and tell the watchers why, in the API's own words
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

// ---------- sign-in values: checked in plain words before anything is sent
assert.deepEqual(session.check_identity({ api_key: "k", user_id: "u", entity_id: "125", tenant_id: "DESC" }), []);
assert.equal(session.check_identity({}).length, 4);
assert.match(session.check_identity({ api_key: "k", user_id: "Zoë", entity_id: "125", tenant_id: "t" }).join(" "), /plain characters/);
for (const entity of ["0", "-3", "1.5", "abc", "2147483648"]) {
  assert.match(session.check_identity({ api_key: "k", user_id: "u", entity_id: entity, tenant_id: "t" }).join(" "), /whole number/, entity);
}

// a client call before sign-in: nothing is sent
let sent_before = calls.length;
const signed_out = await api.call("GET", "/v1/jobs").catch((error) => error);
assert.deepEqual([signed_out instanceof api.ApiError, signed_out.code], [true, "signed_out"]);
assert.equal(calls.length, sent_before);

// a check of candidate values at sign-in: their headers, nothing kept
answers = [{ status: 200, body: { items: [] } }];
await api.request("GET", "/v1/jobs", undefined, { client: { api_key: "ciip_try", user_id: "jane", entity_id: "125", tenant_id: "DESC" } });
assert.equal(calls.at(-1).headers["X-API-Key"], "ciip_try");
assert.equal(session.is_signed_in(), false);

// sign in: kept for the tab, the four headers on every client call, never the admin key
const watched = [];
session.watch_session((who, reason) => watched.push([who?.user_id ?? null, reason]));
api.set_admin_key("secret");
session.sign_in({ api_key: " ciip_x ", user_id: "gopal", entity_id: "125", tenant_id: "69" });
assert.equal(session.is_signed_in(), true);
assert.match(stored.get("tsg.session"), /ciip_x/);
answers = [{ status: 200, body: {} }];
await api.call("GET", "/v1/service-mapper");
let headers = calls.at(-1).headers;
assert.deepEqual([headers["X-API-Key"], headers["X-User-Id"], headers["X-Entity-Id"], headers["X-Tenant-Id"]], ["ciip_x", "gopal", "125", "69"]);
assert.equal("X-Admin-Key" in headers, false);

// an admin call of a signed-in person is audited under their name
answers = [{ status: 200, body: {} }];
await api.request("GET", "/v1/admin/jobs");
assert.deepEqual([calls.at(-1).headers["X-User-Id"], calls.at(-1).headers["X-Admin-Key"]], ["gopal", "secret"]);

// a start carries a fresh Idempotency-Key; a read never does
answers = [{ status: 202, body: {} }, { status: 202, body: {} }, { status: 200, body: {} }];
await api.call("POST", "/v1/mitre_create_session", { asset_id: 1 }, { idempotent: true });
const first_key = calls.at(-1).headers["Idempotency-Key"];
await api.call("POST", "/v1/mitre_create_session", { asset_id: 1 }, { idempotent: true });
assert.ok(first_key && first_key !== calls.at(-1).headers["Idempotency-Key"]);
await api.call("GET", "/v1/jobs");
assert.equal("Idempotency-Key" in calls.at(-1).headers, false);

// a form's start: the same content keeps its key (a retry is replayed, never a second run), new content a new key;
// with_status tells the replay (200) from a new start (202)
const start_key = api.make_start_key();
const key_a = start_key.for_content("/v1/sessions", { asset_id: 1 });
assert.equal(start_key.for_content("/v1/sessions", { asset_id: 1 }), key_a);
assert.notEqual(start_key.for_content("/v1/sessions", { asset_id: 2 }), key_a);
answers = [{ status: 200, body: { session_id: "s1" } }];
const replay = await api.call("POST", "/v1/sessions", { asset_id: 1 }, { idempotent: key_a, with_status: true });
assert.deepEqual(replay, { status: 200, body: { session_id: "s1" } });
assert.equal(calls.at(-1).headers["Idempotency-Key"], key_a);
const bad_key = await api.call("POST", "/v1/sessions", {}, { idempotent: "x".repeat(201) }).catch((error) => error);
assert.ok(bad_key instanceof api.ApiError);

// a client 403 (another entity's run) is only an error; a client 401 signs out with the API's words
answers = [{ status: 403, body: { detail: "This run belongs to another entity." } }];
await api.call("GET", "/v1/sessions/x").catch(() => null);
assert.equal(session.is_signed_in(), true);
assert.equal(api.has_admin_key(), true);
answers = [{ status: 401, body: { detail: "The API key is not valid." } }];
await api.call("GET", "/v1/jobs").catch(() => null);
assert.equal(session.is_signed_in(), false);
assert.equal(stored.has("tsg.session"), false);
assert.equal(watched.at(-1)[0], null); // the watchers are told: signed out
assert.match(watched.at(-1)[1], /The API key is not valid\./); // and why, in the API's words
assert.equal(api.has_admin_key(), true); // the admin key is another matter
api.clear_admin_key();

// the runs opened in this tab: newest first, once each, gone on sign-out
session.sign_in({ api_key: "ciip_x", user_id: "gopal", entity_id: "125", tenant_id: "69" });
session.remember_run({ kind: "mitre", id: "a", label: "Asset A" });
session.remember_run({ kind: "tsg", id: "b" });
session.remember_run({ kind: "mitre", id: "a", label: "Asset A" });
assert.deepEqual(session.recent_runs().map((run) => run.id), ["a", "b"]);
session.sign_out();
assert.deepEqual(session.recent_runs(), []);

// ---------- never another origin: no call is made ("/\host" and a "/" before a tab are "//host" to a browser)
const sent = calls.length;
for (const path of ["https://example.org/v1", "//example.org/v1", "/\\example.org/v1", "/\t/example.org/v1", "\\\\example.org/v1", "v1/x"]) {
  assert.equal(api.is_own_path(path), false, path);
  assert.ok((await api.request("GET", path).catch((error) => error)) instanceof api.ApiError, path);
}
assert.equal(calls.length, sent);
assert.deepEqual(["/health", "/v1/admin/jobs?hours=24", "/v1/tsg/intel/refresh/a%2Fb"].map(api.is_own_path), [true, true, true]);

assert.equal(api.with_query("/v1/admin/jobs", { status: ["queued", "running"], kind: "", hours: 24, module: null }), "/v1/admin/jobs?status=queued&status=running&hours=24");
assert.equal(api.with_query("/v1/ai-usage", {}), "/v1/ai-usage");

// ---------- the event stream: blocks, pings, JSON; a refusal ends it; a drop reconnects
assert.deepEqual(stream.parse_block('event: session.updated\ndata: {"id":1}'), { type: "session.updated", data: { id: 1 } });
assert.equal(stream.parse_block(": ping"), null);
assert.deepEqual(stream.parse_block("data: plain"), { type: "message", data: "plain" });
const encode = (text) => new TextEncoder().encode(text);
const body_of = (...chunks) => {
  let at = 0;
  return { getReader: () => ({ read: async () => (at < chunks.length ? { value: encode(chunks[at++]), done: false } : { done: true }), cancel: async () => {} }) };
};
const events = [];
await stream.read_events(body_of('event: a\ndata: {"n":1}\n\n: ping\n\nevent: b\nda', 'ta: {"n":2}\r\n\r\n'), (type, data) => events.push([type, data.n]), () => false);
assert.deepEqual(events, [["a", 1], ["b", 2]]);

session.sign_in({ api_key: "ciip_x", user_id: "gopal", entity_id: "125", tenant_id: "69" });
let states = [];
answers = [{ status: 401, body: { detail: "The API key is not valid." } }];
stream.follow_stream("/v1/sessions/s1/events", { on_event: () => {}, on_state: (state) => states.push(state) });
await tick();
assert.deepEqual(states, ["connecting", "ended"]);
assert.equal(calls.at(-1).headers.Accept, "text/event-stream");
assert.equal(calls.at(-1).headers["X-API-Key"], "ciip_x");

states = [];
const live = [];
answers = [{ unreachable: true }, { status: 200, stream: body_of('event: session.updated\ndata: {"n":7}\n\n') }, { status: 404, body: { detail: "gone" } }];
stream.follow_stream("/v1/sessions/s1/events", { on_event: (type, data) => live.push([type, data.n]), on_state: (state) => states.push(state) });
await tick();
assert.deepEqual(live, [["session.updated", 7]]);
assert.deepEqual(states, ["connecting", "retrying", "connecting", "live", "retrying", "connecting", "ended"]);

states = [];
const reads_before = calls.length;
answers = [{ unreachable: true }, { unreachable: true }];
const stop_stream = stream.follow_stream("/v1/sessions/s1/events", { on_event: () => {}, on_state: (state) => states.push(state) });
stop_stream();
await tick();
assert.ok(calls.length - reads_before <= 1, "stop() ends the reconnects");
session.sign_out();

// ---------- follow_job: reads until the job is over; tells only changes
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
  throw new api.ApiError("The service did not answer.");
}, (job, error) => seen.push(error.message));
await tick();
assert.deepEqual([reads, seen], [3, ["The service did not answer."]]);

// one failed read between good ones does not end it
reads = 0;
seen = [];
follow_job(async () => {
  reads += 1;
  if (reads === 2) throw new api.ApiError("The service did not answer.");
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

console.log("ui checks passed");
