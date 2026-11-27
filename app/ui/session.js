// Who is signed in, for this browser tab only: the client key, user, entity and tenant, and the runs opened in
// this tab. The ONE file of the UI that keeps anything in the browser: sessionStorage, which the browser clears
// when the tab is closed. Sign out clears it at once. The admin key is never kept here (api.js holds it in memory).

const STORE_KEY = "tsg.session";
const RECENT_RUNS_KEPT = 20;
const HEADER_SAFE = /^[\x20-\x7E]+$/; // a header value the browser accepts: printable ASCII
const MAX_ENTITY_ID = 2147483647; // the SQL INT the API checks X-Entity-Id against
const watchers = new Set();

let current = read_store();

/** @returns {{api_key: string, user_id: string, entity_id: string, tenant_id: string} | null} */
export function identity() {
  return current.identity;
}

/** @returns {boolean} */
export function is_signed_in() {
  return current.identity !== null;
}

/**
 * The problems of sign-in values, in plain words; [] when they can be sent.
 * @param {{api_key?: string, user_id?: string, entity_id?: string, tenant_id?: string}} values
 * @returns {string[]}
 */
export function check_identity(values) {
  const problems = [];
  const named = { api_key: "the API key", user_id: "your user id", tenant_id: "the tenant id", entity_id: "the entity id" };
  for (const [field, name] of Object.entries(named)) {
    const value = String(values?.[field] ?? "").trim();
    if (!value) problems.push(`Enter ${name}.`);
    else if (!HEADER_SAFE.test(value)) problems.push(`${name[0].toUpperCase()}${name.slice(1)} may hold plain characters only.`);
  }
  const entity = String(values?.entity_id ?? "").trim();
  if (entity && (!/^\d+$/.test(entity) || Number(entity) < 1 || Number(entity) > MAX_ENTITY_ID)) {
    problems.push("The entity id is a whole number, 1 or more.");
  }
  return problems;
}

/**
 * The four headers every client call carries, for `values` or the signed-in identity.
 * @param {{api_key: string, user_id: string, entity_id: string, tenant_id: string}} [values]
 * @returns {Record<string, string>}
 */
export function client_headers(values = current.identity) {
  if (!values) return {};
  return {
    "X-API-Key": values.api_key.trim(),
    "X-User-Id": values.user_id.trim(),
    "X-Entity-Id": String(values.entity_id).trim(),
    "X-Tenant-Id": values.tenant_id.trim(),
  };
}

/** Keeps the identity for this tab (the caller checked it with the API first). */
export function sign_in(values) {
  const kept = Object.fromEntries(["api_key", "user_id", "entity_id", "tenant_id"].map((name) => [name, String(values[name]).trim()]));
  current = { identity: kept, runs: [] };
  write_store();
  tell(null);
}

/** Forgets the identity and this tab's runs. @param {string | null} [reason] the API's words when it refused the key */
export function sign_out(reason = null) {
  current = { identity: null, runs: [] };
  write_store();
  tell(reason);
}

/**
 * Calls `watcher(identity, reason)` on every sign-in and sign-out; `reason` is why a sign-out happened (null when
 * the person chose it). @returns {() => void} stops watching
 */
export function watch_session(watcher) {
  watchers.add(watcher);
  return () => watchers.delete(watcher);
}

/**
 * Notes a run opened or started in this tab, newest first, once each.
 * @param {{kind: "mitre" | "tsg", id: string, label?: string}} run
 */
export function remember_run(run) {
  if (!current.identity || !run?.id) return;
  const others = current.runs.filter((kept) => kept.id !== run.id);
  current.runs = [{ kind: run.kind, id: run.id, label: run.label || "", at: new Date().toISOString() }, ...others].slice(0, RECENT_RUNS_KEPT);
  write_store();
}

/** @returns {Array<{kind: string, id: string, label: string, at: string}>} newest first */
export function recent_runs() {
  return [...current.runs];
}

function tell(reason) {
  for (const watcher of watchers) watcher(current.identity, reason);
}

function read_store() {
  try {
    const kept = JSON.parse(window.sessionStorage.getItem(STORE_KEY) || "null");
    if (kept && kept.identity && check_identity(kept.identity).length === 0) {
      return { identity: kept.identity, runs: Array.isArray(kept.runs) ? kept.runs : [] };
    }
  } catch {
    // storage blocked or unreadable: signed out
  }
  return { identity: null, runs: [] };
}

function write_store() {
  try {
    if (current.identity) window.sessionStorage.setItem(STORE_KEY, JSON.stringify(current));
    else window.sessionStorage.removeItem(STORE_KEY);
  } catch {
    // storage blocked: the sign-in lasts until the page is reloaded
  }
}
