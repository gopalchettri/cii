// The one way every page calls the API: same origin, JSON in and out, one readable error.
// The admin key and the name are held in this module's memory only: gone on reload, never stored, never in a URL.

const USER_ID_HEADER = "X-User-Id";
const ADMIN_KEY_HEADER = "X-Admin-Key";
const REQUEST_ID_HEADER = "X-Request-Id";
const DEFAULT_USER_ID = "admin-ui";
const HEADER_SAFE = /^[\x20-\x7E]+$/; // a header value the browser accepts: printable ASCII
const KEY_REFUSED = new Set([401, 403]);

let admin_key = "";
let user_id = "";
const key_watchers = new Set();

/** A call the API refused or that never reached it. `message` is ready to show. */
export class ApiError extends Error {
  /**
   * @param {string} message
   * @param {{status?: number, code?: string, reason?: string, request_id?: string, details?: object, body?: any}} facts
   */
  constructor(message, facts = {}) {
    super(message);
    this.name = "ApiError";
    this.status = facts.status ?? 0; // 0: no answer (network)
    this.code = facts.code ?? null;
    this.reason = facts.reason ?? null; // a 409's reason, e.g. job_in_progress
    this.request_id = facts.request_id ?? null;
    this.details = facts.details ?? null; // e.g. {job_id} of the job already running
    this.body = facts.body ?? null; // the whole answer (GET /ready answers 503 with its report)
  }
}

/** @returns {boolean} */
export function has_admin_key() {
  return admin_key !== "";
}

/** Keeps the key for this tab. @param {string} value @returns {boolean} false: empty or not sendable */
export function set_admin_key(value) {
  const key = String(value ?? "").trim();
  if (!HEADER_SAFE.test(key)) return false;
  admin_key = key;
  tell_key_watchers(null);
  return true;
}

export function clear_admin_key() {
  admin_key = "";
  tell_key_watchers(null);
}

/**
 * Calls `watcher(has_key, refusal)` on every set, clear and refusal (401 or 403). `refusal` is the API's own
 * message of a refusal ("Admin endpoints are disabled on this deployment."), null on a set or a clear.
 * @param {(has_key: boolean, refusal: string | null) => void} watcher
 * @returns {() => void} stops watching
 */
export function watch_admin_key(watcher) {
  key_watchers.add(watcher);
  return () => key_watchers.delete(watcher);
}

/** Who admin changes are audited as. @param {string} value @returns {boolean} false: not sendable (kept unchanged) */
export function set_user_id(value) {
  const name = String(value ?? "").trim();
  if (name && !HEADER_SAFE.test(name)) return false;
  user_id = name;
  return true;
}

/**
 * True for a path of this origin. "//host", "/\host" and a "/" before a tab or line break start with "/" yet
 * name another host, so the browser's own reading of the address decides.
 * @param {string} path
 * @returns {boolean}
 */
export function is_own_path(path) {
  try {
    return path.startsWith("/") && new URL(path, location.origin).origin === location.origin;
  } catch {
    return false;
  }
}

/**
 * `path` with the filled values of `params` as its query; an array repeats the name; empty values are left out.
 * @param {string} path
 * @param {Record<string, any>} params
 * @returns {string}
 */
export function with_query(path, params) {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(params ?? {})) {
    for (const item of [value].flat()) {
      if (item !== null && item !== undefined && item !== "") query.append(name, String(item));
    }
  }
  const text = query.toString();
  return text ? `${path}?${text}` : path;
}

/**
 * One API call. Resolves with the parsed JSON (null for an empty answer); rejects with an ApiError.
 * A 401 or 403 also clears the admin key and tells the watchers.
 * @param {string} method GET, POST, PUT or DELETE
 * @param {string} path a path of this origin, e.g. "/v1/tsg/intel/health"
 * @param {any} [body] sent as JSON when given
 * @returns {Promise<any>}
 */
export async function request(method, path, body) {
  if (!is_own_path(path)) throw new ApiError(`Not a path of this API: ${path}`);
  const headers = { Accept: "application/json", [USER_ID_HEADER]: user_id || DEFAULT_USER_ID };
  if (admin_key) headers[ADMIN_KEY_HEADER] = admin_key;
  const options = { method, headers, cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError("The API did not answer. Check the connection and try again.");
  }
  const answer = read_json(await response.text());
  if (response.ok) return answer;
  const problem = read_problem(response, answer);
  if (KEY_REFUSED.has(response.status)) {
    admin_key = "";
    tell_key_watchers(problem.message);
  }
  throw problem;
}

function tell_key_watchers(refusal) {
  for (const watcher of key_watchers) watcher(admin_key !== "", refusal);
}

function read_json(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// The API's problem body: {status, title, detail, code, request_id, reason?, errors?: [{field, message}], details?}.
function read_problem(response, answer) {
  const problem = answer !== null && typeof answer === "object" ? answer : {};
  const request_id = problem.request_id || response.headers.get(REQUEST_ID_HEADER) || null;
  const fields = Array.isArray(problem.errors)
    ? problem.errors.map((error) => `${error.field}: ${error.message}`).join("; ")
    : "";
  const parts = [
    String(problem.detail || problem.title || `The API answered ${response.status}.`),
    fields && `(${fields})`,
    request_id && `Request id ${request_id}.`,
  ];
  return new ApiError(parts.filter(Boolean).join(" "), {
    status: response.status,
    code: problem.code,
    reason: problem.reason,
    request_id,
    details: problem.details,
    body: answer,
  });
}
