// The one way every page calls the API: same origin, JSON in and out, one readable error.
// Two kinds of call:
//   - an admin call (the default): the admin key, held in this module's memory only (gone on reload, never stored);
//   - a client call ({client: true}): the signed-in person's four headers from session.js.
// A client call that starts work carries an Idempotency-Key: {idempotent: true} a new one, {idempotent: key} that
// key. A form keeps one key per content (make_start_key), so a retry after a lost answer replays the start (200)
// and never starts paid work twice.

import { client_headers, identity, sign_out } from "./session.js";

const USER_ID_HEADER = "X-User-Id";
const ADMIN_KEY_HEADER = "X-Admin-Key";
const REQUEST_ID_HEADER = "X-Request-Id";
const IDEMPOTENCY_HEADER = "Idempotency-Key";
const DEFAULT_USER_ID = "admin-ui";
const HEADER_SAFE = /^[\x20-\x7E]+$/; // a header value the browser accepts: printable ASCII
const IDEMPOTENCY_KEY_MAX = 200; // the API's own limit
const KEY_REFUSED = new Set([401, 403]);

let admin_key = "";
let admin_name = ""; // "Recorded as": who admin changes are audited under (memory only)
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

/** Keeps the key for this tab, in memory. @param {string} value @returns {boolean} false: empty or not sendable */
export function set_admin_key(value) {
  const key = String(value ?? "").trim();
  if (!HEADER_SAFE.test(key)) return false;
  admin_key = key;
  tell_key_watchers(null);
  return true;
}

/** Who admin changes are audited as; empty: the signed-in name, else admin-ui. @returns {boolean} false: not sendable */
export function set_admin_name(value) {
  const name = String(value ?? "").trim();
  if (name && !HEADER_SAFE.test(name)) return false;
  admin_name = name;
  return true;
}

/** @returns {string} */
export function read_admin_name() {
  return admin_name;
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
 * The headers of a call. A client call carries the signed-in person's four headers (or `options.client`'s, an
 * identity being checked at sign-in); an admin call the admin key and the person's name for the audit.
 * @param {{client?: boolean | object, idempotent?: boolean}} [options]
 * @returns {Record<string, string>}
 */
export function build_headers(options = {}) {
  const headers = { Accept: "application/json" };
  if (options.client) {
    const values = typeof options.client === "object" ? options.client : identity();
    if (!values) throw new ApiError("Sign in first.", { status: 401, code: "signed_out" });
    Object.assign(headers, client_headers(values));
  } else {
    headers[USER_ID_HEADER] = admin_name || identity()?.user_id || DEFAULT_USER_ID;
    if (admin_key) headers[ADMIN_KEY_HEADER] = admin_key;
  }
  const unsendable = Object.entries(headers).find(([, value]) => !HEADER_SAFE.test(value));
  if (unsendable) throw new ApiError(`${unsendable[0]} may hold plain characters only.`);
  if (typeof options.idempotent === "string") {
    if (!HEADER_SAFE.test(options.idempotent) || options.idempotent.length > IDEMPOTENCY_KEY_MAX) throw new ApiError("Not a usable request key.");
    headers[IDEMPOTENCY_HEADER] = options.idempotent;
  } else if (options.idempotent) headers[IDEMPOTENCY_HEADER] = new_idempotency_key();
  return headers;
}

/**
 * One API call. Resolves with the parsed JSON (null for an empty answer); rejects with an ApiError.
 * An admin call's 401 or 403 clears the admin key; a client call's 401 signs the person out (the key is no
 * longer accepted); a client 403 is only an error (another entity's run, say).
 * @param {string} method GET, POST, PUT or DELETE
 * @param {string} path a path of this origin, e.g. "/v1/tsg/intel/health"
 * @param {any} [body] sent as JSON when given
 * @param {{client?: boolean | object, idempotent?: boolean | string, with_status?: boolean}} [options]
 *   with_status: resolve {status, body} (a start's 200 is a replay of the same start, 202 a new one)
 * @returns {Promise<any>}
 */
export async function request(method, path, body, options = {}) {
  if (!is_own_path(path)) throw new ApiError(`Not a path of this API: ${path}`);
  const headers = build_headers(options);
  const sent = { method, headers, cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    sent.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, sent);
  } catch {
    throw new ApiError("The service did not answer. Check your connection and try again.");
  }
  const answer = read_json(await response.text());
  if (response.ok) return options.with_status ? { status: response.status, body: answer } : answer;
  const problem = read_problem(response, answer);
  if (options.client === true && response.status === 401) sign_out(problem.message);
  else if (!options.client && KEY_REFUSED.has(response.status) && admin_key) {
    admin_key = "";
    tell_key_watchers(problem.message);
  }
  throw problem;
}

/** A client call: the signed-in person's headers. @returns {Promise<any>} */
export function call(method, path, body, options = {}) {
  return request(method, path, body, { ...options, client: true });
}

/** The API's problem body: {status, title, detail, code, request_id, reason?, errors?: [{field, message}], details?}. */
export function read_problem(response, answer) {
  const problem = answer !== null && typeof answer === "object" ? answer : {};
  const request_id = problem.request_id || response.headers.get(REQUEST_ID_HEADER) || null;
  const fields = Array.isArray(problem.errors)
    ? problem.errors.map((error) => `${String(error.field ?? "").replace(/^body\./, "")}: ${error.message}`).join("; ")
    : "";
  const parts = [
    String(problem.detail || problem.title || `The service answered ${response.status}.`),
    fields && `(${fields})`,
    request_id && `Reference ${request_id}.`,
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

/**
 * One Idempotency-Key per content: for_content(path, body) gives the same key while the same start is sent again
 * (a retry, a double click, the same form sent twice) and a new key once the content changes.
 * @returns {{for_content: (path: string, body: any) => string}}
 */
export function make_start_key() {
  let last = { content: null, key: null };
  return {
    for_content(path, body) {
      const content = `${path} ${JSON.stringify(body ?? null)}`;
      if (content !== last.content) last = { content, key: new_idempotency_key() };
      return last.key;
    },
  };
}

export function new_idempotency_key() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `ui-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
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
