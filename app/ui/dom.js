// The builders every page uses, so no page writes its own markup, states or dialogs.
// Whatever the API answers is put on the page as text; it is never parsed as markup.

import { is_own_path } from "./api.js";

const NONE = "—"; // shown for a missing value
const SAFE_LINK = /^(#|\.\/|https:\/\/)/; // this page, a file beside it, or an https site; a "/…" link: is_own_path
const HAS_ZONE = /(Z|[+-]\d\d:?\d\d)$/i;
/** A badge's look by status word: an icon and a tone, so state never rests on colour alone. */
const BADGES = {
  good: { icon: "✓", statuses: ["done", "ok", "ready", "valid", "active", "enabled", "on", "approved", "linked", "true"] },
  bad: { icon: "✕", statuses: ["failed", "error", "not_ready", "revoked", "rejected", "down", "false"] },
  busy: { icon: "↻", statuses: ["running", "in_progress"] },
  wait: { icon: "…", statuses: ["queued", "pending", "waiting", "retrying"] },
  warn: { icon: "!", statuses: ["warning", "degraded"] },
  idle: { icon: "–", statuses: ["cancelled", "disabled", "off", "inactive", "never_run", "unknown"] },
};
let fields_built = 0;
/** Each container's load in flight (load_into). */
const loads = new WeakMap();

/**
 * One element. `props`: `text` (its text), `class`, `on` ({event: listener}), `value`, `checked`, `href`
 * (kept only when it stays on this origin or is https), and any other attribute (true: present; false,
 * null, undefined: left out). Children: nodes or texts; arrays are flattened; null and false are skipped.
 * @param {string} tag
 * @param {Record<string, any>} [props]
 * @param {...(Node | string | number | null | false | Array)} children
 * @returns {HTMLElement}
 */
export function build_element(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(props ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "text") element.textContent = String(value);
    else if (name === "class") element.className = value;
    else if (name === "on") Object.entries(value).forEach(([event, listener]) => element.addEventListener(event, listener));
    else if (name === "value") element.value = value;
    else if (name === "checked") element.checked = true;
    else if (name === "href") set_link(element, String(value));
    else if (name === "style" || name.startsWith("on")) throw new Error(`build_element takes no ${name}: use a class or props.on`);
    else element.setAttribute(name, value === true ? "" : String(value));
  }
  element.append(...list_nodes(children));
  return element;
}

/** Puts `children` in place of everything `container` holds. @param {Element} container */
export function replace_content(container, ...children) {
  container.replaceChildren(...list_nodes(children));
}

/** A titled block of a page. @param {string} title @returns {HTMLElement} */
export function build_panel(title, ...children) {
  return build_element("section", { class: "panel" }, build_element("h2", { text: title }), children);
}

/** A row of buttons. @returns {HTMLElement} */
export function build_actions(...children) {
  return build_element("div", { class: "actions" }, children);
}

/**
 * Label and value pairs, e.g. [["Next run", format_date(next)], ["State", build_badge("enabled")]].
 * @param {Array<[string, Node | string | number | null]>} pairs
 * @returns {HTMLElement}
 */
export function build_facts(pairs) {
  const cells = pairs.map(([label, value]) => [build_element("dt", { text: label }), build_element("dd", {}, show_value(value))]);
  return build_element("dl", { class: "facts" }, cells);
}

/**
 * A table of `rows`, or the empty state when there is none. A column: `{title, key}` shows `row[key]`;
 * `{title, show: (row) => Node | text}` builds the cell; `numeric: true` right-aligns it; `nowrap: true`
 * keeps it on one line (dates, ids).
 * @param {object[]} rows
 * @param {Array<{title: string, key?: string, show?: (row: object) => any, numeric?: boolean, nowrap?: boolean}>} columns
 * @param {{caption?: string, empty?: string}} [options]
 * @returns {HTMLElement}
 */
export function build_table(rows, columns, options = {}) {
  if (!rows || rows.length === 0) return build_empty(options.empty);
  const cell_class = (column) => [column.numeric && "numeric", column.nowrap && "nowrap"].filter(Boolean).join(" ") || null;
  const head = columns.map((column) => build_element("th", { scope: "col", class: cell_class(column), text: column.title }));
  const body = rows.map((row) =>
    build_element(
      "tr",
      {},
      columns.map((column) =>
        build_element("td", { class: cell_class(column) }, show_value(column.show ? column.show(row) : row[column.key])),
      ),
    ),
  );
  const table = build_element(
    "table",
    {},
    options.caption && build_element("caption", { text: options.caption }),
    build_element("thead", {}, build_element("tr", {}, head)),
    build_element("tbody", {}, body),
  );
  // A wide table scrolls inside its own box, by keyboard too, so a narrow window never scrolls the page sideways.
  return build_element("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": options.caption ?? "Table" }, table);
}

/**
 * A status as icon + text. The status word picks the look (done, failed, running, queued, cancelled, true,
 * false, …); an unknown word is shown plainly. `tone` forces one: good, bad, busy, wait, warn or idle.
 * @param {string | boolean | null} status
 * @param {string} [label] the text shown; default: the status word in plain words
 * @param {string} [tone]
 * @returns {HTMLElement}
 */
export function build_badge(status, label, tone) {
  const word = String(status ?? "unknown").toLowerCase();
  const by_word = Object.keys(BADGES).find((name) => BADGES[name].statuses.includes(word));
  const look = BADGES[tone] ? tone : (by_word ?? "idle");
  return build_element(
    "span",
    { class: `badge badge-${look}` },
    build_element("span", { class: "badge-icon", "aria-hidden": "true", text: BADGES[look].icon }),
    label ?? word.replaceAll("_", " "),
  );
}

/** The loading state. @param {string} [text] @returns {HTMLElement} */
export function build_loading(text = "Loading…") {
  return build_element("div", { class: "state state-loading", role: "status" }, build_element("span", { class: "spinner", "aria-hidden": "true" }), text);
}

/** The empty state. @param {string} [text] @returns {HTMLElement} */
export function build_empty(text = "Nothing to show yet.") {
  return build_element("div", { class: "state state-empty" }, text);
}

/**
 * The error state: the message, and a Retry button when `retry` is given.
 * @param {Error | string} error
 * @param {() => any} [retry]
 * @returns {HTMLElement}
 */
export function build_error(error, retry) {
  const message = build_element("p", { text: error?.message || String(error) });
  return build_element("div", { class: "state state-error", role: "alert" }, message, retry && build_button("Retry", retry));
}

/**
 * The whole read-and-show of a page or a part of it: the loading state, then `build(answer)`, or the error
 * state whose Retry runs it again. Never rejects. Keyboard focus that was inside `container` stays inside it:
 * on the control it was on, or the one built in its place (same tag and name), else on `container` itself.
 * A load of the same container started meanwhile wins: this one then shows nothing.
 * @param {Element} container
 * @param {() => Promise<any>} read
 * @param {(answer: any) => Node | string | Array} build
 * @returns {Promise<void>}
 */
export async function load_into(container, read, build) {
  // An unfinished load of this container already took the focus away: what it remembered is carried on.
  const focused = loads.get(container)?.focused ?? (container.contains(document.activeElement) ? document.activeElement : null);
  const load = { focused };
  loads.set(container, load);
  replace_content(container, build_loading());
  let content;
  try {
    content = build(await read());
  } catch (error) {
    content = build_error(error, () => load_into(container, read, build));
  }
  if (loads.get(container) !== load) return;
  loads.delete(container);
  replace_content(container, content);
  // Only when the rebuild dropped the focus (it then rests on <body>): never taken from where the reader moved it.
  if (focused && document.activeElement === document.body) return_focus(container, focused);
}

/**
 * A button that runs `action`: disabled and marked busy until it settles, so nothing is sent twice; an
 * error it throws is shown as a notice. `options.confirm` asks that question first (use it for anything
 * that deletes, revokes or cancels). To keep the button disabled for a whole job, return a promise that
 * settles when the job ends.
 * @param {string} label
 * @param {() => any} action
 * @param {{kind?: "primary" | "danger" | "quiet", confirm?: string, disabled?: boolean, title?: string}} [options]
 * @returns {HTMLButtonElement}
 */
export function build_button(label, action, options = {}) {
  const button = build_element("button", { type: "button", class: options.kind, text: label, disabled: options.disabled, title: options.title });
  button.addEventListener("click", async () => {
    const is_danger = options.kind === "danger";
    if (options.confirm && !(await ask_to_confirm(options.confirm, { confirm_label: label, danger: is_danger }))) return;
    await run_while_busy(button, action, (error) => show_notice(error?.message || String(error), "bad"));
  });
  return button;
}

/**
 * A form: its fields, one submit button and a place for its error. The browser checks the fields first;
 * the button is disabled while `action` runs; an error it throws is shown under the fields.
 * @param {Array<Node>} fields e.g. build_field(...) results
 * @param {string} submit_label
 * @param {() => any} action
 * @returns {HTMLFormElement}
 */
export function build_form(fields, submit_label, action) {
  const failure = build_element("p", { class: "form-error", role: "alert", hidden: true });
  const submit = build_element("button", { type: "submit", class: "primary", text: submit_label });
  const form = build_element("form", { class: "form" }, fields, failure, build_actions(submit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    failure.hidden = true;
    await run_while_busy(submit, action, (error) => {
      failure.textContent = error?.message || String(error);
      failure.hidden = false;
    });
  });
  return form;
}

/**
 * A label with its control, e.g. build_field("Time", build_element("input", {type: "time", required: true})).
 * A checkbox or radio gets its label on the right.
 * @param {string} label
 * @param {HTMLElement} control
 * @param {{hint?: string}} [options]
 * @returns {HTMLElement}
 */
export function build_field(label, control, options = {}) {
  fields_built += 1;
  control.id ||= `field-${fields_built}`;
  const caption = build_element("label", { for: control.id, text: label });
  const hint = options.hint && build_element("small", { id: `${control.id}-hint`, class: "hint", text: options.hint });
  if (hint) control.setAttribute("aria-describedby", hint.id);
  const is_tick = control.type === "checkbox" || control.type === "radio";
  return build_element("div", { class: is_tick ? "field field-tick" : "field" }, is_tick ? [control, caption] : [caption, control], hint);
}

/**
 * A select. A choice is a text (value and label) or `{value, label}`.
 * @param {Array<string | {value: string | number, label: string}>} choices
 * @param {string | number | null} [selected]
 * @param {Record<string, any>} [props] as build_element's
 * @returns {HTMLSelectElement}
 */
export function build_select(choices, selected, props = {}) {
  const options = choices.map((choice) => {
    const { value, label } = typeof choice === "object" ? choice : { value: choice, label: choice };
    return build_element("option", { value: String(value), text: label, selected: String(value) === String(selected ?? "") });
  });
  return build_element("select", props, options);
}

/**
 * Asks before something that cannot be undone. Resolves true only on the confirm button (Escape: false).
 * @param {string} question
 * @param {{confirm_label?: string, danger?: boolean}} [options]
 * @returns {Promise<boolean>}
 */
export function ask_to_confirm(question, options = {}) {
  return new Promise((resolve) => {
    const cancel = build_element("button", { type: "submit", value: "no", class: "quiet", text: "Cancel", autofocus: true });
    const confirm = build_element("button", {
      type: "submit",
      value: "yes",
      class: options.danger === false ? "primary" : "danger",
      text: options.confirm_label ?? "Confirm",
    });
    const form = build_element("form", { method: "dialog" }, build_element("p", { text: question }), build_actions(cancel, confirm));
    const dialog = build_element("dialog", { class: "confirm", "aria-label": "Please confirm" }, form);
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(dialog.returnValue === "yes");
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

/**
 * One message under the header, replacing the one before; the shell clears it when the page changes.
 * @param {string} message
 * @param {"good" | "bad" | "info"} [tone]
 */
export function show_notice(message, tone = "info") {
  const place = document.getElementById("notices");
  const notice = build_element("div", { class: `notice notice-${tone}` }, build_element("p", { text: message }));
  notice.append(build_element("button", { type: "button", class: "quiet", text: "Dismiss", on: { click: () => notice.remove() } }));
  replace_content(place, notice);
}

/** Removes the message show_notice put up. */
export function clear_notice() {
  replace_content(document.getElementById("notices"));
}

/**
 * A date and time in the browser's language: in the reader's own zone, or in `time_zone` (an IANA name,
 * then named after the time). A missing value is shown as a dash.
 * @param {string | Date | null} value an ISO date-time; one without a zone is read as UTC, as the API means it
 * @param {string} [time_zone]
 * @returns {string}
 */
export function format_date(value, time_zone) {
  if (value === null || value === undefined || value === "") return NONE;
  const date = new Date(typeof value === "string" && !HAS_ZONE.test(value) ? `${value}Z` : value);
  if (Number.isNaN(date.getTime())) return String(value);
  try {
    const shown = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: time_zone }).format(date);
    return time_zone ? `${shown} ${time_zone}` : shown;
  } catch {
    return date.toISOString(); // a zone name this browser does not know
  }
}

/** A whole number with the browser's digit grouping; a dash when missing. @param {number | null} value @returns {string} */
export function format_count(value) {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : NONE;
}

function list_nodes(children) {
  return children
    .flat(Infinity)
    .filter((child) => child !== null && child !== undefined && child !== false && child !== "")
    .map((child) => (child instanceof Node ? child : String(child)));
}

function show_value(value) {
  if (value === null || value === undefined || value === "") return NONE;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return value;
}

function set_link(element, link) {
  if (!SAFE_LINK.test(link) && !is_own_path(link)) return; // the text stays, without a link
  element.setAttribute("href", link);
  if (link.startsWith("https://")) {
    element.setAttribute("target", "_blank");
    element.setAttribute("rel", "noopener noreferrer");
  }
}

function return_focus(container, focused) {
  const read_name = (element) => element.getAttribute("aria-label") ?? element.textContent;
  const candidates = [focused, ...container.querySelectorAll(focused.tagName)];
  const same = candidates.find(
    (element) => container.contains(element) && !element.disabled && read_name(element) === read_name(focused),
  );
  if (same) return same.focus();
  if (!container.hasAttribute("tabindex")) container.setAttribute("tabindex", "-1");
  container.focus({ preventScroll: true }); // the reader stays where they were reading
}

async function run_while_busy(button, action, show_failure) {
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    await action();
  } catch (error) {
    show_failure(error);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}
