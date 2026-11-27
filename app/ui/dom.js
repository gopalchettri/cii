// The builders every page uses, so no page writes its own markup, states or dialogs.
// Whatever the API answers is put on the page as text; it is never parsed as markup.

import { is_own_path } from "./api.js";

const NONE = "—"; // shown for a missing value
const SAFE_LINK = /^(#|\.\/|https:\/\/)/; // this page, a file beside it, or an https site; a "/…" link: is_own_path
const HAS_ZONE = /(Z|[+-]\d\d:?\d\d)$/i;
const TOAST_SECONDS = 6;
/** A badge's look by status word: an icon and a tone, so state never rests on colour alone. */
const BADGES = {
  good: { icon: "✓", statuses: ["done", "ok", "ready", "valid", "active", "enabled", "on", "approved", "accepted", "linked", "true", "complete", "completed", "implemented", "matched", "exact", "retained", "live"] },
  bad: { icon: "✕", statuses: ["failed", "error", "not_ready", "revoked", "rejected", "down", "false", "not_implemented", "ended"] },
  busy: { icon: "↻", statuses: ["running", "in_progress", "generating", "writing", "mapping", "planning", "connecting"] },
  wait: { icon: "…", statuses: ["queued", "pending", "waiting", "retrying", "to_review", "awaiting_review", "proposed", "pending_review"] },
  warn: { icon: "!", statuses: ["warning", "degraded", "partially_implemented", "nearest", "flagged_for_review", "replaced", "gaps"] },
  idle: { icon: "–", statuses: ["cancelled", "disabled", "off", "inactive", "never_run", "unknown", "none", "not_started"] },
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

/**
 * A titled block with a line under the title and buttons on the right of it.
 * @param {{title: string, subtitle?: string, actions?: Array<Node>, class?: string}} head
 * @returns {HTMLElement}
 */
export function build_section(head, ...children) {
  const heading = build_element(
    "div",
    { class: "panel-head" },
    build_element("div", {}, build_element("h2", { text: head.title }), head.subtitle && build_element("p", { class: "muted", text: head.subtitle })),
    head.actions?.length ? build_actions(...head.actions) : null,
  );
  return build_element("section", { class: ["panel", head.class].filter(Boolean).join(" ") }, heading, children);
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
    label ?? capitalise(word.replaceAll("_", " ")),
  );
}

/** A small label: a technique, a system, a group. `href` makes it a link. @returns {HTMLElement} */
export function build_tag(text, href, title) {
  if (href) return build_element("a", { class: "tag", href, title, text });
  return build_element("span", { class: "tag", title, text });
}

/** A link. @returns {HTMLAnchorElement} */
export function build_link(text, href, props = {}) {
  return build_element("a", { ...props, href, text });
}

/**
 * A boxed message inside a page: info, good, warn or bad.
 * @param {string | Node} message
 * @param {"info" | "good" | "warn" | "bad"} [tone]
 * @returns {HTMLElement}
 */
export function build_callout(message, tone = "info", ...more) {
  return build_element("div", { class: `callout callout-${tone}`, role: tone === "bad" ? "alert" : null }, message, more);
}

/**
 * Number tiles: [{label, value, hint?, tone?}].
 * @returns {HTMLElement}
 */
export function build_kpis(items) {
  return build_element(
    "div",
    { class: "kpis" },
    items.map((item) =>
      build_element(
        "div",
        { class: ["kpi", item.tone && `kpi-${item.tone}`].filter(Boolean).join(" ") },
        build_element("span", { class: "kpi-label", text: item.label }),
        item.value instanceof Node
          ? build_element("strong", { class: "kpi-value" }, item.value)
          : build_element("strong", { class: "kpi-value", text: typeof item.value === "number" ? format_count(item.value) : show_value(item.value) }),
        item.hint && build_element("small", { class: "muted", text: item.hint }),
      ),
    ),
  );
}

/**
 * A progress line made of parts, with a legend: [{label, value, tone}] out of `total`.
 * @returns {HTMLElement}
 */
export function build_meter(parts, total) {
  const whole = Math.max(total ?? parts.reduce((sum, part) => sum + (part.value || 0), 0), 1);
  const bar = build_element(
    "div",
    { class: "meter", role: "img", "aria-label": parts.map((part) => `${part.label}: ${part.value}`).join(", ") },
    parts
      .filter((part) => part.value > 0)
      .map((part) => {
        const share = Math.round((100 * part.value) / whole);
        return build_element("span", { class: `meter-part meter-${part.tone} w-${Math.min(100, Math.max(1, share))}` });
      }),
  );
  const legend = build_element(
    "ul",
    { class: "meter-legend" },
    parts.map((part) => build_element("li", {}, build_element("span", { class: `dot dot-${part.tone}`, "aria-hidden": "true" }), `${part.label} ${format_count(part.value)}`)),
  );
  return build_element("div", { class: "meter-wrap" }, bar, legend);
}

/**
 * A row of steps: [{label, state: "done" | "running" | "waiting" | "error" | "idle", detail?}].
 * @returns {HTMLElement}
 */
export function build_stepper(steps) {
  const icons = { done: "✓", running: "↻", waiting: "…", error: "✕", idle: "" };
  return build_element(
    "ol",
    { class: "stepper" },
    steps.map((step, index) =>
      build_element(
        "li",
        { class: `step step-${step.state}`, "aria-current": step.state === "running" ? "step" : null },
        build_element("span", { class: "step-mark", "aria-hidden": "true", text: icons[step.state] || String(index + 1) }),
        build_element(
          "span",
          { class: "step-text" },
          build_element("strong", { text: step.label }),
          build_element("small", { text: step.detail || STEP_WORDS[step.state] || "" }),
        ),
      ),
    ),
  );
}
const STEP_WORDS = { done: "Done", running: "In progress", waiting: "Waiting", error: "Needs attention", idle: "Not started" };

/**
 * A card: title, badges on the right, body, and a footer of buttons.
 * @param {{title: string | Node, subtitle?: string, badges?: Node[], body?: Array<Node | string>, footer?: Node[], tone?: string, class?: string}} card
 * @returns {HTMLElement}
 */
export function build_card(card) {
  return build_element(
    "article",
    { class: ["card", card.tone && `card-${card.tone}`, card.class].filter(Boolean).join(" ") },
    build_element(
      "header",
      { class: "card-head" },
      build_element("div", { class: "card-title" }, typeof card.title === "string" ? build_element("h3", { text: card.title }) : card.title, card.subtitle && build_element("p", { class: "muted", text: card.subtitle })),
      card.badges?.length ? build_element("div", { class: "card-badges" }, card.badges) : null,
    ),
    card.body?.length ? build_element("div", { class: "card-body" }, card.body) : null,
    card.footer?.length ? build_element("footer", { class: "card-foot" }, card.footer) : null,
  );
}

/**
 * A text that may be long: shown cut to `lines` lines with a "Show more" button.
 * @returns {HTMLElement}
 */
export function build_long_text(text, lines = 4) {
  if (!text) return build_element("p", { class: "muted", text: NONE });
  const body = build_element("p", { class: `clamp clamp-${lines}`, text });
  const toggle = build_element("button", { type: "button", class: "link-button", text: "Show more", "aria-expanded": "false" });
  toggle.addEventListener("click", () => {
    const open = body.classList.toggle("clamp-open");
    toggle.textContent = open ? "Show less" : "Show more";
    toggle.setAttribute("aria-expanded", String(open));
  });
  return build_element("div", { class: "long-text" }, body, text.length > lines * 90 ? toggle : null);
}

/**
 * A row of filter choices; one is pressed. choices: [{value, label, count?}].
 * @param {(value: string) => void} on_change
 * @returns {HTMLElement}
 */
export function build_chips(choices, selected, on_change, label = "Filter") {
  const group = build_element("div", { class: "chips", role: "group", "aria-label": label });
  for (const choice of choices) {
    const pressed = String(choice.value) === String(selected);
    const chip = build_element(
      "button",
      { type: "button", class: "chip", "aria-pressed": String(pressed) },
      choice.label,
      choice.count !== undefined && build_element("span", { class: "chip-count", text: format_count(choice.count) }),
    );
    chip.addEventListener("click", () => {
      for (const other of group.querySelectorAll(".chip")) other.setAttribute("aria-pressed", String(other === chip));
      on_change(choice.value);
    });
    group.append(chip);
  }
  return group;
}

/**
 * Tabs: [{label, build: () => Node | Array}]; the first is shown. Arrow keys move between tabs.
 * @returns {HTMLElement}
 */
export function build_tabs(tabs, label = "Sections") {
  fields_built += 1;
  const base = `tabs-${fields_built}`;
  const list = build_element("div", { class: "tab-list", role: "tablist", "aria-label": label });
  const panel = build_element("div", { class: "tab-panel", role: "tabpanel", tabindex: "0" });
  const buttons = tabs.map((tab, index) =>
    build_element("button", { type: "button", role: "tab", id: `${base}-${index}`, "aria-selected": "false", tabindex: "-1", text: tab.label }),
  );
  function select(index) {
    buttons.forEach((button, other) => {
      button.setAttribute("aria-selected", String(other === index));
      button.tabIndex = other === index ? 0 : -1;
    });
    panel.setAttribute("aria-labelledby", buttons[index].id);
    replace_content(panel, tabs[index].build());
  }
  buttons.forEach((button, index) => {
    button.addEventListener("click", () => select(index));
    button.addEventListener("keydown", (event) => {
      const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
      if (!step) return;
      const next = (index + step + buttons.length) % buttons.length;
      buttons[next].focus();
      select(next);
    });
  });
  list.append(...buttons);
  if (tabs.length) select(0);
  return build_element("div", { class: "tabs" }, list, panel);
}

/**
 * Previous / next for a paged list. on_change(new_offset).
 * @param {{offset: number, limit: number, total: number, on_change: (offset: number) => void}} paging
 * @returns {HTMLElement}
 */
export function build_pager({ offset, limit, total, on_change }) {
  const first = total === 0 ? 0 : offset + 1;
  const last = Math.min(offset + limit, total);
  return build_element(
    "nav",
    { class: "pager", "aria-label": "Pages" },
    build_element("span", { class: "muted", text: total ? `${format_count(first)}–${format_count(last)} of ${format_count(total)}` : "No rows" }),
    build_actions(
      build_button("Previous", () => on_change(Math.max(0, offset - limit)), { kind: "quiet", disabled: offset === 0 }),
      build_button("Next", () => on_change(offset + limit), { kind: "quiet", disabled: offset + limit >= total }),
    ),
  );
}

/** A button that copies `text`, then says "Copied". @returns {HTMLButtonElement} */
export function build_copy(text, label = "Copy") {
  const button = build_element("button", { type: "button", class: "quiet small", text: label, title: "Copy to the clipboard" });
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => (button.textContent = label), 1500);
  });
  return button;
}

/** An id shown in mono with its copy button. @returns {HTMLElement} */
export function build_id(text) {
  if (!text) return build_element("span", { class: "muted", text: NONE });
  return build_element("span", { class: "id" }, build_element("code", { class: "mono", text }), build_copy(text));
}

/**
 * A panel sliding in from the right, over the page, for one item's details. Escape or Close shuts it; the
 * focus goes back where it was. @returns {() => void} close
 */
export function open_drawer(title, ...children) {
  const opener = document.activeElement;
  const close_button = build_element("button", { type: "button", class: "quiet", text: "Close", "aria-label": "Close details" });
  const dialog = build_element(
    "dialog",
    { class: "drawer", "aria-label": typeof title === "string" ? title : "Details" },
    build_element("header", { class: "drawer-head" }, build_element("h2", { text: title }), close_button),
    build_element("div", { class: "drawer-body" }, children),
  );
  const close = () => dialog.open && dialog.close();
  close_button.addEventListener("click", close);
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) close(); // a click on the dimmed backdrop
  });
  dialog.addEventListener("close", () => {
    dialog.remove();
    if (opener && typeof opener.focus === "function") opener.focus();
  });
  document.body.append(dialog);
  dialog.showModal();
  return close;
}

/** The loading state. @param {string} [text] @returns {HTMLElement} */
export function build_loading(text = "Loading…") {
  return build_element("div", { class: "state state-loading", role: "status" }, build_element("span", { class: "spinner", "aria-hidden": "true" }), text);
}

/** The empty state. @param {string} [text] @returns {HTMLElement} */
export function build_empty(text = "Nothing to show yet.", ...more) {
  return build_element("div", { class: "state state-empty" }, build_element("p", { text }), more);
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
 * `options.quiet`: no loading state (a refresh keeps the old content until the new one is ready).
 * @param {Element} container
 * @param {() => Promise<any>} read
 * @param {(answer: any) => Node | string | Array} build
 * @param {{quiet?: boolean}} [options]
 * @returns {Promise<void>}
 */
export async function load_into(container, read, build, options = {}) {
  // An unfinished load of this container already took the focus away: what it remembered is carried on.
  const focused = loads.get(container)?.focused ?? (container.contains(document.activeElement) ? document.activeElement : null);
  const load = { focused };
  loads.set(container, load);
  if (!options.quiet || !container.firstChild) replace_content(container, build_loading());
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
 * @param {{kind?: "primary" | "danger" | "quiet" | "ghost", small?: boolean, confirm?: string, disabled?: boolean, title?: string}} [options]
 * @returns {HTMLButtonElement}
 */
export function build_button(label, action, options = {}) {
  const kind = [options.kind, options.small && "small"].filter(Boolean).join(" ") || null;
  const button = build_element("button", { type: "button", class: kind, text: label, disabled: options.disabled, title: options.title });
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
 * @param {{extra?: Array<Node>}} [options] more buttons beside the submit
 * @returns {HTMLFormElement}
 */
export function build_form(fields, submit_label, action, options = {}) {
  const failure = build_element("p", { class: "form-error", role: "alert", hidden: true });
  const submit = build_element("button", { type: "submit", class: "primary", text: submit_label });
  const form = build_element("form", { class: "form" }, fields, failure, build_actions(submit, options.extra ?? []));
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
 * A checkbox or radio gets its label on the right. `options.optional` adds "(optional)".
 * @param {string} label
 * @param {HTMLElement} control
 * @param {{hint?: string, optional?: boolean, wide?: boolean}} [options]
 * @returns {HTMLElement}
 */
export function build_field(label, control, options = {}) {
  fields_built += 1;
  control.id ||= `field-${fields_built}`;
  const caption = build_element("label", { for: control.id }, label, options.optional && build_element("span", { class: "optional", text: " (optional)" }));
  const hint = options.hint && build_element("small", { id: `${control.id}-hint`, class: "hint", text: options.hint });
  if (hint) control.setAttribute("aria-describedby", hint.id);
  const is_tick = control.type === "checkbox" || control.type === "radio";
  const classes = ["field", is_tick && "field-tick", options.wide && "field-wide"].filter(Boolean).join(" ");
  return build_element("div", { class: classes }, is_tick ? [control, caption] : [caption, control], hint);
}

/** Fields side by side (one column on a phone). @returns {HTMLElement} */
export function build_row(...fields) {
  return build_element("div", { class: "field-row" }, fields);
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
 * `options.input`: a text box (e.g. a comment); then resolves {ok, text}.
 * @param {string} question
 * @param {{confirm_label?: string, danger?: boolean, input?: {label: string, required?: boolean}}} [options]
 * @returns {Promise<boolean | {ok: boolean, text: string}>}
 */
export function ask_to_confirm(question, options = {}) {
  return new Promise((resolve) => {
    const cancel = build_element("button", { type: "submit", value: "no", class: "quiet", text: "Cancel", formnovalidate: true, autofocus: !options.input });
    const confirm = build_element("button", {
      type: "submit",
      value: "yes",
      class: options.danger === false ? "primary" : "danger",
      text: options.confirm_label ?? "Confirm",
    });
    const box = options.input && build_element("textarea", { rows: 3, required: options.input.required, autofocus: true });
    const form = build_element(
      "form",
      { method: "dialog" },
      build_element("p", { text: question }),
      box && build_field(options.input.label, box),
      build_actions(cancel, confirm),
    );
    const dialog = build_element("dialog", { class: "confirm", "aria-label": "Please confirm" }, form);
    dialog.addEventListener("close", () => {
      dialog.remove();
      const ok = dialog.returnValue === "yes";
      resolve(options.input ? { ok, text: box.value.trim() } : ok);
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

/**
 * A toast in the corner, replacing none of the others; it goes after TOAST_SECONDS (an error stays until
 * dismissed). The shell clears them when the page changes.
 * @param {string} message
 * @param {"good" | "bad" | "info" | "warn"} [tone]
 */
export function show_notice(message, tone = "info") {
  const place = document.getElementById("notices");
  if (!place) return;
  const notice = build_element(
    "div",
    { class: `notice notice-${tone}`, role: tone === "bad" ? "alert" : "status" },
    build_element("span", { class: "notice-icon", "aria-hidden": "true", text: { good: "✓", bad: "✕", warn: "!", info: "i" }[tone] ?? "i" }),
    build_element("p", { text: message }),
  );
  notice.append(build_element("button", { type: "button", class: "quiet small", text: "Dismiss", on: { click: () => notice.remove() } }));
  place.append(notice);
  while (place.childElementCount > 4) place.firstElementChild.remove();
  if (tone !== "bad") setTimeout(() => notice.remove(), TOAST_SECONDS * 1000);
}

/** The same as show_notice. */
export const show_toast = show_notice;

/** Removes every toast. */
export function clear_notice() {
  const place = document.getElementById("notices");
  if (place) replace_content(place);
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
  const date = new Date(typeof value === "string" && !HAS_ZONE.test(value) && value.includes("T") ? `${value}Z` : value);
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

/** Seconds as "45 s", "3 min 20 s", "1 h 5 min"; a dash when missing. */
export function format_seconds(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return NONE;
  const seconds = Math.round(value);
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
  return `${Math.floor(seconds / 3600)} h ${Math.floor((seconds % 3600) / 60)} min`;
}

/** "risk_level" → "Risk level". */
export function humanise(word) {
  return capitalise(String(word ?? "").replaceAll("_", " ").trim()) || NONE;
}

function capitalise(text) {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
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
