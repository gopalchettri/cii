// The admin UI's shell: the page table, hash routing (#/<page id>), the admin key bar.
//
// PAGE CONTRACT (every file in pages/ follows it exactly)
//
//   pages/<id>.js exports:   export async function show(container, tools) { ... }
//
//   - `container` is an empty <div> made for this visit; build everything inside it. The shell has already
//     written the page's <h1>, the navigation and the notice bar: a page writes none of them.
//   - A page with needs_admin_key: true is only shown once the key is set; while it is missing, or after the
//     API refuses it (401/403), the shell shows "enter the admin key" in the page's place and shows the page
//     again when a key is set. Such a page never asks for the key itself.
//   - If show() throws, the shell shows the error state with Retry. Prefer tools.load_into, which gives the
//     loading, error-with-Retry and loaded states in one call.
//   - No markup strings, no inline style, no browser storage, no other origin: build with the tools below and
//     style with the classes of styles.css (a page may add: columns, toolbar, muted, mono, nowrap, numeric).
//     Write every API path as ONE string or template literal (`/v1/admin/jobs/${job_id}/cancel`):
//     tests/test_admin_ui.py checks each one against the API's routes, and every file for what the page's
//     content policy forbids.
//   - Rows, names and states come from the API's answer; nothing about the data is written into a page.
//
//   `tools` holds:
//     request(method, path, body?)       -> Promise<parsed JSON | null>; rejects with an ApiError whose message is
//                                           ready to show; also .status, .code, .reason, .request_id, .details, .body
//     with_query(path, params)           -> path + "?name=value..." (arrays repeat the name, empty values left out)
//     follow_job(read, on_change)        -> stop(); reads now and every 3 s until done, failed or cancelled;
//                                           on_change(job, null) per change, on_change(null, error) when it gives
//                                           up; paused while the tab is hidden; stopped when the page is left
//     has_admin_key()                    -> boolean
//     when_leaving(cleanup)              -> runs cleanup() when this page is left (timers a page starts itself)
//     and every export of dom.js:
//       build_element(tag, props?, ...children)   build_panel(title, ...children)   build_actions(...children)
//       build_facts(pairs)   build_table(rows, columns, options?)   build_badge(status, label?, tone?)
//       build_loading(text?)   build_empty(text?)   build_error(error, retry?)   load_into(container, read, build)
//       build_button(label, action, options?)   build_form(fields, submit_label, action)
//       build_field(label, control, options?)   build_select(choices, selected?, props?)
//       ask_to_confirm(question, options?)   show_notice(message, tone?)   clear_notice()
//       replace_content(container, ...children)   format_date(value, time_zone?)   format_count(value)
//
//   Example:
//     export async function show(container, tools) {
//       await tools.load_into(container, () => tools.request("GET", "/v1/tsg/intel/health"), (health) =>
//         tools.build_panel("Sources", tools.build_table(health.sources, [{ title: "Source", key: "source" }])));
//     }

import * as api from "./api.js";
import * as dom from "./dom.js";
import { follow_job } from "./poll.js";

const PAGES = [
  { id: "ingestion", title: "Data ingestion", needs_admin_key: false, load: () => import("./pages/ingestion.js") },
  { id: "schedule", title: "Schedule", needs_admin_key: false, load: () => import("./pages/schedule.js") },
  { id: "control_links", title: "Control links", needs_admin_key: false, load: () => import("./pages/control_links.js") },
  { id: "jobs", title: "Jobs", needs_admin_key: true, load: () => import("./pages/jobs.js") },
  { id: "vectors", title: "Search vectors", needs_admin_key: true, load: () => import("./pages/vectors.js") },
  { id: "api_keys", title: "API keys", needs_admin_key: true, load: () => import("./pages/api_keys.js") },
  { id: "curation", title: "Library curation", needs_admin_key: true, load: () => import("./pages/curation.js") },
  { id: "ai_usage", title: "AI usage", needs_admin_key: false, load: () => import("./pages/ai_usage.js") },
  { id: "system", title: "System", needs_admin_key: false, load: () => import("./pages/system.js") },
];
const SITE_TITLE = "CII admin";

const main = document.getElementById("main");
const page_title = document.getElementById("page-title");
const page_place = document.getElementById("page");
const nav = document.getElementById("nav");
const key_input = document.getElementById("admin-key");
/** The page on screen: its id, its cleanups, and whether it was left (a late answer of a left page is dropped). */
let visit = { id: null, cleanups: [], is_over: false };

/** The page id of a "#/<id>" address; no address: the first page; any other fragment ("#main"): not a page, null. */
function read_page_id() {
  if (location.hash.startsWith("#/")) return location.hash.slice(2) || PAGES[0].id;
  return location.hash.length > 1 ? null : PAGES[0].id;
}

function build_tools(this_visit) {
  const when_leaving = (cleanup) => {
    if (this_visit.is_over) cleanup();
    else this_visit.cleanups.push(cleanup);
  };
  return {
    ...dom,
    request: api.request,
    with_query: api.with_query,
    has_admin_key: api.has_admin_key,
    when_leaving,
    follow_job: (read, on_change) => {
      const stop = follow_job(read, on_change);
      when_leaving(stop);
      return stop;
    },
  };
}

function build_state(kind, text, ...more) {
  return dom.build_element("div", { class: `state state-${kind}` }, dom.build_element("p", { text }), more);
}

async function show_page() {
  visit.is_over = true;
  visit.cleanups.forEach((cleanup) => cleanup());
  const id = read_page_id() ?? visit.id ?? PAGES[0].id;
  const this_visit = (visit = { id, cleanups: [], is_over: false });
  const page = PAGES.find((candidate) => candidate.id === id);
  for (const link of nav.querySelectorAll("a")) {
    if (link.dataset.page === id) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  page_title.textContent = page ? page.title : "Page not found";
  document.title = page ? `${page.title} · ${SITE_TITLE}` : SITE_TITLE;
  const container = dom.build_element("div", { class: "page" });
  dom.replace_content(page_place, container);
  if (!page) {
    const home = dom.build_element("a", { href: `#/${PAGES[0].id}`, text: `Go to ${PAGES[0].title}` });
    dom.replace_content(container, build_state("empty", `There is no page "${id}".`, home));
    return;
  }
  if (page.needs_admin_key && !api.has_admin_key()) {
    const ask = "This page needs the admin key. Enter it in the bar at the top and press Set key.";
    dom.replace_content(container, build_state("locked", ask));
    return;
  }
  dom.replace_content(container, dom.build_loading());
  const module = await page.load().catch(() => null);
  if (this_visit.is_over) return;
  if (typeof module?.show !== "function") {
    const why = `${page.title} is not available: its file pages/${page.id}.js could not be loaded.`;
    dom.replace_content(container, build_state("empty", why, dom.build_button("Retry", show_page)));
    return;
  }
  dom.replace_content(container);
  try {
    await module.show(container, build_tools(this_visit));
  } catch (error) {
    if (!this_visit.is_over) dom.replace_content(container, dom.build_error(error, show_page));
  }
}

function show_key_state(has_key) {
  const state = dom.build_badge(has_key, has_key ? "Admin key set" : "No admin key", has_key ? "good" : "idle");
  dom.replace_content(document.getElementById("key-state"), state);
  document.getElementById("clear-key").hidden = !has_key;
  key_input.placeholder = has_key ? "Set for this tab" : "Not set";
}

function start() {
  for (const page of PAGES) {
    nav.append(dom.build_element("a", { href: `#/${page.id}`, "data-page": page.id, text: page.title }));
  }
  document.getElementById("access").addEventListener("submit", (event) => {
    event.preventDefault();
    if (api.set_admin_key(key_input.value)) key_input.value = "";
    else dom.show_notice("Type the admin key first (plain characters, no line breaks).", "bad");
  });
  document.getElementById("clear-key").addEventListener("click", () => api.clear_admin_key());
  document.getElementById("user-id").addEventListener("change", (event) => {
    if (!api.set_user_id(event.target.value)) dom.show_notice("The name can hold plain letters, digits and punctuation only.", "bad");
  });
  api.watch_admin_key((has_key, refusal) => {
    show_key_state(has_key);
    // A page behind the key appears when it is set and gives way to the "enter the key" state when it goes.
    if (PAGES.find((page) => page.id === visit.id)?.needs_admin_key) show_page();
    // The API's own words: a wrong key and "admin endpoints are disabled" are both a refusal.
    if (refusal) dom.show_notice(`${refusal} The admin key was cleared.`, "bad");
  });
  window.addEventListener("hashchange", () => {
    // A fragment that is no page (the skip link's "#main"), or the way back from one, leaves the page as it is.
    if ((read_page_id() ?? visit.id) === visit.id) return;
    dom.clear_notice();
    show_page();
    main.focus();
  });
  show_key_state(false);
  show_page();
}

start();
