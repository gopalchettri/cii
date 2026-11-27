// The UI's shell: sign-in, the menu, the page table, hash routing (#/<page id>/<param>/<param>), the admin key.
//
// PAGE CONTRACT (every file in pages/ follows it exactly)
//
//   pages/<id>.js exports:   export async function show(container, tools) { ... }
//
//   - `container` is an empty <div> made for this visit; build everything inside it. The shell has already
//     written the page's <h1>, the menu and the toast area: a page writes none of them. A page may add a line
//     under the title (tools.set_subtitle) and buttons on the title's right (tools.set_actions).
//   - access "client": shown only to a signed-in person (the shell shows the sign-in screen otherwise); its
//     calls use tools.call(), which sends the person's four headers.
//     access "admin": shown only once the admin key is set (the shell asks for it in the page's place); its calls
//     use tools.request(), which sends the admin key. access "open": anyone; tools.request().
//   - If show() throws, the shell shows the error state with Retry. Prefer tools.load_into, which gives the
//     loading, error-with-Retry and loaded states in one call.
//   - No markup strings, no inline style, no browser storage, no other origin: build with the tools below and
//     style with the classes of styles.css. Write every API path as ONE string or template literal
//     (`/v1/sessions/${id}/results`): tests/test_admin_ui.py checks each one against the API's routes, and every
//     file for what the page's content policy forbids.
//   - Plain words for the person: no route names, stage numbers or reason codes on the page.
//
//   `tools` holds:
//     params                             -> the address's parts after the page id: "#/run/abc" gives ["abc"]
//     go(page_id, ...params)             -> opens another page ("#/run/abc")
//     call(method, path, body?, {idempotent?, with_status?}) -> a client call with the signed-in person's headers;
//                                           idempotent: true sends a new Idempotency-Key, a string that key;
//                                           with_status: resolves {status, body} (200 on a start: a replay)
//     start_key()                        -> {for_content(path, body)}: one key per content, for a form's start
//                                           (a retry of the same start is replayed, never started twice)
//     request(method, path, body?)       -> an admin or open call (the admin key when set)
//     with_query(path, params)           -> path + "?name=value..." (arrays repeat the name, empty values left out)
//     follow_job(read, on_change)        -> stop(); reads now and every 3 s until done, failed or cancelled
//     follow_stream(path, {on_event, on_state}) -> stop(); live events of a client stream (stream.js)
//     every(seconds, action)             -> runs action() every `seconds` while the page is shown and the tab visible
//     when_leaving(cleanup)              -> runs cleanup() when this page is left
//     set_subtitle(text), set_actions(...nodes)
//     identity()                         -> {user_id, entity_id, tenant_id, api_key} | null
//     remember_run({kind, id, label}), recent_runs()   -> the runs opened in this tab
//     download_word(file_name, title, blocks), print_page()   (export.js)
//     has_admin_key()
//     and every export of dom.js (build_element, build_section, build_card, build_table, build_badge, ...).

import * as api from "./api.js";
import * as dom from "./dom.js";
import * as exporting from "./export.js";
import { follow_job } from "./poll.js";
import * as session from "./session.js";
import { follow_stream } from "./stream.js";

const GROUPS = ["Overview", "Threat scenarios", "Treatment plans", "Services", "Administration"];
const PAGES = [
  { id: "home", title: "Home", group: "Overview", access: "client", nav: true, load: () => import("./pages/home.js") },
  { id: "new_run", title: "New run", group: "Threat scenarios", access: "client", nav: true, load: () => import("./pages/new_run.js") },
  { id: "runs", title: "Runs", group: "Threat scenarios", access: "client", nav: true, load: () => import("./pages/runs.js") },
  { id: "mitre_run", title: "MITRE ATT&CK run", group: "Threat scenarios", access: "client", nav: false, load: () => import("./pages/mitre_run.js") },
  { id: "run", title: "Threat scenario run", group: "Threat scenarios", access: "client", nav: false, load: () => import("./pages/run.js") },
  { id: "plans", title: "Treatment plans", group: "Treatment plans", access: "client", nav: true, load: () => import("./pages/plans.js") },
  { id: "plan", title: "Treatment plan", group: "Treatment plans", access: "client", nav: false, load: () => import("./pages/plan.js") },
  { id: "manual_plan", title: "Manual scenario", group: "Treatment plans", access: "client", nav: true, load: () => import("./pages/manual_plan.js") },
  { id: "service_mapper", title: "Service mapper", group: "Services", access: "client", nav: true, load: () => import("./pages/service_mapper.js") },
  { id: "system", title: "System health", group: "Administration", access: "open", nav: true, load: () => import("./pages/system.js") },
  { id: "jobs", title: "Jobs", group: "Administration", access: "admin", nav: true, load: () => import("./pages/jobs.js") },
  { id: "api_keys", title: "API keys", group: "Administration", access: "admin", nav: true, load: () => import("./pages/api_keys.js") },
  { id: "curation", title: "Library curation", group: "Administration", access: "admin", nav: true, load: () => import("./pages/curation.js") },
  { id: "vectors", title: "Search vectors", group: "Administration", access: "admin", nav: true, load: () => import("./pages/vectors.js") },
  { id: "ingestion", title: "Data ingestion", group: "Administration", access: "open", nav: true, load: () => import("./pages/ingestion.js") },
  { id: "schedule", title: "Ingestion schedule", group: "Administration", access: "open", nav: true, load: () => import("./pages/schedule.js") },
  { id: "control_links", title: "Control links", group: "Administration", access: "open", nav: true, load: () => import("./pages/control_links.js") },
  { id: "ai_usage", title: "AI usage", group: "Administration", access: "open", nav: true, load: () => import("./pages/ai_usage.js") },
];
const SITE_TITLE = "Threat Scenario Generator";
const HOME = "home";
const ADMIN_HOME = "system";

const app_root = document.getElementById("app");
const main = document.getElementById("main");
const page_title = document.getElementById("page-title");
const page_subtitle = document.getElementById("page-subtitle");
const page_actions = document.getElementById("page-actions");
const page_place = document.getElementById("page");
const nav = document.getElementById("nav");
const account = document.getElementById("account");
const menu_button = document.getElementById("menu-button");
/** The page on screen: its address, its cleanups, and whether it was left (a late answer of a left page is dropped). */
let visit = { address: null, cleanups: [], is_over: false };
/** Why the person was signed out (the API refused the key), shown once on the sign-in screen. */
let sign_out_reason = null;

/** The page id and params of a "#/<id>/<param>..." address; no address: home; another fragment ("#main"): null. */
export function read_address(hash = location.hash) {
  if (hash.startsWith("#/")) {
    const [id, ...params] = hash.slice(2).split("/").map((part) => decodeURIComponent(part));
    return { id: id || HOME, params: params.filter(Boolean) };
  }
  return hash.length > 1 ? null : { id: HOME, params: [] };
}

/** "#/run/abc" for ("run", "abc"). */
export function address_of(id, ...params) {
  return `#/${[id, ...params.map((param) => encodeURIComponent(String(param)))].join("/")}`;
}

function build_tools(this_visit, params) {
  const when_leaving = (cleanup) => {
    if (this_visit.is_over) cleanup();
    else this_visit.cleanups.push(cleanup);
  };
  return {
    ...dom,
    params,
    go: (id, ...more) => (location.hash = address_of(id, ...more)),
    call: api.call,
    start_key: api.make_start_key,
    request: api.request,
    with_query: api.with_query,
    has_admin_key: api.has_admin_key,
    identity: session.identity,
    remember_run: session.remember_run,
    recent_runs: session.recent_runs,
    download_word: exporting.download_word,
    print_page: exporting.print_page,
    when_leaving,
    set_subtitle: (text) => {
      if (this_visit.is_over) return;
      page_subtitle.textContent = text || "";
      page_subtitle.hidden = !text;
    },
    set_actions: (...nodes) => {
      if (!this_visit.is_over) dom.replace_content(page_actions, ...nodes);
    },
    follow_job: (read, on_change) => {
      const stop = follow_job(read, on_change);
      when_leaving(stop);
      return stop;
    },
    follow_stream: (path, handlers) => {
      const stop = follow_stream(path, handlers);
      when_leaving(stop);
      return stop;
    },
    every: (seconds, action) => {
      const tick = () => {
        if (!document.hidden && !this_visit.is_over) action();
      };
      const timer = setInterval(tick, seconds * 1000);
      when_leaving(() => clearInterval(timer));
    },
  };
}

function build_state(kind, text, ...more) {
  return dom.build_element("div", { class: `state state-${kind}` }, dom.build_element("p", { text }), more);
}

async function show_page() {
  visit.is_over = true;
  visit.cleanups.forEach((cleanup) => cleanup());
  const address = read_address() ?? visit.address ?? { id: HOME, params: [] };
  const this_visit = (visit = { address, cleanups: [], is_over: false });
  const page = PAGES.find((candidate) => candidate.id === address.id);
  set_menu_open(false);
  dom.replace_content(page_actions);
  page_subtitle.hidden = true;
  const signed_in = session.is_signed_in();
  app_root.classList.toggle("is-signed-out", !signed_in && page?.access === "client");
  build_nav(page);
  build_account();
  page_title.textContent = page ? page.title : "Page not found";
  document.title = page ? `${page.title} · ${SITE_TITLE}` : SITE_TITLE;
  const container = dom.build_element("div", { class: "page" });
  dom.replace_content(page_place, container);
  if (!page) {
    const home = dom.build_link("Go to the home page", address_of(signed_in ? HOME : ADMIN_HOME));
    dom.replace_content(container, build_state("empty", `There is no page "${address.id}".`, home));
    return;
  }
  if (page.access === "client" && !signed_in) {
    page_title.textContent = "Sign in";
    document.title = `Sign in · ${SITE_TITLE}`;
    dom.replace_content(container, build_sign_in(sign_out_reason));
    sign_out_reason = null;
    return;
  }
  if (page.access === "admin" && !api.has_admin_key()) {
    dom.replace_content(container, build_admin_key_form());
    return;
  }
  dom.replace_content(container, dom.build_loading());
  const module = await page.load().catch(() => null);
  if (this_visit.is_over) return;
  if (typeof module?.show !== "function") {
    const why = `${page.title} could not be opened. Reload the page; if it stays, tell your administrator.`;
    dom.replace_content(container, build_state("empty", why, dom.build_button("Retry", show_page)));
    return;
  }
  dom.replace_content(container);
  try {
    await module.show(container, build_tools(this_visit, address.params));
  } catch (error) {
    if (!this_visit.is_over) dom.replace_content(container, dom.build_error(error, show_page));
  }
}

function build_nav(current) {
  const signed_in = session.is_signed_in();
  const groups = GROUPS.filter((group) => signed_in || group === "Administration").map((group) => {
    const links = PAGES.filter((page) => page.group === group && page.nav).map((page) => {
      const is_here = current && (current.id === page.id || (!current.nav && current.group === page.group && page.id === nav_parent(current)));
      return dom.build_element(
        "a",
        { href: address_of(page.id), class: "nav-link", "aria-current": is_here ? "page" : null },
        dom.build_element("span", { class: `nav-icon icon-${page.id}`, "aria-hidden": "true" }),
        page.title,
        page.access === "admin" && !api.has_admin_key() ? dom.build_element("span", { class: "nav-lock", title: "Needs the admin key", text: "key" }) : null,
      );
    });
    return dom.build_element("div", { class: "nav-group" }, dom.build_element("p", { class: "nav-heading", text: group }), links);
  });
  if (!signed_in) {
    groups.unshift(dom.build_element("div", { class: "nav-group" }, dom.build_link("Sign in", address_of(HOME), { class: "nav-link" })));
  }
  dom.replace_content(nav, groups);
}

/** The menu entry a page that is not in the menu belongs under (a run under Runs, a plan under the register). */
function nav_parent(page) {
  return { run: "runs", mitre_run: "runs", plan: "plans" }[page.id] ?? null;
}

function build_account() {
  const who = session.identity();
  const parts = [];
  if (api.has_admin_key()) {
    parts.push(dom.build_badge("good", "Admin key set", "good"), dom.build_button("Forget admin key", () => api.clear_admin_key(), { kind: "quiet", small: true }));
  }
  if (who) {
    parts.push(
      dom.build_element(
        "span",
        { class: "who" },
        dom.build_element("span", { class: "avatar", "aria-hidden": "true", text: who.user_id.slice(0, 1).toUpperCase() }),
        dom.build_element("span", { class: "who-text" }, dom.build_element("strong", { text: who.user_id }), dom.build_element("small", { text: `Entity ${who.entity_id} · Tenant ${who.tenant_id}` })),
      ),
      dom.build_button("Sign out", () => session.sign_out(), { kind: "quiet", small: true }),
    );
  } else {
    parts.push(dom.build_link("Sign in", address_of(HOME), { class: "button primary small" }));
  }
  dom.replace_content(account, parts);
}

function build_sign_in(reason) {
  const field = (props) => dom.build_element("input", { type: "text", required: true, autocomplete: "off", spellcheck: "false", ...props });
  const inputs = {
    api_key: field({ type: "password", autocomplete: "current-password", placeholder: "ciip_…" }),
    user_id: field({ autocomplete: "username", placeholder: "e.g. jane.doe" }),
    entity_id: field({ inputmode: "numeric", pattern: "[0-9]+", placeholder: "e.g. 125" }),
    tenant_id: field({ placeholder: "e.g. DESC" }),
  };
  const show_key = dom.build_element("input", { type: "checkbox" });
  show_key.addEventListener("change", () => (inputs.api_key.type = show_key.checked ? "text" : "password"));
  async function sign_in() {
    const values = Object.fromEntries(Object.entries(inputs).map(([name, input]) => [name, input.value.trim()]));
    const problems = session.check_identity(values);
    if (problems.length) throw new Error(problems.join(" "));
    try {
      await api.request("GET", "/v1/jobs", undefined, { client: values });
    } catch (error) {
      if (error.status === 401) throw new Error("The API key was not accepted. Check it, or ask your administrator for a new one.");
      throw error;
    }
    session.sign_in(values);
  }
  const form = dom.build_form(
    [
      dom.build_field("API key", inputs.api_key, { hint: "The key your administrator gave you. Kept in this browser tab only, never saved." }),
      dom.build_field("Show the key", show_key),
      dom.build_row(dom.build_field("User id", inputs.user_id), dom.build_field("Tenant id", inputs.tenant_id)),
      dom.build_field("Entity id", inputs.entity_id, { hint: "The organisation whose assets you assess." }),
    ],
    "Sign in",
    sign_in,
  );
  return dom.build_element(
    "div",
    { class: "sign-in" },
    dom.build_element(
      "div",
      { class: "sign-in-card" },
      dom.build_element("div", { class: "sign-in-brand" }, dom.build_element("span", { class: "brand-mark", "aria-hidden": "true", text: "TSG" }), dom.build_element("div", {}, dom.build_element("h2", { text: "Threat Scenario Generator" }), dom.build_element("p", { class: "muted", text: "Sign in to create and review threat scenarios, treatment plans and service maps." }))),
      reason && dom.build_callout(`You were signed out: ${reason}`, "warn"),
      form,
      dom.build_element("p", { class: "muted sign-in-foot" }, "Administrator? ", dom.build_link("Open the administration pages", address_of(ADMIN_HOME)), "."),
    ),
  );
}

function build_admin_key_form() {
  const key = dom.build_element("input", { type: "password", required: true, autocomplete: "off", spellcheck: "false" });
  const name = dom.build_element("input", { type: "text", autocomplete: "off", spellcheck: "false", value: api.read_admin_name(), placeholder: session.identity()?.user_id || "admin-ui" });
  const fields = [
    dom.build_field("Admin key", key, { hint: "Kept in this tab's memory only: gone when the page is reloaded." }),
    dom.build_field("Recorded as", name, { optional: true, hint: "The name your changes are audited under. Empty: your sign-in name, else admin-ui." }),
  ];
  const form = dom.build_form(fields, "Unlock", () => {
    if (!api.set_admin_name(name.value)) throw new Error("The name may hold plain characters only.");
    if (!api.set_admin_key(key.value)) throw new Error("Type the admin key first (plain characters, no line breaks).");
  });
  return dom.build_element(
    "div",
    { class: "state state-locked" },
    dom.build_element("h2", { text: "This page needs the admin key" }),
    dom.build_element("p", { class: "muted", text: "Administration pages change the whole service. Enter the admin key to continue." }),
    form,
  );
}

function set_menu_open(open) {
  const was_open = app_root.classList.contains("menu-open");
  app_root.classList.toggle("menu-open", open);
  menu_button.setAttribute("aria-expanded", String(open));
  if (open && !was_open) nav.querySelectorAll("a")[0]?.focus(); // the keyboard lands in the menu it opened
}

function show_environment() {
  const host = location.hostname;
  const is_local = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  dom.replace_content(document.getElementById("environment"), dom.build_badge("ok", is_local ? "Local" : host, is_local ? "idle" : "good"));
}

function start() {
  show_environment();
  menu_button.addEventListener("click", () => set_menu_open(!app_root.classList.contains("menu-open")));
  // On a phone the menu lies over the page: Escape or a tap on the page beside it closes it.
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && app_root.classList.contains("menu-open")) {
      set_menu_open(false);
      menu_button.focus();
    }
  });
  main.addEventListener("click", () => {
    if (app_root.classList.contains("menu-open")) set_menu_open(false);
  });
  api.watch_admin_key((has_key, refusal) => {
    const page = PAGES.find((candidate) => candidate.id === visit.address?.id);
    if (page?.access === "admin" || page?.group === "Administration") show_page();
    else build_account();
    if (refusal) dom.show_notice(`${refusal} The admin key was cleared.`, "bad");
  });
  session.watch_session((who, reason) => {
    dom.clear_notice();
    if (!who) sign_out_reason = reason;
    show_page();
  });
  window.addEventListener("hashchange", () => {
    const next = read_address();
    // A fragment that is no page (the skip link's "#main") leaves the page as it is.
    if (next === null) return;
    if (visit.address && next.id === visit.address.id && next.params.join("/") === visit.address.params.join("/")) return;
    dom.clear_notice();
    show_page();
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  });
  show_page();
}

start();
