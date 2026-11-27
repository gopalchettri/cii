// Run by tests/test_admin_ui.py with node: the UI's shell (app.js) with the sign-in, its builders (dom.js), the
// routing and the data ingestion page, on a small stand-in for the browser's document. Exits non-zero on the
// first failed check.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const real_timeout = globalThis.setTimeout;
globalThis.setTimeout = (run) => real_timeout(run, 0); // the 3 s between a followed job's reads, without the wait
globalThis.setInterval = () => 0; // the pages' backstop refreshes: not needed here
globalThis.clearInterval = () => {};
/** Waits until `is_so()` holds; fails after 5 s. */
async function wait_until(is_so, what) {
  for (let waited = 0; !is_so(); waited += 5) {
    assert.ok(waited < 5000, `never happened: ${what}`);
    await new Promise((resolve) => real_timeout(resolve, 5));
  }
}

// The stand-in document: only what app.js, dom.js and the pages shown here use.
class Node {
  parentNode = null;
}
class Text extends Node {
  constructor(text) {
    super();
    this.textContent = text;
  }
}
class ClassList {
  constructor(element) {
    this.element = element;
  }
  #names() {
    return new Set(this.element.className.split(/\s+/).filter(Boolean));
  }
  contains(name) {
    return this.#names().has(name);
  }
  add(...names) {
    const kept = this.#names();
    names.forEach((name) => kept.add(name));
    this.element.className = [...kept].join(" ");
  }
  remove(...names) {
    const kept = this.#names();
    names.forEach((name) => kept.delete(name));
    this.element.className = [...kept].join(" ");
  }
  toggle(name, force) {
    const on = force ?? !this.contains(name);
    if (on) this.add(name);
    else this.remove(name);
    return on;
  }
}
class Element extends Node {
  childNodes = [];
  attributes = new Map();
  listeners = {};
  dataset = {};
  value = "";
  checked = false;
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
    this.classList = new ClassList(this);
  }
  get id() {
    return this.attributes.get("id") ?? "";
  }
  set id(value) {
    this.attributes.set("id", value);
  }
  get className() {
    return this.attributes.get("class") ?? "";
  }
  set className(value) {
    this.attributes.set("class", value);
  }
  get type() {
    return this.attributes.get("type");
  }
  set type(value) {
    this.attributes.set("type", value);
  }
  get disabled() {
    return this.attributes.has("disabled");
  }
  set disabled(is_disabled) {
    if (is_disabled) this.attributes.set("disabled", "");
    else this.attributes.delete("disabled");
  }
  get hidden() {
    return this.attributes.has("hidden");
  }
  set hidden(is_hidden) {
    if (is_hidden) this.attributes.set("hidden", "");
    else this.attributes.delete("hidden");
  }
  get children() {
    return this.childNodes.filter((child) => child instanceof Element);
  }
  get firstElementChild() {
    return this.children[0] ?? null;
  }
  get childElementCount() {
    return this.children.length;
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name.startsWith("data-")) this.dataset[name.slice(5)] = String(value);
  }
  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }
  hasAttribute(name) {
    return this.attributes.has(name);
  }
  removeAttribute(name) {
    this.attributes.delete(name);
  }
  addEventListener(name, listener) {
    (this.listeners[name] ??= []).push(listener);
  }
  append(...children) {
    for (const child of children) {
      const node = child instanceof Node ? child : new Text(String(child));
      node.remove?.();
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }
  before(...nodes) {
    const parent = this.parentNode;
    if (!parent) return;
    const at = parent.childNodes.indexOf(this);
    for (const node of nodes) {
      node.remove?.();
      node.parentNode = parent;
    }
    parent.childNodes.splice(at, 0, ...nodes);
  }
  replaceChildren(...children) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    this.append(...children);
  }
  remove() {
    if (this.parentNode) this.parentNode.childNodes = this.parentNode.childNodes.filter((child) => child !== this);
    this.parentNode = null;
  }
  get textContent() {
    return this.childNodes.map((child) => child.textContent).join("");
  }
  set textContent(text) {
    this.replaceChildren(...(text === "" ? [] : [text]));
  }
  contains(node) {
    for (let at = node; at; at = at.parentNode) if (at === this) return true;
    return false;
  }
  /** Tags ("button") or one class (".hint"). */
  querySelectorAll(selector) {
    const is_class = selector.startsWith(".");
    const fits = (element) => (is_class ? element.classList.contains(selector.slice(1)) : element.tagName === selector.toUpperCase());
    return this.children.flatMap((child) => [...(fits(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
  focus() {
    if (!this.disabled) focused = this;
  }
  scrollIntoView() {}
  reset() {}
  /** Runs the element's listeners of `name` as the browser would on that event. */
  async fire(name) {
    if (this.disabled) return;
    await Promise.all((this.listeners[name] ?? []).map((listener) => listener({ target: this, key: "", preventDefault() {} })));
  }
}

let focused = null;
const body = new Element("body");
const shell = readFileSync(new URL("../app/ui/index.html", import.meta.url), "utf-8");
// Every element of index.html that has an id: an id app.js asks for and index.html lacks is then a failure here.
for (const [, tag, id] of shell.matchAll(/<(\w+)[^>]*\sid="([\w-]+)"/g)) {
  const element = new Element(tag);
  element.id = id;
  body.append(element);
}
const find_by_id = (id) => body.childNodes.find((child) => child.id === id) ?? null;
const window_listeners = {};
const stored = new Map();
globalThis.Node = Node;
globalThis.location = { hash: "", origin: "https://cii.example", hostname: "cii.example" };
globalThis.window = {
  addEventListener: (name, listener) => (window_listeners[name] = listener),
  scrollTo() {},
  print() {},
  sessionStorage: {
    getItem: (key) => (stored.has(key) ? stored.get(key) : null),
    setItem: (key, value) => stored.set(key, String(value)),
    removeItem: (key) => stored.delete(key),
  },
};
globalThis.document = {
  body,
  title: "",
  hidden: false,
  createElement: (tag) => new Element(tag),
  getElementById: (id) => body.childNodes.find((child) => child.id === id) ?? null,
  addEventListener() {},
  removeEventListener() {},
  get activeElement() {
    return focused && body.contains(focused) ? focused : body; // a removed element loses the focus to <body>
  },
};

// The stand-in API: each "METHOD path" answers from this table (a function is asked each time); any other call
// is refused, so a page shows its error state.
const SOURCES = ["mitre_attack_enterprise", "mitre_attack_ics"];
const build_health = () => ({
  switch: { effective: true, runtime_enabled: true, env_enabled: true, changed_at: null, changed_by: null },
  no_data: false,
  snapshot_id: "snap-1",
  pending_sources: [],
  sources: SOURCES.map((source, at) => ({
    source,
    status: "ok",
    source_version: "17.1",
    records: 800,
    last_success_at: "2026-11-10T02:04:00",
    last_attempt_at: "2026-11-10T02:00:00",
    last_error: null,
    claimed_at: at === 1 ? "2026-11-10T02:00:00" : null, // a claim nobody released: its worker died
  })),
});
let job_reads = 0;
const answers = {
  "GET /v1/tsg/intel/health": () => ({ status: 200, body: build_health() }),
  "POST /v1/tsg/intel/refresh": () => ({ status: 202, body: { job_id: "j1" } }),
  "GET /v1/tsg/intel/refresh/j1": () => ({ status: 200, body: { job_id: "j1", status: (job_reads += 1) < 3 ? "running" : "done" } }),
};
const NOT_HERE = { status: 500, body: { detail: "Not read in this check." } };
const calls = [];
globalThis.fetch = async (path, options) => {
  calls.push({ call: `${options.method} ${path}`, headers: options.headers });
  const answer = answers[`${options.method} ${path.split("?")[0]}`]?.() ?? NOT_HERE;
  return { ok: answer.status < 300, status: answer.status, headers: new Map(), body: null, text: async () => JSON.stringify(answer.body) };
};

const dom = await import("../app/ui/dom.js");
await import("../app/ui/app.js"); // the shell starts itself: no address, so the home page

const app_root = find_by_id("app");
const page_place = find_by_id("page");
const title = find_by_id("page-title");
const notices = find_by_id("notices");
const account = find_by_id("account");
const nav = find_by_id("nav");
const read_page = () => page_place.childNodes[0];
const find_control = (tag, name) =>
  read_page().querySelectorAll(tag).find((element) => (element.getAttribute("aria-label") ?? element.textContent) === name);
/** The control a label names: <label for="id"> and the control of that id. */
const find_field = (label) => {
  const caption = read_page().querySelectorAll("label").find((element) => element.textContent.trim() === label);
  assert.ok(caption, `a field labelled ${label}`);
  return [...read_page().querySelectorAll("input"), ...read_page().querySelectorAll("textarea")].find((control) => control.id === caption.getAttribute("for"));
};
const go_to = (hash) => {
  location.hash = hash;
  window_listeners.hashchange();
};

// ---------- signed out: the sign-in screen, no menu but Sign in and the administration pages
await wait_until(() => find_control("button", "Sign in"), "the sign-in screen is shown");
assert.equal(title.textContent, "Sign in");
assert.ok(app_root.classList.contains("is-signed-out"));
assert.match(nav.textContent, /Sign in/);
assert.match(nav.textContent, /System health/);
assert.doesNotMatch(nav.textContent, /New run/);
const sign_in_form = read_page().querySelector("form");
const fill = (values) => {
  for (const [label, value] of Object.entries(values)) find_field(label).value = value;
};

// wrong values are told in plain words and nothing is sent
let sent = calls.length;
fill({ "API key": "ciip_k", "User id": "jane", "Tenant id": "DESC", "Entity id": "abc" });
await sign_in_form.fire("submit");
assert.match(read_page().textContent, /The entity id is a whole number/);
assert.equal(calls.length, sent);

// a key the API refuses: said so, still signed out
answers["GET /v1/jobs"] = () => ({ status: 401, body: { detail: "The API key is not valid." } });
fill({ "Entity id": "125" });
await sign_in_form.fire("submit");
assert.match(read_page().textContent, /was not accepted/);
assert.equal(stored.size, 0);
assert.equal(calls.at(-1).headers["X-API-Key"], "ciip_k");

// accepted: kept for the tab, the home page and the full menu, who is signed in at the top
answers["GET /v1/jobs"] = () => ({ status: 200, body: { items: [], total: 0 } });
await sign_in_form.fire("submit");
await wait_until(() => title.textContent === "Home", "the home page is shown after sign-in");
assert.equal(app_root.classList.contains("is-signed-out"), false);
assert.ok(stored.has("tsg.session"));
assert.match(account.textContent, /jane/);
assert.match(account.textContent, /Entity 125/);
assert.match(nav.textContent, /New run/);
assert.equal(calls.find((call) => call.call.startsWith("GET /v1/jobs") && call.headers["X-API-Key"] === "ciip_k") !== undefined, true);

// ---------- routing: "#/<page>/<param>" opens the page with its param; a page not in the menu marks its parent
go_to("#/run/s1");
await wait_until(() => calls.some((call) => call.call.startsWith("GET /v1/sessions/s1")), "the run page reads its run");
assert.equal(title.textContent, "Threat scenario run");
assert.equal(nav.querySelectorAll("a").find((link) => link.getAttribute("aria-current") === "page")?.textContent.trim(), "Runs");
go_to("#/no_such_page");
assert.match(read_page().textContent, /There is no page "no_such_page"/);

// ---------- the data ingestion page (open to anyone): a source's claim is shown beside its status, never in its place
go_to("#/ingestion");
await wait_until(() => find_control("button", "Import now"), "the ingestion page is shown");
assert.equal(title.textContent, "Data ingestion");
const claimed_row = read_page().querySelectorAll("tr").find((row) => row.textContent.includes(SOURCES[1]));
assert.ok(claimed_row, "the claimed source has its row");
assert.match(claimed_row.textContent, /ok.*claimed for import/i);
assert.doesNotMatch(read_page().textContent, /importing since/);
assert.deepEqual(claimed_row.querySelectorAll("span").filter((span) => span.className.includes("badge-busy")), []);

// The skip link's "#main" is no page: the page on screen stays, with its notice, and nothing is read again.
const ingestion = read_page();
dom.show_notice("An import is followed.");
sent = calls.length;
go_to("#main");
assert.equal(read_page(), ingestion);
assert.equal(title.textContent, "Data ingestion");
assert.match(notices.textContent, /An import is followed\./);
go_to("#/ingestion"); // the browser's Back from "#main" leaves it alone too
assert.equal(read_page(), ingestion);
assert.equal(calls.length, sent);

// A reload of the page keeps the keyboard focus inside it. The pressed button is disabled while the import
// runs, so the focus rests on the page itself; a control that is built again gets it back.
const import_now = find_control("button", "Import now");
import_now.focus();
await import_now.fire("click");
await wait_until(() => job_reads >= 3 && find_control("button", "Import now")?.disabled === false, "the import ended and the page was read again");
assert.equal(calls.filter((call) => call.call === "POST /v1/tsg/intel/refresh").length, 1);
assert.equal(document.activeElement, ingestion);
assert.equal(ingestion.getAttribute("tabindex"), "-1");

const turn_off = "Turn off"; // never disabled by an import, so it is built again and takes the focus back
find_control("button", turn_off).focus();
job_reads = 0;
await find_control("button", "Import now").fire("click");
await wait_until(() => job_reads >= 3 && find_control("button", "Import now")?.disabled === false, "the second import ended");
assert.equal(document.activeElement, find_control("button", turn_off));

// Focus the reader moved out of the page meanwhile is not taken back.
find_control("button", turn_off).focus();
const elsewhere = dom.build_button("Elsewhere", () => {});
body.append(elsewhere);
await dom.load_into(ingestion, async () => elsewhere.focus(), () => "read again");
assert.equal(document.activeElement, elsewhere);

// Buttons that share their word are told apart by their aria-label: the focus goes back to the same source's.
const build_twins = () =>
  SOURCES.map((source) => {
    const button = dom.build_button("Import", () => {});
    button.setAttribute("aria-label", `Import ${source}`);
    return button;
  });
const twins = dom.build_element("div", {}, ...build_twins());
body.append(twins);
twins.childNodes[1].focus();
await dom.load_into(twins, async () => {}, build_twins);
assert.equal(document.activeElement, twins.childNodes[1]);

// Two loads of one place at once (a followed job ends while the page is being read): the later one is shown,
// whichever answers first, and the focus the first one took away still comes back.
for (const answer_order of [["first", "second"], ["second", "first"]]) {
  const place = dom.build_element("div", {}, dom.build_button("Go", () => {}));
  body.append(place);
  place.childNodes[0].focus();
  const answer = {};
  const read = (name) => () => new Promise((resolve) => (answer[name] = resolve));
  const loaded = [dom.load_into(place, read("first"), () => "first"), dom.load_into(place, read("second"), () => dom.build_button("Go", () => {}))];
  for (const name of answer_order) {
    answer[name]();
    await new Promise((resolve) => real_timeout(resolve, 5));
  }
  await Promise.all(loaded);
  assert.equal(place.textContent, "Go", answer_order.join(" then "));
  assert.equal(document.activeElement, place.childNodes[0], answer_order.join(" then "));
  place.remove();
}

// Another page is still a page change, and its notices go.
go_to("#/schedule");
assert.equal(title.textContent, "Ingestion schedule");
assert.notEqual(read_page(), ingestion);
assert.equal(notices.textContent, "");

// ---------- a page behind the admin key: it asks for the key in its place; a 403 is told in the API's own words
go_to("#/jobs");
assert.match(read_page().textContent, /needs the admin key/);
answers["GET /v1/admin/jobs"] = () => ({ status: 403, body: { detail: "Admin endpoints are disabled on this deployment." } });
find_field("Admin key").value = "any-key";
await read_page().querySelector("form").fire("submit");
await wait_until(() => notices.textContent !== "", "the refusal is told");
assert.match(notices.textContent, /Admin endpoints are disabled on this deployment\. The admin key was cleared\./);
await wait_until(() => /needs the admin key/.test(read_page().textContent), "the page asks for the key again");
assert.doesNotMatch(account.textContent, /Admin key set/);

// ---------- the API stops accepting the key: signed out, told why, the sign-in screen again
answers["GET /v1/jobs"] = () => ({ status: 401, body: { detail: "The API key is not valid." } });
go_to("#/home");
await wait_until(() => title.textContent === "Sign in", "a refused key signs out");
assert.match(read_page().textContent, /You were signed out: The API key is not valid\./);
assert.equal(stored.has("tsg.session"), false);

// ---------- a link stays on this origin, or is an https site: "/\host" and "//host" start with "/" and leave it
const read_href = (href) => dom.build_element("a", { href, text: "x" }).getAttribute("href");
const other_hosts = ["/\\evil.example/x", "//evil.example/x", "/\t/evil.example/x", "http://evil.example/x", "javascript:alert(1)"];
assert.deepEqual(other_hosts.map(read_href), [null, null, null, null, null]);
const kept = ["/docs", "#/jobs", "./styles.css", "https://attack.mitre.org/techniques/T0859"];
assert.deepEqual(kept.map(read_href), kept);

// ---------- a plan's alternative replacing nothing reads "Added"; a replacement reads "Replaces X" only
const { build_assessment } = await import("../app/ui/pages/plan.js");
const read_check = (replaces) => {
  const row = { control_code: "C-1", control_name: "Backup", match: "alternative", validation: null, replaces };
  return build_assessment([row], dom).textContent;
};
assert.match(read_check([]), /Added/);
assert.match(read_check(["C-0"]), /Replaces C-0/);
assert.doesNotMatch(read_check(["C-0"]), /Added/);

console.log("ui shell checks passed");
