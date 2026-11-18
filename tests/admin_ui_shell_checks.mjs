// Run by tests/test_admin_ui.py with node: the admin UI's shell (app.js), its builders (dom.js) and the data
// ingestion page, on a small stand-in for the browser's document. Exits non-zero on the first failed check.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const real_timeout = globalThis.setTimeout;
globalThis.setTimeout = (run) => real_timeout(run, 0); // the 3 s between a followed job's reads, without the wait
/** Waits until `is_so()` holds; fails after 5 s. */
async function wait_until(is_so, what) {
  for (let waited = 0; !is_so(); waited += 5) {
    assert.ok(waited < 5000, `never happened: ${what}`);
    await new Promise((resolve) => real_timeout(resolve, 5));
  }
}

// The stand-in document: only what app.js, dom.js and the pages use.
class Node {
  parentNode = null;
}
class Text extends Node {
  constructor(text) {
    super();
    this.textContent = text;
  }
}
class Element extends Node {
  childNodes = [];
  attributes = new Map();
  listeners = {};
  dataset = {};
  value = "";
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
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
  querySelectorAll(tag) {
    const elements = this.childNodes.filter((child) => child instanceof Element);
    return elements.flatMap((child) => [...(child.tagName === tag.toUpperCase() ? [child] : []), ...child.querySelectorAll(tag)]);
  }
  focus() {
    if (!this.disabled) focused = this;
  }
  /** Runs the element's listeners of `name` as the browser would on that event. */
  async fire(name) {
    if (this.disabled) return;
    await Promise.all((this.listeners[name] ?? []).map((listener) => listener({ target: this, preventDefault() {} })));
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
globalThis.Node = Node;
globalThis.location = { hash: "", origin: "https://cii.example" };
globalThis.window = { addEventListener: (name, listener) => (window_listeners[name] = listener) };
globalThis.document = {
  body,
  title: "",
  hidden: false,
  createElement: (tag) => new Element(tag),
  getElementById: find_by_id,
  addEventListener() {},
  removeEventListener() {},
  get activeElement() {
    return focused && body.contains(focused) ? focused : body; // a removed element loses the focus to <body>
  },
};

// The stand-in API: each "METHOD path" answers from this table (a function is asked each time).
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
  "GET /v1/tsg/intel/schedule": () => ({ status: 500, body: { detail: "Not read in this check." } }),
};
const calls = [];
globalThis.fetch = async (path, options) => {
  calls.push(`${options.method} ${path}`);
  const answer = answers[`${options.method} ${path.split("?")[0]}`]();
  return { ok: answer.status < 300, status: answer.status, headers: new Map(), text: async () => JSON.stringify(answer.body) };
};

const dom = await import("../app/ui/dom.js");
await import("../app/ui/app.js"); // the shell starts itself: no address, so the first page

const page_place = find_by_id("page");
const title = find_by_id("page-title");
const notices = find_by_id("notices");
const read_page = () => page_place.childNodes[0];
const find_control = (tag, name) =>
  read_page().querySelectorAll(tag).find((element) => (element.getAttribute("aria-label") ?? element.textContent) === name);
const go_to = (hash) => {
  location.hash = hash;
  window_listeners.hashchange();
};

await wait_until(() => find_control("button", "Import now"), "the first page is shown");
assert.equal(title.textContent, "Data ingestion");

// A source's claim is shown beside its last status, never in its place: a dead worker's claim is not an import.
const claimed_row = read_page().querySelectorAll("tr")[2];
assert.ok(claimed_row.textContent.includes(SOURCES[1]));
assert.match(claimed_row.querySelectorAll("td")[1].textContent, /ok.*claimed for import/);
assert.doesNotMatch(read_page().textContent, /importing since/);
assert.deepEqual(claimed_row.querySelectorAll("span").filter((span) => span.className.includes("badge-busy")), []);

// The skip link's "#main" is no page: the page on screen stays, with its notice, and nothing is read again.
const ingestion = read_page();
dom.show_notice("An import is followed.");
let sent = calls.length;
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
assert.equal(calls.filter((call) => call === "POST /v1/tsg/intel/refresh").length, 1);
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
const reload = dom.load_into(ingestion, async () => find_by_id("admin-key").focus(), () => "read again");
await reload;
assert.equal(document.activeElement, find_by_id("admin-key"));

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

// Another page is still a page change.
go_to("#/schedule");
assert.equal(title.textContent, "Schedule");
assert.notEqual(read_page(), ingestion);
assert.equal(notices.textContent, "");

// A page behind the admin key: a 403 is told in the API's own words (here: no admin key is set on the server).
go_to("#/jobs");
assert.match(read_page().textContent, /needs the admin key/);
answers["GET /v1/admin/jobs"] = () => ({ status: 403, body: { detail: "Admin endpoints are disabled on this deployment." } });
find_by_id("admin-key").value = "any-key";
await find_by_id("access").fire("submit");
await wait_until(() => notices.textContent !== "", "the refusal is told");
assert.match(notices.textContent, /Admin endpoints are disabled on this deployment\. The admin key was cleared\./);
assert.match(read_page().textContent, /needs the admin key/);
assert.equal(find_by_id("clear-key").hidden, true);

// A link stays on this origin, or is an https site: "/\host" and "//host" start with "/" and leave it.
const read_href = (href) => dom.build_element("a", { href, text: "x" }).getAttribute("href");
const other_hosts = ["/\\evil.example/x", "//evil.example/x", "/\t/evil.example/x", "http://evil.example/x", "javascript:alert(1)"];
assert.deepEqual(other_hosts.map(read_href), [null, null, null, null, null]);
const kept = ["/docs", "#/jobs", "./styles.css", "https://attack.mitre.org/techniques/T0859"];
assert.deepEqual(kept.map(read_href), kept);

console.log("admin ui shell checks passed");
