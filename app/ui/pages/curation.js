// Library curation (admin key): the threats waiting for a curator, paged; approve or reject the ticked ones.

const PAGE_SIZES = [25, 50, 100]; // never above the API's ids per decisions call (100): a whole page fits one call
const DEFAULT_PAGE_SIZE = 50;
const DECISIONS = {
  approve: { label: "Approve", kind: "primary", danger: false, effect: "An approved threat joins the live library." },
  reject: { label: "Reject", kind: "danger", danger: true, effect: "A rejected threat is never proposed again." },
};
const SOURCES = { ai: "Promoted from an AI scenario", manual: "A hand-written scenario" };
/** The look of an outcome that changed nothing; the others take the badge's own look. */
const OUTCOME_TONES = { already_approved: "idle", already_rejected: "idle", is_approved: "warn", not_found: "warn" };

/** @param {HTMLElement} container @param {object} tools the shell's tools (app.js) */
export async function show(container, tools) {
  tools.set_subtitle("Threats proposed for the library wait here for a curator. Tick them, then approve or reject.");
  const result_place = tools.build_element("div", { hidden: true }); // no layout class: one would override [hidden]
  const list_place = tools.build_element("div", { class: "stack" });
  const sizes = PAGE_SIZES.map((size) => ({ value: size, label: `${size} a page` }));
  const page_size = tools.build_select(sizes, DEFAULT_PAGE_SIZE, { on: { change: () => load_page(0) } });
  let offset = 0;

  async function read_page() {
    const limit = Number(page_size.value);
    const read = () => tools.request("GET", tools.with_query("/v1/tsg/library/pending", { offset, limit }));
    let page = await read();
    if (page.items.length === 0 && page.total > 0) {
      offset = Math.floor((page.total - 1) / limit) * limit; // the page shown was decided away: the last one now
      page = await read();
    }
    return { ...page, offset, limit };
  }

  /** A new page shows the loading state; the same page read again (`quiet`) keeps the old rows until it answers. */
  function load_page(new_offset = offset, quiet = false) {
    offset = new_offset;
    return tools.load_into(list_place, read_page, (page) => build_pending(page, tools, load_page, decide), { quiet });
  }

  async function decide(decision, rows) {
    const answer = await tools.request("POST", "/v1/tsg/library/decisions", { [decision]: rows.map((row) => row.catalogue_id) });
    const dismiss = () => {
      result_place.hidden = true;
      tools.replace_content(result_place);
    };
    tools.replace_content(result_place, build_result_section(answer.results, rows, tools, dismiss));
    result_place.hidden = false;
    const has_only_changes = answer.results.every((result) => !OUTCOME_TONES[result.outcome]);
    tools.show_notice(`Decided: ${summarise_outcomes(answer.results)}.`, has_only_changes ? "good" : "info");
    await load_page(offset, true);
  }

  const refresh = tools.build_button("Refresh", () => load_page(offset, true), { kind: "quiet" });
  const pending = tools.build_section(
    { title: "Waiting for a curator", subtitle: "Oldest first. A decision is final for each threat.", actions: [refresh] },
    tools.build_element("div", { class: "toolbar" }, tools.build_field("Page size", page_size)),
    list_place,
  );
  container.append(result_place, pending);
  await load_page();
}

function count_threats(count) {
  return `${count} ${count === 1 ? "threat" : "threats"}`;
}

/** E.g. "3 approved, 1 not found", in the order the API answered them. */
function summarise_outcomes(results) {
  const counts = new Map();
  for (const result of results) counts.set(result.outcome, (counts.get(result.outcome) ?? 0) + 1);
  return [...counts].map(([outcome, count]) => `${count} ${outcome.replaceAll("_", " ")}`).join(", ") || "nothing";
}

/** One page of pending threats with its ticks, the two decisions and the paging. */
function build_pending(page, tools, load_page, decide) {
  if (page.total === 0) return tools.build_empty("No threat is waiting for a curator. New proposals appear here as runs suggest them.");
  const { items, offset, limit, total } = page;
  const boxes = new Map(
    items.map((row) => [row, tools.build_element("input", { type: "checkbox", "aria-label": `Tick ${row.threat}`, on: { change: show_ticks } })]),
  );
  const ticked_count = tools.build_element("span", { class: "muted", role: "status" });
  const deciders = Object.keys(DECISIONS).map((decision) =>
    tools.build_button(`${DECISIONS[decision].label} ticked`, () => decide_ticked(decision), { kind: DECISIONS[decision].kind }),
  );
  const tickers = [
    tools.build_button("Tick all on this page", () => tick_all(true), { kind: "quiet" }),
    tools.build_button("Clear ticks", () => tick_all(false), { kind: "quiet" }),
  ];
  let is_deciding = false;

  function list_ticked() {
    return items.filter((row) => boxes.get(row).checked);
  }

  function show_ticks() {
    const ticked = list_ticked().length;
    ticked_count.textContent = `${ticked} of ${items.length} ticked`;
    for (const button of deciders) button.disabled = is_deciding || ticked === 0;
    for (const control of [...tickers, ...boxes.values()]) control.disabled = is_deciding;
  }

  function tick_all(is_ticked) {
    for (const box of boxes.values()) box.checked = is_ticked;
    show_ticks();
  }

  async function decide_ticked(decision) {
    const rows = list_ticked();
    const { label, danger, effect } = DECISIONS[decision];
    if (!(await tools.ask_to_confirm(`${label} ${count_threats(rows.length)}? ${effect}`, { confirm_label: label, danger }))) return;
    is_deciding = true;
    show_ticks(); // nothing can be ticked or sent again while this is decided
    try {
      await decide(decision, rows);
    } finally {
      is_deciding = false;
      show_ticks();
    }
  }

  const columns = [
    { title: "Tick", show: (row) => boxes.get(row) },
    { title: "Threat", key: "threat" },
    { title: "Type", show: (row) => [row.type, row.type_pending && [" ", tools.build_badge("pending", "New type", "wait")]] },
    { title: "Asset type", show: (row) => row.asset_type || "Any" },
    { title: "Categories", show: (row) => (row.categories.length ? tools.build_element("div", { class: "tags" }, row.categories.map((name) => tools.build_tag(name))) : null) },
    { title: "Source", show: (row) => SOURCES[row.source] ?? tools.humanise(row.source) },
    { title: "Proposed by", key: "created_by" },
    { title: "Proposed", show: (row) => tools.format_date(row.created_at), nowrap: true },
    { title: "Library id", key: "catalogue_id", numeric: true },
  ];
  const new_type_note = items.some((row) => row.type_pending) && tools.build_callout("A new type goes live with its first approved threat.", "info");
  show_ticks();
  return [
    tools.build_kpis([{ label: "Waiting for a curator", value: total, tone: "warn" }]),
    tools.build_element("div", { class: "spread" }, tools.build_actions(tickers), tools.build_actions(deciders, ticked_count)),
    tools.build_table(items, columns, { caption: "Threats waiting for a curator, oldest first" }),
    new_type_note,
    tools.build_pager({ offset, limit, total, on_change: (next) => load_page(next) }),
  ];
}

/** What the API answered for each id of the last decision, with the threat's name from the page it was ticked on. */
function build_result_section(results, rows, tools, dismiss) {
  const threats = new Map(rows.map((row) => [row.catalogue_id, row.threat]));
  const columns = [
    { title: "Threat", show: (result) => threats.get(result.catalogue_id) },
    { title: "Library id", key: "catalogue_id", numeric: true },
    { title: "Outcome", show: (result) => tools.build_badge(result.outcome, undefined, OUTCOME_TONES[result.outcome]) },
  ];
  return tools.build_section(
    { title: "Last decision", subtitle: summarise_outcomes(results), actions: [tools.build_button("Dismiss", dismiss, { kind: "quiet" })] },
    tools.build_table(results, columns, { caption: "What happened to each ticked threat", empty: "The service answered no outcome." }),
  );
}
