// AI usage (no key): the AI calls of a chosen period, added up per API call. Numbers in a table, no charts.

const DAYS_SHOWN_FIRST = 30; // the API's own default period
/** The counts every row and the whole period carry: column title and field. */
const COUNTS = [
  ["AI calls", "total_ai_calls"],
  ["Succeeded", "successful_calls"],
  ["Failed", "failed_calls"],
  ["Extra attempts", "extra_attempts"],
  ["Answers reused", "reused_answers"],
  ["Tokens in", "tokens_in"],
  ["Tokens out", "tokens_out"],
  ["Seconds", "seconds"],
];

export async function show(container, tools) {
  const { build_element, build_field } = tools;
  const today = new Date();
  const first_day = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (DAYS_SHOWN_FIRST - 1));
  const from = build_element("input", { type: "date", required: true, value: write_day(first_day), max: write_day(today) });
  const to = build_element("input", { type: "date", required: true, value: write_day(today) });
  // "columns": a plain block inside a panel grows as wide as its table and the page then scrolls sideways.
  const report = build_element("div", { class: "columns" });

  function read_totals() {
    const until = new Date(`${to.value}T00:00`);
    until.setDate(until.getDate() + 1); // the day after: the API leaves `until` out of the range
    const period = { since: new Date(`${from.value}T00:00`).toISOString(), until: until.toISOString() };
    return tools.request("GET", tools.with_query("/v1/ai-usage", period));
  }

  const show_report = () => tools.load_into(report, read_totals, (totals) => build_report(tools, totals));
  const days = build_element("div", { class: "toolbar" }, build_field("From", from), build_field("To", to));
  const hint = build_element("p", { class: "muted", text: "Whole days in this browser's time zone, both included; at most 366 days." });
  container.append(tools.build_panel("Period", tools.build_form([days, hint], "Show", show_report)), tools.build_panel("AI calls per API call", report));
  await show_report();
}

/** A date as a date field holds it: YYYY-MM-DD in the browser's own zone. */
function write_day(date) {
  const two = (number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())}`;
}

function build_report(tools, totals) {
  const whole_period = { ...totals.total, key: {}, requests: null, is_whole_period: true };
  const columns = [
    { title: "API call", show: (row) => name_api_call(tools, row) },
    { title: "Module", show: (row) => String(row.key.module ?? "").replaceAll("_", " ") },
    { title: "Requests", numeric: true, show: (row) => tools.format_count(row.requests) },
    ...COUNTS.map(([title, field]) => ({ title, numeric: true, show: (row) => tools.format_count(Math.round(row[field])) })),
  ];
  const caption = [
    `${tools.format_date(totals.since)} to ${tools.format_date(totals.until)} (not included).`,
    "Requests: API calls whose first AI call falls in the period.",
    totals.truncated && "Only the first rows are listed; the whole period still counts all. Choose a shorter period.",
  ];
  const rows = totals.items.length ? [...totals.items, whole_period] : [];
  return tools.build_table(rows, columns, { caption: caption.filter(Boolean).join(" "), empty: "No AI call was recorded in this period." });
}

function name_api_call(tools, row) {
  if (row.is_whole_period) return tools.build_element("strong", { text: "Whole period" });
  const name = tools.build_element("div", { class: "nowrap", text: row.api_label || row.key.api || "Shared work (no API call)" });
  return [name, row.api_description && tools.build_element("small", { class: "muted", text: row.api_description })];
}
