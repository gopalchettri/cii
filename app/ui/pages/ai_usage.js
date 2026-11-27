// AI usage (no key): the AI calls of a chosen period, added up per API call. Number tiles and a table, no charts.

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
  tools.set_subtitle("How much the service asked of the AI in a period, added up per kind of request.");
  const today = new Date();
  const first_day = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (DAYS_SHOWN_FIRST - 1));
  const from = build_element("input", { type: "date", required: true, value: write_day(first_day), max: write_day(today) });
  const to = build_element("input", { type: "date", required: true, value: write_day(today) });
  const report = build_element("div", { class: "stack" });

  function read_totals() {
    const until = new Date(`${to.value}T00:00`);
    until.setDate(until.getDate() + 1); // the day after: the API leaves `until` out of the range
    const period = { since: new Date(`${from.value}T00:00`).toISOString(), until: until.toISOString() };
    return tools.request("GET", tools.with_query("/v1/ai-usage", period));
  }

  const show_report = () => tools.load_into(report, read_totals, (totals) => build_report(tools, totals), { quiet: true });
  const days = tools.build_row(
    build_field("From", from),
    build_field("To", to, { hint: "Whole days in this browser's time zone, both included; at most 366 days." }),
  );
  container.append(
    tools.build_section({ title: "Period", subtitle: `The last ${DAYS_SHOWN_FIRST} days are shown first.` }, tools.build_form([days], "Show", show_report)),
    tools.build_section({ title: "AI calls per request", subtitle: "Each kind of request, then the whole period." }, report),
  );
  await show_report();
}

/** A date as a date field holds it: YYYY-MM-DD in the browser's own zone. */
function write_day(date) {
  const two = (number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())}`;
}

function build_report(tools, totals) {
  const whole = totals.total ?? {};
  const kpis = tools.build_kpis([
    { label: "AI calls", value: whole.total_ai_calls ?? 0 },
    { label: "Failed", value: whole.failed_calls ?? 0, tone: whole.failed_calls ? "bad" : "good", hint: `${tools.format_count(whole.successful_calls ?? 0)} succeeded` },
    { label: "Tokens in", value: whole.tokens_in ?? 0 },
    { label: "Tokens out", value: whole.tokens_out ?? 0 },
    { label: "Time spent", value: tools.format_seconds(whole.seconds ?? 0) },
  ]);
  const whole_period = { ...whole, key: {}, requests: null, is_whole_period: true };
  const columns = [
    { title: "Request", show: (row) => name_api_call(tools, row) },
    { title: "Area", show: (row) => (row.key.module ? tools.humanise(row.key.module) : null) },
    { title: "Requests", numeric: true, show: (row) => tools.format_count(row.requests) },
    ...COUNTS.map(([title, field]) => ({ title, numeric: true, show: (row) => tools.format_count(Math.round(row[field])) })),
  ];
  const caption = [
    `${tools.format_date(totals.since)} to ${tools.format_date(totals.until)} (not included).`,
    "Requests: those whose first AI call falls in the period.",
  ];
  const truncated = totals.truncated && tools.build_callout("Only the first rows are listed; the tiles and the whole period still count all. Choose a shorter period to see every row.", "warn");
  const rows = totals.items.length ? [...totals.items, whole_period] : [];
  return [
    rows.length > 0 && kpis,
    truncated,
    tools.build_table(rows, columns, { caption: caption.join(" "), empty: "No AI call was recorded in this period. Choose a longer period and press Show." }),
  ];
}

function name_api_call(tools, row) {
  if (row.is_whole_period) return tools.build_element("strong", { text: "Whole period" });
  const name = tools.build_element("div", { class: "nowrap", text: row.api_label || row.key.api || "Shared work (no single request)" });
  return [name, row.api_description && tools.build_element("small", { class: "muted", text: row.api_description })];
}
