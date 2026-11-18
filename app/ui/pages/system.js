// System (no key): is the API alive, is it ready, and the state of each store and of each queue's workers.

export async function show(container, tools) {
  const report = tools.build_element("div", { class: "columns" });
  const read_again = () => tools.load_into(report, () => read_state(tools), (state) => build_report(tools, state));
  container.append(tools.build_actions(tools.build_button("Refresh", read_again)), report);
  await read_again();
}

async function read_state(tools) {
  const [health, readiness] = await Promise.all([tools.request("GET", "/health"), read_readiness(tools)]);
  return { health, readiness, read_at: new Date() };
}

/** Not ready is an answer to show, not a failed read: the API then answers 503 with the same report. */
async function read_readiness(tools) {
  try {
    return await tools.request("GET", "/ready");
  } catch (error) {
    if (error.status === 503 && error.body?.dependencies) return error.body;
    throw error;
  }
}

function build_report(tools, { health, readiness, read_at }) {
  const stores = Object.entries(readiness.dependencies ?? {}).map(([store, is_up]) => ({ store, is_up }));
  const state = tools.build_facts([
    ["Alive", tools.build_badge(health?.status)],
    ["Ready", tools.build_badge(readiness.status)],
    ["Read at", tools.format_date(read_at)],
  ]);
  const store_columns = [
    { title: "Store", show: (row) => write_mono(tools, row.store) },
    { title: "State", show: (row) => tools.build_badge(Boolean(row.is_up), row.is_up ? "Up" : "Down") },
  ];
  return [
    tools.build_panel("API", state),
    tools.build_panel("Stores", tools.build_table(stores, store_columns, { empty: "No store is reported." })),
    tools.build_panel("Workers", build_workers(tools, readiness.workers)),
    tools.build_panel("MongoDB", build_mongodb(tools, readiness.mongodb)),
  ];
}

function build_workers(tools, workers) {
  if (!workers) return tools.build_empty("The workers' heartbeats could not be read.");
  const rows = Object.entries(workers).map(([queue, online]) => ({ queue, online }));
  const columns = [
    { title: "Queue", nowrap: true, show: (row) => write_mono(tools, row.queue) },
    { title: "Online", numeric: true, show: (row) => tools.format_count(row.online) },
    { title: "State", show: (row) => (row.online > 0 ? tools.build_badge("ready", "Online") : tools.build_badge("down", "No worker")) },
  ];
  return tools.build_table(rows, columns, { empty: "No queue is reported." });
}

function build_mongodb(tools, mongodb) {
  if (!mongodb) return tools.build_empty("Not read yet: press Refresh.");
  const write_label = (name) => name.charAt(0).toUpperCase() + name.slice(1).replaceAll("_", " ");
  const show_fact = (value) => (value !== null && typeof value === "object" ? JSON.stringify(value) : value);
  return tools.build_facts(Object.entries(mongodb).map(([name, value]) => [write_label(name), show_fact(value)]));
}

function write_mono(tools, value) {
  return tools.build_element("span", { class: "mono", text: value });
}
