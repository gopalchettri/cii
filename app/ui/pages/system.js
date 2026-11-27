// System health (no key): is the service alive and ready, and the state of each store and of each queue's workers.

const REFRESH_SECONDS = 30; // two open, free reads: cheap enough to keep the page current
const STORE_NAMES = { mongo: "MongoDB (results and jobs)", sql: "SQL Server (library and assets)", redis: "Redis (work queues)" };

export async function show(container, tools) {
  tools.set_subtitle("Whether the service is up, can reach its stores, and has workers to do the work.");
  const report = tools.build_element("div", { class: "stack" });
  const read_again = (quiet) => tools.load_into(report, () => read_state(tools), (state) => build_report(tools, state), { quiet });
  tools.set_actions(tools.build_button("Check again", () => read_again(true), { kind: "quiet" }));
  tools.every(REFRESH_SECONDS, () => read_again(true));
  container.append(report);
  await read_again(false);
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
  const stores = Object.entries(readiness.dependencies ?? {}).map(([store, is_up]) => ({ store, is_up: Boolean(is_up) }));
  const queues = Object.entries(readiness.workers ?? {}).map(([queue, online]) => ({ queue, online }));
  const is_alive = health?.status === "ok";
  const is_ready = readiness.status === "ready";
  const stores_up = stores.filter((row) => row.is_up).length;
  const workers_online = queues.reduce((sum, row) => sum + (Number(row.online) || 0), 0);
  const idle_queues = queues.filter((row) => !(row.online > 0)).length;
  const kpis = tools.build_kpis([
    { label: "Service", value: is_alive ? "Alive" : "Not answering", tone: is_alive ? "good" : "bad" },
    { label: "Ready for work", value: is_ready ? "Ready" : "Not ready", tone: is_ready ? "good" : "bad" },
    { label: "Stores up", value: `${stores_up} of ${stores.length}`, tone: stores_up === stores.length ? "good" : "warn" },
    { label: "Workers online", value: readiness.workers ? workers_online : "Unknown", tone: workers_online > 0 ? "good" : "warn" },
  ]);
  const not_ready = !is_ready && tools.build_callout("The service is not ready: its main database does not answer, so no new work can start.", "bad");
  const idle_note =
    idle_queues > 0 && tools.build_callout(`${idle_queues} ${idle_queues === 1 ? "queue has" : "queues have"} no worker: work sent there waits until one starts.`, "warn");
  return [
    kpis,
    tools.build_element("p", { class: "muted", text: `Last checked ${tools.format_date(read_at)}. Checked again every ${REFRESH_SECONDS} seconds.` }),
    not_ready,
    idle_note,
    tools.build_element(
      "div",
      { class: "grid-2" },
      tools.build_section({ title: "Stores", subtitle: "The databases the service needs." }, build_stores(tools, stores)),
      tools.build_section({ title: "Workers", subtitle: "The background workers listening on each queue." }, build_workers(tools, readiness.workers, queues)),
    ),
    tools.build_section({ title: "Main database details", subtitle: "How MongoDB is set up, as it reports itself." }, build_mongodb(tools, readiness.mongodb)),
  ];
}

function build_stores(tools, stores) {
  const columns = [
    { title: "Store", show: (row) => STORE_NAMES[row.store] ?? tools.humanise(row.store) },
    { title: "State", show: (row) => tools.build_badge(row.is_up, row.is_up ? "Up" : "Down") },
  ];
  return tools.build_table(stores, columns, { caption: "Each store and whether it answers", empty: "No store is reported." });
}

function build_workers(tools, workers, queues) {
  if (!workers) return tools.build_empty("The workers' heartbeats could not be read. Check again in a moment.");
  const columns = [
    { title: "Queue", show: (row) => tools.humanise(row.queue) },
    { title: "Online", numeric: true, show: (row) => tools.format_count(row.online) },
    { title: "State", show: (row) => (row.online > 0 ? tools.build_badge("ready", "Online") : tools.build_badge("down", "No worker")) },
  ];
  return tools.build_table(queues, columns, { caption: "Workers online per queue", empty: "No queue is reported." });
}

function build_mongodb(tools, mongodb) {
  if (!mongodb) return tools.build_empty("Not read yet. Press Check again in a moment.");
  const show_fact = (value) => (value !== null && typeof value === "object" ? JSON.stringify(value) : value);
  return tools.build_facts(Object.entries(mongodb).map(([name, value]) => [tools.humanise(name), show_fact(value)]));
}
