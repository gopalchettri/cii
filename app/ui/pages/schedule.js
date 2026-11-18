// Schedule: when the import runs by itself (on or paused, daily or weekly, day, time, time zone).

const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]; // day_of_week: Monday = 0
const WEEKLY = "weekly";
const FREQUENCIES = [
  { value: "daily", label: "Every day" },
  { value: WEEKLY, label: "Every week" },
];
const SWITCH_NOTE = "The schedule starts an import only while external intelligence is on: see ";

export async function show(container, tools) {
  const { build_element, build_field, build_select, format_date } = tools;
  await tools.load_into(container, () => tools.request("GET", "/v1/tsg/intel/schedule"), build_page);

  function build_page(schedule) {
    const summary_place = build_element("div", {}, build_summary(schedule));
    const enabled = build_element("input", { type: "checkbox", checked: schedule.enabled });
    const frequency = build_select(FREQUENCIES, schedule.frequency, { required: true });
    const day = build_select(DAYS.map((label, value) => ({ value, label })), schedule.day_of_week ?? 0);
    const time = build_element("input", { type: "time", required: true, value: schedule.time });
    const zones = list_time_zones(schedule.timezone);
    // A browser that cannot list the zones gets a text field; the API refuses a name it does not know.
    const zone = zones
      ? build_select(zones, schedule.timezone, { required: true })
      : build_element("input", { type: "text", required: true, maxlength: "64", spellcheck: "false", value: schedule.timezone });
    const day_field = build_field("Day", day);
    const show_day = () => (day_field.hidden = frequency.value !== WEEKLY);
    frequency.addEventListener("change", show_day);
    show_day();

    async function save() {
      const saved = await tools.request("PUT", "/v1/tsg/intel/schedule", {
        enabled: enabled.checked,
        frequency: frequency.value,
        day_of_week: frequency.value === WEEKLY ? Number(day.value) : null,
        time: time.value.slice(0, 5),
        timezone: zone.value.trim(),
      });
      tools.replace_content(summary_place, build_summary(saved));
      const next = saved.enabled ? `Next run: ${format_date(saved.next_run_at, saved.timezone)}.` : "Nothing is imported by itself while it is paused.";
      tools.show_notice(`The schedule was saved. ${next}`, "good");
    }

    const fields = [
      build_field("Import by itself on this schedule", enabled, { hint: "Off: nothing is imported by itself. Import now still works." }),
      build_field("How often", frequency),
      day_field,
      build_field("Time", time, { hint: "24-hour, in the time zone below." }),
      build_field("Time zone", zone, { hint: "An IANA name such as UTC or Asia/Dubai. Daylight saving is followed." }),
    ];
    return [summary_place, tools.build_panel("Change the schedule", tools.build_form(fields, "Save schedule", save))];
  }

  function build_summary(schedule) {
    const when = schedule.frequency === WEEKLY ? `Every ${DAYS[schedule.day_of_week] ?? "week"}` : "Every day";
    const facts = [
      ["State", tools.build_badge(schedule.enabled ? "enabled" : "disabled", schedule.enabled ? "enabled" : "paused")],
      ["Runs", `${when} at ${schedule.time} ${schedule.timezone}`],
      ["Next run", schedule.enabled ? format_date(schedule.next_run_at, schedule.timezone) : "Paused"],
      ["Last run", schedule.last_run_at ? format_date(schedule.last_run_at, schedule.timezone) : "No scheduled run yet"],
      ["Last changed", schedule.updated_at ? format_date(schedule.updated_at) : "Never saved: the default applies"],
    ];
    const note = build_element("p", { class: "muted" }, SWITCH_NOTE, build_element("a", { href: "#/ingestion", text: "Data ingestion" }), ".");
    return tools.build_panel("Current schedule", tools.build_facts(facts), note);
  }
}

/** Every zone the browser knows, with UTC and the saved one (not every browser lists them); null: no list. */
function list_time_zones(saved) {
  const zones = Intl.supportedValuesOf?.("timeZone");
  return zones ? [...new Set([...zones, "UTC", saved])].sort() : null;
}
