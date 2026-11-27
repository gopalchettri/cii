// API keys (admin key): every client and its state, mint a key (shown once), revoke one.

const FILTERS = [
  { value: "", label: "All keys" },
  { value: "true", label: "Active only" },
  { value: "false", label: "Revoked only" },
];
const NAME_MAX = 100; // the API's own limits (MintRequest)
const DESCRIPTION_MAX = 500;

/** @param {HTMLElement} container @param {object} tools the shell's tools (app.js) */
export async function show(container, tools) {
  tools.set_subtitle("The keys other systems use to call the service. A new key is shown once; a revoked key stops working at once.");
  const minted_place = tools.build_element("div", { hidden: true }); // no layout class: one would override [hidden]
  const list_place = tools.build_element("div", { class: "stack" });
  const filter = tools.build_select(FILTERS, "", { on: { change: () => load_keys() } });

  /** `quiet`: the old list stays until the new one is ready (after a revoke or a mint). */
  function load_keys(quiet = false) {
    const read = () => tools.request("GET", tools.with_query("/v1/tsg/api-clients", { active: filter.value }));
    return tools.load_into(list_place, read, (answer) => build_key_list(answer.items, filter.value, tools, revoke_key), { quiet });
  }

  async function revoke_key(client) {
    await tools.request("POST", `/v1/tsg/api-clients/${encodeURIComponent(client.client_id)}/revoke`);
    tools.show_notice(`The key of "${client.name}" is revoked. It no longer works.`, "good");
    await load_keys(true);
  }

  function forget_key() {
    for (const shown of minted_place.querySelectorAll("input")) shown.value = "";
    tools.replace_content(minted_place);
    minted_place.hidden = true;
  }

  async function mint_key(name, description) {
    const minted = await tools.request("POST", "/v1/tsg/api-clients", { name, description: description || null });
    forget_key();
    tools.replace_content(minted_place, build_minted_key(minted, tools, forget_key));
    minted_place.hidden = false;
    minted_place.querySelector("input").focus();
    tools.show_notice(`A key for "${minted.name}" was made. Copy it now: it is shown only this once.`, "good");
    load_keys(true);
  }

  tools.when_leaving(forget_key); // the key is on this page only: gone when the page is left
  const keys_section = tools.build_section(
    { title: "Keys", subtitle: "Every key, newest first. Only the first characters of a key are kept.", actions: [tools.build_button("Refresh", () => load_keys(true), { kind: "quiet" })] },
    tools.build_element("div", { class: "toolbar" }, tools.build_field("Show", filter)),
    list_place,
  );
  container.append(build_mint_section(tools, mint_key), minted_place, keys_section);
  await load_keys();
}

function build_mint_section(tools, mint_key) {
  const name = tools.build_element("input", { type: "text", required: true, maxlength: NAME_MAX, autocomplete: "off", spellcheck: "false" });
  const description = tools.build_element("input", { type: "text", maxlength: DESCRIPTION_MAX, autocomplete: "off" });
  const fields = [
    tools.build_row(
      tools.build_field("Name", name, { hint: "The system that will call the service with this key. One active key per name." }),
      tools.build_field("Description", description, { optional: true, hint: "What the key is for, or who looks after it." }),
    ),
  ];
  const form = tools.build_form(fields, "Make a key", async () => {
    await mint_key(name.value.trim(), description.value.trim());
    form.reset();
  });
  return tools.build_section({ title: "Make a new key", subtitle: "The key is shown once, right after it is made. Have your secret store ready." }, form);
}

/** The new key, shown this once: the API keeps only its hash, so nothing can show it again. */
function build_minted_key(minted, tools, forget_key) {
  const key_box = tools.build_element("input", {
    type: "text",
    readonly: true,
    class: "mono",
    value: minted.api_key,
    autocomplete: "off",
    spellcheck: "false",
    on: { focus: () => key_box.select() }, // no clipboard here (e.g. a page not on https): selected for Ctrl+C
  });
  const warning = tools.build_callout(
    tools.build_element("strong", { text: `New key for "${minted.name}": copy it now` }),
    "warn",
    tools.build_element("p", { text: "This key cannot be shown again. It is gone when you hide it, leave this page or reload. If it is lost, revoke it and make a new one." }),
    tools.build_field("API key (the calling system sends it as X-API-Key)", key_box, { hint: "If Copy does not work, click the key and press Ctrl+C." }),
    tools.build_actions(tools.build_copy(minted.api_key, "Copy key"), tools.build_button("I have stored it: hide", forget_key, { kind: "quiet" })),
  );
  return warning;
}

function build_key_list(clients, filter, tools, revoke_key) {
  const active = clients.filter((client) => client.active).length;
  const counts =
    filter === "" &&
    clients.length > 0 &&
    tools.build_kpis([
      { label: "Active keys", value: active, tone: "good" },
      { label: "Revoked keys", value: clients.length - active },
    ]);
  return [counts, build_key_table(clients, filter, tools, revoke_key)];
}

function build_key_table(clients, filter, tools, revoke_key) {
  const muted_line = (props) => tools.build_element("div", { class: "muted", ...props });
  const show_when = (when, who) => when && [tools.format_date(when), who && muted_line({ text: `by ${who}` })];
  const build_revoke = (client) => {
    const button = tools.build_button("Revoke", () => revoke_key(client), {
      kind: "danger",
      small: true,
      confirm: `Revoke the key of "${client.name}" (starts with ${client.key_prefix})? It stops working at once and cannot be restored.`,
    });
    button.setAttribute("aria-label", `Revoke the key of ${client.name}`);
    return button;
  };
  const columns = [
    {
      title: "Client",
      show: (client) => [
        tools.build_element("strong", { text: client.name }),
        client.description && muted_line({ text: client.description }),
        muted_line({ class: "muted mono", text: client.client_id }),
      ],
    },
    { title: "Key starts with", show: (client) => tools.build_element("span", { class: "mono", text: client.key_prefix }), nowrap: true },
    { title: "State", show: (client) => tools.build_badge(client.active ? "active" : "revoked") },
    { title: "Made", show: (client) => show_when(client.created_at, client.created_by), nowrap: true },
    { title: "Revoked", show: (client) => show_when(client.revoked_at, client.revoked_by), nowrap: true },
    { title: "Action", show: (client) => (client.active ? build_revoke(client) : "") },
  ];
  return tools.build_table(clients, columns, {
    caption: `${tools.format_count(clients.length)} ${clients.length === 1 ? "key" : "keys"}`,
    empty: filter === "" ? "No API key yet. Make the first one above." : "No key matches this choice. Choose All keys to see every key.",
  });
}
