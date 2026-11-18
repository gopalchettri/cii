// API keys (admin key): every client and its state, mint a key (shown once), revoke one.

const FILTERS = [
  { value: "", label: "All" },
  { value: "true", label: "Active" },
  { value: "false", label: "Revoked" },
];
const NAME_MAX = 100; // the API's own limits (MintRequest)
const DESCRIPTION_MAX = 500;

/** @param {HTMLElement} container @param {object} tools the shell's tools (app.js) */
export async function show(container, tools) {
  // "columns" on a place: its content takes the place's width, so a wide table scrolls in its own box, not the page.
  const minted_place = tools.build_element("div", { class: "columns", hidden: true });
  const list_place = tools.build_element("div", { class: "columns" });
  const filter = tools.build_select(FILTERS, "", { on: { change: () => load_keys() } });

  function load_keys() {
    const box = tools.build_element("div"); // a load that is overtaken answers into a box no longer shown
    tools.replace_content(list_place, box);
    const read = () => tools.request("GET", tools.with_query("/v1/tsg/api-clients", { active: filter.value }));
    return tools.load_into(box, read, (answer) => build_key_table(answer.items, filter.value, tools, revoke_key));
  }

  async function revoke_key(client) {
    await tools.request("POST", `/v1/tsg/api-clients/${encodeURIComponent(client.client_id)}/revoke`);
    tools.show_notice(`The key of "${client.name}" is revoked. It no longer works.`, "good");
    await load_keys();
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
    minted_place.querySelector("button").focus();
    load_keys();
  }

  tools.when_leaving(forget_key); // the key is on this page only: gone when the page is left
  const toolbar = tools.build_element("div", { class: "toolbar" }, tools.build_field("Show", filter), tools.build_button("Refresh", () => load_keys()));
  container.append(build_mint_panel(tools, mint_key), minted_place, tools.build_panel("Keys", toolbar, list_place));
  await load_keys();
}

function build_mint_panel(tools, mint_key) {
  const name = tools.build_element("input", { type: "text", required: true, maxlength: NAME_MAX, autocomplete: "off", spellcheck: "false" });
  const description = tools.build_element("input", { type: "text", maxlength: DESCRIPTION_MAX, autocomplete: "off" });
  const fields = [
    tools.build_field("Name", name, { hint: "The system that will call the API with this key. One active key per name." }),
    tools.build_field("Description (optional)", description),
  ];
  const form = tools.build_form(fields, "Mint key", async () => {
    await mint_key(name.value.trim(), description.value.trim());
    form.reset();
  });
  return tools.build_panel("Mint a key", form);
}

/** The new key, shown this once: the API keeps only its hash, so nothing can show it again. */
function build_minted_key(minted, tools, forget_key) {
  const key_box = tools.build_element("input", {
    type: "text",
    readonly: true,
    class: "mono",
    value: minted.api_key,
    size: minted.api_key.length,
    autocomplete: "off",
    spellcheck: "false",
    on: { focus: () => key_box.select() },
  });
  const copy_state = tools.build_element("span", { class: "muted", role: "status" });
  const copy = tools.build_button(
    "Copy key",
    async () => {
      try {
        await navigator.clipboard.writeText(key_box.value);
        copy_state.textContent = "Copied. Store it in your secret store now.";
      } catch {
        key_box.focus(); // no clipboard here (e.g. a page not on https): the key is selected for Ctrl+C
        copy_state.textContent = "This browser did not allow the copy. The key is selected: press Ctrl+C.";
      }
    },
    { kind: "primary" },
  );
  const warning = tools.build_element(
    "p",
    {},
    tools.build_badge("warning", "Shown once", "warn"),
    " Copy this key now and store it safely. It cannot be shown again: it is gone when you hide it, leave this page or reload. ",
    "If it is lost, revoke it and mint a new one.",
  );
  return tools.build_panel(
    `New key for "${minted.name}"`,
    warning,
    tools.build_field("API key (the caller sends it as X-API-Key)", key_box),
    tools.build_actions(copy, tools.build_button("I have stored it: hide", forget_key, { kind: "quiet" }), copy_state),
  );
}

function build_key_table(clients, filter, tools, revoke_key) {
  const muted_line = (props) => tools.build_element("div", { class: "muted", ...props });
  const show_when = (when, who) => when && [tools.format_date(when), who && muted_line({ text: `by ${who}` })];
  const build_revoke = (client) =>
    tools.build_button("Revoke", () => revoke_key(client), {
      kind: "danger",
      confirm: `Revoke the key of "${client.name}" (starts with ${client.key_prefix})? It stops working at once and cannot be restored.`,
    });
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
    { title: "Created", show: (client) => show_when(client.created_at, client.created_by), nowrap: true },
    { title: "Revoked", show: (client) => show_when(client.revoked_at, client.revoked_by), nowrap: true },
    { title: "Action", show: (client) => (client.active ? build_revoke(client) : "") },
  ];
  return tools.build_table(clients, columns, {
    caption: `${tools.format_count(clients.length)} ${clients.length === 1 ? "key" : "keys"}`,
    empty: filter === "" ? "No API key yet. Mint the first one above." : "No key matches this filter.",
  });
}
