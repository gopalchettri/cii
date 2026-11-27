// Word export and printing, with no library: the page's content policy allows no script from another host.
// A Word document is written as a simple HTML document with the Word type (.doc): Word, LibreOffice and Pages
// open it as a formatted document. Every text is escaped; nothing from the API is read as markup.

/**
 * A block of the document:
 *   {heading: "text", level?: 1 | 2 | 3}
 *   {paragraph: "text"}
 *   {facts: [["Label", "value"], ...]}
 *   {list: ["item", ...]}
 *   {table: {columns: ["Title", ...], rows: [["cell", ...], ...]}}
 * @typedef {object} Block
 */

/**
 * Saves `blocks` as a Word document named `file_name` (".doc" is added).
 * @param {string} file_name
 * @param {string} title
 * @param {Block[]} blocks
 */
export function download_word(file_name, title, blocks) {
  const text = build_word_html(title, blocks);
  const blob = new Blob(["﻿", text], { type: "application/msword" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${safe_file_name(file_name)}.doc`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Opens the browser's print dialog (the print styles leave out the menu and the buttons; "Save as PDF" works). */
export function print_page() {
  window.print();
}

/** The document's text. Exported for the checks. @param {string} title @param {Block[]} blocks @returns {string} */
export function build_word_html(title, blocks) {
  const parts = blocks.map(build_block).join("\n");
  return [
    "<html><head><meta charset=\"utf-8\">",
    `<title>${escape(title)}</title>`,
    "<style>",
    "body{font-family:Calibri,Arial,sans-serif;font-size:11pt;color:#1f2937}",
    "h1{font-size:18pt;color:#0f2a5a}h2{font-size:14pt;color:#0f2a5a;margin-top:18pt}h3{font-size:12pt}",
    "table{border-collapse:collapse;width:100%;margin:6pt 0}th,td{border:1px solid #c7cdd8;padding:4pt;vertical-align:top;text-align:left}",
    "th{background:#eef2f8}dt{font-weight:bold;margin-top:4pt}dd{margin:0 0 4pt 0}",
    "</style></head><body>",
    `<h1>${escape(title)}</h1>`,
    `<p>Exported ${escape(new Date().toLocaleString())}</p>`,
    parts,
    "</body></html>",
  ].join("\n");
}

function build_block(block) {
  if (block.heading !== undefined) {
    const level = [1, 2, 3].includes(block.level) ? block.level + 1 : 2;
    return `<h${level}>${escape(block.heading)}</h${level}>`;
  }
  if (block.paragraph !== undefined) return `<p>${escape(block.paragraph)}</p>`;
  if (block.list) return `<ul>${block.list.map((item) => `<li>${escape(item)}</li>`).join("")}</ul>`;
  if (block.facts) {
    return `<dl>${block.facts.map(([label, value]) => `<dt>${escape(label)}</dt><dd>${escape(value)}</dd>`).join("")}</dl>`;
  }
  if (block.table) {
    const head = block.table.columns.map((column) => `<th>${escape(column)}</th>`).join("");
    const rows = block.table.rows.map((row) => `<tr>${row.map((cell) => `<td>${escape(cell)}</td>`).join("")}</tr>`).join("");
    return `<table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`;
  }
  return "";
}

function escape(value) {
  const text = value === null || value === undefined || value === "" ? "—" : String(value);
  return text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function safe_file_name(name) {
  return String(name || "export").replace(/[^\w .-]+/g, "_").slice(0, 120);
}
