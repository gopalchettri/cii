// Live updates from the API's event streams (a run's progress, a plan's, a service mapping's). The browser's
// EventSource cannot send the API key, so the stream is read with fetch(): each "event:"/"data:" block becomes
// one on_event(type, data). A dropped stream reconnects after 1, 2, 4 ... up to 30 s; a refusal (401, 403) or a
// run that is gone (404, 410) ends it. Pages keep a slower poll as a backstop (poll.js).

import { build_headers, is_own_path, read_problem } from "./api.js";

const BACKOFF_SECONDS = [1, 2, 4, 8, 16, 30];
const ENDS_THE_STREAM = new Set([401, 403, 404, 410]);

/**
 * Follows the event stream at `path` with the signed-in person's headers until stop() is called.
 * @param {string} path e.g. `/v1/sessions/${id}/events`
 * @param {{on_event: (type: string, data: any) => void, on_state?: (state: "connecting" | "live" | "retrying" | "ended", error?: Error) => void}} handlers
 * @returns {() => void} stop
 */
export function follow_stream(path, { on_event, on_state = () => {} }) {
  let stopped = false;
  let attempt = 0;
  let timer = null;
  let controller = null;

  function stop() {
    stopped = true;
    clearTimeout(timer);
    controller?.abort();
  }

  function retry(error) {
    if (stopped) return;
    on_state("retrying", error);
    const seconds = BACKOFF_SECONDS[Math.min(attempt, BACKOFF_SECONDS.length - 1)];
    attempt += 1;
    timer = setTimeout(connect, seconds * 1000);
  }

  async function connect() {
    if (stopped) return;
    if (!is_own_path(path)) {
      on_state("ended", new Error(`Not a path of this API: ${path}`));
      return;
    }
    on_state("connecting");
    controller = new AbortController();
    let response;
    try {
      const headers = { ...build_headers({ client: true }), Accept: "text/event-stream" };
      response = await fetch(path, { headers, cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer", signal: controller.signal });
    } catch (error) {
      if (!stopped) retry(error);
      return;
    }
    if (!response.ok || !response.body) {
      const text = await response.text().catch(() => "");
      let answer = null;
      try {
        answer = JSON.parse(text);
      } catch {
        answer = null;
      }
      const problem = read_problem(response, answer);
      if (ENDS_THE_STREAM.has(response.status)) {
        stopped = true;
        on_state("ended", problem);
      } else retry(problem);
      return;
    }
    attempt = 0;
    on_state("live");
    try {
      await read_events(response.body, on_event, () => stopped);
    } catch (error) {
      if (stopped) return;
      retry(error);
      return;
    }
    if (!stopped) retry(null); // the server closed the stream: open it again
  }

  connect();
  return stop;
}

/**
 * Reads a text/event-stream body block by block. Exported for the checks.
 * @param {ReadableStream<Uint8Array>} body
 * @param {(type: string, data: any) => void} on_event
 * @param {() => boolean} is_stopped
 */
export async function read_events(body, on_event, is_stopped) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (!is_stopped()) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true }).replaceAll("\r\n", "\n");
    let end = buffer.indexOf("\n\n");
    while (end !== -1) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      const event = parse_block(block);
      if (event) on_event(event.type, event.data);
      end = buffer.indexOf("\n\n");
    }
  }
  reader.cancel().catch(() => {});
}

/** One block: its "event:" type (default "message") and its "data:" lines read as JSON when they are. */
export function parse_block(block) {
  let type = "message";
  const data = [];
  for (const line of block.split("\n")) {
    if (line.startsWith(":")) continue; // a comment: the server's keep-alive ping
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
    if (field === "event") type = value;
    else if (field === "data") data.push(value);
  }
  if (data.length === 0) return null;
  const text = data.join("\n");
  try {
    return { type, data: JSON.parse(text) };
  } catch {
    return { type, data: text };
  }
}
