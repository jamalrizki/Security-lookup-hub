// Text the Lookup page's Ask box handed over ("Open JWT decoder"), so a token,
// headers or a certificate are read here instead of being sent to the AI. Each
// tool calls takeHandoff() once its own listeners are attached, so there is no
// race with module loading. sessionStorage (this tab only) is cleared on read,
// and a handoff older than a minute is ignored.

export const HANDOFF_KEY = 'slh-analyze-handoff';
const MAX_AGE_MS = 60_000;

/** Returns the handed-over text for this tool (and removes it), or null. */
export function takeHandoff(tool, now = Date.now()) {
  try {
    const h = JSON.parse(sessionStorage.getItem(HANDOFF_KEY) || 'null');
    if (!h || h.tool !== tool) return null;
    sessionStorage.removeItem(HANDOFF_KEY);
    // No "at": handed over by an older cached copy of js/ask.js, so treat it as fresh.
    const stale = h.at !== undefined && !(now - h.at >= 0 && now - h.at <= MAX_AGE_MS);
    if (typeof h.text !== 'string' || stale) return null;
    return h.text;
  } catch {
    return null; // storage blocked: nothing to hand over
  }
}

/** Fills the tool's input, runs it, and scrolls to it, if text was handed over. */
export function receiveHandoff(tool, run) {
  const text = takeHandoff(tool);
  if (text === null) return;
  document.getElementById(`${tool}-input`).value = text;
  run(text);
  document.getElementById(tool)?.scrollIntoView({ block: 'start' });
}
