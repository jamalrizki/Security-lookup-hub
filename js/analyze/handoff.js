// Receives text the Lookup page's Ask box handed over ("Open JWT decoder"), so a
// token, headers or certificate are read here instead of being sent to the AI.
// sessionStorage (this tab only) is cleared as soon as it is read.

const KEY = 'slh-analyze-handoff';
const TOOLS = ['jwt', 'headers', 'cert'];

let handoff = null;
try {
  handoff = JSON.parse(sessionStorage.getItem(KEY) || 'null');
  sessionStorage.removeItem(KEY);
} catch { /* storage blocked: nothing to hand over */ }

if (handoff && TOOLS.includes(handoff.tool) && typeof handoff.text === 'string') {
  const input = document.getElementById(`${handoff.tool}-input`);
  const form = document.getElementById(`${handoff.tool}-form`);
  if (input && form) {
    input.value = handoff.text;
    // Some tool modules attach their listeners after a top-level await, so submit once everything has loaded.
    const run = () => setTimeout(() => {
      form.requestSubmit();
      document.getElementById(handoff.tool)?.scrollIntoView({ block: 'start' });
    }, 0);
    if (document.readyState === 'complete') run();
    else window.addEventListener('load', run, { once: true });
  }
}
