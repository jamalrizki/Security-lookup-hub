// Ask's model providers. The loop in ask.js keeps one internal message format
// (OpenAI-style: system / user / assistant with tool_calls / tool) and calls
// chat(); this file turns that into each provider's request and back, so the
// caps, CVE checks and revision call work the same whatever answers.
//
//   ASK_MODEL (wrangler.toml [vars]) = "<provider>:<model>"
//     anthropic:claude-haiku-5-5   default; Messages API through the official SDK
//     anthropic:claude-sonnet-5-5
//     groq:openai/gpt-oss-120b     free tier
//     openai:<model>               needs OPENAI_API_KEY
//
// Chain: the selected (paid) model -> free Groq -> OpenRouter's free models.
// The paid model is skipped after DAILY_PAID_QUESTIONS a day, or if it fails for
// credit, billing or key reasons; OpenRouter takes over when Groq is busy or times
// out. There are no hub-side limits on the free models: their own rate limits and
// our request timeout are enough. The response says which model answered and why.
// The Explain button is separate and always uses Groq (explain.js).

import Anthropic from '@anthropic-ai/sdk';
import { MODEL as GROQ_MODEL } from './explain.js';
import { parseRetryWaitSeconds } from './retry-wait.js';
import { TOOL_DEFINITIONS } from './ask-tools.js';

export const DEFAULT_ASK_MODEL = 'anthropic:claude-haiku-5-5';
const PROVIDERS = ['anthropic', 'groq', 'openai'];
const KEYS = { anthropic: 'ANTHROPIC_API_KEY', groq: 'GROQ_API_KEY', openai: 'OPENAI_API_KEY' };
const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];
// A Groq 429 asking for a short wait is waited out (total per question); a longer
// one hands the question to OpenRouter.
const GROQ_SHORT_WAIT_S = 5;
const UPSTREAM_TIMEOUT_MS = 30000;
// Questions a day the paid model answers; after that, the free models until midnight
// UTC. The only limit on models.
export const DAILY_PAID_QUESTIONS = 100;
// Claude's adaptive thinking counts toward max_tokens (and is billed as output), so
// Claude calls get room for it; the answer's own length is guarded in ask.js.
const CLAUDE_MAX_TOKENS = 4000;
const OPENAI_STYLE_MAX_TOKENS = 1500;
const OPENROUTER_MODEL = 'openrouter/free';

// What happened, in the visitor's words (js/ask.js shows the notes after "Answered by").
export const ALL_BUSY = 'All free AI providers are busy. Try again in a minute.';

// Tests replace sleep so a "try again in 435ms" retry doesn't really wait.
export const askTiming = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)) };

export class BusyError extends Error {}

const utcDay = (now) => now.toISOString().slice(0, 10);

/**
 * Counts one question against the paid model's daily cap, in KV (one write per
 * question, expires after 2 days). Returns false when today's cap is used up.
 * Without a KV binding (local tests) there is no cap.
 */
export async function takePaidQuestion(kv, now = new Date()) {
  if (!kv) return true;
  const key = `ask:paid:${utcDay(now)}`;
  const used = Number(await kv.get(key)) || 0;
  if (used >= DAILY_PAID_QUESTIONS) return false;
  await kv.put(key, String(used + 1), { expirationTtl: 2 * 86400 });
  return true;
}

/** The selected model from ASK_MODEL: { provider, model }. Anything malformed means the default. */
export function askModel(env = {}) {
  const raw = String(env.ASK_MODEL || '').trim();
  const m = /^([a-z]+):(\S+)$/.exec(raw);
  if (m && PROVIDERS.includes(m[1])) return { provider: m[1], model: m[2] };
  const [provider, model] = DEFAULT_ASK_MODEL.split(':');
  return { provider, model };
}

/** True if this error means the provider can't be used for credit, billing or key reasons. */
export function isBillingError(err) {
  if (err?.noKey) return true;
  const status = err?.status;
  const type = err?.error?.error?.type || err?.error?.type || err?.type || '';
  const text = `${err?.message || ''} ${JSON.stringify(err?.error || '')}`;
  if (status === 401 || status === 402 || status === 403) return true; // bad key, billing_error, permission
  if (/billing_error|insufficient_quota/.test(type) || /insufficient_quota/.test(text)) return true;
  if (status === 400 && /credit balance|billing|purchase credits/i.test(text)) return true;
  return false;
}

// ---------- OpenAI-style providers (Groq, OpenAI, OpenRouter) ----------

class ProviderError extends Error {
  constructor(status, detail) {
    super(`HTTP ${status}: ${detail}`);
    this.status = status;
  }
}

/** Internal messages -> OpenAI chat messages (drops fields only Claude replays). */
function toOpenAI(messages) {
  return messages.map(({ role, content, tool_calls, tool_call_id }) => {
    if (role === 'tool') return { role, tool_call_id, content };
    if (role === 'assistant' && tool_calls) return { role, content: content || null, tool_calls };
    return { role, content: content ?? '' };
  });
}

function openAIStyle(provider, model, env) {
  if (provider === 'groq') {
    return {
      name: 'groq', model, key: env.GROQ_API_KEY,
      url: 'https://api.groq.com/openai/v1/chat/completions',
      // Default (medium) reasoning: 'low' skipped tools it needed (asked whether a product was affected by a flaw, it told the visitor to search).
      extra: { include_reasoning: false, max_completion_tokens: OPENAI_STYLE_MAX_TOKENS, temperature: 0.2 },
    };
  }
  if (provider === 'openai') {
    return { name: 'openai', model, key: env.OPENAI_API_KEY, url: 'https://api.openai.com/v1/chat/completions', extra: { max_completion_tokens: OPENAI_STYLE_MAX_TOKENS } };
  }
  return {
    name: 'openrouter', model: OPENROUTER_MODEL, key: env.OPENROUTER_API_KEY,
    url: 'https://openrouter.ai/api/v1/chat/completions', headers: { 'X-Title': 'Security Lookup Hub' },
    extra: { max_tokens: OPENAI_STYLE_MAX_TOKENS, temperature: 0.2 },
  };
}

async function callOpenAIStyle(p, messages, toolChoice) {
  const res = await fetch(p.url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${p.key}`, ...p.headers },
    body: JSON.stringify({ model: p.model, messages: toOpenAI(messages), tools: TOOL_DEFINITIONS, tool_choice: toolChoice, ...p.extra }),
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  if (!res.ok) throw new ProviderError(res.status, (await res.text()).slice(0, 300));
  const data = await res.json();
  const message = data?.choices?.[0]?.message;
  if (!message) throw new Error('no message in model response');
  return { message, provider: p.name, model: data.model || p.model };
}

// Groq: a 429 that asks for a short wait is waited out (at most GROQ_SHORT_WAIT_S per
// question); a longer one is "busy" and goes to OpenRouter.
async function callGroq(p, messages, toolChoice, run) {
  for (;;) {
    try {
      return await callOpenAIStyle(p, messages, toolChoice);
    } catch (err) {
      if (err.status !== 429) throw err;
      const wait = parseRetryWaitSeconds(err.message);
      if (!(wait > 0) || run.waited + wait > GROQ_SHORT_WAIT_S) throw new BusyError('groq busy');
      run.waited += wait;
      await askTiming.sleep(Math.ceil(wait * 1000) + 250);
    }
  }
}

// ---------- Anthropic (Messages API) ----------

const CLAUDE_TOOLS = TOOL_DEFINITIONS.map(({ function: f }) => ({ name: f.name, description: f.description, input_schema: f.parameters }));
// Instructions the loop adds mid-conversation (final round, revisions) travel as
// user text, so they work on every Claude model.
const NOTE = (text) => `[Ask service instruction] ${text}`;

/**
 * Internal messages -> { system, messages } for the Messages API. Consecutive
 * turns of the same role are merged (tool results from one round go back in a
 * single user turn, results first), and an assistant turn Claude produced is
 * replayed with its original content blocks, thinking included.
 */
export function toAnthropic(messages) {
  const system = [];
  const out = [];
  const push = (role, blocks) => {
    if (!blocks.length) return;
    const last = out[out.length - 1];
    if (last && last.role === role) last.content.push(...blocks);
    else out.push({ role, content: [...blocks] });
  };
  messages.forEach((m, i) => {
    if (m.role === 'system') {
      if (i === 0) system.push({ type: 'text', text: m.content });
      else push('user', [{ type: 'text', text: NOTE(m.content) }]);
    } else if (m.role === 'user') {
      push('user', [{ type: 'text', text: m.content }]);
    } else if (m.role === 'tool') {
      push('user', [{ type: 'tool_result', tool_use_id: m.tool_call_id, content: String(m.content) }]);
    } else if (m.role === 'assistant') {
      if (Array.isArray(m.claude)) return push('assistant', m.claude);
      const blocks = m.content ? [{ type: 'text', text: m.content }] : [];
      for (const c of m.tool_calls || []) {
        let input = {};
        try { input = JSON.parse(c.function?.arguments || '{}'); } catch { /* sent as {} */ }
        blocks.push({ type: 'tool_use', id: c.id, name: c.function?.name, input });
      }
      push('assistant', blocks);
    }
  });
  // Cache the stable prefix: tools render before system, so one breakpoint on the
  // system prompt covers both.
  if (system.length) system[system.length - 1].cache_control = { type: 'ephemeral' };
  return { system, messages: out };
}

/** A Messages API response -> the internal assistant message. */
export function fromAnthropic(response) {
  const blocks = Array.isArray(response?.content) ? response.content : [];
  const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim();
  const calls = blocks.filter((b) => b.type === 'tool_use').map((b) => ({ id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) } }));
  return { role: 'assistant', content: text, ...(calls.length ? { tool_calls: calls } : {}), claude: blocks };
}

async function callAnthropic(model, messages, toolChoice, env) {
  const client = new Anthropic({
    apiKey: env.ANTHROPIC_API_KEY,
    maxRetries: 1,
    timeout: UPSTREAM_TIMEOUT_MS,
    fetch: (...args) => globalThis.fetch(...args),
  });
  const { system, messages: msgs } = toAnthropic(messages);
  // No thinking parameter: adaptive thinking is the default on the Claude 5.5 models.
  // Effort stays at the model's default unless ASK_EFFORT is set. No temperature.
  const effort = EFFORTS.includes(env.ASK_EFFORT) ? env.ASK_EFFORT : null;
  const response = await client.messages.create({
    model,
    max_tokens: CLAUDE_MAX_TOKENS,
    system,
    tools: CLAUDE_TOOLS,
    tool_choice: { type: toolChoice === 'none' ? 'none' : 'auto' },
    messages: msgs,
    ...(effort ? { output_config: { effort } } : {}),
  });
  return { message: fromAnthropic(response), provider: 'anthropic', model: response.model || model };
}

// ---------- One model call ----------

const busyOrDown = (err) => err instanceof BusyError || err?.name === 'TimeoutError' || err?.status >= 500 || Boolean(err?.noKey);

/** Free Groq, then OpenRouter's free models when Groq is busy, times out or is down. */
async function callFree(messages, toolChoice, run) {
  const { env } = run;
  if (!run.relay) {
    try {
      if (!env.GROQ_API_KEY) throw Object.assign(new Error('GROQ_API_KEY is not set'), { noKey: true });
      return await callGroq(openAIStyle('groq', GROQ_MODEL, env), messages, toolChoice, run);
    } catch (err) {
      if (!busyOrDown(err)) throw err;
      if (!env.OPENROUTER_API_KEY) throw new BusyError(ALL_BUSY);
      run.relay = { from: 'groq', to: 'openrouter', reason: err instanceof BusyError ? 'busy' : err?.name === 'TimeoutError' ? 'timeout' : 'unavailable' };
    }
  }
  try {
    return await callOpenAIStyle(openAIStyle('openrouter', null, env), messages, toolChoice);
  } catch (err) {
    if (busyOrDown(err) || err.status === 429) throw new BusyError(ALL_BUSY);
    throw err;
  }
}

/**
 * One model call for the loop: the selected model, unless today's paid cap or a
 * credit/billing/key failure moved the question to the free chain (run.fallback
 * records why; it holds for the rest of the question, as does run.relay).
 */
export async function chat(messages, toolChoice, run) {
  if (!run.selected) run.selected = askModel(run.env);
  const sel = run.selected;
  if (sel.provider === 'groq') return callFree(messages, toolChoice, run);
  if (!run.fallback) {
    try {
      if (!run.env[KEYS[sel.provider]]) throw Object.assign(new Error(`${KEYS[sel.provider]} is not set`), { noKey: true });
      if (sel.provider === 'anthropic') return await callAnthropic(sel.model, messages, toolChoice, run.env);
      return await callOpenAIStyle(openAIStyle(sel.provider, sel.model, run.env), messages, toolChoice);
    } catch (err) {
      if (!isBillingError(err)) throw err;
      run.fallback = { from: `${sel.provider}:${sel.model}`, reason: err.noKey ? 'no API key' : 'credit or billing' };
    }
  }
  return callFree(messages, toolChoice, run);
}
