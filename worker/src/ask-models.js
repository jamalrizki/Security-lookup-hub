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
// If the selected provider can't be used for credit or billing reasons (or its
// key isn't set), the rest of the question goes to free Groq, and the response
// says so. The Explain button is separate and always uses Groq (explain.js).

import Anthropic from '@anthropic-ai/sdk';
import { MODEL as GROQ_MODEL } from './explain.js';
import { parseRetryWaitSeconds } from './retry-wait.js';
import { TOOL_DEFINITIONS } from './ask-tools.js';

export const DEFAULT_ASK_MODEL = 'anthropic:claude-haiku-5-5';
const PROVIDERS = ['anthropic', 'groq', 'openai'];
const KEYS = { anthropic: 'ANTHROPIC_API_KEY', groq: 'GROQ_API_KEY', openai: 'OPENAI_API_KEY' };
const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];
const MAX_RATE_LIMIT_WAIT_S = 20; // total Groq 429 waiting per question
const UPSTREAM_TIMEOUT_MS = 30000;
const GROQ_PER_MINUTE = 20; // shared with the Explain button
// Claude's adaptive thinking counts toward max_tokens (and is billed as output), so
// Claude calls get room for it; the answer's own length is guarded in ask.js.
const CLAUDE_MAX_TOKENS = 4000;
const OPENAI_STYLE_MAX_TOKENS = 1500;
const OPENROUTER_MODEL = 'openrouter/free';

export const BUSY = 'Ask is busy (free tier limit). Try again in a minute.';

// Tests replace sleep so a "try again in 435ms" retry doesn't really wait.
export const askTiming = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)) };

export class BusyError extends Error {}

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
      name: 'groq', model, key: env.GROQ_API_KEY, quota: 'GROQ_API_KEY',
      url: 'https://api.groq.com/openai/v1/chat/completions',
      // Default (medium) reasoning: 'low' skipped tools it needed (the TRIRIGA answer).
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

// Groq: site-wide quota (shared with Explain), and short 429 waits are retried
// while the question's total wait stays within MAX_RATE_LIMIT_WAIT_S.
async function callGroq(p, messages, toolChoice, run) {
  for (;;) {
    if ((await run.quota.paused(p.quota)) || !(await run.quota.allow(p.quota, GROQ_PER_MINUTE))) throw new BusyError(BUSY);
    try {
      return await callOpenAIStyle(p, messages, toolChoice);
    } catch (err) {
      if (err.status !== 429) throw err;
      const wait = parseRetryWaitSeconds(err.message);
      if (!(wait > 0) || run.waited + wait > MAX_RATE_LIMIT_WAIT_S) throw new BusyError(BUSY);
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

async function callSelected(sel, messages, toolChoice, run) {
  const { env } = run;
  if (!env[KEYS[sel.provider]]) throw Object.assign(new Error(`${KEYS[sel.provider]} is not set`), { noKey: true });
  if (sel.provider === 'anthropic') return callAnthropic(sel.model, messages, toolChoice, env);
  const p = openAIStyle(sel.provider, sel.model, env);
  return sel.provider === 'groq' ? callGroq(p, messages, toolChoice, run) : callOpenAIStyle(p, messages, toolChoice);
}

// OpenRouter, if its key is set, is the last resort when the provider in use fails.
async function lastResort(err, messages, toolChoice, env) {
  if (!env.OPENROUTER_API_KEY) throw err;
  try {
    return await callOpenAIStyle(openAIStyle('openrouter', null, env), messages, toolChoice);
  } catch {
    throw err;
  }
}

/**
 * One model call for the loop. Uses the selected model; after a credit, billing
 * or missing-key failure it switches the rest of the question to free Groq
 * (run.fallback records why).
 */
export async function chat(messages, toolChoice, run) {
  if (!run.selected) run.selected = askModel(run.env);
  if (!run.fallback) {
    try {
      return await callSelected(run.selected, messages, toolChoice, run);
    } catch (err) {
      if (run.selected.provider === 'groq' || !isBillingError(err)) return lastResort(err, messages, toolChoice, run.env);
      run.fallback = { from: `${run.selected.provider}:${run.selected.model}`, reason: err.noKey ? 'no API key' : 'credit or billing' };
    }
  }
  try {
    return await callSelected({ provider: 'groq', model: GROQ_MODEL }, messages, toolChoice, run);
  } catch (err) {
    return lastResort(err, messages, toolChoice, run.env);
  }
}
