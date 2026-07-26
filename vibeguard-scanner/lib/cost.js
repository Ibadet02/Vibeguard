// Token accounting and the per-scan spend cap.
//
// The AI pass is an agentic loop: every turn resends the whole conversation, so
// input tokens compound with each tool call. On a large repo that is the
// difference between a scan costing cents and costing dollars, and a free
// public scanner with no ceiling is a way to lose money at the speed of a
// Reddit post. This module prices each turn as it happens so the loop can stop
// itself before the bill lands.
//
// Config (env):
//   VIBEGUARD_LLM_MAX_USD    hard ceiling per scan (default 0.50, 0 disables)
//   VIBEGUARD_LLM_PRICE_IN   $/million input tokens, overrides the table
//   VIBEGUARD_LLM_PRICE_OUT  $/million output tokens, overrides the table

// Anthropic first-party list prices, US dollars per million tokens.
// Update when prices change; an unknown model falls back to FALLBACK_PRICE.
const PRICES = {
  "claude-fable-5": { in: 10, out: 50 },
  "claude-mythos-5": { in: 10, out: 50 },
  "claude-opus-5": { in: 5, out: 25 },
  "claude-opus-4-8": { in: 5, out: 25 },
  "claude-opus-4-7": { in: 5, out: 25 },
  "claude-opus-4-6": { in: 5, out: 25 },
  "claude-opus-4-5": { in: 5, out: 25 },
  "claude-sonnet-5": { in: 3, out: 15 },
  "claude-sonnet-4-6": { in: 3, out: 15 },
  "claude-sonnet-4-5": { in: 3, out: 15 },
  "claude-haiku-4-5": { in: 1, out: 5 },
};

// Anything we don't recognise (an OpenAI model, a gateway's own name) is priced
// at the most expensive tier we support. Over-estimating stops the scan early;
// under-estimating overspends, so guess high and let the operator correct it
// with VIBEGUARD_LLM_PRICE_IN / _OUT.
const FALLBACK_PRICE = { in: 10, out: 50, estimated: true };

// Cached input is billed at a fraction of the base input rate; writing the
// cache costs a premium. We use the default 5-minute TTL.
const CACHE_READ_MULT = 0.1;
const CACHE_WRITE_MULT = 1.25;

export function priceFor(model) {
  const inOverride = Number(process.env.VIBEGUARD_LLM_PRICE_IN);
  const outOverride = Number(process.env.VIBEGUARD_LLM_PRICE_OUT);
  if (Number.isFinite(inOverride) && Number.isFinite(outOverride) && inOverride >= 0 && outOverride >= 0) {
    return { in: inOverride, out: outOverride, estimated: false };
  }
  const id = String(model || "").toLowerCase();
  if (PRICES[id]) return { ...PRICES[id], estimated: false };
  // Tolerate dated or suffixed ids ("claude-opus-5-20260101", "anthropic.claude-opus-5").
  for (const [name, price] of Object.entries(PRICES)) {
    if (id.includes(name)) return { ...price, estimated: false };
  }
  return { ...FALLBACK_PRICE };
}

// Normalise a provider's usage object into { input, output, cacheRead, cacheWrite }.
//
// The two providers count differently and getting this backwards silently
// doubles or halves every estimate: Anthropic's `input_tokens` is the UNCACHED
// remainder (total = input + cache_read + cache_creation), while OpenAI's
// `prompt_tokens` is the TOTAL and `cached_tokens` is a subset of it.
export function normalizeUsage(raw, api) {
  const u = raw && typeof raw === "object" ? raw : {};
  const n = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

  if (api === "anthropic") {
    return {
      input: n(u.input_tokens),
      output: n(u.output_tokens),
      cacheRead: n(u.cache_read_input_tokens),
      cacheWrite: n(u.cache_creation_input_tokens),
    };
  }

  const cached = n(u.prompt_tokens_details?.cached_tokens);
  return {
    input: Math.max(0, n(u.prompt_tokens) - cached),
    output: n(u.completion_tokens),
    cacheRead: cached,
    cacheWrite: 0,
  };
}

export function costOf(usage, price) {
  const perInput = price.in / 1e6;
  return (
    usage.input * perInput +
    usage.cacheRead * perInput * CACHE_READ_MULT +
    usage.cacheWrite * perInput * CACHE_WRITE_MULT +
    (usage.output * price.out) / 1e6
  );
}

export function maxScanUsd() {
  const raw = process.env.VIBEGUARD_LLM_MAX_USD;
  if (raw === undefined || raw === "") return 0.5;
  const v = Number(raw);
  if (!Number.isFinite(v) || v < 0) return 0.5;
  return v; // 0 = no cap
}

// Running total for one scan. `spent()` is what the loop checks between turns.
export class CostMeter {
  constructor(model, maxUsd = maxScanUsd()) {
    this.price = priceFor(model);
    this.maxUsd = maxUsd;
    this.usd = 0;
    this.turns = 0;
    this.tokens = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  }

  // Record one API response. Returns the cost of that turn alone.
  add(rawUsage, api) {
    const u = normalizeUsage(rawUsage, api);
    for (const k of Object.keys(this.tokens)) this.tokens[k] += u[k];
    const turnUsd = costOf(u, this.price);
    this.usd += turnUsd;
    this.turns++;
    return turnUsd;
  }

  // Cap disabled with 0, so an unset ceiling never blocks a scan.
  get capped() {
    return this.maxUsd > 0;
  }

  // Budget is gone: stop exploring and ask the model to write up what it has.
  exhausted() {
    return this.capped && this.usd >= this.maxUsd;
  }

  // Even the wrap-up turn costs money. Past this we abandon the pass entirely
  // rather than let a pathological repo bill its way out of the soft limit.
  overHardCeiling() {
    return this.capped && this.usd >= this.maxUsd * 1.5;
  }

  summary() {
    return {
      usd: Math.round(this.usd * 10000) / 10000,
      maxUsd: this.capped ? this.maxUsd : null,
      estimated: Boolean(this.price.estimated),
      turns: this.turns,
      tokens: { ...this.tokens },
    };
  }

  toString() {
    const t = this.tokens;
    return (
      `$${this.usd.toFixed(4)}${this.price.estimated ? " (est.)" : ""}` +
      `${this.capped ? ` of $${this.maxUsd.toFixed(2)}` : ""}` +
      ` over ${this.turns} call${this.turns === 1 ? "" : "s"}` +
      ` [in ${t.input}, cached ${t.cacheRead}, out ${t.output}]`
    );
  }
}
