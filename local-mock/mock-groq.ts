/**
 * LOCAL TESTING ONLY. Loaded only when MOCK_GROQ=1, MOCK_LLM=1, or MOCK_GEMINI=1.
 * Never calls the real Groq API.
 *
 * Mode is read on every call from the file named by MOCK_GROQ_MODE_FILE or
 * MOCK_GEMINI_MODE_FILE (if it exists), or from MOCK_GROQ_MODE / MOCK_GEMINI_MODE.
 * Modes:
 *   match     model severity = code floor (default)
 *   under     model always says Baseline – Minor (floors must raise it)
 *   over      model always says Severe (max() must keep it)
 *   multi     one cluster per flagged category, model severity Baseline – Minor
 *   benign    model returns no scorecards, everything benign
 *   fail429   every attempt throws 429 RESOURCE_EXHAUSTED
 *   fail503   every attempt throws 503 UNAVAILABLE
 *   once503   first attempt for a given prompt throws 503, the retry succeeds (as "match")
 *   hang      never answers (only ends when the server aborts the attempt)
 *   malformed returns text that is not JSON
 *   empty     returns empty text
 *   maxtokens finishReason MAX_TOKENS
 */
import fs from 'fs';
import crypto from 'crypto';

type Schema = {
  type?: string;
  properties?: Record<string, Schema>;
  items?: Schema;
  enum?: string[];
  required?: string[];
  nullable?: boolean;
};

class MockApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

const seenPrompts = new Set<string>();
export let mockCallCount = 0;

function currentMode(): string {
  for (const file of [process.env.MOCK_GROQ_MODE_FILE, process.env.MOCK_GEMINI_MODE_FILE]) {
    if (file && fs.existsSync(file)) {
      const v = fs.readFileSync(file, 'utf8').trim();
      if (v) return v;
    }
  }
  return (process.env.MOCK_GROQ_MODE || process.env.MOCK_GEMINI_MODE || 'match').trim();
}

export function backoffScale(): number {
  const v = Number(process.env.MOCK_BACKOFF_SCALE ?? '0.1');
  return Number.isFinite(v) && v >= 0 ? v : 0.1;
}

const LEVELS: Record<string, { name: string; color: string }> = {
  EMERGENCY_BLACK: { name: 'Emergency', color: 'Black' },
  SEVERE_RED: { name: 'Severe', color: 'Red' },
  HIGH_ORANGE: { name: 'High', color: 'Orange' },
  MEDIUM_YELLOW: { name: 'Medium', color: 'Yellow' },
  LOW_GREEN: { name: 'Low', color: 'Green' },
  BASELINE_MINOR_BLUE: { name: 'Baseline – Minor', color: 'Blue' },
  BASELINE_NEGLIGIBLE_WHITE: { name: 'Baseline – Negligible', color: 'White' },
  UNSCORABLE_GRAY: { name: 'Unscorable', color: 'Gray' },
};

// Schema-driven filler so the mock always matches the exact responseSchema the server sends.
function fill(schema: Schema | undefined, key: string): unknown {
  if (!schema) return null;
  const t = String(schema.type || '').toUpperCase();
  if (schema.enum && schema.enum.length) return schema.enum[0];
  switch (t) {
    case 'OBJECT': {
      const out: Record<string, unknown> = {};
      for (const [k, s] of Object.entries(schema.properties || {})) out[k] = fill(s, k);
      return out;
    }
    case 'ARRAY':
      return [fill(schema.items, key), fill(schema.items, key)].filter((v) => v !== null);
    case 'BOOLEAN':
      return false;
    case 'NUMBER':
    case 'INTEGER':
      return 1;
    case 'STRING':
    default:
      return `[mock] ${key} text (CISA IR Playbook p. 12)`;
  }
}

function setLevel(card: Record<string, any>, code: string) {
  card.severity = card.severity || {};
  card.severity.levelCode = code;
  // Old-style official NCISS names (Severe, not Critical) — the server must normalize display.
  card.severity.ncissLevelName = LEVELS[code].name;
  card.severity.colorName = LEVELS[code].color;
  card.severity.ncissDefinitionQuote =
    code === 'SEVERE_RED'
      ? 'A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties.'
      : `[mock] Official NCISS definition for ${LEVELS[code].name}.`;
  card.severity.ncissCitation =
    code === 'SEVERE_RED'
      ? 'CISA NCISS, Priority Levels — Severe (Red), p. 5'
      : `CISA NCISS, Priority Levels — ${LEVELS[code].name} (${LEVELS[code].color})`;
  card.severity.ncissJustification = `[mock] Model rated this cluster ${LEVELS[code].name} (${LEVELS[code].color}).`;
  card.severity.unscorableReason = null;
  card.severity.isProvisional = false;
  card.severity.provisionalLabel = null;
  card.severity.provisionalReason = null;
  card.severity.recommendEscalate = code !== 'BASELINE_MINOR_BLUE';
}

function parsePrompt(text: string) {
  const total = Number(/Total lines across the submission = (\d+)/.exec(text)?.[1] || '0');
  let floorCode = 'BASELINE_NEGLIGIBLE_WHITE';
  const m = /"floorLevelCode":\s*"([A-Z_]+)"/.exec(text);
  if (m) floorCode = m[1];
  const repLines = Array.from(text.matchAll(/^\[L(\d+)\] \([^)]*\) \[([^\]]*)\]/gm)).map((x) => ({
    line: Number(x[1]),
    tags: x[2],
  }));
  const categories: Array<{ tag: string; lines: number[] }> = [];
  const catRe = /^- (.+?): (\d+) lines \(min L(\d+), max L(\d+); sample lines: ([\d, ]+)\)/gm;
  for (const x of text.matchAll(catRe)) {
    categories.push({ tag: x[1], lines: x[5].split(',').map((s) => Number(s.trim())).filter(Boolean) });
  }
  return { total, floorCode, repLines, categories };
}

function buildResponse(schema: Schema, promptText: string, mode: string) {
  const { total, floorCode, repLines, categories } = parsePrompt(promptText);
  const base = fill(schema, 'root') as Record<string, any>;
  const cardSchema = schema.properties?.scorecards?.items;
  base.globalScopeFlags.nssOrClassifiedDetected = false;
  base.globalScopeFlags.vulnerabilityPlaybookTriggered = false;
  base.globalScopeFlags.clusteringSummary = `[mock] ${categories.length} flagged categories reviewed.`;

  const makeCard = (id: number, title: string, lines: number[], code: string) => {
    const card = fill(cardSchema, 'card') as Record<string, any>;
    card.clusterId = `MOCK-${id}`;
    card.clusterTitle = `[mock] ${title}`;
    card.connectionCertainty = 'unified';
    card.nssOutOfScope = false;
    card.vulnerabilityCrossover.triggered = false;
    card.vulnerabilityCrossover.status = 'Not Applicable';
    if (card.shortRead) {
      card.shortRead.observedTactics = [];
      card.shortRead.privilegeLevelsObserved = [];
      card.shortRead.affectedHosts = ['host-a'];
      card.shortRead.affectedAccounts = ['user-a'];
    }
    setLevel(card, code);
    card.clusterLineRanges = Array.from(new Set(lines)).sort((a, b) => a - b).map(String);
    return card;
  };

  const flagged = Array.from(new Set([...repLines.map((r) => r.line), ...categories.flatMap((c) => c.lines)]));

  if (mode === 'benign' || flagged.length === 0) {
    base.scorecards = [];
    base.benignGroups = [{ lineRanges: [`1-${total}`], reason: '[mock] Routine baseline activity.' }];
    return base;
  }

  let modelCode = floorCode === 'BASELINE_NEGLIGIBLE_WHITE' ? 'BASELINE_MINOR_BLUE' : floorCode;
  if (mode === 'under' || mode === 'multi') modelCode = 'BASELINE_MINOR_BLUE';
  if (mode === 'over') modelCode = 'SEVERE_RED';

  if (mode === 'multi' && categories.length > 1) {
    base.scorecards = categories.map((c, i) => makeCard(i + 1, c.tag, c.lines, modelCode));
  } else {
    base.scorecards = [makeCard(1, categories[0]?.tag || 'Flagged activity', flagged, modelCode)];
  }
  base.benignGroups = [{ lineRanges: [`1-${total}`], reason: '[mock] Routine entries outside the flagged cluster.' }];
  return base;
}


function promptOf(options: { systemInstruction?: string; userPrompt?: string }): string {
  return `${options.systemInstruction || ''}\n${options.userPrompt || ''}`;
}

async function sleep(ms: number, signal?: AbortSignal) {
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new Error('This operation was aborted'));
    });
  });
}

export async function generateContent(options: {
  systemInstruction: string;
  userPrompt: string;
  responseSchema: Record<string, unknown>;
  abortSignal?: AbortSignal;
}): Promise<{ text: string; finishReason?: string }> {
  mockCallCount++;
  const mode = currentMode();
  const signal = options.abortSignal;
  const latency = Number(process.env.MOCK_GROQ_LATENCY_MS ?? process.env.MOCK_GEMINI_LATENCY_MS ?? '50');
  const text = promptOf(options);
  console.log(`[MOCK GROQ] call #${mockCallCount} mode=${mode}`);

  if (mode === 'hang') {
    await new Promise<void>((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new Error('This operation was aborted')));
    });
  }
  await sleep(latency, signal);
  if (mode === 'fail429') {
    throw new MockApiError(
      429,
      'Groq API 429: Rate limit reached for model. {"error":{"code":429,"message":"Rate limit reached","status":"RESOURCE_EXHAUSTED"}}'
    );
  }
  if (mode === 'fail503') {
    throw new MockApiError(
      503,
      'Groq API 503: {"error":{"code":503,"message":"The model is overloaded. Please try again later.","status":"UNAVAILABLE"}}'
    );
  }
  if (mode === 'once503') {
    const key = crypto.createHash('sha1').update(text).digest('hex');
    if (!seenPrompts.has(key)) {
      seenPrompts.add(key);
      throw new MockApiError(
        503,
        'Groq API 503: {"error":{"code":503,"message":"The model is overloaded. Please try again later.","status":"UNAVAILABLE"}}'
      );
    }
  }
  if (mode === 'malformed') return { text: '{"globalScopeFlags": {"nss', finishReason: 'STOP' };
  if (mode === 'empty') return { text: '', finishReason: 'STOP' };
  if (mode === 'maxtokens') return { text: '{"a":', finishReason: 'MAX_TOKENS' };

  const effective = mode === 'once503' ? 'match' : mode;
  const body = buildResponse(options.responseSchema as Schema, text, effective);
  return { text: JSON.stringify(body), finishReason: 'STOP' };
}
