/**
 * Groq Chat Completions client (OpenAI-compatible).
 * The API key is read only from process.env.GROQ_API_KEY on the server.
 * Set MOCK_GROQ=1 (or MOCK_LLM=1 / MOCK_GEMINI=1) to use the local mock and
 * never call the network.
 */

export const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

/** Current Groq production model on the free / developer tier (Nov 2026).
 *  llama-3.3-70b-versatile is enterprise-only after 16 Aug 2026. */
export const DEFAULT_GROQ_MODEL = 'openai/gpt-oss-120b';

export function groqModel(): string {
  return (process.env.GROQ_MODEL || DEFAULT_GROQ_MODEL).trim();
}

export function isMockLlm(): boolean {
  return (
    process.env.MOCK_GROQ === '1' ||
    process.env.MOCK_LLM === '1' ||
    process.env.MOCK_GEMINI === '1'
  );
}

export type LlmCompletion = {
  text: string;
  finishReason?: string;
};

export class GroqHttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'GroqHttpError';
    this.status = status;
  }
}

function extractErrorMessage(payload: unknown, fallback: string): string {
  if (payload && typeof payload === 'object') {
    const err = (payload as { error?: unknown }).error;
    if (typeof err === 'string' && err.trim()) return err;
    if (err && typeof err === 'object') {
      const msg = (err as { message?: unknown }).message;
      if (typeof msg === 'string' && msg.trim()) return msg;
    }
  }
  return fallback;
}

export async function completeTriageJson(options: {
  systemInstruction: string;
  userPrompt: string;
  responseSchema: Record<string, unknown>;
  abortSignal?: AbortSignal;
  maxCompletionTokens?: number;
}): Promise<LlmCompletion> {
  if (isMockLlm()) {
    const mock = await import('../local-mock/mock-groq.ts');
    return mock.generateContent(options);
  }

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    throw new Error('GROQ_API_KEY is not configured on the server.');
  }

  const body = {
    model: groqModel(),
    temperature: 0,
    max_completion_tokens: options.maxCompletionTokens ?? 16384,
    reasoning_effort: 'low',
    messages: [
      { role: 'system', content: options.systemInstruction },
      { role: 'user', content: options.userPrompt },
    ],
    // json_object keeps the huge triage schema out of the request body. Free Groq
    // tiers cap a single request (and TPM) at 8000 tokens for this model; sending
    // the schema plus a large log digest overflows that ceiling (HTTP 413).
    // The user prompt already describes the schema, and the server still validates
    // the parsed JSON against the same TypeScript checks as before.
    response_format: {
      type: 'json_object',
    },
  };

  const response = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal: options.abortSignal,
  });

  const rawText = await response.text();
  let parsed: unknown = null;
  try {
    parsed = rawText ? JSON.parse(rawText) : null;
  } catch {
    parsed = null;
  }

  if (!response.ok) {
    const detail = extractErrorMessage(
      parsed,
      rawText.slice(0, 400) || response.statusText || 'Groq request failed'
    );
    throw new GroqHttpError(response.status, `Groq API ${response.status}: ${detail}`);
  }

  const choice = (parsed as {
    choices?: Array<{
      finish_reason?: string;
      message?: { content?: string | null };
    }>;
  })?.choices?.[0];
  const content = choice?.message?.content ?? '';
  let finishReason = choice?.finish_reason;
  if (finishReason === 'length') finishReason = 'MAX_TOKENS';
  return { text: content, finishReason };
}
