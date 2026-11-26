import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { completeTriageJson, isMockLlm } from './groq.ts';
import type {
  AuthorizedActivityAnswer,
  BruteForceIpDetail,
  ContextItemBreakdown,
  DeterministicTelemetrySummary,
  IctContractorAnswer,
  IncidentScorecard,
  LogInspectionResult,
  MissionContextInput,
  MissionCriticalAnswer,
  PiiExposureAnswer,
  RoleHandoff,
  SeverityFloorTier,
  SeverityLevelCode,
  SourceIpSummary,
  TriageAnalysisResponse,
} from '../src/types/triage.ts';

/** JSON Schema type strings used by the Groq response_format schema. */
const Type = {
  OBJECT: 'object',
  STRING: 'string',
  BOOLEAN: 'boolean',
  ARRAY: 'array',
  NUMBER: 'number',
  INTEGER: 'integer',
} as const;



const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function resolvePublicAsset(filename: string): string {
  const rel = path.join('assets', 'aistudio', filename);
  const candidates = [
    path.resolve(process.cwd(), 'public', rel),
    path.resolve(process.cwd(), 'dist', rel),
    path.resolve(__dirname, '..', 'public', rel),
    path.resolve(__dirname, '..', 'dist', rel),
  ];
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

const PLAYBOOK_PDF_PATH = resolvePublicAsset(
  'CISA_Incident_Vulnerability_Response_Playbooks_ba8ab053.pdf'
);
const NCISS_PDF_PATH = resolvePublicAsset('CISA-NCISS_6cf528af.pdf');
const FING_PDF_PATH = resolvePublicAsset(
  'CISA-Federal-Incident-Notification-Guidelines_049a1365.pdf'
);

const MANDATORY_GUARDRAILS = [
  'Notify users of compromised systems via phone rather than email to avoid tipping off the attacker (Playbook pp. 9–10, 36).',
  'Do not submit malware samples to a public analysis service to avoid tipping off the attacker (Playbook pp. 9–10, 36).',
  'Capture memory and disk images and account for all evidence in a detailed log (chain of custody: how, when, and who acquired it) before wiping, re-imaging, or patching (Playbook p. 10 Step 3a–3b, p. 14, p. 36).',
];

const NCISS_DEFINITIONS: Record<
  SeverityLevelCode,
  {
    ncissLevelName: IncidentScorecard['severity']['ncissLevelName'];
    colorName: IncidentScorecard['severity']['colorName'];
    definition: string;
    citation: string;
  }
> = {
  EMERGENCY_BLACK: {
    ncissLevelName: 'Emergency',
    colorName: 'Black',
    definition:
      'An Emergency priority incident poses an imminent threat to the provision of wide-scale critical infrastructure services, national government stability, or the lives of U.S. persons.',
    citation: 'CISA NCISS, Priority Levels \u2014 Emergency (Black), p. 4',
  },
  SEVERE_RED: {
    ncissLevelName: 'Critical',
    colorName: 'Red',
    definition:
      'A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties.',
    citation: 'CISA NCISS, Priority Levels \u2014 Severe (Red), p. 5',
  },
  HIGH_ORANGE: {
    ncissLevelName: 'High',
    colorName: 'Orange',
    definition:
      'A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels \u2014 High (Orange), p. 5',
  },
  MEDIUM_YELLOW: {
    ncissLevelName: 'Medium',
    colorName: 'Yellow',
    definition:
      'A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels \u2014 Medium (Yellow), p. 5',
  },
  LOW_GREEN: {
    ncissLevelName: 'Low',
    colorName: 'Green',
    definition:
      'A Low priority incident is unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels \u2014 Low (Green), p. 5',
  },
  BASELINE_MINOR_BLUE: {
    ncissLevelName: 'Baseline – Minor',
    colorName: 'Blue',
    definition:
      'A Baseline–Minor priority incident is an incident that is highly unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. The potential for impact, however, exists and warrants additional scrutiny.',
    citation: 'CISA NCISS, Priority Levels \u2014 Baseline – Minor (Blue), pp. 5–6',
  },
  BASELINE_NEGLIGIBLE_WHITE: {
    ncissLevelName: 'Baseline – Negligible',
    colorName: 'White',
    definition:
      'A Baseline–Negligible priority incident is an incident that is highly unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels \u2014 Baseline – Negligible (White), pp. 5–6',
  },
  UNSCORABLE_GRAY: {
    ncissLevelName: 'Unscorable',
    colorName: 'Gray',
    definition:
      'Cluster cannot be scored under CISA NCISS Priority Levels because required scoring evidence is absent or indeterminate.',
    citation: 'CISA NCISS, Priority Levels & Formula, pp. 3–6',
  },
};

const SEVERITY_ORDER_RANK: Record<SeverityLevelCode, number> = {
  UNSCORABLE_GRAY: 0,
  BASELINE_NEGLIGIBLE_WHITE: 1,
  BASELINE_MINOR_BLUE: 2,
  LOW_GREEN: 3,
  MEDIUM_YELLOW: 4,
  HIGH_ORANGE: 5,
  SEVERE_RED: 6,
  EMERGENCY_BLACK: 7,
};

/** App scorecard label for NCISS Severe (Red). Official NCISS wording stays in definition quotes and citations. */
function normalizeSeverityLevelCode(raw: unknown): SeverityLevelCode | undefined {
  if (typeof raw !== 'string' || !raw.trim()) return undefined;
  const key = raw.trim();
  if (key in SEVERITY_ORDER_RANK) return key as SeverityLevelCode;
  const compact = key
    .toUpperCase()
    .replace(/[\u2010-\u2015]/g, '-')
    .replace(/[()]/g, '')
    .replace(/[\s-]+/g, '_');
  if (compact in SEVERITY_ORDER_RANK) return compact as SeverityLevelCode;
  if (compact === 'SEVERE' || compact === 'CRITICAL' || compact === 'CRITICAL_RED') {
    return 'SEVERE_RED';
  }
  if (compact === 'EMERGENCY') return 'EMERGENCY_BLACK';
  if (compact === 'HIGH') return 'HIGH_ORANGE';
  if (compact === 'MEDIUM') return 'MEDIUM_YELLOW';
  if (compact === 'LOW') return 'LOW_GREEN';
  if (compact.includes('BASELINE') && compact.includes('MINOR')) return 'BASELINE_MINOR_BLUE';
  if (compact.includes('BASELINE') && compact.includes('NEGLIGIBLE')) return 'BASELINE_NEGLIGIBLE_WHITE';
  if (compact === 'UNSCORABLE' || compact === 'GRAY') return 'UNSCORABLE_GRAY';
  return undefined;
}

function normalizeNcissLevelName(
  raw: unknown
): IncidentScorecard['severity']['ncissLevelName'] | undefined {
  if (typeof raw !== 'string' || !raw.trim()) return undefined;
  const compact = raw
    .trim()
    .toLowerCase()
    .replace(/[\u2010-\u2015]/g, '-')
    .replace(/\s+/g, ' ');
  const withoutColor = compact.replace(
    /\s*\((black|red|orange|yellow|green|blue|white|gray)\)\s*$/i,
    ''
  ).trim();
  if (
    withoutColor === 'severe' ||
    withoutColor === 'critical' ||
    compact === 'severe_red' ||
    compact.startsWith('severe (red')
  ) {
    return 'Critical';
  }
  if (withoutColor === 'emergency' || compact.startsWith('emergency (black')) return 'Emergency';
  if (withoutColor === 'high' || compact.startsWith('high (orange')) return 'High';
  if (withoutColor === 'medium' || compact.startsWith('medium (yellow')) return 'Medium';
  if (withoutColor === 'low' || compact.startsWith('low (green')) return 'Low';
  if (withoutColor.includes('baseline') && withoutColor.includes('minor')) return 'Baseline – Minor';
  if (withoutColor.includes('baseline') && withoutColor.includes('negligible')) return 'Baseline – Negligible';
  if (withoutColor === 'unscorable') return 'Unscorable';
  return undefined;
}

const SANITIZE_SKIP_KEYS = new Set([
  'levelCode',
  'floorLevelCode',
  'geminiInitialLevelCode',
  'ncissDefinitionQuote',
  'ncissCitation',
  'definition',
  'citation',
]);

function replaceSevereDisplayLabel(text: string): string {
  return text
    .replace(/\bSevere\s*\(\s*Red\s*\)/gi, 'Critical (Red)')
    .replace(/\bSevere\b/g, 'Critical');
}

function sanitizeSevereDisplayLabels<T>(value: T, key?: string): T {
  if (key && SANITIZE_SKIP_KEYS.has(key)) return value;
  if (typeof value === 'string') return replaceSevereDisplayLabel(value) as T;
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeSevereDisplayLabels(item)) as T;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sanitizeSevereDisplayLabels(v, k);
    }
    return out as T;
  }
  return value;
}


interface TriageJobRecord {
  jobId: string;
  kind?: 'inspect' | 'analyze';
  status: 'running' | 'completed' | 'error';
  statusMessage: string;
  createdAtMs: number;
  updatedAtMs: number;
  result?: TriageAnalysisResponse | LogInspectionResult;
  error?: string;
  retryable?: boolean;
}

const triageJobs = new Map<string, TriageJobRecord>();

function pruneExpiredJobs() {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [id, job] of triageJobs.entries()) {
    if (job.updatedAtMs < cutoff) {
      triageJobs.delete(id);
    }
  }
}

const pdfCache = new Map<string, string>();
function loadPdfBase64(filePath: string): string | null {
  const cached = pdfCache.get(filePath);
  if (cached) return cached;
  if (fs.existsSync(filePath)) {
    const encoded = fs.readFileSync(filePath).toString('base64');
    pdfCache.set(filePath, encoded);
    return encoded;
  }
  return null;
}

function getPlaybookPdfBase64(): string | null {
  return loadPdfBase64(PLAYBOOK_PDF_PATH);
}

function getNcissPdfBase64(): string | null {
  return loadPdfBase64(NCISS_PDF_PATH);
}

function getFingPdfBase64(): string | null {
  return loadPdfBase64(FING_PDF_PATH);
}

function playbookPdfAvailable(): boolean {
  return fs.existsSync(PLAYBOOK_PDF_PATH);
}

function ncissPdfAvailable(): boolean {
  return fs.existsSync(NCISS_PDF_PATH);
}

function fingPdfAvailable(): boolean {
  return fs.existsSync(FING_PDF_PATH);
}

function isRetryableLlmError(err: unknown): {
  retryable: boolean;
  statusCode: number | null;
} {
  const anyErr = err as { status?: number; code?: number | string; message?: string };
  const raw = err instanceof Error ? err.message : String(err);
  const upper = raw.toUpperCase();
  const explicitStatus = typeof anyErr?.status === 'number' ? anyErr.status : null;

  if (
    explicitStatus === 429 ||
    upper.includes('429') ||
    upper.includes('RESOURCE_EXHAUSTED') ||
    upper.includes('RATE LIMIT') ||
    upper.includes('TOO MANY REQUESTS')
  ) {
    return { retryable: true, statusCode: 429 };
  }

  if (
    explicitStatus === 503 ||
    upper.includes('503') ||
    upper.includes('UNAVAILABLE') ||
    upper.includes('OVERLOADED') ||
    upper.includes('SERVICE UNAVAILABLE')
  ) {
    return { retryable: true, statusCode: 503 };
  }

  if (
    explicitStatus === 500 ||
    upper.includes('500') ||
    upper.includes('ECONNRESET') ||
    upper.includes('ETIMEDOUT') ||
    upper.includes('FETCH FAILED')
  ) {
    return { retryable: true, statusCode: 500 };
  }

  return { retryable: false, statusCode: explicitStatus };
}

function formatLlmError(err: unknown): { status: number; message: string; retryable: boolean } {
  const raw = err instanceof Error ? err.message : String(err);
  if (raw.includes('GROQ_API_KEY')) {
    return {
      status: 500,
      message: 'Server GROQ_API_KEY is not configured. Set it in the host environment (Vercel project settings or a local .env file).',
      retryable: false,
    };
  }
  if (raw.includes('403') || raw.includes('PERMISSION_DENIED') || raw.includes('API_KEY_INVALID')) {
    return {
      status: 403,
      message:
        'Groq API authentication failed. Verify the GROQ_API_KEY environment variable.',
      retryable: false,
    };
  }
  if (err instanceof LlmAttemptTimeoutError) {
    return {
      status: 504,
      message:
        'Model busy: the analysis request did not finish in time. Try again in a minute.',
      retryable: true,
    };
  }
  const { retryable, statusCode } = isRetryableLlmError(err);
  if (retryable && (statusCode === 429 || statusCode === 503)) {
    return {
      status: statusCode,
      message: `Model busy (${statusCode}): the analysis service is rate-limited or temporarily unavailable after ${BACKOFF_SCHEDULE_MS.length + 1} automatic attempts. If this is a 429, wait a minute and try again.`,
      retryable: true,
    };
  }
  return {
    status: 500,
    message: `Analysis failed: ${raw}`,
    retryable: false,
  };
}

const BACKOFF_SCHEDULE_MS = [1000, 2000, 4000];
// A single model attempt that has not answered after this long is abandoned so the
// request can never hang forever (no more endless spinner).
const LLM_ATTEMPT_TIMEOUT_MS = Number(process.env.LLM_ATTEMPT_TIMEOUT_MS) || 45_000;
// Maximum size of the pre-summarized log digest sent in the analysis API call text part.
// Counts, floors, and rule matches are still computed on every line of the full log.
const LLM_LOG_PAYLOAD_MAX_CHARS = 32_000;
// Per-line cap applied in parseIndexedLogLines so one huge line cannot crash rule matching.
const MAX_LOG_LINE_CHARS = 64_000;

class LlmAttemptTimeoutError extends Error {
  constructor(ms: number) {
    super(`The analysis model did not respond within ${Math.round(ms / 1000)}s.`);
    this.name = 'LlmAttemptTimeoutError';
  }
}

async function runWithTimeout<T>(fn: (signal: AbortSignal) => Promise<T>, ms: number): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new LlmAttemptTimeoutError(ms));
    }, ms);
  });
  try {
    return await Promise.race([fn(controller.signal), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function generateWithRetry<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  onRetry?: (info: {
    attempt: number;
    maxAttempts: number;
    delayMs: number;
    statusCode: number | null;
    message: string;
  }) => void
): Promise<T> {
  const maxAttempts = BACKOFF_SCHEDULE_MS.length + 1;
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await runWithTimeout(fn, LLM_ATTEMPT_TIMEOUT_MS);
    } catch (err) {
      lastError = err;
      if (err instanceof LlmAttemptTimeoutError) {
        // Do not stack several multi-minute waits; report it right away.
        break;
      }
      const { retryable, statusCode } = isRetryableLlmError(err);
      if (!retryable || attempt === maxAttempts) {
        if (retryable && onRetry) {
          onRetry({
            attempt,
            maxAttempts,
            delayMs: 0,
            statusCode,
            message: `Model busy (${statusCode ?? 'transient error'}) \u2014 all ${maxAttempts} attempts failed.`,
          });
        }
        break;
      }
      const baseDelay = BACKOFF_SCHEDULE_MS[attempt - 1] ?? 4000;
      const jitterMs = Math.floor(Math.random() * 750);
      let delayMs = baseDelay + jitterMs;
      if (isMockLlm()) {
        const scale = Number(process.env.MOCK_BACKOFF_SCALE ?? '0.1');
        delayMs = Math.round(delayMs * (Number.isFinite(scale) && scale >= 0 ? scale : 0.1));
      }
      const friendlyMessage = `Model busy (${statusCode ?? 'transient error'}), retrying in ${(delayMs / 1000).toFixed(1)}s (attempt ${attempt + 1}/${maxAttempts})...`;
      console.warn(`[LLM Retry] ${friendlyMessage}`);
      if (onRetry) {
        onRetry({
          attempt: attempt + 1,
          maxAttempts,
          delayMs,
          statusCode,
          message: friendlyMessage,
        });
      }
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw lastError;
}

interface IndexedLogLine {
  lineNumber: number;
  source: string;
  timestamp: string;
  rawLine: string;
}

function extractBestTimestamp(line: string): string {
  const isoMatch = line.match(
    /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/
  );
  if (isoMatch) return isoMatch[0];

  const clfMatch = line.match(/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]/);
  if (clfMatch) return clfMatch[1];

  const slashDateMatch = line.match(/\b\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\b/);
  if (slashDateMatch) return slashDateMatch[0];

  const us12Match = line.match(/\b\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)\b/i);
  if (us12Match) return us12Match[0];

  const syslogMatch = line.match(/\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/);
  if (syslogMatch) return syslogMatch[0];

  const epochMatch = line.match(/(?:^|[\s,;])(1[6-9]\d{8}|2\d{9})(?:\.\d+)?(?:[\s,;]|$)/);
  if (epochMatch) return epochMatch[1];

  return '';
}

const MONTH_MAP: Record<string, string> = {
  jan: '01',
  feb: '02',
  mar: '03',
  apr: '04',
  may: '05',
  jun: '06',
  jul: '07',
  aug: '08',
  sep: '09',
  oct: '10',
  nov: '11',
  dec: '12',
};

function parseTimestampMs(ts: string): { ms: number | null; utcHour: number | null } {
  if (!ts) return { ms: null, utcHour: null };

  // ISO8601 or YYYY/MM/DD HH:MM:SS
  if (/^\d{4}[-/]\d{2}[-/]\d{2}/.test(ts)) {
    const normalized = ts.replace(/\//g, '-').replace(' ', 'T');
    const ms = Date.parse(normalized);
    if (!Number.isNaN(ms)) {
      const hourMatch = ts.match(/[T ](\d{2}):/);
      return { ms, utcHour: hourMatch ? Number(hourMatch[1]) : new Date(ms).getUTCHours() };
    }
  }

  // Apache CLF: 16/Nov/2026:00:01:59 -0500
  const clf = ts.match(
    /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{2}):?(\d{2}))?/
  );
  if (clf) {
    const mon = MONTH_MAP[clf[2].toLowerCase()];
    if (mon) {
      const tz = clf[7] && clf[8] ? `${clf[7]}:${clf[8]}` : 'Z';
      const iso = `${clf[3]}-${mon}-${clf[1]}T${clf[4]}:${clf[5]}:${clf[6]}${tz}`;
      const ms = Date.parse(iso);
      if (!Number.isNaN(ms)) {
        return { ms, utcHour: Number(clf[4]) };
      }
    }
  }

  // US 12-hour: 11/14/2026 2:38:24 PM
  const us12 = ts.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)$/i);
  if (us12) {
    let hour = Number(us12[4]) % 12;
    if (us12[7].toUpperCase() === 'PM') hour += 12;
    const iso = `${us12[3]}-${us12[1].padStart(2, '0')}-${us12[2].padStart(2, '0')}T${String(hour).padStart(2, '0')}:${us12[5]}:${us12[6]}`;
    const ms = Date.parse(iso);
    if (!Number.isNaN(ms)) return { ms, utcHour: hour };
  }

  // Epoch seconds (10 digits) or milliseconds (13 digits)
  if (/^\d{10,13}$/.test(ts)) {
    const ms = ts.length === 13 ? Number(ts) : Number(ts) * 1000;
    if (ms > 1_000_000_000_000 && ms < 4_000_000_000_000) {
      return { ms, utcHour: new Date(ms).getUTCHours() };
    }
  }

  // Syslog: Nov 16 00:01:59
  const sys = ts.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (sys) {
    const mon = MONTH_MAP[sys[1].toLowerCase()];
    if (mon) {
      const day = sys[2].padStart(2, '0');
      const year = new Date().getUTCFullYear();
      const ms = Date.parse(`${year}-${mon}-${day}T${sys[3]}:${sys[4]}:${sys[5]}Z`);
      if (!Number.isNaN(ms)) {
        return { ms, utcHour: Number(sys[3]) };
      }
    }
  }

  return { ms: null, utcHour: null };
}

function parseIndexedLogLines(rawLogs: string): IndexedLogLine[] {
  const rawLines = rawLogs.split(/\r?\n/);
  const indexed: IndexedLogLine[] = [];
  let currentSource = 'Log Buffer';

  for (const line of rawLines) {
    const clipped =
      line.length > MAX_LOG_LINE_CHARS
        ? line.slice(0, MAX_LOG_LINE_CHARS - 8_192) + line.slice(-8_192)
        : line;
    const trimmed = clipped.trim();
    if (!trimmed) continue;

    if (trimmed === '=== PASTED LOG BUFFER ===') {
      currentSource = 'Pasted Log Buffer';
      continue;
    }
    const fileHeader = trimmed.match(/^=== FILE:\s*(.+?)\s*===$/);
    if (fileHeader) {
      currentSource = fileHeader[1];
      continue;
    }

    indexed.push({
      lineNumber: indexed.length + 1,
      source: currentSource,
      timestamp: extractBestTimestamp(trimmed),
      rawLine: trimmed,
    });
  }

  return indexed;
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function isRfc1918Ip(ip: string): boolean {
  if (!isValidIpv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isCgnatSharedIp(ip: string): boolean {
  if (!isValidIpv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 100 && b >= 64 && b <= 127;
}

// Loopback (127.0.0.0/8, ::1) and link-local (169.254.0.0/16, fe80::/10) addresses never
// leave the host/segment, so they are not "outside" sources for the Low floor.
function isLoopbackOrLinkLocalIp(ip: string): boolean {
  const lower = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const v4 = mapped ? mapped[1] : lower;
  if (isValidIpv4(v4)) {
    const [a, b] = v4.split('.').map(Number);
    return a === 127 || (a === 169 && b === 254);
  }
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  return /^fe[89ab][0-9a-f]:/.test(lower);
}

function isValidIpv6(ip: string): boolean {
  const s = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!s.includes(':')) return false;
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isValidIpv4(mapped[1]);
  if ((s.match(/::/g) || []).length > 1) return false;
  const parts = s.split(':');
  if (parts.length > 8) return false;
  if (!s.includes('::') && parts.length !== 8 && !parts[parts.length - 1].includes('.')) return false;
  return parts.every((g, i) => {
    if (g === '') return true;
    if (i === parts.length - 1 && isValidIpv4(g)) return true;
    return /^[0-9a-f]{1,4}$/.test(g);
  });
}

function isUniqueLocalIpv6(ip: string): boolean {
  const s = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return /^f[cd][0-9a-f]{2}:/.test(s);
}

function isUsableIp(ip: string): boolean {
  const s = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isValidIpv4(mapped[1]);
  return isValidIpv4(s) || isValidIpv6(s);
}

function isNonRfc1918Ip(ip: string): boolean {
  if (isLoopbackOrLinkLocalIp(ip)) return false;
  const lower = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const v4 = mapped ? mapped[1] : lower;
  if (isValidIpv4(v4)) return !isRfc1918Ip(v4) && !isCgnatSharedIp(v4);
  if (isValidIpv6(lower)) return !isUniqueLocalIpv6(lower);
  return false;
}

function isExternalIp(ip: string): boolean {
  const lower = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const v4 = mapped ? mapped[1] : lower;
  if (isValidIpv4(v4)) {
    const [a, b] = v4.split('.').map(Number);
    if (a === 10) return false;
    if (a === 127) return false;
    if (a === 0) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  if (isValidIpv6(lower)) {
    if (isLoopbackOrLinkLocalIp(lower) || isUniqueLocalIpv6(lower)) return false;
    return true;
  }
  return false;
}

function extractAllIpv4(line: string): string[] {
  const matches = line.match(/(?<![\d./vV])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g);
  if (!matches) return [];
  return matches.filter(isValidIpv4);
}

function extractAllIps(line: string): string[] {
  const v4 = extractAllIpv4(line);
  const v6raw =
    line.match(/(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{0,4}(?::[0-9a-f]{1,4})*|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}/gi) || [];
  const v6 = v6raw.filter(isValidIpv6);
  return [...v4, ...v6];
}

function decodeDnsWireLabels(line: string): string {
  // Windows DNS Server debug logs encode qnames as (19)static-assets-cache(7)example(3)org(0)
  return line.replace(/(?:\(\d+\)[A-Za-z0-9_-]+){2,}\(0\)/g, (m) => {
    const labels = [...m.matchAll(/\((\d+)\)([A-Za-z0-9_-]+)/g)].map((p) => p[2]);
    return labels.join('.');
  });
}

const WELL_KNOWN_DNS_SUFFIXES = [
  'cloudfront.net',
  'akamaiedge.net',
  'akamai.net',
  'azureedge.net',
  'microsoft.com',
  'microsoftonline.com',
  'office365.com',
  'office.net',
  'sharepoint.com',
  'windows.net',
  'windowsupdate.com',
  'amazonaws.com',
  'googleapis.com',
  'gstatic.com',
  'google.com',
  'apple.com',
  'icloud.com',
  'cloudflare.com',
  'fastly.net',
  'akamaized.net',
];

function hasWellKnownDnsSuffix(fqdn: string): boolean {
  const h = fqdn.toLowerCase().replace(/\.$/, '');
  return WELL_KNOWN_DNS_SUFFIXES.some((s) => h === s || h.endsWith('.' + s));
}

function parseEnvNameList(envName: string): Set<string> {
  return new Set(
    (process.env[envName] || '')
      .split(/[,\s]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function isUserContentStorageHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (
    /(?:^|\.)(?:web\.core\.windows\.net|blob\.core\.windows\.net|dfs\.core\.windows\.net|file\.core\.windows\.net|storage\.googleapis\.com|storage\.cloud\.google\.com)$/i.test(
      h
    )
  ) {
    return true;
  }
  if (/(?:^|\.)s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i.test(h)) return true;
  // Attacker-rentable hosting / CDN / pages: not trusted SaaS, treated as user content.
  if (
    /(?:^|\.)(?:cloudfront\.net|azureedge\.net|akamaized\.net|pages\.dev|workers\.dev|netlify\.app|web\.app|firebaseapp\.com|github\.io)$/i.test(
      h
    )
  ) {
    return true;
  }
  return false;
}

function registrableSuffix(domain: string): string {
  const h = domain.toLowerCase().replace(/\.$/, '');
  const parts = h.split('.').filter(Boolean);
  if (parts.length < 2) return h;
  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');
  const twoPart = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.jp', 'com.br', 'co.nz']);
  if (parts.length >= 3 && twoPart.has(last2)) return last3;
  return last2;
}

function isOwnDomainHost(host: string, ownDomains: Set<string>): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h || ownDomains.size === 0) return false;
  for (const d of ownDomains) {
    if (h === d || h.endsWith('.' + d)) return true;
  }
  return false;
}

function addDomainAndRegistrable(out: Set<string>, domain: string): void {
  const d = domain.toLowerCase().replace(/\.$/, '');
  if (!d || isUsableIp(d)) return;
  out.add(d);
  out.add(registrableSuffix(d));
}

function addSiblingPublicSuffixes(out: Set<string>, domain: string): void {
  addDomainAndRegistrable(out, domain);
  const suf = registrableSuffix(domain);
  const parts = suf.split('.');
  if (parts.length < 2) return;
  const label = parts[0];
  if (label.length < 3) return;
  for (const alt of ['com', 'net', 'org']) {
    addDomainAndRegistrable(out, `${label}.${alt}`);
  }
}

function collectRecipientDomains(indexedLines: IndexedLogLine[]): Set<string> {
  const out = new Set<string>(parseEnvNameList('FCEB_FIRST_PARTY_DOMAINS'));
  const recRe =
    /(?:\b(?:to|rcpt|rcpt-to|recipient|header\.to|delivered-to|duser)\b\s*[:=]\s*<?|\bto=<)[^\s@,;<>]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/gi;
  const fromRe =
    /(?:\b(?:from|header\.from|suser)\b\s*[:=]\s*<?)[^\s@,;<>]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/gi;
  const destCounts = new Map<string, number>();
  for (const e of indexedLines) {
    recRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = recRe.exec(e.rawLine)) !== null) {
      addDomainAndRegistrable(out, m[1]);
    }
    const mailPass =
      /(?:\bspf\s*=\s*pass\b|\bdkim\s*=\s*pass\b|\bdmarc\s*=\s*pass\b)/i.test(e.rawLine) &&
      !/(?:\bspf\s*=\s*fail\b|\bdkim\s*=\s*fail\b|\bdmarc\s*=\s*fail\b)/i.test(e.rawLine);
    if (mailPass) {
      fromRe.lastIndex = 0;
      while ((m = fromRe.exec(e.rawLine)) !== null) {
        // Filled after the loop once recipient domains are known; stash for now.
        addDomainAndRegistrable(out, `__passfrom__${m[1].toLowerCase()}`);
      }
    }
    const url = extractRequestUrl(e.rawLine);
    // Do not promote upload destinations (repeated PUTs) to first-party.
    const isPut = /\b(?:PUT|requestMethod\s*[:=]\s*"?PUT)\b/i.test(e.rawLine);
    if (url && !isPut) {
      const host = urlHostAndPath(url).host.toLowerCase();
      if (host && !isUsableIp(host) && !isInternalHostname(host) && !isTrustedPublicSaasHost(host)) {
        const suf = registrableSuffix(host);
        destCounts.set(suf, (destCounts.get(suf) || 0) + 1);
      }
    }
  }
  // Promote pass-auth From domains that are not typos of recipient/org domains,
  // including common mail-vs-web siblings (example.net vs example.com).
  const recipients = new Set<string>();
  for (const d of out) {
    if (!d.startsWith('__passfrom__')) recipients.add(d);
  }
  for (const d of [...out]) {
    if (!d.startsWith('__passfrom__')) continue;
    out.delete(d);
    const fromDom = d.slice('__passfrom__'.length);
    if (isTypoOfOwnDomain(fromDom, recipients) || isLikelyPhishHost(fromDom, recipients)) continue;
    addSiblingPublicSuffixes(out, fromDom);
  }
  for (const [suf, n] of destCounts) {
    if (n >= 5 && !isTypoOfOwnDomain(suf, out) && !isLikelyPhishHost(suf, out)) {
      addDomainAndRegistrable(out, suf);
    }
  }
  return out;
}

function normalizeHomoglyph(s: string): string {
  return s
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/rn/g, 'm');
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const row = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) row[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let prev = i - 1;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = row[j];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
      prev = cur;
    }
  }
  return row[b.length];
}

function isTypoOfOwnDomain(host: string, ownDomains: Set<string>): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h || isUsableIp(h) || ownDomains.size === 0) return false;
  const hostSuffix = registrableSuffix(h);
  const hostLabel = hostSuffix.split('.')[0] || '';
  const hostNorm = normalizeHomoglyph(hostSuffix);
  const hostLabelNorm = normalizeHomoglyph(hostLabel);
  for (const d of ownDomains) {
    const ownSuffix = registrableSuffix(d);
    const ownLabel = ownSuffix.split('.')[0] || '';
    if (ownLabel.length < 5) continue;
    if (hostSuffix === ownSuffix) continue;
    const ownNorm = normalizeHomoglyph(ownSuffix);
    const ownLabelNorm = normalizeHomoglyph(ownLabel);
    if (hostNorm === ownNorm || hostLabelNorm === ownLabelNorm) return true;
    if (levenshtein(hostLabelNorm, ownLabelNorm) === 1) return true;
    if (hostLabelNorm.includes(ownLabelNorm) || hostNorm.includes(ownLabelNorm)) return true;
  }
  return false;
}

function isTrustedPublicSaasHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h || isUserContentStorageHost(h)) return false;
  if (hasWellKnownDnsSuffix(h)) return true;
  if (
    /(?:^|\.)(?:okta\.com|okta-gov\.com|login\.gov|awsapps\.com|live\.com|outlook\.com|office\.com|office365\.us|microsoftonline\.us|sharepoint\.us)$/i.test(
      h
    )
  ) {
    return true;
  }
  if (/(?:^|\.)gov$/i.test(h)) return true;
  return false;
}

function isFirstPartyHost(host: string, ownDomains: Set<string> = new Set()): boolean {
  if (!host) return false;
  if (isInternalHostname(host)) return true;
  if (isTrustedPublicSaasHost(host)) return true;
  if (isOwnDomainHost(host, ownDomains)) return true;
  return false;
}

function hostCarriesFirstPartyPrefix(host: string, ownDomains: Set<string>): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h || ownDomains.size === 0) return false;
  for (const raw of ownDomains) {
    const d = raw.toLowerCase().replace(/\.$/, '');
    // Require a multi-label suffix so a short token cannot match as a prefix.
    if (!d || !d.includes('.') || d.length < 5) continue;
    if (h === d || h.endsWith('.' + d)) continue;
    const token = d + '.';
    if (h.startsWith(token) || h.includes('.' + token)) return true;
  }
  return false;
}

function isLikelyPhishHost(host: string, ownDomains: Set<string> = new Set()): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (!h || isUsableIp(h) || isFirstPartyHost(h, ownDomains)) return false;
  if (/^xn--/i.test(h) || h.split('.').some((l) => l.startsWith('xn--'))) return true;
  // Brand as a non-registrable prefix: login.microsoftonline.com.session-check.example.net
  if (/(?:^|\.)(?:login\.)?microsoftonline\.com\./i.test(h) && !h.endsWith('microsoftonline.com')) return true;
  // First-party domain used as a label prefix of another registrable domain
  // (for example sso.agency.gov.securelogon.net when agency.gov is first-party).
  if (hostCarriesFirstPartyPrefix(h, ownDomains)) return true;
  if (
    /(?:m365|microsoft|office365|outlook|paypal|okta|onedrive|sharepoint)/i.test(h) &&
    !isTrustedPublicSaasHost(h)
  ) {
    return true;
  }
  if (isTypoOfOwnDomain(h, ownDomains)) return true;
  // Hyphenated service-lure labels on a non-first-party domain (for example pay-update.org).
  if (
    /(?:^|\.)[a-z0-9-]*-(?:benefits|update|secure|verify|invoice|billing|mfa|password|reset|login|signin|sso|auth)[a-z0-9-]*(?:\.|$)/i.test(
      h
    )
  ) {
    return true;
  }
  return false;
}

function isPathStyleObjectStorageHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (/^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/.test(h)) return true;
  if (/^storage\.(?:googleapis|cloud\.google)\.com$/.test(h)) return true;
  return false;
}

function isVirtualHostedObjectStorageHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (isPathStyleObjectStorageHost(h)) return false;
  if (/(?:^|\.)s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/.test(h)) return true;
  return false;
}

function isAllowlistedStorageTarget(host: string, url?: string | null): boolean {
  const allowed = parseEnvNameList('FCEB_ALLOWED_STORAGE_ACCOUNTS');
  if (allowed.size === 0) return false;
  const h = host.toLowerCase().replace(/\.$/, '');
  if (allowed.has(h)) return true;
  if (isVirtualHostedObjectStorageHost(h)) {
    const bucket = h.split('.')[0];
    if (bucket && allowed.has(bucket)) return true;
    return false;
  }
  if (isPathStyleObjectStorageHost(h) && url) {
    try {
      const u = new URL(url);
      const pathPart = u.pathname.split('/').filter(Boolean)[0];
      if (pathPart && allowed.has(pathPart.toLowerCase())) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}

function isExemptExfilHost(host: string, url?: string | null): boolean {
  if (!host) return false;
  // Large or archive uploads are exempt only through a configured storage allowlist.
  // CDN, API Gateway, Drive, and other trusted-SaaS suffixes count as outside.
  return isAllowlistedStorageTarget(host, url);
}

function isConfiguredBackupEvent(line: string): boolean {
  const accounts = parseEnvNameList('FCEB_BACKUP_ACCOUNTS');
  const dests = parseEnvNameList('FCEB_BACKUP_DESTINATIONS');
  if (accounts.size === 0 || dests.size === 0) return false;
  const user = (extractUsername(line) || '').toLowerCase();
  if (!user || !accounts.has(user)) return false;
  const hosts: string[] = [];
  const url = extractRequestUrl(line);
  if (url) hosts.push(urlHostAndPath(url).host.toLowerCase());
  for (const d of extractExfilDestinations(line)) {
    hosts.push(d.toLowerCase().replace(/^rclone:/, ''));
  }
  const uniq = [...new Set(hosts.filter(Boolean))];
  if (uniq.length === 0) return false;
  const destMatch = (h: string): boolean => dests.has(h) || [...dests].some((x) => h === x || h.endsWith('.' + x));
  return uniq.every((h) => destMatch(h));
}

function configuredScannerIps(): Set<string> {
  return parseEnvNameList('FCEB_AUTHORIZED_SCANNER_IPS');
}

function isInternalHostname(host: string, ownDomains: Set<string> = new Set()): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return false;
  if (isUsableIp(h)) return !isExternalIp(h);
  if (/(?:^|\.)(?:localhost|local|corp|internal|lan|intranet|home|localdomain)$/i.test(h)) return true;
  return isOwnDomainHost(h, ownDomains);
}

const INTERNAL_RCLONE_EXACT = new Set([
  'internal',
  'minio',
  'minio-internal',
  'nas',
  'nas-internal',
  'backup-nas',
  'local',
  'corp',
  'lan',
]);

function isInternalRcloneRemote(name: string): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return false;
  if (INTERNAL_RCLONE_EXACT.has(n)) return true;
  return parseEnvNameList('FCEB_INTERNAL_RCLONE_REMOTES').has(n);
}

function extractExfilDestinations(line: string): string[] {
  const found: string[] = [];
  // Any URI scheme; stop the host at ?, #, /, :, quotes, and whitespace.
  const urlRe = /\b[a-z][a-z0-9+.-]*:\/\/(?:[^@\/\s]*@)?([^\/\s:?#"']+)/gi;
  let m: RegExpExecArray | null;
  while ((m = urlRe.exec(line)) !== null) found.push(m[1]);
  const scpRe =
    /\b(?:scp|sftp)\s+[^\n]*\s+(?:[A-Za-z0-9._-]+@)?(\[?[A-Za-z0-9.:_-]+\]?):[^\s]+/i;
  const scp = line.match(scpRe);
  if (scp) found.push(scp[1]);
  const rcloneRe = /\brclone\s+\S+\s+[^\n]*?\s+([A-Za-z0-9._-]+):/i;
  const rc = line.match(rcloneRe);
  if (rc) found.push('rclone:' + rc[1]);
  return found;
}

function hasExfilDestinationToken(line: string): boolean {
  return /(?:\b[a-z][a-z0-9+.-]*:\/\/|\b(?:scp|sftp)\s|\bcurl\s+[^\n]*\s(?:-T|--upload-file)\b|\brclone\s)/i.test(
    line
  );
}

function isProvablyInternalExfil(line: string): boolean {
  const dests = extractExfilDestinations(line);
  if (dests.length > 0) {
    return dests.every((d) => {
      if (d.startsWith('rclone:')) return isInternalRcloneRemote(d.slice('rclone:'.length));
      return isInternalHostname(d);
    });
  }
  // A destination token we failed to parse is not "internal" just because an internal IP is also on the line.
  if (hasExfilDestinationToken(line)) return false;
  const ips = extractAllIps(line);
  return ips.length > 0 && ips.every((ip) => !isExternalIp(ip));
}

interface CsvHeaderMap {
  srcIdx: number;
  dstIdx: number;
  dptIdx: number;
  actionIdx: number;
  protoIdx: number;
  bytesOutIdx: number;
  flagsIdx: number;
  resultIdx: number;
  userIdx: number;
  delim: string;
}

function csvDelimiter(line: string): string {
  const semi = (line.match(/;/g) || []).length;
  const comma = (line.match(/,/g) || []).length;
  return semi > comma ? ';' : ',';
}

function splitCsvLine(line: string, delim: string): string[] {
  return line.split(delim).map((c) => c.trim().replace(/^["']|["']$/g, ''));
}

function tryParseCsvHeaderMap(line: string): CsvHeaderMap | null {
  if (line.startsWith('{') || line.startsWith('<')) return null;
  if (!line.includes(',') && !line.includes(';')) return null;
  const delim = csvDelimiter(line);
  const cols = splitCsvLine(line, delim).map((c) => c.toLowerCase().replace(/[\s_]/g, ''));
  if (cols.length < 4) return null;

  const findIdx = (names: string[]) => cols.findIndex((c) => names.map((n) => n.replace(/[\s_]/g, '')).includes(c));
  const srcIdx = findIdx([
    'src',
    'src_ip',
    'srcip',
    'source_ip',
    'sourceip',
    'source',
    'client_ip',
    'clientip',
    'srcaddr',
    'sourceipaddress',
    'calleripaddress',
    'cip',
    'rhost',
    'ipaddress',
  ]);
  const dstIdx = findIdx([
    'dst',
    'dst_ip',
    'dstip',
    'dest_ip',
    'destination_ip',
    'destinationip',
    'dstaddr',
    'destination',
    'destinationhostname',
  ]);
  const dptIdx = findIdx([
    'dpt',
    'dst_port',
    'dport',
    'dest_port',
    'destination_port',
    'dstport',
    'destinationport',
  ]);
  if (srcIdx === -1 && dstIdx === -1 && dptIdx === -1) return null;

  return {
    srcIdx,
    dstIdx,
    dptIdx,
    actionIdx: findIdx(['action', 'disposition', 'verdict', 'status', 'rule_action']),
    protoIdx: findIdx(['proto', 'protocol']),
    bytesOutIdx: findIdx([
      'bytes_out',
      'sent_bytes',
      'bytes_sent',
      'sentbyte',
      'out_bytes',
      'bytes',
      'total_bytes',
      'reqsize',
      'cs-bytes',
      'tx_bytes',
    ]),
    flagsIdx: findIdx(['flags', 'tcp_flags']),
    resultIdx: findIdx(['result', 'outcome', 'disposition', 'status']),
    userIdx: findIdx(['user', 'username', 'targetusername', 'suser', 'duser', 'account', 'acct']),
    delim,
  };
}

interface NetworkTuple {
  srcIp: string | null;
  dstIp: string | null;
  dstPort: number | null;
  bytesOut: number | null;
  isBlockedOrSyn: boolean;
  isAllowedOrOutbound: boolean;
}

function extractNetworkTuple(line: string, headerMap: CsvHeaderMap | null): NetworkTuple {
  let srcIp: string | null = null;
  let dstIp: string | null = null;
  let dstPort: number | null = null;
  let bytesOut: number | null = null;
  let isBlockedOrSyn = false;
  let isAllowedOrOutbound = false;

  // 1. Check CSV header mapping first if active on comma-separated lines
  if (headerMap && (line.includes(headerMap.delim) || line.includes(',') || line.includes(';')) && !line.startsWith('{')) {
    const cols = splitCsvLine(line, headerMap.delim);
    if (headerMap.srcIdx >= 0 && cols[headerMap.srcIdx] && isUsableIp(cols[headerMap.srcIdx])) {
      srcIp = cols[headerMap.srcIdx].replace(/^\[|\]$/g, '');
    }
    if (headerMap.dstIdx >= 0 && cols[headerMap.dstIdx] && isUsableIp(cols[headerMap.dstIdx])) {
      dstIp = cols[headerMap.dstIdx].replace(/^\[|\]$/g, '');
    }
    if (headerMap.dptIdx >= 0 && cols[headerMap.dptIdx] && /^\d{1,5}$/.test(cols[headerMap.dptIdx])) {
      const p = Number(cols[headerMap.dptIdx]);
      if (p >= 1 && p <= 65535) dstPort = p;
    }
    if (
      headerMap.bytesOutIdx >= 0 &&
      cols[headerMap.bytesOutIdx] &&
      /^\d+$/.test(cols[headerMap.bytesOutIdx])
    ) {
      bytesOut = Number(cols[headerMap.bytesOutIdx]);
    }
    if (headerMap.actionIdx >= 0 && cols[headerMap.actionIdx]) {
      const act = cols[headerMap.actionIdx].toUpperCase();
      if (/DENY|BLOCK|DROP|REJECT|RESET/.test(act)) isBlockedOrSyn = true;
      if (/ALLOW|ACCEPT|PERMIT|PASS/.test(act)) isAllowedOrOutbound = true;
    }
    if (headerMap.flagsIdx >= 0 && cols[headerMap.flagsIdx]) {
      if (/\bSYN\b/i.test(cols[headerMap.flagsIdx])) isBlockedOrSyn = true;
    }
  }

  // 2. Key-value / structured fields
  if (!srcIp) {
    const taggedSrc = [
      /\b(?:srcIp|srcIP|src_ip|source_ip|sourceip|sourceIPAddress|callerIpAddress|client_ip|clientip|c-ip|remote_addr|sourceaddress|ipaddress|srcaddr|rhost|cip|srcip)["']?\s*[:=]\s*"?([^"\s,]+)"?/i,
      /\bsrc["']?\s*[:=]\s*"?([^"\s,]+)"?/i,
      /<Data Name=['"]IpAddress['"]>([^<]+)<\/Data>/i,
      /\bfrom\s+(\S+)\s+port\b/i,
      /\bUDP Rcv\s+(\S+)/i,
    ];
    for (const rx of taggedSrc) {
      const m = line.match(rx);
      if (m && isUsableIp(m[1])) {
        srcIp = m[1].replace(/^\[|\]$/g, '');
        break;
      }
    }
  }

  if (!dstIp) {
    const taggedDst =
      /\b(?:dstIp|dstIP|dst_ip|dest_ip|destination_ip|destinationIp|DestinationIp|dstip|dest|dstaddr|remote_ip|server_ip|dst)["']?\s*[:=]\s*"?([^"\s,]+)"?/i;
    const m = line.match(taggedDst);
    if (m && isUsableIp(m[1])) dstIp = m[1].replace(/^\[|\]$/g, '');
  }

  // Arrow notation: 10.0.0.5:51234 -> 203.0.113.9:4444
  const arrowMatch = line.match(
    /\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\s*(?:->|=>)\s*(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/
  );
  if (arrowMatch) {
    if (!srcIp && isValidIpv4(arrowMatch[1])) srcIp = arrowMatch[1];
    if (!dstIp && isValidIpv4(arrowMatch[3])) dstIp = arrowMatch[3];
    if (dstPort === null && arrowMatch[4]) {
      const p = Number(arrowMatch[4]);
      if (p >= 1 && p <= 65535) dstPort = p;
    }
  }

  // IPs written after "://" or "DIRECT/" (proxy / web-gateway lines). extractAllIpv4
  // does not take these because a leading "/" is excluded from its lookbehind.
  if (!dstIp) {
    const urlHost = extractRequestUrl(line);
    const urlOrDirect = line.match(
      /(?:https?:\/\/|\bDIRECT\/)(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/i
    );
    // HIER_DIRECT/IP is a cache next-hop, not the destination, when a URL host is already on the line.
    const skipDirect = Boolean(urlHost) && /\bDIRECT\//i.test(line);
    if (urlOrDirect && isValidIpv4(urlOrDirect[1]) && !skipDirect) {
      dstIp = urlOrDirect[1];
      if (dstPort === null && urlOrDirect[2]) {
        const p = Number(urlOrDirect[2]);
        if (p >= 1 && p <= 65535) dstPort = p;
      }
    }
  }

  // ASA / firewall "outside:ip/port" and "inside:ip/port" (IPv4 or IPv6)
  const asaPairs = line.matchAll(/\b(outside|inside|src|dst)\s*:\s*(\[?[0-9a-fA-F:.]+\]?)(?:\/(\d{1,5}))?/gi);
  for (const m of asaPairs) {
    const side = m[1].toLowerCase();
    const ip = m[2].replace(/^\[|\]$/g, '');
    if (!isUsableIp(ip)) continue;
    if ((side === 'outside' || side === 'dst') && !dstIp) {
      dstIp = ip;
      if (dstPort === null && m[3]) {
        const p = Number(m[3]);
        if (p >= 1 && p <= 65535) dstPort = p;
      }
    }
    if ((side === 'inside' || side === 'src') && !srcIp) srcIp = ip;
  }

  // Fallback IP extraction for headerless firewall CSV / CLF / syslog
  const allIps = extractAllIpv4(line);
  if (!srcIp && allIps.length >= 1) {
    srcIp = allIps[0];
  }
  if (!dstIp && allIps.length >= 2) {
    dstIp = allIps.find((ip) => ip !== srcIp) ?? allIps[1];
  }

  // Key-value destination port
  if (dstPort === null) {
    const dptMatch = line.match(
      /\b(?:dpt|dst_port|dport|dest_port|destination_port|dstport|DestinationPort|destinationPort)\s*[:=]\s*"?(\d{1,5})"?/i
    );
    if (dptMatch) {
      const p = Number(dptMatch[1]);
      if (p >= 1 && p <= 65535) dstPort = p;
    }
  }

  // Headerless firewall CSV fallback: e.g. ts,srcIp,dstIp,srcPort,dstPort,proto,action,bytes
  // or ts,action,proto,srcIp,srcPort,dstIp,dstPort,...
  if (dstPort === null && dstIp && line.includes(',') && !line.includes('"HTTP/')) {
    const cols = line.split(',').map((c) => c.trim());
    const dstColIdx = cols.findIndex((c) => c === dstIp || c.startsWith(`${dstIp}:`));
    if (dstColIdx !== -1) {
      if (cols[dstColIdx].includes(':')) {
        const p = Number(cols[dstColIdx].split(':')[1]);
        if (p >= 1 && p <= 65535) dstPort = p;
      } else {
        // Look at adjacent columns (+1 or +2 if srcPort follows srcIp)
        for (const offset of [1, 2]) {
          const candidate = cols[dstColIdx + offset];
          if (candidate && /^\d{1,5}$/.test(candidate)) {
            const p = Number(candidate);
            if (p >= 1 && p <= 65535) {
              dstPort = p;
              break;
            }
          }
        }
      }
    }
  }

  // Outbound bytes extraction (KV / JSON first, then CSV trailing byte count)
  if (bytesOut === null) {
    const bytesMatch = line.match(
      /\b(?:bytes_out|sent_bytes|bytes_sent|sentbyte|out_bytes|cs-bytes|tx_bytes|reqsize|bytesout|(?<!(?:sc|rs|in|rcvd|received|server|dst)-)BYTES)"?\s*[:=]\s*"?(\d{3,15})"?/i
    );
    if (bytesMatch) {
      bytesOut = Number(bytesMatch[1]);
    } else if (dstIp && line.includes(',') && !line.includes('"HTTP/')) {
      const cols = line.split(',').map((c) => c.trim());
      for (let i = cols.length - 1; i >= 0; i--) {
        if (/^\d{5,15}$/.test(cols[i])) {
          bytesOut = Number(cols[i]);
          break;
        }
      }
    }
  }

  if (
    /\b(?:DENY|DENIED|BLOCK|BLOCKED|DROP|DROPPED|REJECT|REJECTED|SYN)\b/i.test(line) ||
    /\baction\s*=\s*["']?(?:block|blocked|deny|denied|drop|dropped|reject)["']?/i.test(line)
  ) {
    isBlockedOrSyn = true;
  }
  if (
    /\b(?:ALLOW|ALLOWED|ACCEPT|ACCEPTED|PERMIT|PERMITTED|ESTABLISHED|OUTBOUND)\b/i.test(line)
  ) {
    isAllowedOrOutbound = true;
  }

  return {
    srcIp,
    dstIp,
    dstPort,
    bytesOut,
    isBlockedOrSyn,
    isAllowedOrOutbound,
  };
}

function extractHttpStatus(line: string): number | null {
  const clf = line.match(/"\s+(4\d{2}|5\d{2}|[123]\d{2})\s+(?:\d+|-)(?:\s|$)/);
  if (clf) return Number(clf[1]);

  const kv = line.match(
    /\b(?:status|sc-status|http_status|statusCode|response_code)\s*[:=]\s*"?([1-5]\d{2})"?\b/i
  );
  if (kv) return Number(kv[1]);

  return null;
}

// (A) Strict Windows Event ID extraction  -  NEVER match bare numbers in HTTP, firewall CSV, or syslog
function extractWindowsEventIds(line: string): number[] {
  // Never infer Windows Event IDs from HTTP access log lines unless an explicit EventID field is present
  const isHttpAccess = /"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP\/\d\.\d"/.test(line);
  const hasExplicitWinField =
    /\b(?:EventID|EventCode|event_id|winlog\.event_id|Event\s*ID|WinEvent|ProviderName|providername|LogName|MachineName)\b|<EventID|Microsoft-Windows-/i.test(
      line
    );

  if (isHttpAccess && !hasExplicitWinField) {
    return [];
  }
  if (!hasExplicitWinField) {
    return [];
  }

  const ids = new Set<number>();
  const strictPatterns = [
    /["']?(?:EventID|EventCode|event_id|winlog\.event_id)["']?\s*[:=]\s*["']?(\d{3,5})\b/gi,
    /["'](?:Id|id)["']\s*:\s*["']?(\d{3,5})\b/g,
    /<EventID[^>]*>\s*(\d{3,5})\s*<\/EventID>/gi,
    /\b(?:Event\s*ID|WinEvent(?:\s*ID)?)\s*[:#=]\s*(\d{3,5})\b/gi,
    /\b(?:Microsoft-Windows-[A-Za-z0-9-]+|Audit\s+(?:Failure|Success)|Service Control Manager)\b[^,\n]*,(\d{3,5})(?:,|$)/gi,
  ];
  for (const rx of strictPatterns) {
    let m: RegExpExecArray | null;
    while ((m = rx.exec(line)) !== null) {
      const id = Number(m[1]);
      if (!Number.isNaN(id)) ids.add(id);
    }
  }
  return Array.from(ids);
}

function extractUsername(line: string): string | null {
  const patterns = [
    /\bfor\s+(?:invalid\s+user\s+)?([A-Za-z0-9._@-]{2,40})\s+from\b/i,
    /\b(?:user|username|TargetUserName|acct|account|suser|duser)["']?\s*[:=]\s*["']?([A-Za-z0-9._@\\-]{2,40})["']?/i,
    /<Data Name=['"]TargetUserName['"]>([A-Za-z0-9._@-]{2,40})<\/Data>/i,
  ];
  for (const rx of patterns) {
    const m = line.match(rx);
    if (m && !/^(?:-|unknown|null|none)$/i.test(m[1])) {
      return m[1].toLowerCase();
    }
  }
  return null;
}

function hasLongRandomSubdomain(line: string): boolean {
  const decoded = decodeDnsWireLabels(line);
  const domainMatches = decoded.match(/\b([a-zA-Z0-9_-]{28,253}\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63})\b/g);
  if (!domainMatches) return false;
  for (const fqdn of domainMatches) {
    if (hasWellKnownDnsSuffix(fqdn)) continue;
    const firstLabel = fqdn.split('.')[0];
    const hasDigits = /\d/.test(firstLabel);
    const hasLetters = /[a-zA-Z]/.test(firstLabel);
    const hexOnly = /^[0-9a-f]+$/i.test(firstLabel);
    if (firstLabel.length >= 28 && ((hasDigits && hasLetters) || (hexOnly && firstLabel.length >= 32))) {
      return true;
    }
  }
  return false;
}

function extractRequestUrl(line: string): string | null {
  // Prefer the actual request target, never a Referer or User-Agent URL.
  const access = line.match(
    /"(?:GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+([a-z][a-z0-9+.-]*:\/\/[^\s"]+)\s+HTTP\/\d/i
  );
  if (access) return access[1];
  const tagged = line.match(
    /\b(?:request|url|requestUrl|cs-uri)"?\s*[:=]\s*"?([a-z][a-z0-9+.-]*:\/\/[^\s"'|,]+)"?/i
  );
  if (tagged) return tagged[1];
  // Proxy / squid / w3c often have a bare request URL in a field, not inside a referer quote.
  const stripped = line.replace(/\b(?:referer|referrer|user-agent|ua)\s*[:=]\s*[^\s]+/gi, ' ').replace(/"[^"]*"/g, ' ');
  const bare = stripped.match(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>|,]+/i);
  return bare ? bare[0] : null;
}

function urlHostAndPath(url: string): { host: string; path: string; hostIsIp: boolean } {
  try {
    const u = new URL(url);
    return {
      host: u.hostname,
      path: `${u.pathname}${u.search}`,
      hostIsIp: isValidIpv4(u.hostname),
    };
  } catch {
    const m = url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/:]+)([^?]*)?(\?.*)?/i);
    if (!m) return { host: '', path: url, hostIsIp: false };
    return {
      host: m[1],
      path: `${m[2] || '/'}${m[3] || ''}`,
      hostIsIp: isUsableIp(m[1]),
    };
  }
}

function isCredentialHarvestPath(pathOrLine: string): boolean {
  return /\/(?:login|signin|logon|wp-login|owa\/auth|adfs(?:\/|$)|session\/auth|oauth\/authorize|resetpassword|reset-password|auth(?:\/|$))/i.test(
    pathOrLine
  );
}

function isCredentialLikePath(pathOrLine: string): boolean {
  return (
    isCredentialHarvestPath(pathOrLine) ||
    /\/(?:verify|mfa|submit|reset|account\/login)/i.test(pathOrLine)
  );
}

function isPrivilegedGroupName(text: string): boolean {
  return /(?:\b(?:Administrators|Domain Admins|Enterprise Admins|Schema Admins|Backup Operators|Account Operators|Organization Management|DnsAdmins|sudo|wheel)\b|S-1-5-32-544)/i.test(
    text
  );
}

function hasSuspiciousLolbin(line: string): boolean {
  return /(?:(?:powershell|pwsh)(?:\.exe)?[^\n]{0,160}(?:-(?:e|ec|en|enc|encodedcommand)\b|\/enc)[^\n]{0,20}[A-Za-z0-9+/]{20,}|\bcertutil(?:\.exe)?[^\n]{0,80}(?:-urlcache|-decode)|\bbitsadmin(?:\.exe)?[^\n]{0,60}\/transfer|\bmshta(?:\.exe)?[^\n]{0,80}https?:\/\/|\bregsvr32(?:\.exe)?[^\n]{0,80}(?:\/i:https?:\/\/|-i:https?:\/\/)|\brundll32(?:\.exe)?[^\n]{0,80}javascript:)/i.test(
    line
  );
}

function isLateralMovementIndicator(line: string): boolean {
  return /(?:\bPSEXESVC\b|\bpsexec(?:\.exe)?\b|\bwmiexec\b|\bsmbexec\b|\batexec\b|\bsecretsdump\b|\bdcsync\b|\bpass-the-hash\b|\b(?:ADMIN|C)\$(?:\\|\/|"|'|\s|$|\b)|\bEnter-PSSession\b|\binvoke-command\b[^\n]{0,60}-computername|\bwinrs(?:\.exe)?\b|\bWmiPrvSE\.exe\b|\bwsmprovhost\.exe\b|\bwinrm\b|\bnet\s+group\b|\bnltest\b|\bwhoami\s+\/?all\b)/i.test(
    line
  );
}

function isPersistenceIndicator(line: string): boolean {
  if (
    /(?:\\+CurrentVersion\\+Run(?:Once)?\b|\\+Winlogon\\+(?:Shell|Userinit)\b|\\+Image File Execution Options\\+|\bschtasks\s+\/create\b)/i.test(
      line
    )
  ) {
    return true;
  }
  // Stock cron run-parts of /etc/cron.hourly|daily|weekly is not an edit.
  if (/\b(?:CRON\[|run-parts\b)/i.test(line) && /\/etc\/cron\.(?:hourly|daily|weekly)\b/i.test(line)) {
    return false;
  }
  if (/(?:>>|>|tee(?:\s+-a)?)\s+\/(?:etc\/cron(?:tab|\.d\/)|var\/spool\/cron)/i.test(line)) {
    return true;
  }
  // crontab -e / crontab <file> / piped crontab -, not -l or -r
  if (/\bcrontab\b/i.test(line)) {
    if (/\bcrontab\s+(?:-u\s+\S+\s+)?-(?:l|r)(?:\s|$)/i.test(line)) return false;
    if (/\bcrontab\s+(?:-u\s+\S+\s+)?-e\b/i.test(line)) return true;
    if (/\|\s*crontab\s+-\s*$/i.test(line) || /\bcrontab\s+-\s*$/i.test(line)) return true;
    if (/\bcrontab\s+(?:-u\s+\S+\s+)?\/\S+/i.test(line)) return true;
    if (/\bREPLACE\b/i.test(line)) return true;
  }
  // authorized_keys writes, not mere mentions
  if (
    /\bauthorized_keys\b/i.test(line) &&
    /(?:>>|tee\s+-a|ssh-copy-id|\bappended\b|\bwrote\b|\bmodified\b|\bupdated\b)/i.test(line)
  ) {
    return true;
  }
  return false;
}

function isPrivilegedCloudPolicyOrRole(line: string): boolean {
  return /(?:AdministratorAccess|IAMFullAccess|\*:\\*|["']Owner["']|"roleDefinitionName":\s*"Owner"|User Access Administrator|Privileged Role Administrator|Contributor)/i.test(
    line
  );
}

function isCloudIamAbuse(line: string): boolean {
  if (isScheduledKeyRotation(line)) return false;
  if (
    /(?:\b(?:CreateAccessKey|PutUserPolicy|PutRolePolicy|PutGroupPolicy|UpdateAssumeRolePolicy|CreatePolicyVersion|DeactivateMFADevice|DeleteVirtualMFADevice|DeleteTrail|StopLogging|PutBucketAcl|UpdateTrail|PutEventSelectors|DeleteDetector|DeleteFlowLogs|DisassociateFromMasterAccount|elevateAccess|GetSecretValue)\b|\biam\.serviceAccountKeys\.create\b|\bSetIamPolicy\b|\bRoleManagement\.ReadWrite\.Directory\b|\bAdd-MsolRoleMember\b|\bAdd member to role\b|\bConsent to application\b|roleAssignments\/write|diagnosticSettings\/delete|\bTruffleHog\b)/i.test(
      line
    )
  ) {
    // GetSecretValue alone from an internal AWS path is routine; require an outside caller or recon/tooling.
    if (/\bGetSecretValue\b/i.test(line) && !/\b(?:ListUsers|ListAttachedRolePolicies|TruffleHog)\b/i.test(line)) {
      const ips = extractAllIps(line);
      if (ips.length === 0 || ips.every((ip) => !isExternalIp(ip))) return false;
    }
    return true;
  }
  // Attach or group-add only when the target policy or role is privileged
  if (
    /\b(?:AttachUserPolicy|AttachRolePolicy|AttachGroupPolicy|AddUserToGroup)\b/i.test(line) &&
    isPrivilegedCloudPolicyOrRole(line)
  ) {
    return true;
  }
  return false;
}

function decodePercentSequences(s: string): string {
  return s.replace(/\+/g, ' ').replace(/%([0-9A-Fa-f]{2})/g, (_m, h) =>
    String.fromCharCode(parseInt(h, 16))
  );
}

function decodeRequestForWebRules(line: string): string {
  let s = line;
  for (let i = 0; i < 2; i++) {
    const decoded = decodePercentSequences(s);
    if (decoded === s) break;
    s = decoded;
  }
  return s;
}

function normalizeForSqli(line: string): string {
  let s = decodeRequestForWebRules(line);
  // Keep MySQL versioned-comment bodies; strip nested plain comments until stable.
  let prev = '';
  while (s !== prev) {
    prev = s;
    s = s.replace(/\/\*!\d*([\s\S]*?)\*\//g, ' $1 ');
    s = s.replace(/\/\*(?:(?!\/\*|\*\/)[\s\S])*\*\//g, ' ');
  }
  // Replace comment markers with a space; do not delete the rest of the line.
  s = s.replace(/--|#/g, ' ');
  return s.replace(/\s+/g, ' ');
}

function isLinuxLogClearing(line: string): boolean {
  if (/\b(?:logrotate\b|journalctl\b[^\n]{0,80}--vacuum|(?:find|xargs)\b[^\n]{0,80}\/var\/log[^\n]{0,80}\.(?:gz|xz|bz2)[^\n]{0,40}-delete)/i.test(line)) {
    return false;
  }
  return /(?:\bshred\b[^\n]{0,80}\/var\/log|\btruncate\s+-s\s*0\s+\/var\/log|\brm\s+(?:-\w+\s+)*\/var\/log\/|>\s*\/var\/log\/|\bhistory\s+-c\b|\bunset\s+HISTFILE\b)/i.test(
    line
  );
}

function isSensitiveSudoCommand(command: string): boolean {
  const cmd = command.trim().replace(/^["']|["']$/g, '');
  const base = (cmd.split(/\s+/)[0] || '').split('/').pop() || '';
  if (/^(?:useradd|adduser|visudo)$/i.test(base)) return true;
  if (/^usermod$/i.test(base) && /(?:-aG|-a\s+-G|-G)/.test(cmd) && /\b(?:sudo|wheel|administrators)\b/i.test(cmd)) {
    return true;
  }
  if (
    /(?:^|\s|\/)chmod\b/i.test(cmd) &&
    /(?:\b[24][0-7]{3}\b|\bu\+s\b|\+[a-z]*s\b)/i.test(cmd)
  ) {
    return true;
  }
  if (/(?:>>|>|tee(?:\s+-a)?)\s+\/etc\/sudoers(?:\.d\/|\s|$)/i.test(cmd)) return true;
  if (/(?:\bfind\b[^\n]{0,80}-exec\s+\/(?:bin\/)?(?:sh|bash)|\bvim\b[^\n]{0,40}:!(?:\/bin\/)?(?:ba)?sh|\bawk\b[^\n]{0,40}system\s*\(\s*["']\/(?:bin\/)?(?:ba)?sh)/i.test(cmd)) {
    return true;
  }
  if (/^crontab$/i.test(base)) {
    if (/\s-(?:l|r)(?:\s|$)/i.test(' ' + cmd)) return false;
    return /(?:\s-e\b|\s-u\s+\S+\s+-e\b|\s-\s*$|\s+\/\S+)/i.test(' ' + cmd);
  }
  if (/\bauthorized_keys\b/i.test(cmd) && /(?:>>|tee\s+-a|ssh-copy-id)/i.test(cmd)) return true;
  if (isLinuxLogClearing(cmd)) return true;
  return false;
}

function isUnixPrivEsc(line: string): boolean {
  if (/\bpkexec\b/i.test(line) && /(?:GCONV_PATH|SHELL variable was not found)/i.test(line)) return true;
  const commandOnly = line.match(/COMMAND=\s*(.+)$/i)?.[1];
  if (commandOnly && isSensitiveSudoCommand(commandOnly)) return true;
  if (/(?:>>|>|tee(?:\s+-a)?)\s+\/etc\/sudoers(?:\.d\/|\s|$)/i.test(line)) return true;
  if (/(?:\bfind\b[^\n]{0,80}-exec\s+\/(?:bin\/)?(?:sh|bash)|\bvim\b[^\n]{0,40}:!(?:\/bin\/)?(?:ba)?sh|\bawk\b[^\n]{0,40}system\s*\(\s*["']\/(?:bin\/)?(?:ba)?sh)/i.test(line)) {
    return true;
  }
  return false;
}

function isScheduledKeyRotation(line: string): boolean {
  return /(?:KeyRotationLambda|\bkey[-_ ]?rotation\b)/i.test(line) &&
    /\b(?:CreateAccessKey|UpdateAccessKey|DeleteAccessKey)\b/i.test(line) &&
    /(?:AWS Internal|AWS Lambda)/i.test(line);
}

function isLog4ShellOrShellshock(line: string): boolean {
  return /\$\{(?:jndi|lower|upper|env|::-|\$\{)/i.test(line) || /\(\)\s*\{\s*:\s*;\s*\}\s*;/.test(line);
}

function validateContextAnswers(ctx: unknown): string | null {
  if (!ctx || typeof ctx !== 'object') return 'Mission context answers are required.';
  const c = ctx as Record<string, unknown>;
  const allowed: Record<string, string[]> = {
    missionCritical: ['yes', 'no', 'unknown'],
    piiExposure: ['yes_100k_plus', 'yes_under_100k', 'yes_unknown_volume', 'no', 'unknown'],
    authorizedActivity: ['unauthorized', 'authorized', 'unknown'],
    ictContractor: ['yes', 'no', 'unknown'],
  };
  for (const [key, values] of Object.entries(allowed)) {
    if (typeof c[key] !== 'string' || !values.includes(c[key] as string)) {
      return `Invalid context answer for ${key}.`;
    }
  }
  if (typeof c.skippedAll !== 'boolean') return 'skippedAll must be a boolean.';
  return null;
}

function enforceTotalPromptCap(prompt: string, cap: number): string {
  if (prompt.length <= cap) return prompt;
  const marker =
    '\n[Prompt truncated to LLM_LOG_PAYLOAD_MAX_CHARS, including mission context; floors were still computed on every line.]\n';
  return prompt.slice(0, Math.max(0, cap - marker.length)) + marker;
}

function parseWindowsLogonType(line: string): number | null {
  const m =
    line.match(/\b(?:LogonType|Logon\s+Type|logon_type)["']?\s*[:=]\s*"?(\d{1,2})"?/i) ||
    line.match(/<Data Name=['"]LogonType['"]>\s*(\d{1,2})\s*<\/Data>/i);
  return m ? Number(m[1]) : null;
}

function enforceLlmLogPayloadCap(digest: string, cap: number): string {
  if (digest.length <= cap) return digest;
  const marker =
    '\n[Log digest truncated to the named LLM_LOG_PAYLOAD_MAX_CHARS cap; counts, top IPs, and severity floors were still computed on every line.]\n';
  const keep = Math.max(0, cap - marker.length);
  // Prefer keeping the telemetry summary (counts, floor, top IPs) at the start.
  return digest.slice(0, keep) + marker;
}

function maxCountInWindow(sortedTimestamps: number[], windowMs: number): number {
  if (sortedTimestamps.length === 0) return 0;
  let maxCount = 1;
  let left = 0;
  for (let right = 0; right < sortedTimestamps.length; right++) {
    while (sortedTimestamps[right] - sortedTimestamps[left] > windowMs) {
      left++;
    }
    const count = right - left + 1;
    if (count > maxCount) maxCount = count;
  }
  return maxCount;
}

interface ParsedTelemetryInternal {
  summary: DeterministicTelemetrySummary;
  detectedFormats: string[];
  nssDetected: boolean;
  nssEvidence: string;
  explicitContext: LogInspectionResult['clearContextFromLogs'];
  suspiciousLines: IndexedLogLine[];
  lineTags: Map<number, string[]>;
  floorLineNumbers: {
    critical: Set<number>;
    high: Set<number>;
    medium: Set<number>;
    low: Set<number>;
  };
  lowFloorReasons: string[];
  perLineBenignReason: Map<number, string>;
}

function computeDeterministicTelemetry(indexedLines: IndexedLogLine[]): ParsedTelemetryInternal {
  const ipCounts = new Map<string, number>();
  const ipFailedCounts = new Map<string, number>();
  const ipFailedTimestamps = new Map<string, number[]>();
  const ipFailedUsers = new Map<string, Set<string>>();
  const ipLastFailedIndex = new Map<string, number>();
  const ipSucceededAfterFailure = new Set<string>();
  const ipFailedLineNums = new Map<string, number[]>();
  const ipSuccessLineNums = new Map<string, number[]>();

  // Port scan tracking per srcIp
  interface PortProbeEvent {
    tsMs: number | null;
    dstIp: string | null;
    dstPort: number | null;
    isBlockedOrSyn: boolean;
    lineNumber: number;
  }
  const ipProbeEvents = new Map<string, PortProbeEvent[]>();
  const authorizedScannerIps = configuredScannerIps();
  const ownDomains = collectRecipientDomains(indexedLines);
  const hostActivity = new Map<string, { gets: number; posts: number; nrd: boolean; mailFail: boolean }>();
  const mailFailHosts = new Set<string>();
  for (const pre of indexedLines) {
    const preLine = pre.rawLine;
    const preUrl = extractRequestUrl(preLine);
    const preHost = preUrl ? urlHostAndPath(preUrl).host.toLowerCase() : '';
    if (preHost) {
      const rec = hostActivity.get(preHost) || { gets: 0, posts: 0, nrd: false, mailFail: false };
      if (/\b(?:GET|requestMethod\s*[:=]\s*"?GET)\b/i.test(preLine)) rec.gets += 1;
      if (/\b(?:POST|PUT|requestMethod\s*[:=]\s*"?POST)\b/i.test(preLine)) rec.posts += 1;
      if (/Newly Registered Domain/i.test(preLine)) rec.nrd = true;
      hostActivity.set(preHost, rec);
    }
    if (/(?:\bspf\s*=\s*fail\b|\bdkim\s*=\s*fail\b|\bdmarc\s*=\s*fail\b)/i.test(preLine)) {
      if (preHost) {
        mailFailHosts.add(preHost);
        const rec = hostActivity.get(preHost) || { gets: 0, posts: 0, nrd: false, mailFail: false };
        rec.mailFail = true;
        hostActivity.set(preHost, rec);
      }
      const fromDom = preLine.match(/\b(?:from|header\.from)\s*[:=]\s*<?[^@\s>]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/i);
      if (fromDom) mailFailHosts.add(fromDom[1].toLowerCase());
      const lureUrls = preLine.match(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi) || [];
      for (const u of lureUrls) {
        const lh = urlHostAndPath(u).host.toLowerCase();
        if (lh) mailFailHosts.add(lh);
      }
    }
  }

  // Beaconing & outbound bytes tracking per (srcIp -> dstIp:dstPort) and (srcIp -> dstIp)
  interface FlowRecord {
    srcIp: string;
    dstIp: string;
    dstPort: number | null;
    timestampsMs: number[];
    lineNumbers: number[];
  }
  const flowMap = new Map<string, FlowRecord>();
  const outboundBytesByPair = new Map<string, { totalBytes: number; lineNumbers: number[]; dstIp: string; srcIp: string }>();

  // Password spray tracking per targetUser -> Set<srcIp>
  const userSpraySources = new Map<string, { ips: Set<string>; lineNumbers: number[]; failCount: number }>();
  const userSuccessLineNums = new Map<string, number[]>();
  const userSuccessIps = new Map<string, Set<string>>();
  const userPasswordChangeLines = new Map<string, number[]>();

  // Webshell uploaded files tracking
  const uploadedWebScripts = new Set<string>();

  const detectedFormatsSet = new Set<string>();
  const lineTags = new Map<number, string[]>();
  const suspiciousLineSet = new Set<number>();
  const perLineBenignReason = new Map<number, string>();

  const criticalLines = new Set<number>();
  const highLines = new Set<number>();
  const mediumLines = new Set<number>();
  const lowLines = new Set<number>();
  let externalFailedLoginCount = 0;
  const externalFailedLoginIps = new Set<string>();

  let failedLogins = 0;
  let successfulLogins = 0;
  let blockedDeniedConnections = 0;
  let http4xxCount = 0;
  let http5xxCount = 0;

  let sqliCount = 0;
  let xssCount = 0;
  let webshellCount = 0;
  let pathTraversalCount = 0;
  let dnsTunnelingCount = 0;
  let explicitPortScanLines = 0;
  let beaconingCount = 0;
  let exfiltrationCount = 0;

  let event4625 = 0;
  let event4720 = 0;
  let event4732 = 0;
  let event1102 = 0;
  let event7045 = 0;
  let event4624 = 0;
  let event4698 = 0;
  let event104 = 0;
  let event4728 = 0;
  let event4756 = 0;
  let explicitLogClearCmdCount = 0;
  let phishingCount = 0;
  let phishingHighCount = 0;
  let privEscCount = 0;
  let lateralCount = 0;
  let persistenceCount = 0;
  let cloudIamCount = 0;
  let lolbinCount = 0;

  let nssDetected = false;
  const nssEvidenceList: string[] = [];

  const explicitContext: LogInspectionResult['clearContextFromLogs'] = {
    missionCritical: { detected: false, suggestedValue: 'unknown', evidence: '' },
    piiExposure: { detected: false, suggestedValue: 'unknown', evidence: '' },
    authorizedActivity: { detected: false, suggestedValue: 'unknown', evidence: '' },
    ictContractor: { detected: false, suggestedValue: 'unknown', evidence: '' },
  };

  let activeCsvHeaderMap: CsvHeaderMap | null = null;
  let lastSource = '';

  const addTag = (lineNumber: number, tag: string) => {
    const existing = lineTags.get(lineNumber) || [];
    if (!existing.includes(tag)) {
      existing.push(tag);
      lineTags.set(lineNumber, existing);
    }
    suspiciousLineSet.add(lineNumber);
  };

  const sqliRegex =
    /(?:\bUNION(?:\s|\+|%20)+(?:ALL(?:\s|\+|%20)+)?SELECT\b|'\s*OR\s*['"]?\d+['"]?\s*=\s*['"]?\d+|\bOR\s+1\s*=\s*1\b|\bSLEEP\s*\(\s*\d|\bBENCHMARK\s*\(|\bWAITFOR\s+DELAY\b|\bxp_cmdshell\b|\bINFORMATION_SCHEMA\b|\bsqlmap\b|%27\s*(?:OR|UNION)|%27%20(?:OR|UNION))/i;
  const xssRegex =
    /(?:<script\b|%3cscript|<\/script>|%3c%2fscript%3e|\bjavascript:|onerror\s*=|onload\s*=|onfocus\s*=|onmouseover\s*=|\balert\s*\(|document\.cookie)/i;
  const traversalRegex =
    /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|\/|%5c)|(?:%c0%ae|%c0%af|%e0%80%ae){2,}|(?:\.\.|%2e%2e).{0,60}(?:\/etc\/(?:passwd|shadow)|(?:win|boot)\.ini))/i;
  const blockedRegex =
    /(?:\b(?:DENY|DENIED|BLOCK|BLOCKED|DROP|DROPPED|REJECT|REJECTED)\b|\baction\s*=\s*["']?(?:block|blocked|deny|denied|drop|dropped|reject)["']?|\bUFW\s+BLOCK\b)/i;
  const sshFailRegex =
    /(?:\bFailed\s+(?:password|publickey|keyboard-interactive)\b|\bauthentication\s+failure\b|\bInvalid\s+user\b|\bLogon\s+Failure\b|\bbad\s+password\b|\binvalid\s+credentials\b|\bauth(?:entication)?\s+(?:failed|denied)\b|\bLOGIN_FAILED\b)/i;
  const sshSuccessRegex =
    /(?:\bAccepted\s+(?:password|publickey|keyboard-interactive)\b|\bsession\s+opened\s+for\s+user\b|\bSuccessful\s+logon\b|\blogin\s+succeeded\b|\bResultType\s*[:=]\s*0\b|\bLOGIN_OK\b|\bauthentication succeeded\b)/i;
  const portScanRegex =
    /(?:\bport[\s_-]?scan\b|\bnmap\b|\bmasscan\b|\bSYN[\s_-]?scan\b|\bnetwork\s+sweep\b)/i;
  const exfilRegex =
    /(?:\bexfiltrat(?:e|ed|ion)\b|\brclone\b|\bmega\.nz\b|\bcurl\s+[^\n]*(?:-T|--upload-file)\b|\b(?:scp|sftp)\s+[^\n]*\.(?:zip|7z|tar|gz|rar|sql|csv)\b|\bInvoke-WebRequest\b[^\n]*-Method\s+Post\b)/i;
  const dnsExplicitRegex = /(?:\bdns[\s_-]?tunnel(?:ing)?\b|\biodine\b|\bdnscat\b)/i;
  const logClearCmdRegex =
    /(?:\bwevtutil\s+(?:cl|clear-log)\b|\bClear-EventLog\b|\baudit\s+log\s+was\s+cleared\b|\bsecurity\s+log\s+cleared\b)/i;
  const nssRegex =
    /(?:\bTOP\s+SECRET\b|\bSECRET\/\/|\bTS\/\/SI\b|\bCNSSI\s*1010\b|\bNational\s+Security\s+System\b|\bclassified\s+(?:information|network|system)\b|\bSIPRNET\b|\bJWICS\b)/i;
  const webshellParamRegex =
    /(?:[?&](?:cmd|exec|command|shell|run|c)=[^&\s"]+|eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|shell_exec\s*\()/i;

  for (let idx = 0; idx < indexedLines.length; idx++) {
    const item = indexedLines[idx];
    const line = item.rawLine;
    const ln = item.lineNumber;

    if (item.source !== lastSource) {
      activeCsvHeaderMap = null;
      lastSource = item.source;
    }

    const maybeHeader = tryParseCsvHeaderMap(line);
    if (maybeHeader) {
      activeCsvHeaderMap = maybeHeader;
      perLineBenignReason.set(ln, 'CSV log header row defining column schema.');
      continue;
    }

    const { ms: tsMs, utcHour } = parseTimestampMs(item.timestamp);

    let csvAuthFail = false;
    let csvAuthSuccess = false;
    let csvAuthUser: string | null = null;
    let csvAuthSrc: string | null = null;
    if (activeCsvHeaderMap && (activeCsvHeaderMap.resultIdx >= 0 || activeCsvHeaderMap.userIdx >= 0)) {
      const cols = splitCsvLine(line, activeCsvHeaderMap.delim);
      if (activeCsvHeaderMap.resultIdx >= 0 && cols[activeCsvHeaderMap.resultIdx]) {
        const rv = cols[activeCsvHeaderMap.resultIdx].toLowerCase();
        if (/^(?:failure|fail|failed|denied|error)$/.test(rv)) csvAuthFail = true;
        if (/^(?:success|successful|accepted|ok)$/.test(rv)) csvAuthSuccess = true;
      }
      if (activeCsvHeaderMap.userIdx >= 0 && cols[activeCsvHeaderMap.userIdx]) {
        csvAuthUser = cols[activeCsvHeaderMap.userIdx].toLowerCase();
      }
      if (activeCsvHeaderMap.srcIdx >= 0 && cols[activeCsvHeaderMap.srcIdx] && isUsableIp(cols[activeCsvHeaderMap.srcIdx])) {
        csvAuthSrc = cols[activeCsvHeaderMap.srcIdx];
      }
    } else if (!line.startsWith('{') && !line.startsWith('<') && (line.includes(',') || line.includes(';'))) {
      const delim = csvDelimiter(line);
      const cols = splitCsvLine(line, delim);
      // Headerless auth row: ts, service, success|failure, host, srcIp, ...
      if (
        cols.length >= 5 &&
        /^(?:sshd|sso|vpn|owa|auth|openconnect|auth-gw)$/i.test(cols[1] || '') &&
        /^(?:success|failure|failed|ok)$/i.test(cols[2] || '')
      ) {
        const rv = cols[2].toLowerCase();
        csvAuthFail = rv === 'failure' || rv === 'failed';
        csvAuthSuccess = rv === 'success' || rv === 'ok';
        if (isUsableIp(cols[4] || '')) csvAuthSrc = cols[4];
        const userGuess = cols[8] || cols[7] || cols[6];
        if (userGuess && /^[A-Za-z0-9._@-]{2,40}$/.test(userGuess) && !isUsableIp(userGuess)) {
          csvAuthUser = userGuess.toLowerCase();
        }
      }
    }

    // Format detection
    if (/\bCEF:\d+\|/.test(line)) {
      detectedFormatsSet.add('CEF');
    } else if (
      /\b(?:TCP_MISS|TCP_DENIED|TCP_TUNNEL|PROXY_HIT)\//.test(line) ||
      /\b(?:proxy_host|proxy-id|elff|cs-uri)\b/i.test(line)
    ) {
      detectedFormatsSet.add('Proxy / Web Gateway Log');
    } else if (/"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP\/\d\.\d"/.test(line)) {
      detectedFormatsSet.add('Web Server / HTTP Access Log');
    } else if (/\b(?:EventID|EventCode|event_id)["']?\s*[:=]|\b<EventID|Microsoft-Windows-/i.test(line)) {
      detectedFormatsSet.add('Windows Event Log');
    } else if (/\bsshd\b|\bpam_unix\b|\bsudo\b/i.test(line)) {
      detectedFormatsSet.add('Linux / SSH Authentication Log');
    } else if (
      activeCsvHeaderMap !== null ||
      /\b(?:SRC|DST)=|\bUFW\b|\baction=(?:allow|block|deny|drop)/i.test(line)
    ) {
      detectedFormatsSet.add('Firewall / Network ACL Log');
    } else if (/\b(?:query|NXDOMAIN|NOERROR|A|AAAA|TXT|CNAME)\b/i.test(line) && /\bdns\b/i.test(line)) {
      detectedFormatsSet.add('DNS Query Log');
    } else if (line.startsWith('{') && line.endsWith('}')) {
      detectedFormatsSet.add('Structured JSON Log');
    }

    // NSS / Classified
    if (nssRegex.test(line)) {
      nssDetected = true;
      if (nssEvidenceList.length < 3) {
        nssEvidenceList.push(`L${ln}: ${line.slice(0, 140)}`);
      }
      addTag(ln, 'NSS / Classified Indicator');
    }

    // Explicit context checks
    if (
      !explicitContext.piiExposure.detected &&
      /\b(1[0-9]{5,}|[2-9][0-9]{5,})\s+(?:PII|SSN|records|individuals)\b/i.test(line)
    ) {
      explicitContext.piiExposure = {
        detected: true,
        suggestedValue: 'yes_100k_plus',
        evidence: `L${ln}: explicit 100,000+ PII record reference`,
      };
    }
    if (
      !explicitContext.ictContractor.detected &&
      /\b(?:contractor|CSP|AWS|Azure|GCP|cloud\s+provider|SaaS\s+vendor)\b/i.test(line)
    ) {
      explicitContext.ictContractor = {
        detected: true,
        suggestedValue: 'yes',
        evidence: `L${ln}: explicit cloud/contractor system indicator`,
      };
    }

    // Network 5-tuple & bytes extraction
    const net = extractNetworkTuple(line, activeCsvHeaderMap);
    const srcIp = net.srcIp || csvAuthSrc;
    if (srcIp) {
      ipCounts.set(srcIp, (ipCounts.get(srcIp) || 0) + 1);
    }

    // Collect port probes for port-scan detection
    if (srcIp && (net.dstPort !== null || net.dstIp !== null)) {
      const arr = ipProbeEvents.get(srcIp) || [];
      arr.push({
        tsMs,
        dstIp: net.dstIp,
        dstPort: net.dstPort,
        isBlockedOrSyn: net.isBlockedOrSyn,
        lineNumber: ln,
      });
      ipProbeEvents.set(srcIp, arr);
    }

    // Collect flow timestamps for C2 beaconing detection (srcIp -> dstIp:dstPort)
    if (srcIp && tsMs !== null) {
      const decoded = decodeDnsWireLabels(line);
      const qn = decoded.match(
        /(?:\bquery(?:\[\w+\])?\s+|\bquery:\s+|\bQ \[[^\]]+\]\s+\S+\s+)([A-Za-z0-9._-]+\.[A-Za-z]{2,63})/i
      );
      if (qn && !hasWellKnownDnsSuffix(qn[1])) {
        const labels = qn[1].toLowerCase().replace(/\.$/, '').split('.');
        const apex = labels.slice(-3).join('.');
        const flowKey = `${srcIp}->dns:${apex}`;
        const existing = flowMap.get(flowKey);
        if (existing) {
          existing.timestampsMs.push(tsMs);
          existing.lineNumbers.push(ln);
        } else {
          flowMap.set(flowKey, {
            srcIp,
            dstIp: apex,
            dstPort: 53,
            timestampsMs: [tsMs],
            lineNumbers: [ln],
          });
        }
      }
    }
    if (srcIp && net.dstIp && tsMs !== null && !/"(?:GET|POST|PUT|DELETE|HEAD)/.test(line)) {
      const flowKey = `${srcIp}->${net.dstIp}:${net.dstPort ?? 0}`;
      let flow = flowMap.get(flowKey);
      if (!flow) {
        flow = {
          srcIp,
          dstIp: net.dstIp,
          dstPort: net.dstPort,
          timestampsMs: [],
          lineNumbers: [],
        };
        flowMap.set(flowKey, flow);
      }
      flow.timestampsMs.push(tsMs);
      flow.lineNumbers.push(ln);
    }

    // Large outbound transfer / exfiltration detection
    const exfilUrl = extractRequestUrl(line);
    const exfilUrlHost = exfilUrl ? urlHostAndPath(exfilUrl).host : '';
    const trustedExfilUrl = Boolean(exfilUrlHost && isExemptExfilHost(exfilUrlHost, exfilUrl));
    if (srcIp && net.dstIp && net.bytesOut !== null && isExternalIp(net.dstIp) && !isConfiguredBackupEvent(line) && !trustedExfilUrl) {
      const pairKey = `${srcIp}->${net.dstIp}`;
      const existing = outboundBytesByPair.get(pairKey) || {
        totalBytes: 0,
        lineNumbers: [],
        dstIp: net.dstIp,
        srcIp,
      };
      existing.totalBytes += net.bytesOut;
      existing.lineNumbers.push(ln);
      outboundBytesByPair.set(pairKey, existing);

      const isNonStandardPort =
        net.dstPort !== null && net.dstPort !== 80 && net.dstPort !== 443 && net.dstPort !== 53;
      const isNightHours = utcHour !== null && utcHour >= 0 && utcHour < 6;
      const singleTransferSuspicious =
        net.bytesOut >= 50_000_000 ||
        (net.bytesOut >= 10_000_000 && (isNonStandardPort || isNightHours));

      if (singleTransferSuspicious) {
        exfiltrationCount++;
        addTag(
          ln,
          `Large Outbound Transfer (${Math.round(net.bytesOut / 1_000_000)} MB to external ${net.dstIp}${net.dstPort ? `:${net.dstPort}` : ''})`
        );
        highLines.add(ln);
      }
    }

    // HTTP 4xx / 5xx & Webshell / Upload correlation
    const httpStatus = extractHttpStatus(line);
    if (httpStatus !== null) {
      if (httpStatus >= 400 && httpStatus < 500) http4xxCount++;
      if (httpStatus >= 500 && httpStatus < 600) http5xxCount++;
    }

    const httpReqMatch = line.match(/"(GET|POST|PUT|DELETE|PATCH)\s+([^\s?"]+)([^"\s]*)\s+HTTP\/\d\.\d"/i);
    if (httpReqMatch) {
      const method = httpReqMatch[1].toUpperCase();
      const urlPath = httpReqMatch[2];
      const queryPart = httpReqMatch[3] || '';

      // Track uploaded scripts on POST/PUT (e.g. POST /upload ... shell.php or POST /uploads/cmd.php)
      if ((method === 'POST' || method === 'PUT') && (httpStatus === null || httpStatus < 400)) {
        const scriptMatches = `${urlPath} ${line}`.match(/\b([A-Za-z0-9_.-]+\.(?:php\d?|jsp|jspx|asp|aspx|phtml))\b/gi);
        if (
          scriptMatches &&
          (/upload|shell|webshell|backdoor|cmd/i.test(line) || /\.(?:php\d?|jsp|jspx|asp|aspx|phtml)$/i.test(urlPath))
        ) {
          for (const fname of scriptMatches) {
            uploadedWebScripts.add(fname.toLowerCase());
          }
          addTag(ln, `Web Script Upload (${method} ${urlPath})`);
          highLines.add(ln);
          webshellCount++;
        }
      }

      // Check GET/POST execution of uploaded web script OR webshell parameter
      const pathBase = path.posix.basename(urlPath).toLowerCase();
      const isUploadedFollowup =
        uploadedWebScripts.has(pathBase) &&
        /\.(?:php\d?|jsp|jspx|asp|aspx|phtml)$/i.test(pathBase) &&
        (method === 'GET' || method === 'POST');
      const hasShellParam = webshellParamRegex.test(`${queryPart} ${line}`);

      if (isUploadedFollowup || hasShellParam) {
        webshellCount++;
        addTag(ln, `Webshell Execution Indicator (${method} ${urlPath}${queryPart})`);
        highLines.add(ln);
      }
    } else if (webshellParamRegex.test(line)) {
      webshellCount++;
      addTag(ln, 'Webshell Command Execution Parameter');
      highLines.add(ln);
    }

    // Blocked / denied
    if (blockedRegex.test(line)) {
      blockedDeniedConnections++;
    }

    // Windows Event IDs (strict)
    const winIds = extractWindowsEventIds(line);
    let lineIsWinFail = false;
    let lineIsWinSuccess = false;
    for (const id of winIds) {
      if (id === 4625) {
        event4625++;
        lineIsWinFail = true;
      } else if (id === 4720) {
        event4720++;
        addTag(ln, 'Windows Event 4720 (Account Created)');
      } else if (id === 4723 || id === 4724) {
        const chUser = (line.match(/\b(?:TargetUserName)["']?\s*[:=]\s*"?([^"\s,]+)"?/i) || [])[1] || extractUsername(line);
        if (chUser) {
          const arr = userPasswordChangeLines.get(chUser) || [];
          arr.push(ln);
          userPasswordChangeLines.set(chUser, arr);
        }
      } else if (id === 4732) {
        event4732++;
        addTag(ln, 'Windows Event 4732 (Added to Security Group)');
      } else if (id === 4728) {
        event4728++;
        addTag(ln, 'Windows Event 4728 (Added to Global Security Group)');
      } else if (id === 4756) {
        event4756++;
        addTag(ln, 'Windows Event 4756 (Added to Universal Security Group)');
      } else if (id === 1102) {
        event1102++;
        addTag(ln, 'Windows Event 1102 (Audit Log Cleared)');
        criticalLines.add(ln);
      } else if (id === 104) {
        event104++;
        addTag(ln, 'Windows Event 104 (System Log Cleared)');
        criticalLines.add(ln);
      } else if (id === 7045) {
        event7045++;
        addTag(ln, 'Windows Event 7045 (New Service Installed)');
        criticalLines.add(ln);
      } else if (id === 4624) {
        event4624++;
        lineIsWinSuccess = true;
      } else if (id === 4698) {
        event4698++;
        persistenceCount++;
        addTag(ln, 'Windows Event 4698 (Scheduled Task Created)');
        highLines.add(ln);
      } else if (id === 5140 || id === 5145) {
        if (isLateralMovementIndicator(line)) {
          lateralCount++;
          addTag(ln, `Windows Event ${id} (Admin or hidden share access)`);
          highLines.add(ln);
        }
      } else if (id === 4648) {
        const targetHost = line.match(
          /\b(?:TargetServerName|WorkstationName)["']?\s*[:=]\s*"?([A-Za-z0-9._-]+)"?/i
        );
        const host = targetHost?.[1] || '';
        if (
          isLateralMovementIndicator(line) ||
          (host && !/^(?:localhost|127\.0\.0\.1|-|%local%)$/i.test(host))
        ) {
          lateralCount++;
          addTag(ln, 'Windows Event 4648 (explicit credentials to another host)');
          highLines.add(ln);
        }
      }
    }

    if (logClearCmdRegex.test(line) || isLinuxLogClearing(line)) {
      explicitLogClearCmdCount++;
      addTag(ln, 'Audit / Event Log Clear Command');
      criticalLines.add(ln);
    }

    // Failed / Successful Login tracking
    const isHttpAuthPath = /\/(?:login|signin|auth|wp-login|admin)\b/i.test(line);
    const isHttpAuthFail = isHttpAuthPath && (httpStatus === 401 || httpStatus === 403);
    const isHttpAuthSuccess =
      isHttpAuthPath && (httpStatus === 200 || httpStatus === 302) && /\bPOST\b/i.test(line);

    const authContext = /(?:\b(?:user|username|TargetUserName|authMethod|service|sshd|vpn|sso|owa|openconnect|auth-gw)\b)/i.test(
      line
    );
    const structuredFail =
      authContext &&
      /(?:["'](?:result|outcome|reason)["']\s*:\s*["'](?:failure|fail|failed|denied|bad_password|nouser)["']|\boutcome\s*=\s*(?:failure|fail)\b)/i.test(
        line
      );
    const structuredSuccess =
      authContext &&
      /(?:["'](?:result|outcome)["']\s*:\s*["']success(?:ful)?["']|\boutcome\s*=\s*success\b)/i.test(line);
    const isFailedLogin = lineIsWinFail || sshFailRegex.test(line) || isHttpAuthFail || structuredFail || csvAuthFail;
    const isSuccessLogin = lineIsWinSuccess || sshSuccessRegex.test(line) || isHttpAuthSuccess || structuredSuccess || csvAuthSuccess;

    if (isFailedLogin) {
      failedLogins++;
      const username = extractUsername(line) || csvAuthUser;
      if (srcIp) {
        if (isNonRfc1918Ip(srcIp)) {
          externalFailedLoginCount++;
          externalFailedLoginIps.add(srcIp);
          addTag(ln, `Failed Login from Non-RFC1918 Source (${srcIp})`);
          lowLines.add(ln);
        }
        ipFailedCounts.set(srcIp, (ipFailedCounts.get(srcIp) || 0) + 1);
        ipLastFailedIndex.set(srcIp, idx);
        const arr = ipFailedLineNums.get(srcIp) || [];
        arr.push(ln);
        ipFailedLineNums.set(srcIp, arr);

        if (tsMs !== null) {
          const tsArr = ipFailedTimestamps.get(srcIp) || [];
          tsArr.push(tsMs);
          ipFailedTimestamps.set(srcIp, tsArr);
        }
        if (username) {
          const uSet = ipFailedUsers.get(srcIp) || new Set<string>();
          uSet.add(username);
          ipFailedUsers.set(srcIp, uSet);
        }
      }
      if (username && srcIp) {
        const sp = userSpraySources.get(username) || {
          ips: new Set<string>(),
          lineNumbers: [],
          failCount: 0,
        };
        sp.ips.add(srcIp);
        sp.lineNumbers.push(ln);
        sp.failCount++;
        userSpraySources.set(username, sp);
      }
    } else if (isSuccessLogin) {
      successfulLogins++;
      const successUser = extractUsername(line);
      if (successUser) {
        const arr = userSuccessLineNums.get(successUser) || [];
        arr.push(ln);
        userSuccessLineNums.set(successUser, arr);
        if (srcIp) {
          const ips = userSuccessIps.get(successUser) || new Set<string>();
          ips.add(srcIp);
          userSuccessIps.set(successUser, ips);
        }
      }
      const pwChg = line.match(/\bpassword (?:was )?changed (?:for|by)\s+(\S+)/i);
      if (pwChg) {
        const u = pwChg[1].replace(/[,:;]+$/, '');
        const arr = userPasswordChangeLines.get(u) || [];
        arr.push(ln);
        userPasswordChangeLines.set(u, arr);
      }
      if (srcIp) {
        const lastFailIdx = ipLastFailedIndex.get(srcIp);
        if (lastFailIdx !== undefined && idx > lastFailIdx) {
          ipSucceededAfterFailure.add(srcIp);
          const arr = ipSuccessLineNums.get(srcIp) || [];
          arr.push(ln);
          ipSuccessLineNums.set(srcIp, arr);
        }
      }
    }

    // Privilege escalation: privileged group add or sudoers/usermod change
    if (
      ((winIds.includes(4732) || winIds.includes(4728) || winIds.includes(4756)) &&
        isPrivilegedGroupName(line)) ||
      /(?:\busermod\b[^\n]{0,80}(?:-aG|-a -G)\s+(?:sudo|wheel|administrators)|\bgpasswd\s+-a\s+\S+\s+(?:sudo|wheel)|\badduser\s+\S+\s+(?:sudo|wheel|admin)|\badd(?:ed)?\s+'[^']+'\s+to group ['\"]?(?:sudo|wheel|administrators)|\badded to group (?:sudo|wheel|administrators)\b)/i.test(
        line
      )
    ) {
      privEscCount++;
      addTag(ln, 'Privilege Escalation (privileged group or sudoers change)');
      if (winIds.includes(4728) || winIds.includes(4756)) {
        criticalLines.add(ln);
      } else {
        highLines.add(ln);
      }
    }
    if (isUnixPrivEsc(line)) {
      privEscCount++;
      addTag(ln, 'Privilege Escalation (unix sudoers, GTFOBins, or pkexec)');
      if (/\bpkexec\b/i.test(line) && /(?:GCONV_PATH|SHELL variable was not found)/i.test(line)) {
        criticalLines.add(ln);
      } else {
        highLines.add(ln);
      }
    }
    const sudoRoot = line.match(/sudo:\s+(\S+)\s*:[^\n]*USER=root\s*;\s*COMMAND=\s*(.+)$/i);
    if (sudoRoot && !/\bCRON\[/.test(line) && isSensitiveSudoCommand(sudoRoot[2])) {
      privEscCount++;
      addTag(ln, `Privilege Escalation (sudo to root: ${sudoRoot[2].slice(0, 80)})`);
      highLines.add(ln);
    }

    // Persistence (registry Run keys, crontab files, authorized_keys, schtasks)
    if (isPersistenceIndicator(line)) {
      persistenceCount++;
      addTag(ln, 'Persistence Indicator (autorun, scheduled task, or SSH key)');
      highLines.add(ln);
    }

    // Lateral movement keywords / external RDP
    if (isLateralMovementIndicator(line) && !highLines.has(ln)) {
      lateralCount++;
      addTag(ln, 'Lateral Movement Indicator');
      highLines.add(ln);
    }
    const logonType = parseWindowsLogonType(line);
    if (winIds.includes(4624) && logonType === 10 && srcIp && isNonRfc1918Ip(srcIp)) {
      lateralCount++;
      addTag(ln, `External RDP logon type 10 from ${srcIp}`);
      highLines.add(ln);
    }

    // Phishing: require a look-alike, a newly registered domain, a failed mail lure,
    // or a click-then-POST chain to the same untrusted host. A login-path POST alone is not High.
    const requestUrl = extractRequestUrl(line);
    const clientLooksInternal = !srcIp || !isExternalIp(srcIp);
    const urlParts = requestUrl ? urlHostAndPath(requestUrl) : null;
    const nrdCategory = /Newly Registered Domain/i.test(line);
    let phishHost = '';
    if (urlParts && isLikelyPhishHost(urlParts.host, ownDomains)) phishHost = urlParts.host;
    // DNS query logs only: a lookalike qname, not referer or user-agent hosts.
    if (!phishHost && /(?:\bquery(?:\[\w+\])?\s+|\bquery:\s+|\bQ \[[^\]]+\]|\bNXDOMAIN\b|\bNOERROR\b)/i.test(line)) {
      const decodedForDns = decodeDnsWireLabels(line);
      const hostCandidates = decodedForDns.match(/\b(?:[a-z0-9-]+\.){1,}[a-z]{2,63}\b/gi) || [];
      phishHost = hostCandidates.find((h) => isLikelyPhishHost(h, ownDomains)) || '';
    }
    const reqHost = (urlParts?.host || phishHost || '').toLowerCase();
    const activity = reqHost ? hostActivity.get(reqHost) : undefined;
    const untrustedUrlHost = Boolean(
      reqHost && !isUsableIp(reqHost) && !isFirstPartyHost(reqHost, ownDomains)
    );
    const mailLure =
      Boolean(reqHost && (mailFailHosts.has(reqHost) || activity?.mailFail)) ||
      (/(?:\bspf\s*=\s*fail\b|\bdkim\s*=\s*fail\b|\bdmarc\s*=\s*fail\b)/i.test(line) &&
        Boolean(requestUrl));
    const clickThenPost =
      Boolean(reqHost && untrustedUrlHost && activity && activity.gets > 0 && activity.posts > 0) &&
      (isUserContentStorageHost(reqHost) || Boolean(phishHost) || mailLure || nrdCategory);
    const phishSignal =
      Boolean(phishHost) ||
      nrdCategory ||
      mailLure ||
      clickThenPost;
    const isPost = /\b(?:POST|requestMethod\s*[:=]\s*"?POST)\b/i.test(line);
    if (clientLooksInternal && phishSignal && (untrustedUrlHost || phishHost || nrdCategory || mailLure)) {
      const host = phishHost || urlParts?.host || 'external-host';
      phishingCount++;
      addTag(ln, `Credential-harvest or lookalike login activity toward ${host}`);
      if (isPost && phishSignal) {
        phishingHighCount++;
        highLines.add(ln);
      } else {
        mediumLines.add(ln);
      }
    }

    // Cloud control-plane IAM abuse (credential creation, policy attach, audit disable)
    if (isCloudIamAbuse(line)) {
      cloudIamCount++;
      addTag(ln, 'Cloud IAM abuse (credential, policy, or logging change)');
      highLines.add(ln);
    }

    // Encoded PowerShell / living-off-the-land download cradles
    if (hasSuspiciousLolbin(line)) {
      lolbinCount++;
      addTag(ln, 'Suspicious encoded command or living-off-the-land download');
      highLines.add(ln);
    }

    // Suspicious Web / DNS / Network patterns (URL-decode up to twice)
    const webHaystack = decodeRequestForWebRules(line);
    const sqliHaystack = normalizeForSqli(line);
    if (sqliRegex.test(line) || sqliRegex.test(webHaystack) || sqliRegex.test(sqliHaystack)) {
      sqliCount++;
      addTag(ln, 'SQL Injection Pattern');
      highLines.add(ln);
    }
    if (xssRegex.test(line) || xssRegex.test(webHaystack)) {
      xssCount++;
      addTag(ln, 'XSS Attempt Pattern');
      highLines.add(ln);
    }
    if (traversalRegex.test(line) || traversalRegex.test(webHaystack)) {
      pathTraversalCount++;
      addTag(ln, 'Path Traversal Pattern');
      mediumLines.add(ln);
    }
    if (isLog4ShellOrShellshock(line) || isLog4ShellOrShellshock(webHaystack)) {
      xssCount++;
      addTag(ln, 'Log4Shell or Shellshock Pattern');
      highLines.add(ln);
    }
    if (dnsExplicitRegex.test(line) || hasLongRandomSubdomain(line)) {
      dnsTunnelingCount++;
      addTag(ln, 'DNS Tunneling / Long Random Subdomain');
      highLines.add(ln);
    }
    if (portScanRegex.test(line)) {
      explicitPortScanLines++;
      addTag(ln, 'Port Scan Indicator');
      mediumLines.add(ln);
    }
    if (exfilRegex.test(line) && !isProvablyInternalExfil(line) && !isConfiguredBackupEvent(line)) {
      exfiltrationCount++;
      addTag(ln, 'Data Exfiltration Indicator');
      highLines.add(ln);
    }
    if (!isConfiguredBackupEvent(line) && !isProvablyInternalExfil(line)) {
      const upUrl = extractRequestUrl(line);
      if (upUrl && /\b(?:PUT|POST)\b/i.test(line)) {
        const { host } = urlHostAndPath(upUrl);
        const size = net.bytesOut;
        const archiveUpload = /\.(?:7z|zip|tar|gz|tgz|rar|vbk|sql|bak)(?:\s|"|$|HTTP)/i.test(line);
        const configuredOwn = parseEnvNameList('FCEB_FIRST_PARTY_DOMAINS');
        if (
          host &&
          !isInternalHostname(host, configuredOwn) &&
          !isExemptExfilHost(host, upUrl) &&
          ((size !== null && size >= 50_000_000) || archiveUpload)
        ) {
          exfiltrationCount++;
          addTag(
            ln,
            size !== null && size >= 50_000_000
              ? `Large outbound transfer (${Math.round(size / 1_000_000)} MB) to ${host}`
              : `Archive upload to unsanctioned host ${host}`
          );
          highLines.add(ln);
        }
      }
    }

    // Concise benign defaults
    if (httpStatus !== null && httpStatus < 400) {
      perLineBenignReason.set(
        ln,
        `Routine HTTP ${httpStatus} web request with no suspicious parameters or indicators.`
      );
    } else if (httpStatus === 404) {
      perLineBenignReason.set(
        ln,
        'Standard HTTP 404 not-found response without traversal, SQLi, XSS, or webshell indicators.'
      );
    } else if (blockedRegex.test(line)) {
      perLineBenignReason.set(
        ln,
        'Routine firewall/ACL block of unestablished connection without follow-on intrusion indicators.'
      );
    }
  }

  // Post-pass 1: correlate 4720 + 4732 (new account + security group add) -> Critical
  if (event4720 > 0 && (event4732 > 0 || event4728 > 0 || event4756 > 0)) {
    for (const [ln, tags] of lineTags.entries()) {
      if (
        tags.includes('Windows Event 4720 (Account Created)') ||
        tags.includes('Windows Event 4732 (Added to Security Group)') ||
        tags.includes('Windows Event 4728 (Added to Global Security Group)') ||
        tags.includes('Windows Event 4756 (Added to Universal Security Group)')
      ) {
        criticalLines.add(ln);
      }
    }
  }

  // Post-pass: lateral fan-out over admin-service ports to a small set of internal hosts
  const lateralPorts = new Set([135, 445, 3389, 5985, 5986]);
  for (const [src, evs] of ipProbeEvents.entries()) {
    if (!src || isExternalIp(src)) continue;
    const hits = evs.filter(
      (e) => e.dstIp && !isExternalIp(e.dstIp) && e.dstPort !== null && lateralPorts.has(e.dstPort) && !e.isBlockedOrSyn
    );
    const dests = new Set(hits.map((e) => e.dstIp as string));
    if (dests.size >= 2 && dests.size <= 8 && hits.length >= 2) {
      lateralCount++;
      for (const e of hits) {
        addTag(e.lineNumber, `Lateral movement fan-out from ${src} to ${dests.size} internal hosts`);
        highLines.add(e.lineNumber);
      }
    }
  }

  // Post-pass 2: (B) Failed-login burst (>=14 in 15m) or password spray vs scattered failures
  const bruteForceIps: BruteForceIpDetail[] = [];
  const tenMinutesMs = 10 * 60 * 1000;
  let hasMediumAuthBurstOrSpray = false;
  let hasHighSpraySuccess = false;

  for (const [ip, failCount] of ipFailedCounts.entries()) {
    const followedBySuccess = ipSucceededAfterFailure.has(ip);
    const tsList = (ipFailedTimestamps.get(ip) || []).slice().sort((a, b) => a - b);
    // Short burst window (15 minutes). A day of spaced-out guesses is not a burst.
    const authBurstWindowMs = 15 * 60 * 1000;
    const burstCount =
      tsList.length > 0 ? maxCountInWindow(tsList, authBurstWindowMs) : failCount;
    const distinctUsersCount = ipFailedUsers.get(ip)?.size || 0;
    const isPasswordSpray = distinctUsersCount >= 5 && failCount >= 8;

    if (burstCount >= 14 && followedBySuccess) {
      bruteForceIps.push({ ip, failedCount: failCount, followedBySuccess: true });
      (ipFailedLineNums.get(ip) || []).forEach((ln) => {
        addTag(ln, `Brute Force (>=14 fails in 15m + success) from ${ip}`);
        highLines.add(ln);
      });
      (ipSuccessLineNums.get(ip) || []).forEach((ln) => {
        addTag(ln, `Post-Brute-Force Successful Login from ${ip}`);
        highLines.add(ln);
      });
    } else if (isPasswordSpray || burstCount >= 14) {
      const raiseHigh = Boolean(isPasswordSpray && followedBySuccess);
      if (raiseHigh) hasHighSpraySuccess = true;
      if (!raiseHigh) hasMediumAuthBurstOrSpray = true;
      bruteForceIps.push({ ip, failedCount: failCount, followedBySuccess });
      const label = isPasswordSpray
        ? `Password Spray (${distinctUsersCount} distinct users, ${failCount} fails) from ${ip}`
        : `Failed Login Burst (${burstCount} fails within 15m) from ${ip}`;
      (ipFailedLineNums.get(ip) || []).forEach((ln) => {
        addTag(ln, label);
        if (raiseHigh) highLines.add(ln);
        else mediumLines.add(ln);
      });
      if (followedBySuccess) {
        (ipSuccessLineNums.get(ip) || []).forEach((ln) => {
          addTag(ln, `Login After Burst/Spray from ${ip}`);
          if (raiseHigh) highLines.add(ln);
          else mediumLines.add(ln);
        });
      }
    } else if (failCount >= 14 && followedBySuccess) {
      (ipFailedLineNums.get(ip) || []).forEach((ln) => {
        addTag(ln, `Long-window failures then success from ${ip} (stale credential)`);
      });
      (ipSuccessLineNums.get(ip) || []).forEach((ln) => {
        addTag(ln, `Successful logon after long-window failures from ${ip} (stale credential)`);
      });
    }
  }

  // Multi-IP password spray targeting a single account (>= 4 distinct IPs, >= 15 fails)
  for (const [username, info] of userSpraySources.entries()) {
    if (info.ips.size >= 4 && info.failCount >= 15) {
      const hasExternalSprayIp = Array.from(info.ips).some((ip) => isExternalIp(ip));
      if (!hasExternalSprayIp) continue;
      const pwChanged = (userPasswordChangeLines.get(username) || []).length > 0;
      if (pwChanged) continue;
      const successLines = userSuccessLineNums.get(username) || [];
      const successIps = userSuccessIps.get(username) || new Set<string>();
      const successFromSprayIp = Array.from(successIps).some((ip) => info.ips.has(ip));
      const raiseHigh = successLines.length > 0 && successFromSprayIp;
      if (raiseHigh) hasHighSpraySuccess = true;
      if (!raiseHigh) hasMediumAuthBurstOrSpray = true;
      info.lineNumbers.forEach((ln) => {
        addTag(
          ln,
          `Distributed Password Spray against ${username} (${info.ips.size} IPs, ${info.failCount} fails)`
        );
        if (raiseHigh) highLines.add(ln);
        else mediumLines.add(ln);
      });
      if (raiseHigh) {
        successLines.forEach((ln) => {
          addTag(ln, `Successful logon after distributed spray against ${username}`);
          highLines.add(ln);
        });
      }
    }
  }

  // Post-pass 3: (C) Port scan detection across firewall CSV & network logs
  // (>=15 distinct dst ports OR >=3 dst hosts with DENY/SYN within 10 minutes)
  let detectedPortScanIps = 0;
  for (const [ip, events] of ipProbeEvents.entries()) {
    if (authorizedScannerIps.has(ip)) continue;
    const withTs = events.filter((e) => e.tsMs !== null).sort((a, b) => (a.tsMs ?? 0) - (b.tsMs ?? 0));
    let scanTriggered = false;
    let triggerDesc = '';

    if (withTs.length > 0) {
      let left = 0;
      for (let right = 0; right < withTs.length; right++) {
        while ((withTs[right].tsMs ?? 0) - (withTs[left].tsMs ?? 0) > tenMinutesMs) {
          left++;
        }
        const winSlice = withTs.slice(left, right + 1);
        const probeSlice = winSlice.filter((e) => e.isBlockedOrSyn);
        const dstPorts = new Set(
          (probeSlice.length > 0 ? probeSlice : winSlice)
            .map((e) => e.dstPort)
            .filter((p): p is number => p !== null)
        );
        const deniedHosts = new Set(
          probeSlice.map((e) => e.dstIp).filter((h): h is string => Boolean(h))
        );
        const deniedHostPorts = new Set(
          probeSlice
            .filter((e) => e.dstIp && e.dstPort !== null)
            .map((e) => `${e.dstIp}:${e.dstPort}`)
        );

        if (dstPorts.size >= 15) {
          scanTriggered = true;
          triggerDesc = `Port Scan (${dstPorts.size} distinct dst ports in <=10m) from ${ip}`;
          break;
        }
        if (deniedHosts.size >= 3 && deniedHostPorts.size >= 6) {
          scanTriggered = true;
          triggerDesc = `Host/Port Sweep (${deniedHosts.size} distinct hosts, ${deniedHostPorts.size} DENY/SYN probes in <=10m) from ${ip}`;
          break;
        }
      }
    } else {
      const probeEvents = events.filter((e) => e.isBlockedOrSyn);
      const dstPorts = new Set(
        (probeEvents.length > 0 ? probeEvents : events)
          .map((e) => e.dstPort)
          .filter((p): p is number => p !== null)
      );
      const deniedHosts = new Set(
        probeEvents.map((e) => e.dstIp).filter((h): h is string => Boolean(h))
      );
      if (dstPorts.size >= 15) {
        scanTriggered = true;
        triggerDesc = `Port Scan (${dstPorts.size} distinct dst ports) from ${ip}`;
      } else if (deniedHosts.size >= 3 && probeEvents.length >= 6) {
        scanTriggered = true;
        triggerDesc = `Host/Port Sweep (${deniedHosts.size} distinct hosts with DENY/SYN) from ${ip}`;
      }
    }

    if (scanTriggered) {
      detectedPortScanIps++;
      events.forEach((e) => {
        if (e.isBlockedOrSyn || events.length <= 200) {
          addTag(e.lineNumber, triggerDesc);
          mediumLines.add(e.lineNumber);
        }
      });
    }
  }
  const portScanCount = explicitPortScanLines + detectedPortScanIps;

  // Post-pass 4: (D) C2 Beaconing detection (>=20 connections with low interval variance)
  const beaconingDetails: string[] = [];
  for (const flow of flowMap.values()) {
    if (flow.timestampsMs.length < 20) continue;
    const sorted = flow.timestampsMs.slice().sort((a, b) => a - b);
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      const dt = sorted[i] - sorted[i - 1];
      if (dt > 0) intervals.push(dt);
    }
    if (intervals.length < 19) continue;

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (mean < 5000 || mean > 3_600_000) continue; // 5s to 1h periodic beacons
    const variance =
      intervals.reduce((sum, x) => sum + (x - mean) * (x - mean), 0) / intervals.length;
    const stddev = Math.sqrt(variance);
    const cv = stddev / mean;

    if (cv <= 0.25 && isExternalIp(flow.dstIp)) {
      beaconingCount++;
      const intervalSec = (mean / 1000).toFixed(1);
      const msg = `C2 Beaconing (${flow.srcIp} -> ${flow.dstIp}:${flow.dstPort ?? 0}, ${flow.timestampsMs.length} connections every ~${intervalSec}s, CV=${cv.toFixed(2)})`;
      beaconingDetails.push(msg);
      flow.lineNumbers.forEach((ln) => {
        addTag(ln, msg);
        highLines.add(ln);
      });
    }
  }

  // Post-pass 5: (D) Cumulative Large Outbound Transfers (>=100 MB to external IP)
  for (const pair of outboundBytesByPair.values()) {
    if (pair.totalBytes >= 100_000_000) {
      const alreadyTagged = pair.lineNumbers.some((ln) => highLines.has(ln));
      if (!alreadyTagged) {
        exfiltrationCount++;
      }
      const mb = Math.round(pair.totalBytes / 1_000_000);
      const msg = `Cumulative Large Outbound Transfer (${mb} MB from ${pair.srcIp} to external ${pair.dstIp})`;
      pair.lineNumbers.forEach((ln) => {
        addTag(ln, msg);
        highLines.add(ln);
      });
    }
  }

  const topSourceIps: SourceIpSummary[] = Array.from(ipCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({
      ip,
      count,
      failedLogins: ipFailedCounts.get(ip) || 0,
      succeededAfterFailure: ipSucceededAfterFailure.has(ip),
    }));

  // Compute deterministic Severity Floor
  const criticalReasons: string[] = [];
  if (event1102 > 0 || event104 > 0 || explicitLogClearCmdCount > 0) {
    criticalReasons.push(
      `Audit or system log cleared detected (Event ID 1102: ${event1102}, Event ID 104: ${event104}, log-clear commands: ${explicitLogClearCmdCount})`
    );
  }
  if (event4720 > 0 && (event4732 > 0 || event4728 > 0 || event4756 > 0)) {
    criticalReasons.push(
      `New account creation + privileged group addition detected (Event 4720: ${event4720}, Event 4732: ${event4732}, Event 4728: ${event4728}, Event 4756: ${event4756})`
    );
  } else if (event4728 > 0 || event4756 > 0) {
    criticalReasons.push(
      `Privileged directory group addition detected (Event 4728: ${event4728}, Event 4756: ${event4756})`
    );
  }
  if (event7045 > 0) {
    criticalReasons.push(`New service installation detected (Event ID 7045: ${event7045})`);
  }
  if ([...criticalLines].some((n) => (lineTags.get(n) || []).some((t) => /pkexec/i.test(t)))) {
    criticalReasons.push('Local root exploit via pkexec (PwnKit pattern)');
  }

  const highReasons: string[] = [];
  const bruteSuccessIps = bruteForceIps.filter((b) => b.failedCount >= 14 && b.followedBySuccess);
  if (bruteSuccessIps.length > 0) {
    highReasons.push(
      `Brute force (>=14 failed logins followed by success) from ${bruteSuccessIps.map((b) => `${b.ip} (${b.failedCount} fails)`).join(', ')}`
    );
  }
  if (sqliCount > 0) {
    highReasons.push(`SQL injection patterns detected (${sqliCount} events)`);
  }
  if (xssCount > 0) {
    highReasons.push(`XSS attack patterns detected (${xssCount} events)`);
  }
  if (webshellCount > 0) {
    highReasons.push(`Webshell upload/command execution indicators detected (${webshellCount} events)`);
  }
  if (beaconingCount > 0) {
    highReasons.push(beaconingDetails.join('; ') || `C2 beaconing detected (${beaconingCount} flows)`);
  }
  if (exfiltrationCount > 0) {
    highReasons.push(`Large outbound transfer / exfiltration indicators detected (${exfiltrationCount} events)`);
  }
  if (dnsTunnelingCount > 0) {
    highReasons.push(`DNS tunneling / long random subdomains detected (${dnsTunnelingCount} events)`);
  }
  if (privEscCount > 0) {
    highReasons.push(`Privilege escalation indicators detected (${privEscCount} events)`);
  }
  if (lateralCount > 0) {
    highReasons.push(`Lateral movement indicators detected (${lateralCount} events)`);
  }
  if (persistenceCount > 0 || event4698 > 0) {
    highReasons.push(
      `Persistence indicators detected (scheduled task / autorun / SSH key: ${persistenceCount + event4698} events)`
    );
  }
  if (cloudIamCount > 0) {
    highReasons.push(`Cloud IAM abuse indicators detected (${cloudIamCount} events)`);
  }
  if (lolbinCount > 0) {
    highReasons.push(`Suspicious encoded command or living-off-the-land download detected (${lolbinCount} events)`);
  }
  if (phishingHighCount > 0) {
    highReasons.push(`Credential-harvest POST to an external login page detected (${phishingHighCount} events)`);
  }
  if (hasHighSpraySuccess) {
    highReasons.push('Successful logon after password spray');
  }

  const mediumReasons: string[] = [];
  if (hasMediumAuthBurstOrSpray) {
    mediumReasons.push(
      `Failed-login burst (>=14 in 15m) or password spray detected without confirmed breach`
    );
  }
  if (portScanCount > 0) {
    mediumReasons.push(`Port/host scan activity detected (${portScanCount} indicators)`);
  }
  if (pathTraversalCount > 0) {
    mediumReasons.push(`Path traversal attempts detected (${pathTraversalCount} events)`);
  }
  if (phishingCount > 0 && phishingHighCount === 0) {
    mediumReasons.push(`Phishing / credential-harvest click activity detected (${phishingCount} events)`);
  }

  const lowReasons: string[] = [];
  if (externalFailedLoginCount > 0) {
    lowReasons.push(
      `Failed login(s) from non-RFC1918 source IP(s): ${Array.from(externalFailedLoginIps).slice(0, 8).join(', ')} (${externalFailedLoginCount} events)`
    );
  }

  let floorTier: SeverityFloorTier = 'Informational/Low';
  let floorLevelCode: SeverityLevelCode = 'BASELINE_NEGLIGIBLE_WHITE';
  let floorReasons: string[] = ['Clean baseline or scattered low-volume noise  -  no elevated severity floor triggered'];

  if (criticalReasons.length > 0) {
    floorTier = 'Critical';
    floorLevelCode = 'SEVERE_RED';
    floorReasons = criticalReasons;
  } else if (highReasons.length > 0) {
    floorTier = 'High';
    floorLevelCode = 'HIGH_ORANGE';
    floorReasons = highReasons;
  } else if (mediumReasons.length > 0) {
    floorTier = 'Medium';
    floorLevelCode = 'MEDIUM_YELLOW';
    floorReasons = mediumReasons;
  } else if (lowReasons.length > 0) {
    floorTier = 'Low';
    floorLevelCode = 'LOW_GREEN';
    floorReasons = lowReasons;
  }

  const suspiciousLines = indexedLines.filter((l) => suspiciousLineSet.has(l.lineNumber));

  return {
    summary: {
      totalLinesParsed: indexedLines.length,
      totalEvents: indexedLines.length,
      failedLogins,
      successfulLogins,
      uniqueSourceIps: ipCounts.size,
      topSourceIps,
      blockedDeniedConnections,
      http4xxCount,
      http5xxCount,
      suspiciousPatterns: {
        sqliCount,
        xssCount,
        webshellCount,
        pathTraversalCount,
        bruteForceIps,
        dnsTunnelingCount,
        portScanCount,
        beaconingCount,
        exfiltrationCount,
        windowsEventIds: {
          event4625,
          event4720,
          event4732,
          event1102,
          event7045,
          event4624,
        },
      },
      computedSeverityFloor: {
        floorTier,
        floorLevelCode,
        reasons: floorReasons,
      },
    },
    detectedFormats: Array.from(detectedFormatsSet),
    nssDetected,
    nssEvidence: nssEvidenceList.join('; '),
    explicitContext,
    suspiciousLines,
    lineTags,
    floorLineNumbers: {
      critical: criticalLines,
      high: highLines,
      medium: mediumLines,
      low: lowLines,
    },
    lowFloorReasons: lowReasons,
    perLineBenignReason,
  };
}

// (F) Compact prompt digest: send exact summary + up to 60 representative flagged lines (capped per tag)
function buildSinglePromptLogDigest(
  indexedLines: IndexedLogLine[],
  telemetry: ParsedTelemetryInternal
): string {
  const sections: string[] = [];
  sections.push(
    `PRE-COMPUTED EXACT TELEMETRY SUMMARY (100% DETERMINISTIC TYPESCRIPT PARSER ACROSS ALL ${indexedLines.length} LINES):`
  );
  const compactSummary = {
    totalLinesParsed: telemetry.summary.totalLinesParsed,
    totalEvents: telemetry.summary.totalEvents,
    failedLogins: telemetry.summary.failedLogins,
    successfulLogins: telemetry.summary.successfulLogins,
    uniqueSourceIps: telemetry.summary.uniqueSourceIps,
    topSourceIps: telemetry.summary.topSourceIps.slice(0, 10),
    blockedDeniedConnections: telemetry.summary.blockedDeniedConnections,
    http4xxCount: telemetry.summary.http4xxCount,
    http5xxCount: telemetry.summary.http5xxCount,
    suspiciousPatterns: {
      ...telemetry.summary.suspiciousPatterns,
      bruteForceIps: telemetry.summary.suspiciousPatterns.bruteForceIps.slice(0, 15),
    },
    computedSeverityFloor: telemetry.summary.computedSeverityFloor,
  };
  sections.push(JSON.stringify(compactSummary, null, 2));
  sections.push(
    `PAYLOAD CAP: LLM_LOG_PAYLOAD_MAX_CHARS=${LLM_LOG_PAYLOAD_MAX_CHARS}`
  );

  if (telemetry.suspiciousLines.length > 0) {
    const perTagCap = 5;
    const maxTotalRepresentative = 60;
    const tagCounts = new Map<string, number>();
    const tagLineRanges = new Map<string, number[]>();
    const selected: IndexedLogLine[] = [];

    for (const item of telemetry.suspiciousLines) {
      const tags = telemetry.lineTags.get(item.lineNumber) || ['Flagged'];
      const primaryTag = tags[0];
      const arr = tagLineRanges.get(primaryTag) || [];
      arr.push(item.lineNumber);
      tagLineRanges.set(primaryTag, arr);

      const used = tagCounts.get(primaryTag) || 0;
      if (used < perTagCap && selected.length < maxTotalRepresentative) {
        tagCounts.set(primaryTag, used + 1);
        selected.push(item);
      }
    }

    sections.push(
      `\nREPRESENTATIVE FLAGGED LOG LINES (${selected.length} samples shown out of ${telemetry.suspiciousLines.length} flagged lines):`
    );
    for (const item of selected) {
      const tags = telemetry.lineTags.get(item.lineNumber)?.join(', ') || 'Flagged';
      sections.push(`[L${item.lineNumber}] (${item.source}) [${tags}] ${item.rawLine.slice(0, 320)}`);
    }

    sections.push('\nFLAGGED LINE NUMBER DISTRIBUTION BY CATEGORY (USE COMPACT LINE RANGES IN JSON):');
    for (const [tag, nums] of tagLineRanges.entries()) {
      const minL = nums[0];
      const maxL = nums[nums.length - 1];
      sections.push(
        `- ${tag}: ${nums.length} lines (min L${minL}, max L${maxL}; sample lines: ${nums.slice(0, 12).join(', ')})`
      );
    }
  } else {
    sections.push('\nFLAGGED SUSPICIOUS / TRIGGERED LOG LINES: 0 (no suspicious indicators matched).');
    const sampleCount = Math.min(10, indexedLines.length);
    const step = indexedLines.length / Math.max(1, sampleCount);
    sections.push(`\nREPRESENTATIVE BASELINE SAMPLES (${sampleCount} of ${indexedLines.length} lines):`);
    for (let i = 0; i < sampleCount; i++) {
      const item = indexedLines[Math.floor(i * step)];
      sections.push(`[L${item.lineNumber}] (${item.source}) ${item.rawLine.slice(0, 260)}`);
    }
  }

  return sections.join('\n');
}

function buildContextSummary(
  context: MissionContextInput,
  detectedContext?: LogInspectionResult['clearContextFromLogs']
): ContextItemBreakdown[] {
  const mcLabelMap: Record<MissionCriticalAnswer, string> = {
    yes: 'Yes  -  Mission-critical system',
    no: 'No  -  Non-mission-critical system',
    unknown: 'Unknown / Skipped (Assume potentially mission-critical)',
  };
  const piiLabelMap: Record<PiiExposureAnswer, string> = {
    yes_100k_plus: 'Yes  -  100,000+ PII records (Major Incident threshold met)',
    yes_under_100k: 'Yes  -  Under 100,000 PII records',
    yes_unknown_volume: 'Yes  -  PII involved, record volume unknown',
    no: 'No sensitive data or PII identified',
    unknown: 'Unknown / Skipped (PII involvement not yet ruled out)',
  };
  const authLabelMap: Record<AuthorizedActivityAnswer, string> = {
    unauthorized: 'Confirmed unauthorized / malicious activity',
    authorized: 'Confirmed authorized admin or scheduled maintenance',
    unknown: 'Unknown / Skipped (Not yet deconflicted against authorized admin work)',
  };

  const getProvenance = (
    answer: string,
    detected?: { detected: boolean; suggestedValue: string }
  ): ContextItemBreakdown['provenance'] => {
    if (answer === 'unknown') {
      return 'Assumed (Conservative Default — Missing Context)';
    }
    if (detected?.detected && detected.suggestedValue === answer) {
      return 'Confirmed (Observed in Logs)';
    }
    return 'Confirmed (Analyst)';
  };

  return [
    {
      dimension: 'Mission-Critical System',
      valueLabel: mcLabelMap[context.missionCritical],
      provenance: getProvenance(context.missionCritical, detectedContext?.missionCritical),
      note:
        context.missionCritical === 'unknown'
          ? 'Missing context never lowers severity; mission impact remains unruled out.'
          : detectedContext?.missionCritical.evidence || 'Provided during pre-score context check.',
    },
    {
      dimension: 'Sensitive Data / PII (100,000+ Threshold)',
      valueLabel: piiLabelMap[context.piiExposure],
      provenance: getProvenance(context.piiExposure, detectedContext?.piiExposure),
      note:
        context.piiExposure === 'yes_100k_plus'
          ? 'Per OMB M-20-04 (Playbook Appendix E), breaches involving PII of 100,000+ people require Major Incident determination.'
          : context.piiExposure === 'unknown'
            ? 'PII exposure cannot be ruled out without system owner / SAOP confirmation.'
            : detectedContext?.piiExposure.evidence || 'Provided during pre-score context check.',
    },
    {
      dimension: 'Authorized Activity Deconfliction',
      valueLabel: authLabelMap[context.authorizedActivity],
      provenance: getProvenance(context.authorizedActivity, detectedContext?.authorizedActivity),
      note:
        context.authorizedActivity === 'unknown'
          ? 'Playbook Page 10 requires deconfliction with system admins to confirm activity is not legitimate remote administration.'
          : detectedContext?.authorizedActivity.evidence || 'Provided during pre-score context check.',
    },
  ];
}

function buildCanonicalRoleHandoffs(
  ictApplicable: boolean,
  isMajorOrProvisional: boolean
): RoleHandoff[] {
  const handoffs: RoleHandoff[] = [
    {
      role: 'Incident Manager / Agency Incident Coordination Lead',
      urgencyOrDeadline: isMajorOrProvisional
        ? 'Immediate escalation  -  CISA initial report within 1 hour of incident determination; Major Incident report within 1 hour of Major Incident declaration'
        : 'Immediate escalation upon incident determination  -  CISA initial report within 1 hour',
      actions: [
        'Manage the within-1-hour initial incident report to CISA at https://myservices.cisa.gov/irf or contact@mail.cisa.dhs.gov (FING pp. 3–4; OMB M-20-04 / Playbook pp. 10, 18, 34 Step 11a).',
        'Convene Major Incident determination analysis with the agency CIO, CISO, mission or system owners, and - if a breach - the Senior Agency Official for Privacy (SAOP). Ensure CISA receives the Major Incident report within 1 hour of declaration regardless of internal reporting chain (Playbook p. 18 fn 25, p. 34 fn 36).',
        'Where applicable, coordinate mandatory notifications to OMB Office of the Federal Chief Information Officer (OFCIO), Office of Inspector General (OIG), and appropriate Congressional Committees within 7 days per OMB M-20-04 (Playbook p. 18; FING p. 5).',
        'Notify the Agency Director, Legal Department, and Public Affairs Department per agency IR policy (Playbook p. 7, 27 Step 1c).',
        'Invoke the agency standing Federal Network Authorization (FNA) on file with CISA to request CISA threat-hunting and incident response support if outside assistance is needed (Playbook p. 13, 29 Step 5b).',
        'Coordinate with Federal Law Enforcement (DOJ / FBI / NCIJTF) for threat response/criminal nexus and support Cyber Unified Coordination Group (C-UCG) readiness under PPD-41 if recommended by CISA or FBI (Playbook p. 18–19, Appendix G).',
      ],
      playbookCitation: 'CISA IR Playbook pp. 7, 10, 13, 18–20, 27, 29, 34; Appendix G pp. 43–45',
    },
  ];

  if (ictApplicable) {
    handoffs.push({
      role: 'ICT Service Provider / Contractor & Agency Contracting Officer (CO)',
      urgencyOrDeadline: 'Prompt notification required by EO 14028 Sec. 2',
      actions: [
        'Verify the ICT service provider or contractor promptly reports the cyber incident both to the affected FCEB agency (per Contracting Officer requirements, including any NSS terms) and directly to CISA (Playbook p. 4, 18, 34 Step 11h, Appendix G p. 45).',
        'Require the contractor to collect and preserve data, logs, and artifacts on contractor-operated systems and collaborate with federal cybersecurity or investigative agencies (EO 14028 Sec. 2 & Sec. 8).',
      ],
      playbookCitation: 'CISA IR Playbook pp. 4, 18, 34 Step 11h; Appendix G p. 45 (EO 14028 Sec. 2)',
    });
  }

  return handoffs;
}

function getSeveritySortRank(card: IncidentScorecard): number {
  const base = SEVERITY_ORDER_RANK[card.severity.levelCode] ?? 0;
  if (card.severity.isProvisional && base < 5) {
    return base + 0.5;
  }
  return base;
}

function getFloorForLines(
  lineNumbers: number[],
  telemetry: ParsedTelemetryInternal,
  applyGlobalFallback = false
): {
  floorTier: SeverityFloorTier;
  floorLevelCode: SeverityLevelCode;
  reasons: string[];
} {
  let hasCritical = false;
  let hasHigh = false;
  let hasMedium = false;
  let hasLow = false;

  for (const ln of lineNumbers) {
    if (telemetry.floorLineNumbers.critical.has(ln)) hasCritical = true;
    if (telemetry.floorLineNumbers.high.has(ln)) hasHigh = true;
    if (telemetry.floorLineNumbers.medium.has(ln)) hasMedium = true;
    if (telemetry.floorLineNumbers.low.has(ln)) hasLow = true;
  }

  if (hasCritical) {
    return {
      floorTier: 'Critical',
      floorLevelCode: 'SEVERE_RED',
      reasons: telemetry.summary.computedSeverityFloor.reasons,
    };
  }
  if (hasHigh) {
    return {
      floorTier: 'High',
      floorLevelCode: 'HIGH_ORANGE',
      reasons: telemetry.summary.computedSeverityFloor.reasons,
    };
  }
  if (hasMedium) {
    return {
      floorTier: 'Medium',
      floorLevelCode: 'MEDIUM_YELLOW',
      reasons: telemetry.summary.computedSeverityFloor.reasons,
    };
  }
  if (hasLow) {
    return {
      floorTier: 'Low',
      floorLevelCode: 'LOW_GREEN',
      reasons:
        telemetry.lowFloorReasons.length > 0
          ? telemetry.lowFloorReasons
          : telemetry.summary.computedSeverityFloor.reasons,
    };
  }

  if (applyGlobalFallback) {
    return telemetry.summary.computedSeverityFloor;
  }

  return {
    floorTier: 'Informational/Low',
    floorLevelCode: 'BASELINE_NEGLIGIBLE_WHITE',
    reasons: ['No deterministic floor triggers present in cluster lines'],
  };
}

function buildFallbackFloorCluster(
  unassignedLines: IndexedLogLine[],
  telemetry: ParsedTelemetryInternal,
  contextSummary: ContextItemBreakdown[],
  context: MissionContextInput
): IncidentScorecard {
  const lineNums = unassignedLines.map((l) => l.lineNumber);
  const floor = getFloorForLines(lineNums, telemetry, true);
  const nciss = NCISS_DEFINITIONS[floor.floorLevelCode];
  const hosts = Array.from(new Set(unassignedLines.map((l) => l.source))).slice(0, 8);
  const ips = Array.from(
    new Set(
      unassignedLines
        .map((l) => extractAllIpv4(l.rawLine)[0])
        .filter((ip): ip is string => Boolean(ip))
    )
  ).slice(0, 10);
  const timestamps = unassignedLines.map((l) => l.timestamp).filter(Boolean);
  const timeframe =
    timestamps.length > 0
      ? `${timestamps[0]} to ${timestamps[timestamps.length - 1]}`
      : 'See log lines';
  const prominent = SEVERITY_ORDER_RANK[floor.floorLevelCode] >= SEVERITY_ORDER_RANK.MEDIUM_YELLOW;
  const ictApplicable = context.ictContractor === 'yes';

  return {
    clusterId: 'deterministic-floor-cluster',
    clusterTitle: `Deterministic Security Pattern Cluster (${floor.floorTier} Floor Triggered)`,
    connectionCertainty: 'distinct',
    connectionNote:
      'Automatically grouped from deterministic log pattern detection to enforce minimum severity floors and ensure zero critical/high/medium events are omitted.',
    clusteringBasis: {
      hosts,
      users: [],
      ips,
      timeframe,
    },
    nssOutOfScope: telemetry.nssDetected,
    nssGuidance: telemetry.nssDetected ? telemetry.nssEvidence : '',
    vulnerabilityCrossover: {
      triggered: false,
      status: 'Not Applicable',
      cveOrVulnerability: 'None',
      explanation: 'No specific CVE exploit tag parsed deterministically; verify indicators below.',
      playbookCitation: 'CISA Vulnerability Response Playbook, pp. 21–24',
    },
    severity: {
      levelCode: floor.floorLevelCode,
      ncissLevelName: nciss.ncissLevelName,
      colorName: nciss.colorName,
      ncissDefinitionQuote: nciss.definition,
      ncissJustification: `Deterministic severity floor (${floor.floorTier}) enforced: ${floor.reasons.join('; ')}.`,
      ncissCitation: nciss.citation,
      unscorableReason: null,
      geminiInitialLevelCode: floor.floorLevelCode,
      severityFloorApplied: {
        floorTier: floor.floorTier,
        floorLevelCode: floor.floorLevelCode,
        enforced: true,
        reasons: floor.reasons,
      },
      isProvisional: false,
      provisionalLabel: null,
      provisionalReason: null,
      recommendEscalate: prominent,
    },
    notificationAssessment: {
      attackVectorCategory:
        telemetry.summary.suspiciousPatterns.sqliCount > 0 ||
        telemetry.summary.suspiciousPatterns.xssCount > 0 ||
        telemetry.summary.suspiciousPatterns.webshellCount > 0 ||
        telemetry.summary.suspiciousPatterns.pathTraversalCount > 0
          ? 'Web'
          : telemetry.summary.suspiciousPatterns.bruteForceIps.length > 0
            ? 'Attrition'
            : 'Unknown',
      attackVectorRationale: `Derived from deterministic log pattern counts (${floor.reasons.join('; ')}).`,
      attackVectorCitation: 'CISA Federal Incident Notification Guidelines, Attack Vectors Taxonomy, pp. 9–11',
      functionalImpactCategory:
        floor.floorTier === 'Critical' ? 'HIGH' : floor.floorTier === 'High' ? 'MEDIUM' : 'LOW',
      functionalImpactRationale: 'Estimated conservatively from deterministic severity floor triggers.',
      informationImpactCategories:
        telemetry.summary.suspiciousPatterns.exfiltrationCount > 0 ||
        telemetry.summary.suspiciousPatterns.sqliCount > 0 ||
        telemetry.summary.suspiciousPatterns.webshellCount > 0
          ? ['PRIVACY', 'PROPRIETARY']
          : ['NONE'],
      informationImpactRationale: 'Requires full host/data inspection per Playbook Key Questions.',
      recoverabilityCategory: floor.floorTier === 'Critical' ? 'SUPPLEMENTED' : 'REGULAR',
      recoverabilityRationale: 'Estimated from observed persistence/tampering/attack indicators.',
      impactCitation: 'CISA Federal Incident Notification Guidelines, Impact Category Descriptions, pp. 6–9',
      reportingTimeline:
        'Report to CISA within 1 hour of incident identification (FING pp. 3–4; Playbook pp. 10, 18, 34 Step 11a); Major Incidents to Congress within 7 days (FING p. 5).',
      reportingChannelsAndRequiredData:
        'Submit via CISA Incident Reporting Form (https://myservices.cisa.gov/irf), contact@mail.cisa.dhs.gov, or STIX with Required Steps 1–7 (omit sensitive PII).',
      reportingCitation: 'CISA Federal Incident Notification Guidelines, pp. 2–6; CISA Playbook pp. 10, 18, 34',
    },
    contextSummary,
    shortRead: {
      classification: floor.floorTier === 'Critical' ? 'Confirmed Incident' : 'Major Incident Not Yet Ruled Out',
      playbookPhase: 'Detection & Analysis -> Containment, Eradication & Recovery',
      playbookCitation: 'CISA IR Playbook pp. 8–15',
      summary: `Deterministic log parsing flagged ${unassignedLines.length} security-relevant events triggering a minimum ${floor.floorTier} severity floor: ${floor.reasons.join('; ')}.`,
      observedTactics: [],
      affectedHosts: hosts,
      affectedAccounts: [],
      privilegeLevelsObserved: [],
      knownFacts: floor.reasons,
      unknownFacts: [
        'Full scope of lateral movement, affected accounts, and data impact pending host/SIEM correlation (Playbook pp. 12–13).',
      ],
    },
    warningSigns: {
      indicators: unassignedLines.slice(0, 10).map((item) => ({
        technicalIndicator: `L${item.lineNumber}: ${item.rawLine.slice(0, 140)}`,
        isLivingOffTheLand: /wevtutil|powershell|Clear-EventLog/i.test(item.rawLine),
        plainEnglishExplanation:
          telemetry.lineTags.get(item.lineNumber)?.join(', ') || 'Security-relevant event flagged by log parser.',
        whyItMatters: 'Matched deterministic CISA triage pattern requiring analyst verification.',
      })),
      missingLogSources: [],
      keyQuestions: [],
      playbookCitation: 'CISA IR Playbook pp. 12–13',
    },
    nextSteps: {
      guardrailProminence: prominent ? 'prominent' : 'reminder',
      guardrails: MANDATORY_GUARDRAILS,
      guardrailsCitation: 'CISA IR Playbook pp. 9–10, 14, 36–37',
      analystImmediateSteps: {
        deconfliction: ['Verify with system administrators whether flagged actions match an approved change ticket (Playbook p. 10).'],
        evidencePreservation: ['Preserve raw logs, memory, and disk images with chain-of-custody logging before remediation (Playbook p. 10 Step 3a–3b, p. 36).'],
        keyQuestionInvestigation: ['Correlate source IPs, user accounts, and process trees against Playbook Key Questions (pp. 12–13).'],
        safeContainmentOptions: ['Isolate confirmed compromised endpoints or block offending external IPs per agency SOP (Playbook p. 14 Step 7).'],
      },
      checklistCitations: ['CISA IR Playbook Appendix F (IR Checklist) pp. 33–38'],
      roleHandoffs: buildCanonicalRoleHandoffs(ictApplicable, prominent),
      ictContractorApplicable: ictApplicable,
      ictContractorNote: ictApplicable
        ? 'ICT Service Providers / Contractors must promptly report incidents to both the FCEB agency and CISA (EO 14028 Sec. 2; Playbook pp. 4, 18, 34 Step 11h).'
        : null,
    },
    clusterLogs: unassignedLines.map((l) => ({
      lineNumber: l.lineNumber,
      timestamp: l.timestamp,
      source: l.source,
      excerpt: l.rawLine,
    })),
  };
}

function enforcePlaybookRules(
  rawResult: TriageAnalysisResponse,
  context: MissionContextInput,
  telemetry: ParsedTelemetryInternal,
  detectedContext?: LogInspectionResult['clearContextFromLogs']
): TriageAnalysisResponse {
  const hasMissingContext =
    context.skippedAll ||
    context.missionCritical === 'unknown' ||
    context.piiExposure === 'unknown' ||
    context.piiExposure === 'yes_unknown_volume' ||
    context.authorizedActivity === 'unknown';

  const contextSummary = buildContextSummary(context, detectedContext);
  const totalScorecards = rawResult.scorecards?.length || 0;

  const normalizedScorecards: IncidentScorecard[] = (rawResult.scorecards || []).map((card) => {
    const severity = { ...card.severity };
    const normalizedIncoming = normalizeSeverityLevelCode(severity.levelCode);
    if (normalizedIncoming) {
      severity.levelCode = normalizedIncoming;
    }
    const normalizedIncomingName = normalizeNcissLevelName(severity.ncissLevelName);
    if (normalizedIncomingName) {
      severity.ncissLevelName = normalizedIncomingName;
    }
    const geminiInitial = severity.levelCode;
    severity.geminiInitialLevelCode = geminiInitial;

    const clusterLineNums = (card.clusterLogs || [])
      .map((l) => l.lineNumber)
      .filter((n): n is number => typeof n === 'number');
    const clusterFloor = getFloorForLines(
      clusterLineNums,
      telemetry,
      totalScorecards <= 1
    );

    const tactics = (card.shortRead?.observedTactics || []).map((t) => t.tactic);
    const privs = (card.shortRead?.privilegeLevelsObserved || []).join(' ').toLowerCase();

    const hasSeriousWarningSigns =
      tactics.includes('Credential Access') ||
      tactics.includes('Lateral Movement') ||
      tactics.includes('Exfiltration') ||
      privs.includes('admin') ||
      privs.includes('root') ||
      privs.includes('system') ||
      (card.shortRead?.affectedHosts?.length || 0) > 1 ||
      (card.shortRead?.affectedAccounts?.length || 0) > 1 ||
      card.vulnerabilityCrossover?.triggered === true ||
      clusterFloor.floorTier === 'Critical' ||
      clusterFloor.floorTier === 'High';

    const hasMaliciousOrSuspiciousIndicators =
      hasSeriousWarningSigns ||
      clusterFloor.floorTier === 'Medium' ||
      clusterFloor.floorTier === 'Low' ||
      tactics.length > 0 ||
      card.shortRead?.classification !== 'Observable Event' ||
      card.vulnerabilityCrossover?.triggered === true ||
      card.nssOutOfScope === true;

    // 100,000+ PII breach requires Major Incident (minimum High / Orange) only when incident/unauthorized activity exists
    if (
      context.piiExposure === 'yes_100k_plus' &&
      context.authorizedActivity !== 'authorized' &&
      hasMaliciousOrSuspiciousIndicators &&
      SEVERITY_ORDER_RANK[severity.levelCode] < SEVERITY_ORDER_RANK.HIGH_ORANGE
    ) {
      severity.levelCode = 'HIGH_ORANGE';
    }

    // DETERMINISTIC SEVERITY FLOOR: Final severity = max(model severity, floor)
    const currentRank = SEVERITY_ORDER_RANK[severity.levelCode] ?? 0;
    const floorRank = SEVERITY_ORDER_RANK[clusterFloor.floorLevelCode] ?? 0;
    const floorWasRaised = floorRank > currentRank;
    if (floorWasRaised) {
      severity.levelCode = clusterFloor.floorLevelCode;
    }

    severity.severityFloorApplied = {
      floorTier: clusterFloor.floorTier,
      floorLevelCode: clusterFloor.floorLevelCode,
      enforced: clusterFloor.floorTier !== 'Informational/Low',
      reasons: clusterFloor.reasons,
    };

    const canonicalNciss =
      NCISS_DEFINITIONS[severity.levelCode] || NCISS_DEFINITIONS.UNSCORABLE_GRAY;
    severity.ncissLevelName = canonicalNciss.ncissLevelName;
    severity.colorName = canonicalNciss.colorName;
    severity.ncissDefinitionQuote = canonicalNciss.definition;
    severity.ncissCitation = canonicalNciss.citation;

    if (floorWasRaised) {
      const prevDef = NCISS_DEFINITIONS[geminiInitial];
      const suffix = ` [Deterministic code floor (${clusterFloor.floorTier} / ${canonicalNciss.ncissLevelName}) raised severity from ${prevDef ? prevDef.ncissLevelName : geminiInitial}: ${clusterFloor.reasons.join('; ')}.]`;
      severity.ncissJustification = `${severity.ncissJustification || ''}${suffix}`.trim();
    }

    if (severity.levelCode !== 'UNSCORABLE_GRAY') {
      severity.unscorableReason = null;
    } else if (!severity.unscorableReason || !severity.unscorableReason.trim()) {
      severity.unscorableReason =
        'Logs do not provide sufficient evidence to assess NCISS Functional Impact, Information Impact, Observed Activity, or Recoverability.';
    }

    const isBaselineCode =
      severity.levelCode === 'BASELINE_NEGLIGIBLE_WHITE' ||
      severity.levelCode === 'BASELINE_MINOR_BLUE';

    const isMajorLevel = ['EMERGENCY_BLACK', 'SEVERE_RED', 'HIGH_ORANGE'].includes(
      severity.levelCode
    );
    const isConfirmedAuthorizedOnly =
      context.authorizedActivity === 'authorized' && !hasSeriousWarningSigns;

    // STRICT RULE: Missing mission context must NEVER raise a clean/Baseline log above Baseline by itself.
    if (isBaselineCode && !hasMaliciousOrSuspiciousIndicators) {
      severity.isProvisional = false;
      severity.provisionalLabel = null;
      severity.provisionalReason = null;
      severity.recommendEscalate = false;
    } else if (
      !isMajorLevel &&
      !isConfirmedAuthorizedOnly &&
      (hasSeriousWarningSigns || (!isBaselineCode && hasMissingContext))
    ) {
      severity.isProvisional = true;
      severity.provisionalLabel = 'Major Incident Not Yet Ruled Out';
      const reasons: string[] = [];
      if (hasMissingContext) {
        reasons.push(
          'mission context is incomplete or skipped (missing context must never lower a rating when suspicious activity is present)'
        );
      }
      if (hasSeriousWarningSigns) {
        reasons.push(
          'logs show serious technical warning signs (such as credential access, lateral movement, exfiltration, multi-host/user scope, privileged access, or active vulnerability exploitation)'
        );
      }
      severity.provisionalReason = `Assigned provisional status because ${reasons.join(' and ')}. Per CISA IR Playbook pp. 3 & 5, treat as in-scope for Incident Response and escalate.`;
      severity.recommendEscalate = true;
    } else if (isMajorLevel) {
      severity.recommendEscalate = true;
      if (hasMissingContext) {
        severity.isProvisional = true;
        severity.provisionalLabel = 'Major Incident Not Yet Ruled Out (Additional Scope Pending)';
        severity.provisionalReason =
          'Rated at High (Orange) / Critical (Red) / Emergency (Black) with incomplete mission context; missing context cannot lower this NCISS severity.';
      }
    }

    const prominentGuardrails =
      isMajorLevel ||
      severity.isProvisional ||
      card.nssOutOfScope ||
      card.vulnerabilityCrossover?.triggered;

    const ictApplicable =
      context.ictContractor === 'yes' ||
      Boolean(card.nextSteps?.ictContractorApplicable) ||
      Boolean(
        detectedContext?.ictContractor?.detected &&
          detectedContext.ictContractor.suggestedValue === 'yes'
      );

    const notificationAssessment = {
      attackVectorCategory: card.notificationAssessment?.attackVectorCategory || 'Unknown',
      attackVectorRationale:
        card.notificationAssessment?.attackVectorRationale ||
        'Attack vector evaluated from available telemetry.',
      attackVectorCitation:
        card.notificationAssessment?.attackVectorCitation ||
        'CISA Federal Incident Notification Guidelines, Attack Vectors Taxonomy, pp. 9–11',
      functionalImpactCategory:
        card.notificationAssessment?.functionalImpactCategory || 'NO IMPACT TO SERVICES',
      functionalImpactRationale:
        card.notificationAssessment?.functionalImpactRationale ||
        'Functional impact evaluated from observed system and service behavior.',
      informationImpactCategories:
        card.notificationAssessment?.informationImpactCategories?.length
          ? card.notificationAssessment.informationImpactCategories
          : ['NO IMPACT'],
      informationImpactRationale:
        card.notificationAssessment?.informationImpactRationale ||
        'Information impact evaluated from observed log data.',
      recoverabilityCategory:
        card.notificationAssessment?.recoverabilityCategory || 'REGULAR',
      recoverabilityRationale:
        card.notificationAssessment?.recoverabilityRationale ||
        'Recovery scope estimated from affected systems and indicators.',
      impactCitation:
        card.notificationAssessment?.impactCitation ||
        'CISA Federal Incident Notification Guidelines, Impact Category Descriptions, pp. 6–9',
      reportingTimeline:
        card.notificationAssessment?.reportingTimeline ||
        (isMajorLevel || severity.isProvisional || hasMaliciousOrSuspiciousIndicators
          ? 'Report to CISA within 1 hour of identification by CSIRT/SOC/IT (FING p. 3; Playbook pp. 10, 18, 34 Step 11a); Major Incident report within 1 hour of declaration (Playbook p. 18 fn 25, p. 34 fn 36) and to Congress within 7 days (FING p. 5).'
          : 'Routine/Baseline activity with no C/I/A impact found: internal logging only; voluntary CISA reporting optional (FING p. 3).'),
      reportingChannelsAndRequiredData:
        card.notificationAssessment?.reportingChannelsAndRequiredData ||
        'Submit via CISA Incident Reporting Form (https://myservices.cisa.gov/irf), contact@mail.cisa.dhs.gov, or STIX with Required Steps 1–7 (omit sensitive PII). CISA provides tracking number and NCISS risk rating within 1 hour (FING pp. 3–4).',
      reportingCitation:
        card.notificationAssessment?.reportingCitation ||
        'CISA Federal Incident Notification Guidelines, Notification Requirement & Submitting Incident Notifications, pp. 2–6; CISA Playbook pp. 10, 18, 34',
    };

    return {
      ...card,
      severity,
      notificationAssessment,
      contextSummary,
      nextSteps: {
        ...card.nextSteps,
        guardrailProminence: prominentGuardrails ? 'prominent' : 'reminder',
        guardrails: MANDATORY_GUARDRAILS,
        guardrailsCitation:
          card.nextSteps?.guardrailsCitation || 'CISA IR Playbook pp. 9–10, 14, 36–37',
        checklistCitations:
          card.nextSteps?.checklistCitations?.length
            ? card.nextSteps.checklistCitations
            : ['CISA IR Playbook Appendix F (IR Checklist) pp. 33–38'],
        roleHandoffs: buildCanonicalRoleHandoffs(ictApplicable, prominentGuardrails),
        ictContractorApplicable: ictApplicable,
        ictContractorNote: ictApplicable
          ? 'ICT Service Providers / Contractors operating systems on behalf of FCEB agencies must promptly report cyber incidents to both the FCEB agency and directly to CISA (EO 14028 Sec. 2; Playbook pp. 4, 18, 34 Step 11h, Appendix G p. 45).'
          : null,
      },
    };
  });

  normalizedScorecards.sort((a, b) => getSeveritySortRank(b) - getSeveritySortRank(a));

  const clusteredCount = normalizedScorecards.reduce(
    (sum, card) => sum + (card.clusterLogs?.length || 0),
    0
  );
  const benignCount = (rawResult.likelyBenign || []).length;
  const evaluatedCount = clusteredCount + benignCount;

  return sanitizeSevereDisplayLabels({
    ...rawResult,
    analyzedAtUtc: new Date().toISOString(),
    triageCounts: {
      totalLinesParsed: rawResult.triageCounts?.totalLinesParsed ?? evaluatedCount,
      evaluatedCount,
      clusteredCount,
      benignCount,
      clusterCount: normalizedScorecards.length,
    },
    scorecards: normalizedScorecards,
    likelyBenign: rawResult.likelyBenign || [],
  });
}

function expandLineRanges(
  ranges: string[] | undefined,
  minLine: number,
  maxLine: number
): number[] {
  if (!Array.isArray(ranges) || maxLine < minLine) return [];
  const result: number[] = [];
  const seen = new Set<number>();

  for (const rawRange of ranges) {
    const cleaned = String(rawRange || '')
      .replace(/L/gi, '')
      .trim();
    if (!cleaned) continue;

    const parts = cleaned.split(/\s*(?:-|\u2013|\u2014|:|\.\.|to)\s*/i);
    if (parts.length === 2 && /^\d+$/.test(parts[0]) && /^\d+$/.test(parts[1])) {
      const start = Math.max(minLine, Number.parseInt(parts[0], 10));
      const end = Math.min(maxLine, Number.parseInt(parts[1], 10));
      if (!Number.isNaN(start) && !Number.isNaN(end) && start <= end) {
        for (let n = start; n <= end; n++) {
          if (!seen.has(n)) {
            seen.add(n);
            result.push(n);
          }
        }
      }
    } else if (/^\d+$/.test(cleaned)) {
      const single = Number.parseInt(cleaned, 10);
      if (!Number.isNaN(single) && single >= minLine && single <= maxLine && !seen.has(single)) {
        seen.add(single);
        result.push(single);
      }
    }
  }

  return result;
}

function parseModelJson<T>(rawText: string | undefined, finishReason?: string): T {
  if (finishReason === 'MAX_TOKENS') {
    throw new Error('Model response exceeded output token limit while formatting scorecards.');
  }
  let text = (rawText ?? '').trim();
  if (text.startsWith('```')) {
    text = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
  }
  if (!text) {
    throw new Error('Empty JSON response returned by the analysis model.');
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error('The analysis model returned an incomplete or invalid JSON answer. Please run the triage again.');
  }
}

async function executeSingleCallTriage(
  rawLogs: string,
  contextAnswers: MissionContextInput,
  detectedContext: LogInspectionResult['clearContextFromLogs'] | undefined,
  onStatus: (message: string) => void
): Promise<TriageAnalysisResponse> {
  const indexedLines = parseIndexedLogLines(rawLogs);
  if (indexedLines.length === 0) {
    throw new Error('No non-empty log lines were found to analyze.');
  }

  onStatus(
    `Parsing ${indexedLines.length.toLocaleString()} log lines and computing deterministic security counts...`
  );
  const telemetry = computeDeterministicTelemetry(indexedLines);
  const logDigestUncapped = buildSinglePromptLogDigest(indexedLines, telemetry);

  const playbookLoaded = playbookPdfAvailable();
  const ncissLoaded = ncissPdfAvailable();
  const fingLoaded = fingPdfAvailable();

  interface RawModelScorecard extends Omit<IncidentScorecard, 'clusterLogs'> {
    clusterLineRanges: string[];
  }

  interface RawModelAnalyzeResponse {
    globalScopeFlags: TriageAnalysisResponse['globalScopeFlags'];
    scorecards: RawModelScorecard[];
    benignGroups: Array<{
      lineRanges: string[];
      reason: string;
    }>;
  }

  const promptPrefix = `Analyze the pre-computed TypeScript telemetry summary and flagged log lines below using ONLY the CISA rules stated in this prompt, taken from:
- CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks (Nov 2021)  -  response process, phases, Table 1 tactics, Key Questions, mandatory guardrails, escalation steps, and checklists. ALWAYS cite exact Playbook page numbers!
- CISA National Cyber Incident Scoring System (CISA-NCISS)  -  ONLY source for severity levels!
- CISA Federal Incident Notification Guidelines (FING)  -  ONLY source for attack vector category, Functional/Information/Recoverability impact categories, and CISA reporting timeline/requirements!

ANALYST MISSION CONTEXT ANSWERS:
- Mission-critical system: ${contextAnswers.missionCritical}
- Sensitive data / PII involvement: ${contextAnswers.piiExposure}
- Authorized admin/maintenance deconfliction: ${contextAnswers.authorizedActivity}
- ICT Service Provider / Contractor-operated system: ${contextAnswers.ictContractor}
- Skipped all context questions: ${contextAnswers.skippedAll}

STRICT RULES TO FOLLOW:
1. USE THE CODE-COMPUTED COUNTS & EXACT LINE RANGES:
   - Total lines across the submission = ${indexedLines.length} (numbered [L1] through [L${indexedLines.length}]).
   - Never re-estimate or contradict the TypeScript-computed numbers in the telemetry summary below.
   - Do NOT repeat or echo full log lines in JSON; reference log lines ONLY via compact line ranges (e.g. "12-18", "42", "1-2200") in clusterLineRanges and benignGroups[].lineRanges.
   - If the logs represent clean routine baseline activity with zero malicious or suspicious indicators (and code-computed floor is Informational/Low), return scorecards: [] and put "1-${indexedLines.length}" in benignGroups with a clear one-line reason.
2. SEVERITY LEVELS & FLOORS  -  STRICTLY FROM CISA-NCISS.pdf (pp. 4–6):
   - Map every cluster to ONE NCISS level and quote its verbatim one-line NCISS definition:
     * EMERGENCY_BLACK -> Emergency (Black) [NCISS p. 4]
     * SEVERE_RED -> Severe (Red) [NCISS p. 5]
     * HIGH_ORANGE -> High (Orange) [NCISS p. 5]
     * MEDIUM_YELLOW -> Medium (Yellow) [NCISS p. 5]
     * LOW_GREEN -> Low (Green) [NCISS p. 5]
     * BASELINE_MINOR_BLUE -> Baseline – Minor (Blue) [NCISS pp. 5–6]
     * BASELINE_NEGLIGIBLE_WHITE -> Baseline – Negligible (White) [NCISS pp. 5–6]
     * UNSCORABLE_GRAY -> Unscorable (Gray): use ONLY if the cluster truly cannot be scored under NCISS, and explain why in unscorableReason.
   - Server enforces minimum code severity floors: Critical (SEVERE_RED) for audit log clear (1102), new admin/security group account add (4720+4732), or service install (7045); High (HIGH_ORANGE) for brute force (>=20 failed logins from one IP followed by success), SQLi, XSS, webshell, C2 beaconing, large outbound exfiltration, DNS tunneling, privilege escalation, lateral movement, persistence, cloud IAM abuse, encoded living-off-the-land commands, or a credential-harvest POST to an external login page; Medium (MEDIUM_YELLOW) for failed-login burst/spray without success, port scans, path traversal, or phishing clicks to an external login page; Low (LOW_GREEN) for any failed login from a non-RFC1918 external source IP; clean internal baseline logs stay Baseline.
   - Missing mission context must NEVER raise a clean or Baseline log above Baseline by itself.
3. SCOPE & CROSSOVER GATES (Playbook pp. 4, 21–24, 26):
   - NSS / Classified (44 U.S.C. 3552(b)(6)): set nssOutOfScope=true and direct to CNSSI 1010 (Playbook p. 4, p. 26).
   - Vulnerability Crossover: active exploitation marks system Compromised (Playbook p. 23) and immediately triggers Incident Response.
4. FING NOTIFICATION ASSESSMENT (FING pp. 2–11):
   - attackVectorCategory (pp. 9–11): Unknown, Attrition, Web, Email/Phishing, External/Removable Media, Impersonation/Spoofing, Improper Usage, Loss or Theft of Equipment, or Other.
   - functionalImpactCategory (p. 7), informationImpactCategories (p. 8), recoverabilityCategory (p. 9).
   - reportingTimeline (pp. 2–6): within 1 hour of identification to CISA (https://myservices.cisa.gov/irf, contact@mail.cisa.dhs.gov, or STIX; Major Incidents to Congress within 7 days; omit sensitive PII).
5. PLAYBOOK RESPONSE & CITATIONS (Playbook 2021):
   - Cite exact Playbook page numbers on every section (Phases pp. 8–15, Table 1 p. 12, Key Questions pp. 12–13, Guardrails pp. 9–10/36, Checklists pp. 33–42).

`;
  const room = Math.max(256, LLM_LOG_PAYLOAD_MAX_CHARS - promptPrefix.length - 1);
  const logDigest = enforceLlmLogPayloadCap(logDigestUncapped, room);
  const promptText = enforceTotalPromptCap(promptPrefix + logDigest, LLM_LOG_PAYLOAD_MAX_CHARS);
  console.log(
    `[LLM payload] logDigestChars=${logDigest.length} promptTextChars=${promptText.length} cap=${LLM_LOG_PAYLOAD_MAX_CHARS}`
  );
  onStatus('Running single CISA-grounded analysis call...');

  let modelParsed: RawModelAnalyzeResponse;
  try {
  const response = await generateWithRetry(
    (abortSignal) =>
      completeTriageJson({
        systemInstruction:
          'You are a senior FCEB SOC Incident Response Analyst. Use ONLY the CISA rules and page citations in the user prompt (Incident and Vulnerability Response Playbooks 2021, CISA NCISS, and Federal Incident Notification Guidelines) plus the exact TypeScript-computed telemetry counts provided. Assign severity strictly from CISA NCISS, attack vector, impact, and timeline strictly from FING, and response phases, steps, and checklists with page citations strictly from the Playbook. Never echo raw log lines in JSON; reference line ranges only. Return a single JSON object that matches the provided schema.',
        userPrompt: promptText,
        abortSignal,
        maxCompletionTokens: 16384,
        responseSchema: {
            type: Type.OBJECT,
            properties: {
              globalScopeFlags: {
                type: Type.OBJECT,
                properties: {
                  nssOrClassifiedDetected: { type: Type.BOOLEAN },
                  nssDetails: { type: Type.STRING },
                  vulnerabilityPlaybookTriggered: { type: Type.BOOLEAN },
                  vulnerabilityDetails: { type: Type.STRING },
                  clusteringSummary: { type: Type.STRING },
                },
                required: [
                  'nssOrClassifiedDetected',
                  'nssDetails',
                  'vulnerabilityPlaybookTriggered',
                  'vulnerabilityDetails',
                  'clusteringSummary',
                ],
              },
              scorecards: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    clusterId: { type: Type.STRING },
                    clusterTitle: { type: Type.STRING },
                    connectionCertainty: {
                      type: Type.STRING,
                      enum: ['unified', 'uncertain_connection', 'distinct'],
                    },
                    connectionNote: { type: Type.STRING },
                    clusteringBasis: {
                      type: Type.OBJECT,
                      properties: {
                        hosts: { type: Type.ARRAY, items: { type: Type.STRING } },
                        users: { type: Type.ARRAY, items: { type: Type.STRING } },
                        ips: { type: Type.ARRAY, items: { type: Type.STRING } },
                        timeframe: { type: Type.STRING },
                      },
                      required: ['hosts', 'users', 'ips', 'timeframe'],
                    },
                    nssOutOfScope: { type: Type.BOOLEAN },
                    nssGuidance: { type: Type.STRING },
                    vulnerabilityCrossover: {
                      type: Type.OBJECT,
                      properties: {
                        triggered: { type: Type.BOOLEAN },
                        status: {
                          type: Type.STRING,
                          enum: ['Compromised', 'Susceptible', 'Not Applicable'],
                        },
                        cveOrVulnerability: { type: Type.STRING },
                        explanation: { type: Type.STRING },
                        playbookCitation: { type: Type.STRING },
                      },
                      required: [
                        'triggered',
                        'status',
                        'cveOrVulnerability',
                        'explanation',
                        'playbookCitation',
                      ],
                    },
                    severity: {
                      type: Type.OBJECT,
                      properties: {
                        levelCode: {
                          type: Type.STRING,
                          enum: [
                            'EMERGENCY_BLACK',
                            'SEVERE_RED',
                            'HIGH_ORANGE',
                            'MEDIUM_YELLOW',
                            'LOW_GREEN',
                            'BASELINE_MINOR_BLUE',
                            'BASELINE_NEGLIGIBLE_WHITE',
                            'UNSCORABLE_GRAY',
                          ],
                        },
                        ncissLevelName: {
                          type: Type.STRING,
                          enum: [
                            'Emergency',
                            'Severe',
                            'Critical',
                            'High',
                            'Medium',
                            'Low',
                            'Baseline – Minor',
                            'Baseline – Negligible',
                            'Unscorable',
                          ],
                        },
                        colorName: {
                          type: Type.STRING,
                          enum: ['Black', 'Red', 'Orange', 'Yellow', 'Green', 'Blue', 'White', 'Gray'],
                        },
                        ncissDefinitionQuote: { type: Type.STRING },
                        ncissJustification: { type: Type.STRING },
                        ncissCitation: { type: Type.STRING },
                        unscorableReason: { type: Type.STRING, nullable: true },
                        isProvisional: { type: Type.BOOLEAN },
                        provisionalLabel: { type: Type.STRING, nullable: true },
                        provisionalReason: { type: Type.STRING, nullable: true },
                        recommendEscalate: { type: Type.BOOLEAN },
                      },
                      required: [
                        'levelCode',
                        'ncissLevelName',
                        'colorName',
                        'ncissDefinitionQuote',
                        'ncissJustification',
                        'ncissCitation',
                        'isProvisional',
                        'recommendEscalate',
                      ],
                    },
                    notificationAssessment: {
                      type: Type.OBJECT,
                      properties: {
                        attackVectorCategory: {
                          type: Type.STRING,
                          enum: [
                            'Unknown',
                            'Attrition',
                            'Web',
                            'Email/Phishing',
                            'External/Removable Media',
                            'Impersonation/Spoofing',
                            'Improper Usage',
                            'Loss or Theft of Equipment',
                            'Other',
                          ],
                        },
                        attackVectorRationale: { type: Type.STRING },
                        attackVectorCitation: { type: Type.STRING },
                        functionalImpactCategory: { type: Type.STRING },
                        functionalImpactRationale: { type: Type.STRING },
                        informationImpactCategories: {
                          type: Type.ARRAY,
                          items: { type: Type.STRING },
                        },
                        informationImpactRationale: { type: Type.STRING },
                        recoverabilityCategory: { type: Type.STRING },
                        recoverabilityRationale: { type: Type.STRING },
                        impactCitation: { type: Type.STRING },
                        reportingTimeline: { type: Type.STRING },
                        reportingChannelsAndRequiredData: { type: Type.STRING },
                        reportingCitation: { type: Type.STRING },
                      },
                      required: [
                        'attackVectorCategory',
                        'attackVectorRationale',
                        'attackVectorCitation',
                        'functionalImpactCategory',
                        'functionalImpactRationale',
                        'informationImpactCategories',
                        'informationImpactRationale',
                        'recoverabilityCategory',
                        'recoverabilityRationale',
                        'impactCitation',
                        'reportingTimeline',
                        'reportingChannelsAndRequiredData',
                        'reportingCitation',
                      ],
                    },
                    shortRead: {
                      type: Type.OBJECT,
                      properties: {
                        classification: {
                          type: Type.STRING,
                          enum: [
                            'Observable Event',
                            'Confirmed Incident',
                            'Breach',
                            'Major Incident',
                            'Major Incident Not Yet Ruled Out',
                            'Exploited Vulnerability',
                          ],
                        },
                        playbookPhase: { type: Type.STRING },
                        playbookCitation: { type: Type.STRING },
                        summary: { type: Type.STRING },
                        observedTactics: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              tactic: {
                                type: Type.STRING,
                                enum: [
                                  'Initial Access',
                                  'Execution',
                                  'Persistence',
                                  'Lateral Movement',
                                  'Credential Access',
                                  'C2',
                                  'Exfiltration',
                                ],
                              },
                              mitreTacticId: { type: Type.STRING },
                              techniquesObserved: { type: Type.STRING },
                              logSourcesUsed: {
                                type: Type.ARRAY,
                                items: { type: Type.STRING },
                              },
                              evidenceIndicators: {
                                type: Type.ARRAY,
                                items: { type: Type.STRING },
                              },
                              playbookCitation: { type: Type.STRING },
                            },
                            required: [
                              'tactic',
                              'mitreTacticId',
                              'techniquesObserved',
                              'logSourcesUsed',
                              'evidenceIndicators',
                              'playbookCitation',
                            ],
                          },
                        },
                        affectedHosts: { type: Type.ARRAY, items: { type: Type.STRING } },
                        affectedAccounts: { type: Type.ARRAY, items: { type: Type.STRING } },
                        privilegeLevelsObserved: {
                          type: Type.ARRAY,
                          items: { type: Type.STRING },
                        },
                        knownFacts: { type: Type.ARRAY, items: { type: Type.STRING } },
                        unknownFacts: { type: Type.ARRAY, items: { type: Type.STRING } },
                      },
                      required: [
                        'classification',
                        'playbookPhase',
                        'playbookCitation',
                        'summary',
                        'observedTactics',
                        'affectedHosts',
                        'affectedAccounts',
                        'privilegeLevelsObserved',
                        'knownFacts',
                        'unknownFacts',
                      ],
                    },
                    warningSigns: {
                      type: Type.OBJECT,
                      properties: {
                        indicators: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              technicalIndicator: { type: Type.STRING },
                              isLivingOffTheLand: { type: Type.BOOLEAN },
                              plainEnglishExplanation: { type: Type.STRING },
                              whyItMatters: { type: Type.STRING },
                            },
                            required: [
                              'technicalIndicator',
                              'isLivingOffTheLand',
                              'plainEnglishExplanation',
                              'whyItMatters',
                            ],
                          },
                        },
                        missingLogSources: { type: Type.ARRAY, items: { type: Type.STRING } },
                        keyQuestions: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              question: { type: Type.STRING },
                              status: {
                                type: Type.STRING,
                                enum: [
                                  'Answered',
                                  'Partially Answered',
                                  'Unanswered (Blind Spot)',
                                ],
                              },
                              finding: { type: Type.STRING },
                              neededLogSources: {
                                type: Type.ARRAY,
                                items: { type: Type.STRING },
                              },
                            },
                            required: ['question', 'status', 'finding', 'neededLogSources'],
                          },
                        },
                        playbookCitation: { type: Type.STRING },
                      },
                      required: [
                        'indicators',
                        'missingLogSources',
                        'keyQuestions',
                        'playbookCitation',
                      ],
                    },
                    nextSteps: {
                      type: Type.OBJECT,
                      properties: {
                        analystImmediateSteps: {
                          type: Type.OBJECT,
                          properties: {
                            deconfliction: { type: Type.ARRAY, items: { type: Type.STRING } },
                            evidencePreservation: {
                              type: Type.ARRAY,
                              items: { type: Type.STRING },
                            },
                            keyQuestionInvestigation: {
                              type: Type.ARRAY,
                              items: { type: Type.STRING },
                            },
                            safeContainmentOptions: {
                              type: Type.ARRAY,
                              items: { type: Type.STRING },
                            },
                          },
                          required: [
                            'deconfliction',
                            'evidencePreservation',
                            'keyQuestionInvestigation',
                            'safeContainmentOptions',
                          ],
                        },
                        checklistCitations: {
                          type: Type.ARRAY,
                          items: { type: Type.STRING },
                        },
                        ictContractorApplicable: { type: Type.BOOLEAN },
                      },
                      required: [
                        'analystImmediateSteps',
                        'checklistCitations',
                        'ictContractorApplicable',
                      ],
                    },
                    clusterLineRanges: {
                      type: Type.ARRAY,
                      items: { type: Type.STRING },
                    },
                  },
                  required: [
                    'clusterId',
                    'clusterTitle',
                    'connectionCertainty',
                    'connectionNote',
                    'clusteringBasis',
                    'nssOutOfScope',
                    'nssGuidance',
                    'vulnerabilityCrossover',
                    'severity',
                    'notificationAssessment',
                    'shortRead',
                    'warningSigns',
                    'nextSteps',
                    'clusterLineRanges',
                  ],
                },
              },
              benignGroups: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    lineRanges: {
                      type: Type.ARRAY,
                      items: { type: Type.STRING },
                    },
                    reason: { type: Type.STRING },
                  },
                  required: ['lineRanges', 'reason'],
                },
              },
            },
            required: ['globalScopeFlags', 'scorecards', 'benignGroups'],
          },
      }),
    (retryInfo) => {
      onStatus(retryInfo.message);
    }
  );

  modelParsed = parseModelJson<RawModelAnalyzeResponse>(response.text, response.finishReason);
  } catch (llmErr) {
    const floorTier = telemetry.summary.computedSeverityFloor.floorTier;
    const floorLineCount =
      telemetry.floorLineNumbers.critical.size +
      telemetry.floorLineNumbers.high.size +
      telemetry.floorLineNumbers.medium.size +
      telemetry.floorLineNumbers.low.size;
    if (floorTier === 'Informational/Low' && floorLineCount === 0) {
      throw llmErr;
    }
    const fallbackDetail = formatLlmError(llmErr).message;
    console.error('[LLM fallback]', fallbackDetail, llmErr);
    onStatus(
      `Analysis API call failed after retries; continuing with code-computed severity floors. (${fallbackDetail})`
    );
    modelParsed = {
      globalScopeFlags: {
        nssOrClassifiedDetected: telemetry.nssDetected,
        nssDetails: telemetry.nssEvidence || '',
        vulnerabilityPlaybookTriggered: false,
        vulnerabilityDetails: '',
        clusteringSummary:
          `Analysis API call failed after retries; scorecards use code-computed severity floors only. (${fallbackDetail})`,
      },
      scorecards: [],
      benignGroups: [],
    };
  }

  const lineMap = new Map<number, IndexedLogLine>();
  indexedLines.forEach((l) => lineMap.set(l.lineNumber, l));

  const assignedLines = new Set<number>();
  const expandedScorecards: IncidentScorecard[] = [];
  const expandedBenign: TriageAnalysisResponse['likelyBenign'] = [];
  let lastBenignReason = '';

  for (const card of modelParsed.scorecards || []) {
    const rawNums = expandLineRanges(card.clusterLineRanges, 1, indexedLines.length);
    const uniqueClusterNums = rawNums.filter((n) => !assignedLines.has(n));
    if (uniqueClusterNums.length === 0) continue;

    uniqueClusterNums.forEach((n) => assignedLines.add(n));
    const clusterLogs = uniqueClusterNums
      .map((n) => lineMap.get(n))
      .filter((item): item is IndexedLogLine => Boolean(item))
      .map((item) => ({
        lineNumber: item.lineNumber,
        timestamp: item.timestamp,
        source: item.source,
        excerpt: item.rawLine,
      }));

    const { clusterLineRanges: _omit, ...rest } = card;
    expandedScorecards.push({
      ...rest,
      clusterLogs,
    });
  }

  // Ensure no deterministic floor-triggering lines were dropped into benign or omitted
  const unassignedFloorLines = telemetry.suspiciousLines.filter(
    (item) =>
      !assignedLines.has(item.lineNumber) &&
      (telemetry.floorLineNumbers.critical.has(item.lineNumber) ||
        telemetry.floorLineNumbers.high.has(item.lineNumber) ||
        telemetry.floorLineNumbers.medium.has(item.lineNumber) ||
        telemetry.floorLineNumbers.low.has(item.lineNumber))
  );

  if (unassignedFloorLines.length > 0) {
    const fallbackContextSummary = buildContextSummary(contextAnswers, detectedContext);
    if (expandedScorecards.length === 0) {
      unassignedFloorLines.forEach((l) => assignedLines.add(l.lineNumber));
      expandedScorecards.push(
        buildFallbackFloorCluster(
          unassignedFloorLines,
          telemetry,
          fallbackContextSummary,
          contextAnswers
        )
      );
    } else {
      const target = expandedScorecards[0];
      unassignedFloorLines.forEach((l) => {
        assignedLines.add(l.lineNumber);
        target.clusterLogs.push({
          lineNumber: l.lineNumber,
          timestamp: l.timestamp,
          source: l.source,
          excerpt: l.rawLine,
        });
      });
    }
  }

  for (const group of modelParsed.benignGroups || []) {
    if (!lastBenignReason && group.reason) {
      lastBenignReason = group.reason;
    }
    const lineNums = expandLineRanges(group.lineRanges, 1, indexedLines.length);
    for (const n of lineNums) {
      if (assignedLines.has(n)) continue;
      const item = lineMap.get(n);
      if (!item) continue;
      assignedLines.add(n);
      expandedBenign.push({
        lineNumber: item.lineNumber,
        timestamp: item.timestamp,
        source: item.source,
        excerpt: item.rawLine,
        reason:
          telemetry.perLineBenignReason.get(item.lineNumber) ||
          group.reason ||
          'Routine entry not assigned to an incident cluster.',
      });
    }
  }

  const fallbackBenignReason =
    expandedScorecards.length === 0 && lastBenignReason
      ? lastBenignReason
      : 'Routine baseline entry with no malicious or suspicious indicators detected.';

  for (const item of indexedLines) {
    if (!assignedLines.has(item.lineNumber)) {
      assignedLines.add(item.lineNumber);
      expandedBenign.push({
        lineNumber: item.lineNumber,
        timestamp: item.timestamp,
        source: item.source,
        excerpt: item.rawLine,
        reason: telemetry.perLineBenignReason.get(item.lineNumber) || fallbackBenignReason,
      });
    }
  }

  expandedBenign.sort((a, b) => (a.lineNumber || 0) - (b.lineNumber || 0));

  const clusteredCount = expandedScorecards.reduce(
    (sum, card) => sum + card.clusterLogs.length,
    0
  );
  const benignCount = expandedBenign.length;
  const evaluatedCount = clusteredCount + benignCount;

  const assembled: TriageAnalysisResponse = {
    analyzedAtUtc: new Date().toISOString(),
    documentsStatus: {
      playbookLoaded,
      ncissLoaded,
      fingLoaded,
    },
    geminiCallsMade: 1,
    triageCounts: {
      totalLinesParsed: indexedLines.length,
      evaluatedCount,
      clusteredCount,
      benignCount,
      clusterCount: expandedScorecards.length,
    },
    telemetrySummary: telemetry.summary,
    globalScopeFlags: {
      nssOrClassifiedDetected:
        Boolean(modelParsed.globalScopeFlags?.nssOrClassifiedDetected) || telemetry.nssDetected,
      nssDetails: modelParsed.globalScopeFlags?.nssDetails || telemetry.nssEvidence || '',
      vulnerabilityPlaybookTriggered: Boolean(
        modelParsed.globalScopeFlags?.vulnerabilityPlaybookTriggered
      ),
      vulnerabilityDetails: modelParsed.globalScopeFlags?.vulnerabilityDetails || '',
      clusteringSummary:
        modelParsed.globalScopeFlags?.clusteringSummary ||
        `Parsed ${indexedLines.length.toLocaleString()} log lines once in TypeScript and evaluated all ${evaluatedCount.toLocaleString()} entries in 1 analysis call (${clusteredCount.toLocaleString()} clustered + ${benignCount.toLocaleString()} likely benign).`,
    },
    scorecards: expandedScorecards,
    likelyBenign: expandedBenign,
  };

  return enforcePlaybookRules(assembled, contextAnswers, telemetry, detectedContext);
}

export async function createApp(options?: { serveStatic?: boolean }): Promise<express.Express> {
  const serveStatic = options?.serveStatic !== false && !process.env.VERCEL;
  const app = express();
  // Vercel Hobby request bodies cap at 4.5 MB; keep a matching limit.
  app.use(express.json({ limit: '4mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      playbookAvailable: playbookPdfAvailable(),
      ncissAvailable: ncissPdfAvailable(),
      fingAvailable: fingPdfAvailable(),
    });
  });

  // Deterministic pre-inspection so each triage run makes exactly one analysis call
  app.post('/api/triage/inspect', (req, res) => {
    try {
      const { rawLogs } = req.body as { rawLogs?: string };
      if (!rawLogs || typeof rawLogs !== 'string' || !rawLogs.trim()) {
        res.status(400).json({ error: 'Real log text is required for inspection.' });
        return;
      }

      const indexedLines = parseIndexedLogLines(rawLogs);
      if (indexedLines.length === 0) {
        res.status(400).json({ error: 'No non-empty log lines were found to inspect.' });
        return;
      }

      const telemetry = computeDeterministicTelemetry(indexedLines);
      const s = telemetry.summary;
      const needsPrompt =
        !telemetry.explicitContext.missionCritical.detected ||
        !telemetry.explicitContext.piiExposure.detected ||
        !telemetry.explicitContext.authorizedActivity.detected;

      const inspectionResult: LogInspectionResult = {
        detectedFormats:
          telemetry.detectedFormats.length > 0
            ? telemetry.detectedFormats
            : ['Text / Generic Event Log'],
        entryCountEstimate: indexedLines.length,
        totalLinesParsed: indexedLines.length,
        inspectedLineCount: indexedLines.length,
        clearContextFromLogs: telemetry.explicitContext,
        nssOrClassifiedDetected: telemetry.nssDetected,
        nssEvidence: telemetry.nssEvidence,
        needsAnalystContextPrompt: needsPrompt,
        inspectionSummary: `Parsed all ${indexedLines.length.toLocaleString()} log lines deterministically (${s.uniqueSourceIps.toLocaleString()} unique source IPs, ${s.failedLogins.toLocaleString()} failed logins, ${s.blockedDeniedConnections.toLocaleString()} blocked/denied events, ${s.http4xxCount.toLocaleString()} HTTP 4xx, ${s.http5xxCount.toLocaleString()} HTTP 5xx; code-computed minimum floor: ${s.computedSeverityFloor.floorTier}).`,
      };

      res.json(inspectionResult);
    } catch (err) {
      const formatted = formatLlmError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  // Job polling endpoint when an SSE stream drops mid-flight on large logs or during backoff
  app.get('/api/triage/jobs/:jobId', (req, res) => {
    pruneExpiredJobs();
    const job = triageJobs.get(req.params.jobId);
    if (!job) {
      res.status(404).json({ error: 'Triage job not found or expired.' });
      return;
    }
    res.json({
      jobId: job.jobId,
      kind: job.kind,
      // Live light-theme App.tsx expects 'failed' (not 'error') and a 'progress' field
      status: job.status === 'error' ? 'failed' : job.status,
      progress: job.statusMessage,
      statusMessage: job.statusMessage,
      result: job.result,
      error: job.error,
      retryable: job.retryable,
    });
  });

  app.post('/api/triage/analyze', async (req, res) => {
    pruneExpiredJobs();

    const wantsStream =
      !process.env.VERCEL &&
      (req.body?.streamProgress === true ||
        String(req.headers.accept || '').includes('text/event-stream'));

    const {
      rawLogs,
      contextAnswers,
      detectedContext,
      jobId: clientJobId,
    } = req.body as {
      rawLogs?: string;
      contextAnswers?: MissionContextInput;
      detectedContext?: LogInspectionResult['clearContextFromLogs'];
      jobId?: string;
    };

    const jobId =
      typeof clientJobId === 'string' && clientJobId.trim()
        ? clientJobId.trim()
        : crypto.randomUUID();

    if (!rawLogs || typeof rawLogs !== 'string' || !rawLogs.trim()) {
      res.status(400).json({ error: 'Real log entries are required.' });
      return;
    }
    if (!contextAnswers) {
      res.status(400).json({ error: 'Mission context answers are required.' });
      return;
    }
    const contextError = validateContextAnswers(contextAnswers);
    if (contextError) {
      res.status(400).json({ error: contextError });
      return;
    }

    const job: TriageJobRecord = {
      jobId,
      status: 'running',
      statusMessage: 'Starting deterministic log parser & CISA triage...',
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
    };
    triageJobs.set(jobId, job);

    const emitSse = (event: string, payload: unknown) => {
      if (!wantsStream || res.writableEnded || res.destroyed) return;
      try {
        res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
      } catch {
        // Client stream closed; background job continues for polling fallback
      }
    };

    let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
    if (wantsStream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders();
      emitSse('status', { jobId, message: job.statusMessage });

      heartbeatTimer = setInterval(() => {
        if (res.writableEnded || res.destroyed) {
          if (heartbeatTimer) clearInterval(heartbeatTimer);
          return;
        }
        const elapsedSec = Math.round((Date.now() - job.createdAtMs) / 1000);
        try {
          res.write(`: keepalive ${elapsedSec}s\n\n`);
          emitSse('heartbeat', { jobId, elapsedSec, message: job.statusMessage });
        } catch {
          if (heartbeatTimer) clearInterval(heartbeatTimer);
        }
      }, 10_000);

      res.on('close', () => {
        if (heartbeatTimer) clearInterval(heartbeatTimer);
      });
    }

    try {
      const finalResult = await executeSingleCallTriage(
        rawLogs,
        contextAnswers,
        detectedContext,
        (message) => {
          job.statusMessage = message;
          job.updatedAtMs = Date.now();
          emitSse('status', { jobId, message });
        }
      );

      job.status = 'completed';
      job.statusMessage = 'Triage analysis complete.';
      job.updatedAtMs = Date.now();
      job.result = finalResult;

      if (heartbeatTimer) clearInterval(heartbeatTimer);

      if (wantsStream) {
        emitSse('result', finalResult);
        if (!res.writableEnded) res.end();
      } else {
        res.json(finalResult);
      }
    } catch (err) {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      const formatted = formatLlmError(err);
      job.status = 'error';
      job.error = formatted.message;
      job.retryable = formatted.retryable;
      job.updatedAtMs = Date.now();

      if (wantsStream) {
        emitSse('error', { error: formatted.message, retryable: formatted.retryable });
        if (!res.writableEnded) res.end();
      } else {
        res.status(formatted.status).json({ error: formatted.message, retryable: formatted.retryable });
      }
    }
  });

  // Job-style endpoints used by the live light-theme App.tsx (start a job, then poll /api/triage/jobs/:jobId)
  app.post('/api/triage/jobs/inspect', (req, res) => {
    pruneExpiredJobs();
    try {
      const { rawLogs } = req.body as { rawLogs?: string };
      if (!rawLogs || typeof rawLogs !== 'string' || !rawLogs.trim()) {
        res.status(400).json({ error: 'Real log text is required for inspection.' });
        return;
      }
      const indexedLines = parseIndexedLogLines(rawLogs);
      if (indexedLines.length === 0) {
        res.status(400).json({ error: 'No non-empty log lines were found to inspect.' });
        return;
      }
      const telemetry = computeDeterministicTelemetry(indexedLines);
      const s = telemetry.summary;
      const needsPrompt =
        !telemetry.explicitContext.missionCritical.detected ||
        !telemetry.explicitContext.piiExposure.detected ||
        !telemetry.explicitContext.authorizedActivity.detected;
      const inspectionResult: LogInspectionResult = {
        detectedFormats:
          telemetry.detectedFormats.length > 0
            ? telemetry.detectedFormats
            : ['Text / Generic Event Log'],
        entryCountEstimate: indexedLines.length,
        totalLinesParsed: indexedLines.length,
        inspectedLineCount: indexedLines.length,
        clearContextFromLogs: telemetry.explicitContext,
        nssOrClassifiedDetected: telemetry.nssDetected,
        nssEvidence: telemetry.nssEvidence,
        needsAnalystContextPrompt: needsPrompt,
        inspectionSummary: `Parsed all ${indexedLines.length.toLocaleString()} log lines deterministically (${s.uniqueSourceIps.toLocaleString()} unique source IPs, ${s.failedLogins.toLocaleString()} failed logins, ${s.blockedDeniedConnections.toLocaleString()} blocked/denied events, ${s.http4xxCount.toLocaleString()} HTTP 4xx, ${s.http5xxCount.toLocaleString()} HTTP 5xx; code-computed minimum floor: ${s.computedSeverityFloor.floorTier}).`,
      };
      const jobId = crypto.randomUUID();
      const now = Date.now();
      triageJobs.set(jobId, {
        jobId,
        kind: 'inspect',
        status: 'completed',
        statusMessage: 'Inspection complete.',
        createdAtMs: now,
        updatedAtMs: now,
        result: inspectionResult,
      });
      res.json({ jobId, kind: 'inspect', status: 'running', progress: 'Inspecting staged logs...' });
    } catch (err) {
      const formatted = formatLlmError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/triage/jobs/analyze', async (req, res) => {
    pruneExpiredJobs();
    const { rawLogs, contextAnswers, detectedContext } = req.body as {
      rawLogs?: string;
      contextAnswers?: MissionContextInput;
      detectedContext?: LogInspectionResult['clearContextFromLogs'];
    };
    if (!rawLogs || typeof rawLogs !== 'string' || !rawLogs.trim()) {
      res.status(400).json({ error: 'Real log entries are required.' });
      return;
    }
    if (!contextAnswers) {
      res.status(400).json({ error: 'Mission context answers are required.' });
      return;
    }
    const contextError = validateContextAnswers(contextAnswers);
    if (contextError) {
      res.status(400).json({ error: contextError });
      return;
    }
    const jobId = crypto.randomUUID();
    const job: TriageJobRecord = {
      jobId,
      kind: 'analyze',
      status: 'running',
      statusMessage: 'Starting deterministic log parser & CISA triage...',
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
    };
    triageJobs.set(jobId, job);
    // Await in this invocation so the work survives Vercel serverless (no background after the response).
    try {
      const finalResult = await executeSingleCallTriage(
        rawLogs,
        contextAnswers,
        detectedContext,
        (message) => {
          job.statusMessage = message;
          job.updatedAtMs = Date.now();
        }
      );
      job.status = 'completed';
      job.statusMessage = 'Triage analysis complete.';
      job.result = finalResult;
      job.updatedAtMs = Date.now();
      res.json({
        jobId,
        kind: 'analyze',
        status: 'completed',
        progress: job.statusMessage,
        result: finalResult,
      });
    } catch (err) {
      const formatted = formatLlmError(err);
      job.status = 'error';
      job.error = formatted.message;
      job.retryable = formatted.retryable;
      job.updatedAtMs = Date.now();
      res.status(formatted.status || 500).json({
        jobId,
        kind: 'analyze',
        status: 'failed',
        error: formatted.message,
        retryable: formatted.retryable,
      });
    }
  });

  if (!serveStatic) {
    return app;
  }

  if (process.env.NODE_ENV !== 'production') {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: {
        middlewareMode: true,
        hmr: false,
        ws: false,
        watch: null,
      },
      appType: 'spa',
    });

    app.get('/@vite/client', async (_req, res, next) => {
      try {
        const transformed = await vite.transformRequest('/@vite/client');
        if (!transformed) {
          next();
          return;
        }
        const safeClientCode = transformed.code
          .replace(
            'console.debug("[vite] connecting...");',
            'console.debug("[vite] HMR disabled.");'
          )
          .replace(
            /transport\.connect\(createHMRHandler\(handleMessage\)\);/g,
            '/* HMR disabled: WebSocket connection skipped */'
          );
        res.type('application/javascript').send(safeClientCode);
      } catch {
        next();
      }
    });

    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, '..', 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  return app;
}
