import React, { useRef, useState } from 'react';
import { Upload, FileText, Trash2, ArrowRight, ShieldAlert, BookOpen } from 'lucide-react';
import type { ServerDocsHealth } from '../App';

export interface UploadedLogFile {
  id: string;
  name: string;
  sizeBytes: number;
  content: string;
}

interface LogInputStageProps {
  pastedLogs: string;
  uploadedFiles: UploadedLogFile[];
  docsHealth: ServerDocsHealth | null;
  isInspecting: boolean;
  statusMessage?: string | null;
  errorMessage: string | null;
  onPastedLogsChange: (value: string) => void;
  onAddLogFiles: (files: UploadedLogFile[]) => void;
  onRemoveLogFile: (id: string) => void;
  onClearAllLogFiles: () => void;
  onSubmitLogs: () => void;
  onOpenReference: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function countNonEmptyLogLines(text: string): number {
  if (!text.trim()) return 0;
  return text.split(/\r?\n/).filter((line) => {
    const t = line.trim();
    if (!t) return false;
    if (t === '=== PASTED LOG BUFFER ===') return false;
    if (/^=== FILE:\s*(.+?)\s*===$/.test(t)) return false;
    return true;
  }).length;
}

export const LogInputStage: React.FC<LogInputStageProps> = ({
  pastedLogs,
  uploadedFiles,
  docsHealth,
  isInspecting,
  statusMessage,
  errorMessage,
  onPastedLogsChange,
  onAddLogFiles,
  onRemoveLogFile,
  onClearAllLogFiles,
  onSubmitLogs,
  onOpenReference,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const logFileInputRef = useRef<HTMLInputElement>(null);

  const pastedLineCount = countNonEmptyLogLines(pastedLogs);
  const totalLogLines =
    pastedLineCount +
    uploadedFiles.reduce((acc, f) => acc + countNonEmptyLogLines(f.content), 0);

  const hasAnyLogs = totalLogLines > 0;

  const handleReadLogFiles = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setFileError(null);
    const loaded: UploadedLogFile[] = [];
    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      const lower = file.name.toLowerCase();
      if (lower.endsWith('.evtx')) {
        setFileError(
          `"${file.name}" is a binary Windows .evtx file. Export it from Event Viewer or PowerShell as .xml, .csv, or .txt/.json first, then upload.`
        );
        continue;
      }
      if (lower.endsWith('.pdf') || lower.endsWith('.zip') || lower.endsWith('.gz')) {
        setFileError(
          `"${file.name}" cannot be read as plain-text logs. Extract or export log entries to .log, .txt, .json, .csv, or .xml.`
        );
        continue;
      }
      if (file.size > 5 * 1024 * 1024) {
        setFileError(`"${file.name}" exceeds the 5 MB per-file limit for browser text triage.`);
        continue;
      }
      const text = await file.text();
      if (!text.trim()) {
        setFileError(`"${file.name}" appears to be empty.`);
        continue;
      }
      loaded.push({
        id: `${file.name}-${Date.now()}-${i}`,
        name: file.name,
        sizeBytes: file.size,
        content: text,
      });
    }
    if (loaded.length > 0) {
      onAddLogFiles(loaded);
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div className="max-w-3xl">
          <p className="text-xs font-medium text-slate-500">
            Step 1 of 4 · Real Log Ingestion
          </p>
          <h1 className="mt-1 font-display text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl text-balance">
            Submit Raw Log Entries for CISA Playbook Triage
          </h1>
          <p className="mt-2 text-sm text-slate-600 leading-relaxed">
            Paste real event logs or upload exported log files from your SIEM, EDR, firewall, or host telemetry. Activity is clustered, checked against scope gates, and graded strictly against the CISA Incident & Vulnerability Response Playbooks.
          </p>
        </div>
        <div className="text-xs text-slate-500 tabular-nums shrink-0">
          {hasAnyLogs ? `${totalLogLines.toLocaleString()} log lines staged` : 'Awaiting real log input'}
        </div>
      </div>

      {statusMessage && (
        <div
          role="status"
          className="mb-6 flex items-center gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950"
        >
          <span className="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-amber-700/30 border-t-amber-800" />
          <div>{statusMessage}</div>
        </div>
      )}

      {(errorMessage || fileError) && (
        <div
          role="alert"
          className="mb-6 flex items-start gap-3 rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-900"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-700" aria-hidden="true" />
          <div>{errorMessage || fileError}</div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 items-start">
        {/* Main Input Column */}
        <div className="lg:col-span-8 space-y-4">
          <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-slate-50 px-4 py-3">
              <div className="text-xs font-semibold text-slate-800">
                Raw Log Paste Buffer
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-500 tabular-nums">
                  {pastedLineCount.toLocaleString()} {pastedLineCount === 1 ? 'line' : 'lines'}
                </span>
                {pastedLogs.trim() && (
                  <button
                    type="button"
                    onClick={() => onPastedLogsChange('')}
                    className="text-xs font-medium text-slate-600 hover:text-slate-950 cursor-pointer"
                  >
                    Clear Paste
                  </button>
                )}
              </div>
            </div>

            <textarea
              aria-label="Paste raw log entries"
              value={pastedLogs}
              onChange={(e) => onPastedLogsChange(e.target.value)}
              rows={13}
              spellCheck={false}
              placeholder="Paste raw log entries here (e.g., Windows Security/Sysmon XML or CSV, PowerShell ScriptBlock logs, EDR detections, Firewall/Proxy/DNS records, IDS/IPS alerts, CloudTrail/Entra ID auth logs, or email gateway logs). No sample or synthetic logs are provided."
              className="block w-full resize-y bg-white p-4 font-mono text-xs leading-relaxed text-slate-900 placeholder:text-slate-400 focus:outline-none"
            />
          </div>

          {/* File Dropzone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              void handleReadLogFiles(e.dataTransfer.files);
            }}
            className={`rounded-xl border border-dashed p-5 transition-colors ${
              isDragging
                ? 'border-slate-900 bg-slate-100'
                : 'border-slate-300 bg-white hover:border-slate-400'
            }`}
          >
            <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
              <div className="flex items-start gap-3">
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-slate-700">
                  <Upload className="h-5 w-5" aria-hidden="true" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-slate-900">
                    Upload Real Log Files
                  </p>
                  <p className="mt-0.5 text-xs text-slate-600">
                    Drag and drop exported text log files (.log, .txt, .json, .jsonl, .ndjson, .csv, .xml, .syslog, .cef) up to 5 MB each.
                  </p>
                </div>
              </div>
              <input
                ref={logFileInputRef}
                type="file"
                multiple
                accept=".log,.txt,.json,.jsonl,.ndjson,.csv,.xml,.syslog,.cef,.leef,.tsv,.out"
                onChange={(e) => {
                  void handleReadLogFiles(e.target.files);
                  e.target.value = '';
                }}
                className="sr-only"
              />
              <button
                type="button"
                onClick={() => logFileInputRef.current?.click()}
                className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 whitespace-nowrap shrink-0 cursor-pointer"
              >
                Select Log Files
              </button>
            </div>

            {uploadedFiles.length > 0 && (
              <div className="mt-4 border-t border-slate-200 pt-3 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-medium text-slate-600">
                    Attached Log Files ({uploadedFiles.length})
                  </p>
                  <button
                    type="button"
                    onClick={onClearAllLogFiles}
                    className="text-xs font-medium text-slate-600 hover:text-slate-950 cursor-pointer"
                  >
                    Clear All Files
                  </button>
                </div>
                <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-slate-50">
                  {uploadedFiles.map((file) => {
                    const lineCount = countNonEmptyLogLines(file.content);
                    return (
                      <li
                        key={file.id}
                        className="flex items-center justify-between gap-3 px-3 py-2 text-xs"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <FileText className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
                          <span className="truncate font-medium text-slate-900">{file.name}</span>
                          <span className="text-slate-600 tabular-nums shrink-0">
                            {lineCount.toLocaleString()} {lineCount === 1 ? 'line' : 'lines'}
                          </span>
                          <span className="text-slate-400 tabular-nums shrink-0">
                            · {formatBytes(file.sizeBytes)}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => onRemoveLogFile(file.id)}
                          aria-label={`Remove ${file.name}`}
                          className="rounded p-1 text-slate-500 hover:bg-slate-200 hover:text-slate-900 cursor-pointer"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>

          {/* Primary Triage Action Bar directly under staged logs */}
          <div className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-xs text-slate-600 tabular-nums">
              {hasAnyLogs ? (
                <span>
                  <strong className="text-slate-900">Ready to run:</strong>{' '}
                  {uploadedFiles.length > 0
                    ? `${uploadedFiles.length} attached ${uploadedFiles.length === 1 ? 'file' : 'files'}`
                    : 'Pasted log buffer'}
                  {uploadedFiles.length > 0 && pastedLogs.trim() ? ' + pasted buffer' : ''}
                  {' · '}
                  {totalLogLines.toLocaleString()} total lines
                </span>
              ) : (
                <span>Paste log entries or attach at least one log file to run triage.</span>
              )}
            </div>

            <button
              type="button"
              disabled={!hasAnyLogs || isInspecting}
              onClick={onSubmitLogs}
              className={`inline-flex items-center justify-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold transition-colors whitespace-nowrap shrink-0 ${
                !hasAnyLogs || isInspecting
                  ? 'bg-slate-200 text-slate-500 cursor-not-allowed'
                  : 'bg-slate-950 text-white hover:bg-slate-800 cursor-pointer'
              }`}
            >
              {isInspecting ? (
                <>
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  Inspecting Logs...
                </>
              ) : (
                <>
                  Run Triage on Staged Logs
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Authority & Guidance Column */}
        <aside className="lg:col-span-4 space-y-4">
          <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4">
            <div>
              <h2 className="font-display text-sm font-bold text-slate-950">
                Authoritative Reference Documents
              </h2>
              <p className="mt-1 text-xs text-slate-600 leading-relaxed">
                Every triage decision, NCISS severity level, impact classification, guardrail, and reporting deadline is grounded strictly in these three CISA PDFs.
              </p>
            </div>

            <div className="space-y-3 border-t border-slate-100 pt-3 text-xs">
              <div>
                <div className="font-semibold text-slate-900">
                  1. CISA Incident & Vulnerability Response Playbooks (Nov 2021)
                </div>
                <div className="mt-0.5 text-slate-600">
                  <span
                    className={
                      docsHealth && !docsHealth.playbookAvailable
                        ? 'font-semibold text-red-700'
                        : 'font-semibold text-emerald-800'
                    }
                  >
                    {docsHealth && !docsHealth.playbookAvailable
                      ? 'Not found on server'
                      : 'Loaded on server'}
                  </span>
                  {' · '}
                  Response phases, Table 1 tactics, Key Questions, OPSEC guardrails, escalation steps, and checklists with page citations.
                </div>
              </div>

              <div className="border-t border-slate-100 pt-3">
                <div className="font-semibold text-slate-900">
                  2. CISA National Cyber Incident Scoring System (CISA-NCISS.pdf)
                </div>
                <div className="mt-0.5 text-slate-600">
                  <span
                    className={
                      docsHealth && !docsHealth.ncissAvailable
                        ? 'font-semibold text-red-700'
                        : 'font-semibold text-emerald-800'
                    }
                  >
                    {docsHealth && !docsHealth.ncissAvailable
                      ? 'Not found on server'
                      : 'Loaded on server'}
                  </span>
                  {' · '}
                  Exclusive authority for cluster severity levels: Baseline (White / Blue), Low (Green), Medium (Yellow), High (Orange), Critical (Red), and Emergency (Black).
                </div>
              </div>

              <div className="border-t border-slate-100 pt-3">
                <div className="font-semibold text-slate-900">
                  3. CISA Federal Incident Notification Guidelines
                </div>
                <div className="mt-0.5 text-slate-600">
                  <span
                    className={
                      docsHealth && !docsHealth.fingAvailable
                        ? 'font-semibold text-red-700'
                        : 'font-semibold text-emerald-800'
                    }
                  >
                    {docsHealth && !docsHealth.fingAvailable
                      ? 'Not found on server'
                      : 'Loaded on server'}
                  </span>
                  {' · '}
                  Attack vector taxonomy, Functional / Information / Recoverability impact categories, and 1-hour / 7-day CISA reporting timelines.
                </div>
              </div>

              <div className="border-t border-slate-100 pt-3">
                <button
                  type="button"
                  onClick={onOpenReference}
                  className="inline-flex items-center gap-1.5 font-medium text-slate-900 underline underline-offset-4 hover:text-slate-700 cursor-pointer"
                >
                  <BookOpen className="h-3.5 w-3.5" aria-hidden="true" />
                  Inspect All 3 Reference PDFs & Rules
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-3">
            <h2 className="font-display text-sm font-bold text-slate-950">
              Supported Log Formats
            </h2>
            <p className="text-xs text-slate-600 leading-relaxed">
              Host & Windows Event Logs · Sysmon · PowerShell · EDR · Firewall · Web Proxy · DNS · IDS/IPS · Email Gateway · Cloud Audit · Authentication & Domain Controller Logs
            </p>
            <div className="border-t border-slate-100 pt-3 text-xs text-slate-600">
              Strict grounding policy: no mock data, no pre-filled sample incidents, and no simulated findings.
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
};
