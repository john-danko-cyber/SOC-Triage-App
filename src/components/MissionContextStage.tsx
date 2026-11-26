import React from 'react';
import { ArrowLeft, ArrowRight, AlertTriangle } from 'lucide-react';
import type {
  AuthorizedActivityAnswer,
  IctContractorAnswer,
  LogInspectionResult,
  MissionContextInput,
  MissionCriticalAnswer,
  PiiExposureAnswer,
} from '../types/triage';

interface MissionContextStageProps {
  inspection: LogInspectionResult;
  context: MissionContextInput;
  isAnalyzing: boolean;
  statusMessage?: string | null;
  errorMessage: string | null;
  onChangeContext: (next: MissionContextInput) => void;
  onBackToInput: () => void;
  onSkipAllAndAnalyze: () => void;
  onConfirmAndAnalyze: () => void;
}

export const MissionContextStage: React.FC<MissionContextStageProps> = ({
  inspection,
  context,
  isAnalyzing,
  statusMessage,
  errorMessage,
  onChangeContext,
  onBackToInput,
  onSkipAllAndAnalyze,
  onConfirmAndAnalyze,
}) => {
  const c = inspection.clearContextFromLogs;

  const mcOptions: Array<{ value: MissionCriticalAnswer; label: string; detail: string }> = [
    {
      value: 'yes',
      label: 'Yes — Mission-Critical',
      detail: 'System supports essential agency operations or public services.',
    },
    {
      value: 'no',
      label: 'No — Non-Critical',
      detail: 'System is routine/administrative with limited operational impact.',
    },
    {
      value: 'unknown',
      label: 'Skip / Unknown',
      detail: 'Cannot confirm yet; missing context will not lower rating.',
    },
  ];

  const piiOptions: Array<{ value: PiiExposureAnswer; label: string; detail: string }> = [
    {
      value: 'yes_100k_plus',
      label: 'Yes — 100,000+ PII Records',
      detail: 'Meets OMB M-20-04 mandatory Major Incident breach threshold.',
    },
    {
      value: 'yes_under_100k',
      label: 'Yes — Under 100,000 PII Records',
      detail: 'Evaluate potential demonstrable harm with SAOP.',
    },
    {
      value: 'yes_unknown_volume',
      label: 'Yes — Unknown Record Volume',
      detail: 'PII involved, total affected individuals not yet determined.',
    },
    {
      value: 'no',
      label: 'No PII / Sensitive Data',
      detail: 'Confirmed no PII or sensitive records on affected assets.',
    },
    {
      value: 'unknown',
      label: 'Skip / Unknown',
      detail: 'Cannot confirm yet; PII exposure remains unruled out.',
    },
  ];

  const authOptions: Array<{ value: AuthorizedActivityAnswer; label: string; detail: string }> = [
    {
      value: 'unauthorized',
      label: 'Confirmed Unauthorized',
      detail: 'Verified not scheduled maintenance, admin work, or authorized test.',
    },
    {
      value: 'authorized',
      label: 'Confirmed Authorized Admin / Maintenance',
      detail: 'Deconflicted with verified change ticket or admin activity.',
    },
    {
      value: 'unknown',
      label: 'Skip / Unknown',
      detail: 'Pending admin deconfliction (Playbook p. 10).',
    },
  ];

  const ictOptions: Array<{ value: IctContractorAnswer; label: string; detail: string }> = [
    {
      value: 'yes',
      label: 'Yes — ICT Contractor / CSP Operated',
      detail: 'Triggers EO 14028 dual reporting to FCEB agency and CISA.',
    },
    {
      value: 'no',
      label: 'No — Agency Operated',
      detail: 'Operated directly by the FCEB agency.',
    },
    {
      value: 'unknown',
      label: 'Unknown',
      detail: 'System hosting/operator status not confirmed.',
    },
  ];

  return (
    <div className="mx-auto max-w-5xl px-6 py-8 space-y-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500">
            Step 2 of 4 · Pre-Score Mission Context Check
          </p>
          <h1 className="mt-1 font-display text-2xl font-bold tracking-tight text-slate-950 text-balance">
            Confirm Mission Context Before Locking Severity
          </h1>
        </div>
        <button
          type="button"
          onClick={onBackToInput}
          disabled={isAnalyzing}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700 hover:text-slate-950 cursor-pointer whitespace-nowrap"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
          Edit Submitted Logs
        </button>
      </div>

      {/* Inspection Summary */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600">
          <span>
            <strong className="text-slate-900">Detected Log Formats:</strong>{' '}
            {inspection.detectedFormats.length > 0
              ? inspection.detectedFormats.join(' · ')
              : 'General Text / Unstructured Logs'}
          </span>
          <span className="tabular-nums">
            {(inspection.totalLinesParsed ?? inspection.entryCountEstimate).toLocaleString()} log lines parsed
            {typeof inspection.inspectedLineCount === 'number' &&
            inspection.inspectedLineCount < (inspection.totalLinesParsed ?? inspection.entryCountEstimate)
              ? ` (${inspection.inspectedLineCount.toLocaleString()} pre-screened; all lines evaluated in Step 3)`
              : ''}
          </span>
        </div>
        <p className="text-sm text-slate-700 leading-relaxed">{inspection.inspectionSummary}</p>

        {inspection.nssOrClassifiedDetected && (
          <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-950 flex items-start gap-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-700 mt-0.5" aria-hidden="true" />
            <div>
              <strong>Potential NSS / Classified Indicator Observed:</strong> {inspection.nssEvidence}. Continue to generate the formal scope gate notice directing to CNSSI 1010.
            </div>
          </div>
        )}
      </div>

      {/* Conservative Rule Banner */}
      <div className="rounded-xl border border-slate-300 bg-slate-100 p-4 text-xs text-slate-800 leading-relaxed">
        <strong>CISA Context Rules:</strong> When suspicious or malicious indicators are observed, missing context never lowers a severity rating and triggers provisional status <strong>"Major Incident Not Yet Ruled Out"</strong> (Playbook pp. 3, 5). Conversely, <strong>missing mission context never raises a clean/baseline log above Baseline by itself</strong>. All Confirmed vs. Assumed answers are shown transparently on the scorecard.
      </div>

      {statusMessage && (
        <div
          role="status"
          className="flex items-center gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950"
        >
          <span className="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-amber-700/30 border-t-amber-800" />
          <div>{statusMessage}</div>
        </div>
      )}

      {errorMessage && (
        <div
          role="alert"
          className="rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-900"
        >
          {errorMessage}
        </div>
      )}

      {/* Question 1 */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="font-display text-base font-bold text-slate-950">
            1. Is the affected system mission-critical?
          </h2>
          <span className="text-xs text-slate-500">
            {c.missionCritical.detected
              ? `Observed in logs: ${c.missionCritical.evidence}`
              : 'Not clearly revealed in logs'}
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
          {mcOptions.map((opt) => {
            const selected = context.missionCritical === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() =>
                  onChangeContext({
                    ...context,
                    missionCritical: opt.value,
                    skippedAll: false,
                  })
                }
                className={`rounded-lg border p-3.5 text-left transition-colors cursor-pointer ${
                  selected
                    ? 'border-slate-950 bg-slate-950 text-white'
                    : 'border-slate-200 bg-white text-slate-900 hover:border-slate-400'
                }`}
              >
                <div className="text-xs font-semibold">{opt.label}</div>
                <div className={`mt-1 text-xs ${selected ? 'text-slate-300' : 'text-slate-600'}`}>
                  {opt.detail}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Question 2 */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="font-display text-base font-bold text-slate-950">
            2. Is sensitive data or PII involved (100,000+ PII records threshold)?
          </h2>
          <span className="text-xs text-slate-500">
            {c.piiExposure.detected
              ? `Observed in logs: ${c.piiExposure.evidence}`
              : 'Not clearly revealed in logs'}
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
          {piiOptions.map((opt) => {
            const selected = context.piiExposure === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() =>
                  onChangeContext({
                    ...context,
                    piiExposure: opt.value,
                    skippedAll: false,
                  })
                }
                className={`rounded-lg border p-3.5 text-left transition-colors cursor-pointer ${
                  selected
                    ? 'border-slate-950 bg-slate-950 text-white'
                    : 'border-slate-200 bg-white text-slate-900 hover:border-slate-400'
                }`}
              >
                <div className="text-xs font-semibold">{opt.label}</div>
                <div className={`mt-1 text-xs ${selected ? 'text-slate-300' : 'text-slate-600'}`}>
                  {opt.detail}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Question 3 */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="font-display text-base font-bold text-slate-950">
            3. Could this activity be authorized admin or maintenance work (deconfliction)?
          </h2>
          <span className="text-xs text-slate-500">
            {c.authorizedActivity.detected
              ? `Observed in logs: ${c.authorizedActivity.evidence}`
              : 'Not clearly revealed in logs'}
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
          {authOptions.map((opt) => {
            const selected = context.authorizedActivity === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() =>
                  onChangeContext({
                    ...context,
                    authorizedActivity: opt.value,
                    skippedAll: false,
                  })
                }
                className={`rounded-lg border p-3.5 text-left transition-colors cursor-pointer ${
                  selected
                    ? 'border-slate-950 bg-slate-950 text-white'
                    : 'border-slate-200 bg-white text-slate-900 hover:border-slate-400'
                }`}
              >
                <div className="text-xs font-semibold">{opt.label}</div>
                <div className={`mt-1 text-xs ${selected ? 'text-slate-300' : 'text-slate-600'}`}>
                  {opt.detail}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Optional Contractor / ICT Operator Check */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="font-display text-sm font-bold text-slate-950">
            Optional Scope Check: Is the affected system operated by an ICT Service Provider / Contractor?
          </h2>
          <span className="text-xs text-slate-500">
            {c.ictContractor.detected
              ? `Observed in logs: ${c.ictContractor.evidence}`
              : 'Determines EO 14028 contractor handoff'}
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
          {ictOptions.map((opt) => {
            const selected = context.ictContractor === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() =>
                  onChangeContext({
                    ...context,
                    ictContractor: opt.value,
                  })
                }
                className={`rounded-lg border p-3 text-left transition-colors cursor-pointer ${
                  selected
                    ? 'border-slate-950 bg-slate-950 text-white'
                    : 'border-slate-200 bg-white text-slate-900 hover:border-slate-400'
                }`}
              >
                <div className="text-xs font-semibold">{opt.label}</div>
                <div className={`mt-0.5 text-xs ${selected ? 'text-slate-300' : 'text-slate-600'}`}>
                  {opt.detail}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Bottom Actions */}
      <div className="flex flex-col-reverse gap-3 sm:flex-row sm:items-center sm:justify-between pt-2">
        <button
          type="button"
          disabled={isAnalyzing}
          onClick={onSkipAllAndAnalyze}
          className="rounded-xl border border-slate-300 bg-white px-5 py-3 text-xs font-semibold text-slate-800 hover:bg-slate-50 transition-colors cursor-pointer disabled:opacity-50"
        >
          Skip / Unknown All & Score Conservatively
        </button>

        <button
          type="button"
          disabled={isAnalyzing}
          onClick={onConfirmAndAnalyze}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-slate-950 px-6 py-3 text-sm font-semibold text-white hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
        >
          {isAnalyzing ? (
            <>
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
              Clustering & Generating Playbook Scorecards...
            </>
          ) : (
            <>
              Lock In Context & Generate Scorecards
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </>
          )}
        </button>
      </div>
    </div>
  );
};
