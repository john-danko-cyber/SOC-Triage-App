import React, { useState } from 'react';
import { X, FileText, Download } from 'lucide-react';
import {
  FING_ATTACK_VECTORS,
  FING_PDF_URL,
  MANDATORY_GUARDRAILS,
  NCISS_LEVEL_DEFINITIONS,
  NCISS_PDF_URL,
  PLAYBOOK_KEY_QUESTIONS,
  PLAYBOOK_PDF_URL,
  PLAYBOOK_TABLE_1,
  SEVERITY_STYLES,
} from '../constants/playbook';
import type { SeverityLevelCode } from '../types/triage';

interface PlaybookReferenceModalProps {
  open: boolean;
  onClose: () => void;
}

const NCISS_ORDERED_LEVELS: SeverityLevelCode[] = [
  'EMERGENCY_BLACK',
  'SEVERE_RED',
  'HIGH_ORANGE',
  'MEDIUM_YELLOW',
  'LOW_GREEN',
  'BASELINE_MINOR_BLUE',
  'BASELINE_NEGLIGIBLE_WHITE',
];

export const PlaybookReferenceModal: React.FC<PlaybookReferenceModalProps> = ({
  open,
  onClose,
}) => {
  const [tab, setTab] = useState<'summary' | 'playbook' | 'nciss' | 'fing'>('summary');

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="playbook-ref-title"
    >
      <div className="flex max-h-[90vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl">
        <div className="flex items-center justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div>
            <h2
              id="playbook-ref-title"
              className="font-display text-lg font-bold text-slate-950"
            >
              CISA Authoritative Reference Documents (All 3 Loaded)
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Playbooks (Nov 2021) · CISA NCISS · Federal Incident Notification Guidelines (FING)
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <a
              href={PLAYBOOK_PDF_URL}
              download="CISA_Incident_Vulnerability_Response_Playbooks_Nov2021.pdf"
              className="hidden sm:inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              Playbook PDF
            </a>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close Playbook Reference"
              className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 cursor-pointer"
            >
              <X className="h-5 w-5" aria-hidden="true" />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 bg-slate-50 px-6 py-2">
          <button
            type="button"
            onClick={() => setTab('summary')}
            className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
              tab === 'summary'
                ? 'bg-white text-slate-950 border border-slate-200 shadow-xs'
                : 'text-slate-600 hover:text-slate-950'
            }`}
          >
            NCISS Levels, FING & Playbook Rules
          </button>
          <button
            type="button"
            onClick={() => setTab('playbook')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
              tab === 'playbook'
                ? 'bg-white text-slate-950 border border-slate-200 shadow-xs'
                : 'text-slate-600 hover:text-slate-950'
            }`}
          >
            <FileText className="h-3.5 w-3.5" aria-hidden="true" />
            1. Playbooks (2021)
          </button>
          <button
            type="button"
            onClick={() => setTab('nciss')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
              tab === 'nciss'
                ? 'bg-white text-slate-950 border border-slate-200 shadow-xs'
                : 'text-slate-600 hover:text-slate-950'
            }`}
          >
            <FileText className="h-3.5 w-3.5" aria-hidden="true" />
            2. CISA-NCISS
          </button>
          <button
            type="button"
            onClick={() => setTab('fing')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
              tab === 'fing'
                ? 'bg-white text-slate-950 border border-slate-200 shadow-xs'
                : 'text-slate-600 hover:text-slate-950'
            }`}
          >
            <FileText className="h-3.5 w-3.5" aria-hidden="true" />
            3. Notification Guidelines
          </button>
        </div>

        {tab === 'summary' && (
          <div className="overflow-y-auto p-6 space-y-6 text-sm text-slate-700">
            <section className="space-y-2">
              <h3 className="font-display text-base font-semibold text-slate-950">
                CISA-NCISS.pdf Priority Levels (pp. 4–6)
              </h3>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {NCISS_ORDERED_LEVELS.map((code) => {
                  const def = NCISS_LEVEL_DEFINITIONS[code];
                  const st = SEVERITY_STYLES[code];
                  return (
                    <div
                      key={code}
                      className={`rounded-lg border p-3 ${st.badgeBorder} ${st.badgeBg} ${st.badgeText}`}
                    >
                      <div className="text-xs font-semibold">
                        {def.levelName} ({def.colorName})
                      </div>
                      <p className="mt-1 text-xs opacity-90">{def.definition}</p>
                      <p className="mt-1 text-[11px] opacity-75">{def.citation}</p>
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="space-y-2">
              <h3 className="font-display text-base font-semibold text-slate-950">
                Federal Incident Notification Guidelines — Attack Vectors & Timelines (pp. 2–11)
              </h3>
              <p className="text-xs text-slate-600">
                Agencies must report incidents potentially compromising C/I/A to CISA <strong>within 1 hour</strong> of identification (pp. 3–4) via <code className="font-mono">https://myservices.cisa.gov/irf</code>, <code className="font-mono">contact@mail.cisa.dhs.gov</code>, or STIX; Major Incidents must be reported to Congress <strong>within 7 days</strong> (p. 5).
              </p>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 text-xs">
                {FING_ATTACK_VECTORS.map((item) => (
                  <div key={item.vector} className="rounded-lg border border-slate-200 bg-slate-50 p-2.5">
                    <div className="font-semibold text-slate-900">{item.vector}</div>
                    <div className="mt-0.5 text-slate-600">{item.description}</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="space-y-2">
              <h3 className="font-display text-base font-semibold text-slate-950">
                Playbook Table 1: Adversary Tactics, Techniques, and Relevant Log Data (Playbook p. 12)
              </h3>
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200 bg-slate-50 text-slate-700">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Tactic</th>
                      <th className="px-3 py-2 font-semibold">Common Techniques</th>
                      <th className="px-3 py-2 font-semibold">Log and Event Sources</th>
                      <th className="px-3 py-2 font-semibold">Indicators</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {PLAYBOOK_TABLE_1.map((row) => (
                      <tr key={row.tactic} className="align-top">
                        <td className="px-3 py-2 font-semibold text-slate-950 whitespace-nowrap">
                          {row.tactic} ({row.mitreId})
                        </td>
                        <td className="px-3 py-2 text-slate-700">{row.commonTechniques}</td>
                        <td className="px-3 py-2 text-slate-700">{row.logSources}</td>
                        <td className="px-3 py-2 text-slate-700">{row.indicators}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="grid grid-cols-1 gap-6 md:grid-cols-2">
              <div className="space-y-2">
                <h3 className="font-display text-base font-semibold text-slate-950">
                  Key Questions to Answer (Playbook pp. 12–13)
                </h3>
                <ol className="list-decimal space-y-1.5 pl-5 text-xs text-slate-700">
                  {PLAYBOOK_KEY_QUESTIONS.map((q) => (
                    <li key={q}>{q}</li>
                  ))}
                </ol>
              </div>
              <div className="space-y-2">
                <h3 className="font-display text-base font-semibold text-slate-950">
                  Mandatory OPSEC & Evidence Guardrails (Playbook pp. 9–10, 14, 36–37)
                </h3>
                <ul className="list-disc space-y-1.5 pl-5 text-xs text-slate-700">
                  {MANDATORY_GUARDRAILS.map((g) => (
                    <li key={g}>{g}</li>
                  ))}
                </ul>
                <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
                  <p className="font-semibold text-slate-900">Scope & Crossover Authorities:</p>
                  <p className="mt-1">
                    <strong>NSS / Classified (Playbook p. 4, p. 26):</strong> Out of scope; see CNSSI 1010.
                  </p>
                  <p className="mt-1">
                    <strong>Active Vulnerability Exploitation (Playbook pp. 21–24):</strong> Flag Compromised status in Vulnerability Response Playbook and immediately initiate Incident Response.
                  </p>
                  <p className="mt-1">
                    <strong>CISA Reporting (Playbook pp. 10, 18, 34; FING pp. 3–5):</strong> Initial report within 1 hour of identification; Major Incident report within 1 hour of declaration; Congress report within 7 days.
                  </p>
                </div>
              </div>
            </section>
          </div>
        )}

        {tab === 'playbook' && (
          <div className="flex-1 bg-slate-100 p-4">
            <iframe
              src={PLAYBOOK_PDF_URL}
              title="CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks"
              className="h-[70vh] w-full rounded-lg border border-slate-200 bg-white"
            />
          </div>
        )}

        {tab === 'nciss' && (
          <div className="flex-1 bg-slate-100 p-4">
            <iframe
              src={NCISS_PDF_URL}
              title="CISA National Cyber Incident Scoring System (NCISS)"
              className="h-[70vh] w-full rounded-lg border border-slate-200 bg-white"
            />
          </div>
        )}

        {tab === 'fing' && (
          <div className="flex-1 bg-slate-100 p-4">
            <iframe
              src={FING_PDF_URL}
              title="CISA Federal Incident Notification Guidelines"
              className="h-[70vh] w-full rounded-lg border border-slate-200 bg-white"
            />
          </div>
        )}
      </div>
    </div>
  );
};
