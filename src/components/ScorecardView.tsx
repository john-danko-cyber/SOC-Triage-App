import React, { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Printer,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { SEVERITY_STYLES } from '../constants/playbook';
import type { IncidentScorecard, TriageAnalysisResponse } from '../types/triage';

interface ScorecardViewProps {
  result: TriageAnalysisResponse;
  onAdjustContext: () => void;
  onBackToLogs: () => void;
}

function formatTriageBrief(result: TriageAnalysisResponse): string {
  const lines: string[] = [];
  const clusteredFallback = result.scorecards.reduce(
    (sum, c) => sum + (c.clusterLogs?.length || 0),
    0
  );
  const counts = result.triageCounts ?? {
    totalLinesParsed: clusteredFallback + result.likelyBenign.length,
    evaluatedCount: clusteredFallback + result.likelyBenign.length,
    clusteredCount: clusteredFallback,
    benignCount: result.likelyBenign.length,
    clusterCount: result.scorecards.length,
  };
  const docs = result.documentsStatus ?? {
    playbookLoaded: true,
    ncissLoaded: true,
    fingLoaded: true,
  };

  lines.push('FCEB SOC TRIAGE SCORECARD BRIEF (CISA 3-DOCUMENT GROUNDED)');
  lines.push(`Analyzed UTC: ${result.analyzedAtUtc}`);
  lines.push(
    `Reference Authorities: Playbooks 2021 (${docs.playbookLoaded ? 'Loaded' : 'Unavailable'}) · CISA-NCISS (${docs.ncissLoaded ? 'Loaded' : 'Unavailable'}) · CISA FING (${docs.fingLoaded ? 'Loaded' : 'Unavailable'})`
  );
  lines.push(
    `Line Accounting: ${counts.totalLinesParsed.toLocaleString()} total parsed · ${counts.evaluatedCount.toLocaleString()} evaluated (${counts.clusteredCount.toLocaleString()} in clusters + ${counts.benignCount.toLocaleString()} likely benign) · Analysis calls: ${result.geminiCallsMade ?? 1}`
  );
  if (result.telemetrySummary) {
    const t = result.telemetrySummary;
    const sp = t.suspiciousPatterns;
    lines.push(
      `Code-Computed Counts: ${t.totalEvents.toLocaleString()} events | Failed Logins: ${t.failedLogins.toLocaleString()} | Unique Source IPs: ${t.uniqueSourceIps.toLocaleString()} | Blocked/Denied: ${t.blockedDeniedConnections.toLocaleString()} | HTTP 4xx: ${t.http4xxCount.toLocaleString()} | HTTP 5xx: ${t.http5xxCount.toLocaleString()}`
    );
    lines.push(
      `Suspicious Patterns: SQLi=${sp.sqliCount} | PathTraversal=${sp.pathTraversalCount} | BruteForceIPs=${sp.bruteForceIps.length} | DNSTunneling=${sp.dnsTunnelingCount} | PortScans=${sp.portScanCount} | Exfil=${sp.exfiltrationCount} | WinEvents(4625=${sp.windowsEventIds.event4625}, 4720=${sp.windowsEventIds.event4720}, 4732=${sp.windowsEventIds.event4732}, 1102=${sp.windowsEventIds.event1102}, 7045=${sp.windowsEventIds.event7045})`
    );
    lines.push(
      `Code Severity Floor: ${t.computedSeverityFloor.floorTier} (${t.computedSeverityFloor.reasons.join('; ')})`
    );
  }
  lines.push('');

  if (result.globalScopeFlags.nssOrClassifiedDetected) {
    lines.push(`[SCOPE GATE — NSS / CLASSIFIED]: ${result.globalScopeFlags.nssDetails}`);
    lines.push('Action: Out of scope for FCEB Playbooks (p. 4, p. 26). Follow CNSSI 1010.');
    lines.push('');
  }
  if (result.globalScopeFlags.vulnerabilityPlaybookTriggered) {
    lines.push(
      `[CROSSOVER GATE — VULNERABILITY RESPONSE PLAYBOOK (p. 23)]: ${result.globalScopeFlags.vulnerabilityDetails}`
    );
    lines.push('');
  }

  result.scorecards.forEach((card, idx) => {
    lines.push(`============================================================`);
    lines.push(`CLUSTER ${idx + 1}: ${card.clusterTitle}`);
    lines.push(
      `NCISS Severity: ${card.severity.ncissLevelName} (${card.severity.colorName})${
        card.severity.isProvisional && card.severity.provisionalLabel
          ? ` | PROVISIONAL: ${card.severity.provisionalLabel}`
          : ''
      }`
    );
    lines.push(
      `NCISS Definition (${card.severity.ncissCitation}): "${card.severity.ncissDefinitionQuote}"`
    );
    lines.push(`NCISS Justification: ${card.severity.ncissJustification}`);
    if (card.severity.levelCode === 'UNSCORABLE_GRAY' && card.severity.unscorableReason) {
      lines.push(`Unscorable Explanation: ${card.severity.unscorableReason}`);
    }
    lines.push(
      `Playbook Classification: ${card.shortRead.classification} | Phase: ${card.shortRead.playbookPhase} (${card.shortRead.playbookCitation})`
    );
    if (card.notificationAssessment) {
      lines.push(
        `FING Attack Vector (${card.notificationAssessment.attackVectorCitation}): ${card.notificationAssessment.attackVectorCategory} — ${card.notificationAssessment.attackVectorRationale}`
      );
      lines.push(
        `FING Functional Impact: ${card.notificationAssessment.functionalImpactCategory} — ${card.notificationAssessment.functionalImpactRationale}`
      );
      lines.push(
        `FING Information Impact: ${card.notificationAssessment.informationImpactCategories.join(', ')} — ${card.notificationAssessment.informationImpactRationale}`
      );
      lines.push(
        `FING Recoverability (${card.notificationAssessment.impactCitation}): ${card.notificationAssessment.recoverabilityCategory} — ${card.notificationAssessment.recoverabilityRationale}`
      );
      lines.push(
        `FING Reporting Timeline (${card.notificationAssessment.reportingCitation}): ${card.notificationAssessment.reportingTimeline} | Channels: ${card.notificationAssessment.reportingChannelsAndRequiredData}`
      );
    }
    lines.push(
      `Affected Hosts: ${card.shortRead.affectedHosts.join(', ') || 'Unknown'} | Accounts: ${
        card.shortRead.affectedAccounts.join(', ') || 'Unknown'
      }`
    );
    lines.push('');
    lines.push('Context (Confirmed vs. Assumed):');
    card.contextSummary.forEach((ctx) => {
      lines.push(`- ${ctx.dimension}: ${ctx.valueLabel} [${ctx.provenance}]`);
    });
    lines.push('');
    lines.push(`Short Read: ${card.shortRead.summary}`);
    lines.push('');
    lines.push(`Mandatory Guardrails (${card.nextSteps.guardrailsCitation}):`);
    card.nextSteps.guardrails.forEach((g, gIdx) => {
      lines.push(`${gIdx + 1}. ${g}`);
    });
    lines.push('');
    lines.push(
      `Part A — SOC Analyst Immediate Steps (${card.nextSteps.checklistCitations.join('; ')}):`
    );
    [
      ...card.nextSteps.analystImmediateSteps.deconfliction,
      ...card.nextSteps.analystImmediateSteps.evidencePreservation,
      ...card.nextSteps.analystImmediateSteps.keyQuestionInvestigation,
      ...card.nextSteps.analystImmediateSteps.safeContainmentOptions,
    ].forEach((s) => lines.push(`- ${s}`));
    lines.push('');
    lines.push('Part B — Escalate to Role:');
    card.nextSteps.roleHandoffs.forEach((h) => {
      lines.push(`* Escalate to ${h.role} (${h.urgencyOrDeadline}) [${h.playbookCitation}]`);
      h.actions.forEach((a) => lines.push(`  - ${a}`));
    });
    lines.push('');
  });

  if (result.likelyBenign.length > 0) {
    lines.push(`LIKELY BENIGN LOG ENTRIES (${result.likelyBenign.length} total):`);
    const preview = result.likelyBenign.slice(0, 25);
    preview.forEach((b) => {
      const lineTag = b.lineNumber ? `L${b.lineNumber} ` : '';
      lines.push(
        `- ${lineTag}[${b.timestamp || 'No timestamp'}] (${b.source}) ${b.excerpt} — Reason: ${b.reason}`
      );
    });
    if (result.likelyBenign.length > 25) {
      lines.push(
        `... and ${result.likelyBenign.length - 25} additional likely benign entries accounted for in triage results.`
      );
    }
  }

  return lines.join('\n');
}

const ClusterScorecard: React.FC<{ card: IncidentScorecard; index: number }> = ({
  card,
  index,
}) => {
  const [logsExpanded, setLogsExpanded] = useState(false);
  const style = SEVERITY_STYLES[card.severity.levelCode] ?? SEVERITY_STYLES.UNSCORABLE_GRAY;
  const isProminentGuardrail = card.nextSteps.guardrailProminence === 'prominent';
  const fing = card.notificationAssessment;

  return (
    <article
      aria-labelledby={`cluster-heading-${card.clusterId}`}
      className="overflow-hidden rounded-xl border border-slate-200 bg-white"
    >
      {/* Top Color-Coded NCISS Severity Banner */}
      <div
        className={`flex flex-col gap-3 border-b border-slate-200 px-6 py-4 sm:flex-row sm:items-center sm:justify-between ${style.headerBg} ${style.headerText}`}
      >
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-xs font-semibold opacity-95">
            <span>Cluster {index + 1}</span>
            <span aria-hidden="true">·</span>
            <span>
              NCISS: {card.severity.ncissLevelName} ({card.severity.colorName})
            </span>
            {card.severity.isProvisional && card.severity.provisionalLabel && (
              <>
                <span aria-hidden="true">·</span>
                <span className="underline underline-offset-4">
                  {card.severity.provisionalLabel}
                </span>
              </>
            )}
          </div>
          <h2
            id={`cluster-heading-${card.clusterId}`}
            className="font-display text-lg font-bold tracking-tight sm:text-xl"
          >
            {card.clusterTitle}
          </h2>
        </div>

        <div className="shrink-0 text-xs font-medium opacity-95">
          {card.severity.recommendEscalate ? 'Escalation Recommended' : 'Monitor / Document'}
        </div>
      </div>

      {/* Cluster Scope / Connection Sub-strip */}
      <div className="border-b border-slate-200 bg-slate-50 px-6 py-3 text-xs text-slate-700 space-y-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-semibold text-slate-900">
            {card.connectionCertainty === 'unified'
              ? 'Unified Attack Chain'
              : card.connectionCertainty === 'uncertain_connection'
                ? 'Uncertain Connection (Cannot Be Determined From Logs)'
                : 'Distinct Activity Cluster'}
          </span>
          <span aria-hidden="true">·</span>
          <span>Hosts: {card.clusteringBasis.hosts.join(', ') || 'None identified'}</span>
          <span aria-hidden="true">·</span>
          <span>Users: {card.clusteringBasis.users.join(', ') || 'None identified'}</span>
          <span aria-hidden="true">·</span>
          <span>IPs: {card.clusteringBasis.ips.join(', ') || 'None identified'}</span>
          <span aria-hidden="true">·</span>
          <span className="tabular-nums">
            Timeframe: {card.clusteringBasis.timeframe || 'Not specified'}
          </span>
        </div>
        <p className="text-slate-600">{card.connectionNote}</p>
      </div>

      {/* Cluster-Specific Scope & Crossover Alerts */}
      {(card.nssOutOfScope || card.vulnerabilityCrossover.triggered) && (
        <div className="border-b border-slate-200 bg-amber-50 px-6 py-3.5 space-y-2 text-xs text-amber-950">
          {card.nssOutOfScope && (
            <div className="flex items-start gap-2">
              <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0 text-red-700" aria-hidden="true" />
              <div>
                <strong>Out of Scope — NSS / Classified Information:</strong>{' '}
                {card.nssGuidance ||
                  'Logs indicate National Security Systems (44 U.S.C. § 3552(b)(6)) or classified information. CISA FCEB Playbooks (p. 4, p. 26) do not cover NSS/classified threats; see CNSSI 1010 for coordination and reporting guidance.'}
              </div>
            </div>
          )}
          {card.vulnerabilityCrossover.triggered && (
            <div className="flex items-start gap-2">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-orange-700" aria-hidden="true" />
              <div>
                <strong>
                  Vulnerability Response Playbook Crossover ({card.vulnerabilityCrossover.status}):
                </strong>{' '}
                {card.vulnerabilityCrossover.cveOrVulnerability !== 'None' &&
                card.vulnerabilityCrossover.cveOrVulnerability
                  ? `${card.vulnerabilityCrossover.cveOrVulnerability} — `
                  : ''}
                {card.vulnerabilityCrossover.explanation} (
                {card.vulnerabilityCrossover.playbookCitation || 'Playbook p. 23'}: active
                exploitation marks the system <em>Compromised</em> and immediately triggers Incident
                Response alongside vulnerability remediation.)
              </div>
            </div>
          )}
        </div>
      )}

      <div className="divide-y divide-slate-200">
        {/* SECTION 1: NCISS Severity Rating, FING Notification Categories & Context */}
        <section className="p-6 space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="font-display text-base font-bold text-slate-950">
              1. NCISS Severity Rating, FING Impact &amp; Confidence
            </h3>
            <span className="text-xs text-slate-500">
              CISA-NCISS.pdf · CISA Notification Guidelines · Confirmed vs. Assumed Context
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <div className={`lg:col-span-5 rounded-lg border border-slate-200 p-4 ${style.surfaceTint}`}>
              <div className="flex items-center gap-3">
                <span
                  aria-hidden="true"
                  className="h-4 w-4 shrink-0 rounded-sm border border-slate-400"
                  style={{ backgroundColor: style.swatchColor }}
                />
                <div className="text-sm font-bold text-slate-950">
                  {card.severity.ncissLevelName} ({card.severity.colorName})
                </div>
              </div>

              <blockquote className="mt-3 rounded-md border border-slate-200 bg-white/90 p-3 text-xs leading-relaxed text-slate-900">
                <p className="italic">“{card.severity.ncissDefinitionQuote}”</p>
                <footer className="mt-1.5 text-[11px] font-medium not-italic text-slate-600">
                  Source: {card.severity.ncissCitation}
                </footer>
              </blockquote>

              <p className="mt-2.5 text-xs leading-relaxed text-slate-700">
                <strong className="text-slate-900">Scoring Justification:</strong>{' '}
                {card.severity.ncissJustification}
              </p>

              {card.severity.severityFloorApplied?.enforced && (
                <div className="mt-3 rounded-md border border-slate-300 bg-white p-3 text-xs text-slate-800">
                  <strong className="text-slate-950">
                    Code Severity Floor ({card.severity.severityFloorApplied.floorTier}):
                  </strong>{' '}
                  {card.severity.severityFloorApplied.reasons.join('; ')}.{' '}
                  {card.severity.geminiInitialLevelCode &&
                  card.severity.geminiInitialLevelCode !== card.severity.levelCode
                    ? `Final rating enforced as max(model, floor) — raised to ${card.severity.ncissLevelName}.`
                    : 'Final rating satisfies code-enforced minimum floor.'}
                </div>
              )}

              {card.severity.levelCode === 'UNSCORABLE_GRAY' && card.severity.unscorableReason && (
                <div className="mt-3 rounded-md border border-slate-300 bg-white p-3 text-xs text-slate-800">
                  <strong className="text-slate-950">Why Cluster Cannot Be Scored (Gray):</strong>{' '}
                  {card.severity.unscorableReason}
                </div>
              )}

              {card.severity.isProvisional && (
                <div className="mt-3 rounded-md border border-orange-300 bg-orange-50 p-3 text-xs text-orange-950">
                  <div className="font-bold">
                    Provisional Status:{' '}
                    {card.severity.provisionalLabel || 'Major Incident Not Yet Ruled Out'}
                  </div>
                  {card.severity.provisionalReason && (
                    <p className="mt-1 leading-relaxed">{card.severity.provisionalReason}</p>
                  )}
                </div>
              )}
            </div>

            <div className="lg:col-span-7 overflow-x-auto rounded-lg border border-slate-200">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-200 bg-slate-50 text-slate-700">
                  <tr>
                    <th className="px-3.5 py-2.5 font-semibold">Context Dimension</th>
                    <th className="px-3.5 py-2.5 font-semibold">Evaluation</th>
                    <th className="px-3.5 py-2.5 font-semibold">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {card.contextSummary.map((item) => (
                    <tr key={item.dimension} className="align-top">
                      <td className="px-3.5 py-2.5 font-medium text-slate-900">
                        {item.dimension}
                      </td>
                      <td className="px-3.5 py-2.5 text-slate-700">
                        <div>{item.valueLabel}</div>
                        <div className="mt-0.5 text-[11px] text-slate-500">{item.note}</div>
                      </td>
                      <td className="px-3.5 py-2.5 font-semibold whitespace-nowrap">
                        <span
                          className={
                            item.provenance.startsWith('Confirmed')
                              ? 'text-emerald-800'
                              : 'text-amber-800'
                          }
                        >
                          {item.provenance}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* CISA Federal Incident Notification Guidelines (FING) Assessment */}
          {fing && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 overflow-hidden">
              <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-200 bg-white px-4 py-2.5">
                <h4 className="text-xs font-bold text-slate-950">
                  CISA Federal Incident Notification Guidelines (FING) Assessment
                </h4>
                <span className="text-[11px] text-slate-500">
                  Attack Vector (pp. 9–11) · Impact Categories (pp. 6–9) · Reporting Timeline (pp. 2–6)
                </span>
              </div>
              <div className="grid grid-cols-1 divide-y divide-slate-200 text-xs md:grid-cols-3 md:divide-y-0 md:divide-x">
                <div className="p-4 space-y-1.5">
                  <div className="font-semibold text-slate-900">Attack Vector Category</div>
                  <div className="font-bold text-slate-950">{fing.attackVectorCategory}</div>
                  <p className="text-slate-700 leading-relaxed">{fing.attackVectorRationale}</p>
                  <div className="text-[11px] text-slate-500">{fing.attackVectorCitation}</div>
                </div>

                <div className="p-4 space-y-2">
                  <div className="font-semibold text-slate-900">Impact Categories</div>
                  <div className="space-y-1.5 text-slate-700">
                    <div>
                      <span className="font-semibold text-slate-900">Functional:</span>{' '}
                      <span className="font-medium text-slate-950">
                        {fing.functionalImpactCategory}
                      </span>{' '}
                      — {fing.functionalImpactRationale}
                    </div>
                    <div>
                      <span className="font-semibold text-slate-900">Information:</span>{' '}
                      <span className="font-medium text-slate-950">
                        {fing.informationImpactCategories.join(', ')}
                      </span>{' '}
                      — {fing.informationImpactRationale}
                    </div>
                    <div>
                      <span className="font-semibold text-slate-900">Recoverability:</span>{' '}
                      <span className="font-medium text-slate-950">
                        {fing.recoverabilityCategory}
                      </span>{' '}
                      — {fing.recoverabilityRationale}
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-500">{fing.impactCitation}</div>
                </div>

                <div className="p-4 space-y-1.5">
                  <div className="font-semibold text-slate-900">Reporting Timeline &amp; Channels</div>
                  <div className="font-semibold text-slate-950 leading-relaxed">
                    {fing.reportingTimeline}
                  </div>
                  <p className="text-slate-700 leading-relaxed">
                    {fing.reportingChannelsAndRequiredData}
                  </p>
                  <div className="text-[11px] text-slate-500">{fing.reportingCitation}</div>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* SECTION 2: Short Read on What's Happening */}
        <section className="p-6 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="font-display text-base font-bold text-slate-950">
              2. Short Read on What's Happening
            </h3>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-700">
              <span className="font-semibold text-slate-950">
                Classification: {card.shortRead.classification}
              </span>
              {card.shortRead.playbookPhase && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>Phase: {card.shortRead.playbookPhase}</span>
                </>
              )}
              {card.shortRead.playbookCitation && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-slate-500">{card.shortRead.playbookCitation}</span>
                </>
              )}
            </div>
          </div>

          <p className="text-sm leading-relaxed text-slate-800">{card.shortRead.summary}</p>

          {/* Affected Scope Line */}
          <div className="grid grid-cols-1 gap-3 rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs sm:grid-cols-3">
            <div>
              <div className="font-semibold text-slate-900">Affected Hosts</div>
              <div className="mt-1 font-mono text-slate-700">
                {card.shortRead.affectedHosts.join(', ') || 'Not established in logs'}
              </div>
            </div>
            <div>
              <div className="font-semibold text-slate-900">Affected Accounts</div>
              <div className="mt-1 font-mono text-slate-700">
                {card.shortRead.affectedAccounts.join(', ') || 'Not established in logs'}
              </div>
            </div>
            <div>
              <div className="font-semibold text-slate-900">Privilege Levels Observed</div>
              <div className="mt-1 text-slate-700">
                {card.shortRead.privilegeLevelsObserved.join(', ') || 'Unknown / Not shown in logs'}
              </div>
            </div>
          </div>

          {/* Table 1 Tactics Mapping */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-900">
              Playbook Table 1 Tactic Mapping (p. 12)
            </h4>
            {card.shortRead.observedTactics.length > 0 ? (
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200 bg-slate-50 text-slate-700">
                    <tr>
                      <th className="px-3.5 py-2 font-semibold">Table 1 Tactic</th>
                      <th className="px-3.5 py-2 font-semibold">Observed Techniques</th>
                      <th className="px-3.5 py-2 font-semibold">Log Sources</th>
                      <th className="px-3.5 py-2 font-semibold">Evidence Indicators</th>
                      <th className="px-3.5 py-2 font-semibold">Playbook Citation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {card.shortRead.observedTactics.map((t, i) => (
                      <tr key={`${t.tactic}-${i}`} className="align-top">
                        <td className="px-3.5 py-2.5 font-semibold text-slate-950 whitespace-nowrap">
                          {t.tactic} ({t.mitreTacticId})
                        </td>
                        <td className="px-3.5 py-2.5 text-slate-700">{t.techniquesObserved}</td>
                        <td className="px-3.5 py-2.5 text-slate-600">
                          {t.logSourcesUsed.join(', ')}
                        </td>
                        <td className="px-3.5 py-2.5 font-mono text-[11px] text-slate-700">
                          {t.evidenceIndicators.join(' · ')}
                        </td>
                        <td className="px-3.5 py-2.5 text-[11px] text-slate-500 whitespace-nowrap">
                          {t.playbookCitation || 'Playbook Table 1, p. 12'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-xs text-slate-600">
                No Table 1 adversarial tactics (Initial Access, Execution, Persistence, Lateral Movement, Credential Access, C2, Exfiltration — Playbook p. 12) were definitively matched in these log entries.
              </p>
            )}
          </div>

          {/* Known vs Unknown */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-slate-200 p-4">
              <h4 className="text-xs font-semibold text-slate-900">What Is Known From Logs</h4>
              <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-700">
                {card.shortRead.knownFacts.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>
            <div className="rounded-lg border border-slate-200 p-4">
              <h4 className="text-xs font-semibold text-slate-900">What Remains Unknown</h4>
              <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-700">
                {card.shortRead.unknownFacts.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Collapsible Cluster Logs */}
          {card.clusterLogs.length > 0 && (
            <div className="rounded-lg border border-slate-200">
              <button
                type="button"
                onClick={() => setLogsExpanded((prev) => !prev)}
                className="flex w-full items-center justify-between px-4 py-2.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 cursor-pointer"
              >
                <span className="tabular-nums">
                  Clustered Log Entries ({card.clusterLogs.length.toLocaleString()})
                </span>
                {logsExpanded ? (
                  <ChevronDown className="h-4 w-4 text-slate-500" aria-hidden="true" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-slate-500" aria-hidden="true" />
                )}
              </button>
              {logsExpanded && (
                <div className="border-t border-slate-200 bg-slate-50 p-3 space-y-1.5 max-h-72 overflow-y-auto">
                  {card.clusterLogs.map((log, i) => (
                    <div
                      key={i}
                      className="rounded border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] text-slate-800"
                    >
                      <div className="text-slate-500 tabular-nums">
                        {log.lineNumber ? `L${log.lineNumber} · ` : ''}
                        {log.timestamp || 'No timestamp'} · {log.source || 'Log entry'}
                      </div>
                      <div className="mt-0.5 break-all">{log.excerpt}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>

        {/* SECTION 3: Warning Signs in Plain Language */}
        <section className="p-6 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="font-display text-base font-bold text-slate-950">
              3. Warning Signs in Plain Language
            </h3>
            <span className="text-xs text-slate-500">
              {card.warningSigns.playbookCitation ||
                'Indicator Translation, Blind Spots & Key Questions (Playbook pp. 12–13)'}
            </span>
          </div>

          {card.warningSigns.indicators.length > 0 && (
            <div className="space-y-2.5">
              {card.warningSigns.indicators.map((ind, i) => (
                <div
                  key={i}
                  className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <code className="font-mono text-xs font-semibold text-slate-950">
                      {ind.technicalIndicator}
                    </code>
                    {ind.isLivingOffTheLand && (
                      <span className="text-xs font-semibold text-amber-800">
                        Living off the Land (Native Utility / Script)
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-800 leading-relaxed">
                    <strong>What looks suspicious:</strong> {ind.plainEnglishExplanation}
                  </p>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    <strong>Why it matters:</strong> {ind.whyItMatters}
                  </p>
                </div>
              ))}
            </div>
          )}

          {card.warningSigns.missingLogSources.length > 0 && (
            <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-4 text-xs text-amber-950">
              <div className="font-semibold">
                Missing Log Sources &amp; Visibility Blind Spots (Playbook Table 1, p. 12)
              </div>
              <p className="mt-1 leading-relaxed">
                To answer remaining Key Questions, pull telemetry from:{' '}
                <span className="font-medium">
                  {card.warningSigns.missingLogSources.join(' · ')}
                </span>
              </p>
            </div>
          )}

          {card.warningSigns.keyQuestions.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-900">
                Playbook Key Questions to Answer (pp. 12–13)
              </h4>
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200 bg-slate-50 text-slate-700">
                    <tr>
                      <th className="px-3.5 py-2 font-semibold">Key Question</th>
                      <th className="px-3.5 py-2 font-semibold">Status</th>
                      <th className="px-3.5 py-2 font-semibold">Current Finding / Needed Logs</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {card.warningSigns.keyQuestions.map((kq, i) => (
                      <tr key={i} className="align-top">
                        <td className="px-3.5 py-2.5 font-medium text-slate-900">
                          {kq.question}
                        </td>
                        <td className="px-3.5 py-2.5 font-semibold whitespace-nowrap">
                          <span
                            className={
                              kq.status === 'Answered'
                                ? 'text-emerald-800'
                                : kq.status === 'Partially Answered'
                                  ? 'text-amber-800'
                                  : 'text-red-800'
                            }
                          >
                            {kq.status}
                          </span>
                        </td>
                        <td className="px-3.5 py-2.5 text-slate-700">
                          <div>{kq.finding}</div>
                          {kq.neededLogSources.length > 0 && (
                            <div className="mt-0.5 text-[11px] text-slate-500">
                              Check: {kq.neededLogSources.join(', ')}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>

        {/* SECTION 4: What to Do Next (Analyst-First + Mandatory Guardrails) */}
        <section className="p-6 space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="font-display text-base font-bold text-slate-950">
              4. What to Do Next (Analyst-First &amp; Mandatory Guardrails)
            </h3>
            <span className="text-xs text-slate-500">
              CISA IR Playbook Phases &amp; Checklists ({card.nextSteps.checklistCitations.join(' · ')})
            </span>
          </div>

          {/* Mandatory "Before You Act" Guardrails */}
          {isProminentGuardrail ? (
            <div className="rounded-xl border-2 border-red-700 bg-red-50 p-5 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-bold text-red-950">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-red-700" aria-hidden="true" />
                  Before You Act — Mandatory Playbook OPSEC &amp; Evidence Guardrails
                </div>
                <span className="text-[11px] font-medium text-red-900">
                  {card.nextSteps.guardrailsCitation}
                </span>
              </div>
              <ol className="list-decimal space-y-1.5 pl-5 text-xs font-medium text-red-950 leading-relaxed">
                {card.nextSteps.guardrails.map((g, i) => (
                  <li key={i}>{g}</li>
                ))}
              </ol>
            </div>
          ) : (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 text-xs text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-2 font-semibold text-slate-900">
                <span>Reminder — Standard Playbook Guardrails</span>
                <span className="text-[11px] font-normal text-slate-500">
                  {card.nextSteps.guardrailsCitation}
                </span>
              </div>
              <ul className="mt-1 list-disc space-y-1 pl-4">
                {card.nextSteps.guardrails.map((g, i) => (
                  <li key={i}>{g}</li>
                ))}
              </ul>
            </div>
          )}

          {card.nextSteps.ictContractorApplicable && card.nextSteps.ictContractorNote && (
            <div className="rounded-lg border border-slate-300 bg-slate-50 p-4 text-xs text-slate-800">
              <strong className="text-slate-950">ICT Service Provider / Contractor Duty:</strong>{' '}
              {card.nextSteps.ictContractorNote}
            </div>
          )}

          {/* Part A: SOC Analyst's Immediate Steps First */}
          <div className="space-y-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h4 className="font-display text-sm font-bold text-slate-950">
                Part A — SOC Analyst Immediate Steps
              </h4>
              <span className="text-[11px] text-slate-500">
                {card.nextSteps.checklistCitations.join(' · ')}
              </span>
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-slate-200 p-4 space-y-1.5">
                <div className="text-xs font-semibold text-slate-900">
                  A1. Deconflict Authorized Activity (Playbook p. 10)
                </div>
                <ul className="list-disc space-y-1 pl-4 text-xs text-slate-700">
                  {card.nextSteps.analystImmediateSteps.deconfliction.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>

              <div className="rounded-lg border border-slate-200 p-4 space-y-1.5">
                <div className="text-xs font-semibold text-slate-900">
                  A2. Preserve Logs &amp; Forensic Evidence (Playbook p. 10 Step 3a–3b, p. 36)
                </div>
                <ul className="list-disc space-y-1 pl-4 text-xs text-slate-700">
                  {card.nextSteps.analystImmediateSteps.evidencePreservation.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>

              <div className="rounded-lg border border-slate-200 p-4 space-y-1.5">
                <div className="text-xs font-semibold text-slate-900">
                  A3. Investigate Remaining Key Questions &amp; Vulnerabilities (Playbook pp. 12–13, 23)
                </div>
                <ul className="list-disc space-y-1 pl-4 text-xs text-slate-700">
                  {card.nextSteps.analystImmediateSteps.keyQuestionInvestigation.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>

              <div className="rounded-lg border border-slate-200 p-4 space-y-1.5">
                <div className="text-xs font-semibold text-slate-900">
                  A4. Safe Short-Term Containment Within SOC Scope (Playbook p. 14 Step 7, pp. 37–38)
                </div>
                <ul className="list-disc space-y-1 pl-4 text-xs text-slate-700">
                  {card.nextSteps.analystImmediateSteps.safeContainmentOptions.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Part B: Explicit Role Handoffs */}
          <div className="space-y-3">
            <h4 className="font-display text-sm font-bold text-slate-950">
              Part B — Explicit Role Handoffs (Escalate Outside First-Line SOC)
            </h4>
            <div className="space-y-3">
              {card.nextSteps.roleHandoffs.map((handoff, i) => (
                <div
                  key={i}
                  className="rounded-lg border border-slate-300 bg-slate-50 p-4 space-y-2"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <div className="text-xs font-bold text-slate-950">
                      Escalate to {handoff.role}
                    </div>
                    <div className="text-xs font-semibold text-red-800">
                      {handoff.urgencyOrDeadline}
                    </div>
                  </div>
                  <ul className="list-disc space-y-1 pl-4 text-xs text-slate-800 leading-relaxed">
                    {handoff.actions.map((act, aIdx) => (
                      <li key={aIdx}>{act}</li>
                    ))}
                  </ul>
                  <div className="text-[11px] text-slate-500">
                    Authority: {handoff.playbookCitation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </article>
  );
};

export const ScorecardView: React.FC<ScorecardViewProps> = ({
  result,
  onAdjustContext,
  onBackToLogs,
}) => {
  const [copied, setCopied] = useState(false);
  const [benignSearch, setBenignSearch] = useState('');
  const [benignPage, setBenignPage] = useState(1);
  const benignPageSize = 50;

  const filteredBenign = result.likelyBenign.filter((entry) => {
    if (!benignSearch.trim()) return true;
    const q = benignSearch.toLowerCase();
    return (
      entry.excerpt.toLowerCase().includes(q) ||
      entry.reason.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q) ||
      entry.timestamp.toLowerCase().includes(q)
    );
  });
  const totalBenignPages = Math.max(1, Math.ceil(filteredBenign.length / benignPageSize));
  const safeBenignPage = Math.min(benignPage, totalBenignPages);
  const visibleBenign = filteredBenign.slice(
    (safeBenignPage - 1) * benignPageSize,
    safeBenignPage * benignPageSize
  );

  const handleCopyBrief = async () => {
    const brief = formatTriageBrief(result);
    try {
      await navigator.clipboard.writeText(brief);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  };

  const clusteredFallback = result.scorecards.reduce(
    (sum, c) => sum + (c.clusterLogs?.length || 0),
    0
  );
  const counts = result.triageCounts ?? {
    totalLinesParsed: clusteredFallback + result.likelyBenign.length,
    evaluatedCount: clusteredFallback + result.likelyBenign.length,
    clusteredCount: clusteredFallback,
    benignCount: result.likelyBenign.length,
    clusterCount: result.scorecards.length,
  };
  const docs = result.documentsStatus ?? {
    playbookLoaded: true,
    ncissLoaded: true,
    fingLoaded: true,
  };

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 space-y-6">
      {/* Header & Action Toolbar */}
      <div className="flex flex-col gap-4 border-b border-slate-200 pb-6 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500">
            Step 3 &amp; 4 · CISA 3-Document Grounded Triage Results
          </p>
          <h1 className="mt-1 font-display text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl">
            Triage Scorecards ({result.scorecards.length}{' '}
            {result.scorecards.length === 1 ? 'Cluster' : 'Clusters'})
          </h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-600">
            <span className="tabular-nums">
              Evaluated {new Date(result.analyzedAtUtc).toUTCString()}
            </span>
            <span aria-hidden="true">·</span>
            <span className={docs.playbookLoaded ? 'font-medium text-emerald-800' : 'text-red-800'}>
              Playbooks (2021): {docs.playbookLoaded ? 'Loaded' : 'Missing'}
            </span>
            <span aria-hidden="true">·</span>
            <span className={docs.ncissLoaded ? 'font-medium text-emerald-800' : 'text-red-800'}>
              CISA-NCISS: {docs.ncissLoaded ? 'Loaded' : 'Missing'}
            </span>
            <span aria-hidden="true">·</span>
            <span className={docs.fingLoaded ? 'font-medium text-emerald-800' : 'text-red-800'}>
              Notification Guidelines: {docs.fingLoaded ? 'Loaded' : 'Missing'}
            </span>
            <span aria-hidden="true">·</span>
            <span>Sorted by highest NCISS severity first</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0 no-print">
          <button
            type="button"
            onClick={onBackToLogs}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 cursor-pointer whitespace-nowrap"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            Edit Logs
          </button>
          <button
            type="button"
            onClick={onAdjustContext}
            className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 cursor-pointer whitespace-nowrap"
          >
            Adjust Context
          </button>
          <button
            type="button"
            onClick={() => void handleCopyBrief()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 cursor-pointer whitespace-nowrap"
          >
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-700" aria-hidden="true" />
                Copied Brief
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                Copy Triage Brief
              </>
            )}
          </button>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-950 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 cursor-pointer whitespace-nowrap"
          >
            <Printer className="h-3.5 w-3.5" aria-hidden="true" />
            Print
          </button>
        </div>
      </div>

      {/* Global Scope & Crossover Gates */}
      {result.globalScopeFlags.nssOrClassifiedDetected && (
        <div
          role="alert"
          className="rounded-xl border-2 border-red-700 bg-red-50 p-5 text-sm text-red-950 space-y-1.5"
        >
          <div className="flex items-center gap-2 font-display font-bold text-base">
            <AlertOctagon className="h-5 w-5 text-red-700 shrink-0" aria-hidden="true" />
            Scope Gate Triggered: National Security Systems (NSS) / Classified Information Detected
          </div>
          <p className="text-xs leading-relaxed">
            {result.globalScopeFlags.nssDetails} Per the CISA Playbook (p. 4 &amp; Appendix A p.
            26), these playbooks do <strong>not</strong> cover threats to classified information or
            NSS as defined by 44 U.S.C. § 3552(b)(6). Direct coordination and reporting strictly
            under <strong>CNSSI 1010</strong>.
          </p>
        </div>
      )}

      {result.globalScopeFlags.vulnerabilityPlaybookTriggered && (
        <div className="rounded-xl border border-orange-300 bg-orange-50 p-5 text-sm text-orange-950 space-y-1.5">
          <div className="flex items-center gap-2 font-display font-bold text-base">
            <ShieldAlert className="h-5 w-5 text-orange-700 shrink-0" aria-hidden="true" />
            Vulnerability Crossover Gate: Active Exploitation Detected (Status: Compromised)
          </div>
          <p className="text-xs leading-relaxed">
            {result.globalScopeFlags.vulnerabilityDetails} Flag affected systems as{' '}
            <strong>Compromised</strong> under the <strong>Vulnerability Response Playbook</strong>{' '}
            (p. 23) and immediately execute the <strong>Incident Response Playbook</strong>{' '}
            alongside patching/mitigation.
          </p>
        </div>
      )}

      {/* Deterministic Line Accounting + Clustering Determination */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <div className="grid grid-cols-2 divide-y divide-slate-200 border-b border-slate-200 bg-slate-50 sm:grid-cols-4 sm:divide-y-0 sm:divide-x">
          <div className="px-5 py-3">
            <div className="text-[11px] font-medium text-slate-500">Total Lines Parsed</div>
            <div className="mt-0.5 font-display text-lg font-bold text-slate-950 tabular-nums">
              {counts.totalLinesParsed.toLocaleString()}
            </div>
          </div>
          <div className="px-5 py-3">
            <div className="text-[11px] font-medium text-slate-500">
              Evaluated (Clusters + Benign)
            </div>
            <div className="mt-0.5 font-display text-lg font-bold text-slate-950 tabular-nums">
              {counts.evaluatedCount.toLocaleString()}
            </div>
          </div>
          <div className="px-5 py-3">
            <div className="text-[11px] font-medium text-slate-500">
              In Incident Clusters ({counts.clusterCount})
            </div>
            <div className="mt-0.5 font-display text-lg font-bold text-slate-950 tabular-nums">
              {counts.clusteredCount.toLocaleString()}
            </div>
          </div>
          <div className="px-5 py-3">
            <div className="text-[11px] font-medium text-slate-500">Likely Benign</div>
            <div className="mt-0.5 font-display text-lg font-bold text-slate-950 tabular-nums">
              {counts.benignCount.toLocaleString()}
            </div>
          </div>
        </div>
        <div className="px-5 py-3.5 text-xs text-slate-700">
          <strong className="text-slate-900">Clustering Determination:</strong>{' '}
          {result.globalScopeFlags.clusteringSummary}
        </div>
      </div>

      {/* Deterministic Code-Computed Telemetry Summary */}
      {result.telemetrySummary && (
        <section
          aria-labelledby="code-telemetry-heading"
          className="rounded-xl border border-slate-200 bg-white overflow-hidden"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-slate-50 px-5 py-3">
            <div>
              <h2
                id="code-telemetry-heading"
                className="font-display text-sm font-bold text-slate-950"
              >
                Code-Computed Telemetry &amp; Pattern Counts (TypeScript Parser)
              </h2>
              <p className="text-xs text-slate-600">
                Every count below is calculated deterministically in server code across all{' '}
                {result.telemetrySummary.totalLinesParsed.toLocaleString()} lines and enforced before
                display ({result.geminiCallsMade ?? 1} analysis call used).
              </p>
            </div>
            <div className="text-xs font-semibold text-slate-900">
              Minimum Floor: {result.telemetrySummary.computedSeverityFloor.floorTier}
            </div>
          </div>

          <div className="grid grid-cols-2 divide-y divide-slate-200 border-b border-slate-200 sm:grid-cols-3 lg:grid-cols-6 sm:divide-y-0 sm:divide-x">
            <div className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">Failed Logins</div>
              <div className="mt-0.5 font-display text-base font-bold text-slate-950 tabular-nums">
                {result.telemetrySummary.failedLogins.toLocaleString()}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">Unique Source IPs</div>
              <div className="mt-0.5 font-display text-base font-bold text-slate-950 tabular-nums">
                {result.telemetrySummary.uniqueSourceIps.toLocaleString()}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">Blocked / Denied</div>
              <div className="mt-0.5 font-display text-base font-bold text-slate-950 tabular-nums">
                {result.telemetrySummary.blockedDeniedConnections.toLocaleString()}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">HTTP 4xx</div>
              <div className="mt-0.5 font-display text-base font-bold text-slate-950 tabular-nums">
                {result.telemetrySummary.http4xxCount.toLocaleString()}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">HTTP 5xx</div>
              <div className="mt-0.5 font-display text-base font-bold text-slate-950 tabular-nums">
                {result.telemetrySummary.http5xxCount.toLocaleString()}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[11px] font-medium text-slate-500">Brute-Force IPs</div>
              <div className="mt-0.5 font-display text-base font-bold text-slate-950 tabular-nums">
                {result.telemetrySummary.suspiciousPatterns.bruteForceIps.length.toLocaleString()}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 divide-y divide-slate-200 text-xs lg:grid-cols-12 lg:divide-y-0 lg:divide-x">
            <div className="lg:col-span-7 p-4 space-y-2.5">
              <div className="font-semibold text-slate-900">
                Suspicious Pattern &amp; Windows Event ID Counts
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-3 text-slate-700 tabular-nums">
                <div>
                  SQL Injection: <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.sqliCount.toLocaleString()}</strong>
                </div>
                <div>
                  Path Traversal: <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.pathTraversalCount.toLocaleString()}</strong>
                </div>
                <div>
                  DNS Tunneling: <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.dnsTunnelingCount.toLocaleString()}</strong>
                </div>
                <div>
                  Port Scans: <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.portScanCount.toLocaleString()}</strong>
                </div>
                <div>
                  Exfiltration: <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.exfiltrationCount.toLocaleString()}</strong>
                </div>
                <div>
                  Win 4625 (Fail Logon): <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.windowsEventIds.event4625.toLocaleString()}</strong>
                </div>
                <div>
                  Win 4720 (New User): <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.windowsEventIds.event4720.toLocaleString()}</strong>
                </div>
                <div>
                  Win 4732 (Group Add): <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.windowsEventIds.event4732.toLocaleString()}</strong>
                </div>
                <div>
                  Win 1102 (Log Clear): <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.windowsEventIds.event1102.toLocaleString()}</strong>
                </div>
                <div>
                  Win 7045 (Svc Install): <strong className="text-slate-950">{result.telemetrySummary.suspiciousPatterns.windowsEventIds.event7045.toLocaleString()}</strong>
                </div>
              </div>
              <div className="border-t border-slate-100 pt-2 text-[11px] text-slate-600">
                <strong className="text-slate-800">Floor Trigger Basis:</strong>{' '}
                {result.telemetrySummary.computedSeverityFloor.reasons.join(' · ')}
              </div>
            </div>

            <div className="lg:col-span-5 p-4 space-y-2">
              <div className="font-semibold text-slate-900">Top Source IPs</div>
              {result.telemetrySummary.topSourceIps.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[11px]">
                    <thead className="border-b border-slate-200 text-slate-500">
                      <tr>
                        <th className="py-1 pr-3 font-semibold">Source IP</th>
                        <th className="py-1 pr-3 font-semibold">Events</th>
                        <th className="py-1 pr-3 font-semibold">Failed Logins</th>
                        <th className="py-1 font-semibold">Post-Fail Success</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 tabular-nums">
                      {result.telemetrySummary.topSourceIps.slice(0, 6).map((ipRow) => (
                        <tr key={ipRow.ip}>
                          <td className="py-1 pr-3 font-mono text-slate-900">{ipRow.ip}</td>
                          <td className="py-1 pr-3 text-slate-700">{ipRow.count.toLocaleString()}</td>
                          <td className="py-1 pr-3 text-slate-700">{ipRow.failedLogins.toLocaleString()}</td>
                          <td className="py-1 font-medium text-slate-800">
                            {ipRow.succeededAfterFailure ? 'Yes' : 'No'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-slate-500">No IPv4 source addresses found in log lines.</p>
              )}
            </div>
          </div>
        </section>
      )}

      {/* Incident Scorecards */}
      {result.scorecards.length > 0 ? (
        <div className="space-y-8">
          {result.scorecards.map((card, idx) => (
            <ClusterScorecard key={card.clusterId || idx} card={card} index={idx} />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white p-6 text-center space-y-2">
          <ShieldCheck className="mx-auto h-7 w-7 text-emerald-700" aria-hidden="true" />
          <h2 className="font-display text-base font-bold text-slate-950">
            No Malicious or Suspicious Activity Clusters Identified (Baseline / Routine Activity)
          </h2>
          <p className="mx-auto max-w-2xl text-xs text-slate-600 leading-relaxed">
            All {counts.totalLinesParsed.toLocaleString()} parsed log lines reflect routine baseline
            activity with no observable cybersecurity incident or NCISS impact above Baseline.
            Every line is accounted for in the &ldquo;Likely Benign&rdquo; audit table below.
          </p>
        </div>
      )}

      {/* Bottom Compact "Likely Benign" List */}
      <section
        aria-labelledby="likely-benign-heading"
        className="rounded-xl border border-slate-200 bg-white overflow-hidden"
      >
        <div className="border-b border-slate-200 bg-slate-50 px-6 py-3.5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2
              id="likely-benign-heading"
              className="font-display text-sm font-bold text-slate-950 tabular-nums"
            >
              Likely Benign Log Entries ({result.likelyBenign.length.toLocaleString()})
            </h2>
            <p className="text-xs text-slate-600">
              Routine activity separated from incident clusters—every entry is accounted for with a
              one-line reason.
            </p>
          </div>
          {result.likelyBenign.length > 0 && (
            <div className="flex items-center gap-2 shrink-0 no-print">
              <input
                type="search"
                value={benignSearch}
                onChange={(e) => {
                  setBenignSearch(e.target.value);
                  setBenignPage(1);
                }}
                placeholder="Filter benign entries..."
                aria-label="Filter likely benign entries"
                className="w-52 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
              />
            </div>
          )}
        </div>

        {result.likelyBenign.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-200 bg-white text-slate-600">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Line</th>
                    <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Timestamp</th>
                    <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Source</th>
                    <th className="px-4 py-2.5 font-semibold">Log Excerpt</th>
                    <th className="px-4 py-2.5 font-semibold">One-Line Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {visibleBenign.map((entry, idx) => (
                    <tr key={entry.lineNumber ?? idx} className="align-top hover:bg-slate-50/70">
                      <td className="px-4 py-2.5 font-mono text-[11px] text-slate-500 whitespace-nowrap tabular-nums">
                        {entry.lineNumber ? `L${entry.lineNumber}` : '—'}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-slate-600 whitespace-nowrap">
                        {entry.timestamp || '—'}
                      </td>
                      <td className="px-4 py-2.5 text-slate-700 whitespace-nowrap">
                        {entry.source || 'Log'}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-slate-800 max-w-md break-all">
                        {entry.excerpt}
                      </td>
                      <td className="px-4 py-2.5 text-slate-700">{entry.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {filteredBenign.length > benignPageSize && (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 bg-slate-50 px-6 py-3 text-xs text-slate-600 no-print">
                <span className="tabular-nums">
                  Showing {((safeBenignPage - 1) * benignPageSize + 1).toLocaleString()}–
                  {Math.min(safeBenignPage * benignPageSize, filteredBenign.length).toLocaleString()}{' '}
                  of {filteredBenign.length.toLocaleString()} entries
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={safeBenignPage <= 1}
                    onClick={() => setBenignPage((p) => Math.max(1, p - 1))}
                    className="rounded-lg border border-slate-300 bg-white px-3 py-1 text-xs font-medium text-slate-800 hover:bg-slate-100 disabled:opacity-40 cursor-pointer"
                  >
                    Previous
                  </button>
                  <span className="tabular-nums">
                    Page {safeBenignPage} of {totalBenignPages}
                  </span>
                  <button
                    type="button"
                    disabled={safeBenignPage >= totalBenignPages}
                    onClick={() => setBenignPage((p) => Math.min(totalBenignPages, p + 1))}
                    className="rounded-lg border border-slate-300 bg-white px-3 py-1 text-xs font-medium text-slate-800 hover:bg-slate-100 disabled:opacity-40 cursor-pointer"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="px-6 py-4 text-xs text-slate-600">
            No entries were classified as routine benign noise; all submitted log entries were
            assigned to the incident cluster scorecard(s) above.
          </div>
        )}
      </section>
    </div>
  );
};
