export type MissionCriticalAnswer = 'yes' | 'no' | 'unknown';

export type PiiExposureAnswer =
  | 'yes_100k_plus'
  | 'yes_under_100k'
  | 'yes_unknown_volume'
  | 'no'
  | 'unknown';

export type AuthorizedActivityAnswer = 'unauthorized' | 'authorized' | 'unknown';

export type IctContractorAnswer = 'yes' | 'no' | 'unknown';

export interface MissionContextInput {
  missionCritical: MissionCriticalAnswer;
  piiExposure: PiiExposureAnswer;
  authorizedActivity: AuthorizedActivityAnswer;
  ictContractor: IctContractorAnswer;
  skippedAll: boolean;
}

export interface LogInspectionResult {
  detectedFormats: string[];
  entryCountEstimate: number;
  totalLinesParsed: number;
  inspectedLineCount: number;
  clearContextFromLogs: {
    missionCritical: {
      detected: boolean;
      suggestedValue: MissionCriticalAnswer;
      evidence: string;
    };
    piiExposure: {
      detected: boolean;
      suggestedValue: PiiExposureAnswer;
      evidence: string;
    };
    authorizedActivity: {
      detected: boolean;
      suggestedValue: AuthorizedActivityAnswer;
      evidence: string;
    };
    ictContractor: {
      detected: boolean;
      suggestedValue: IctContractorAnswer;
      evidence: string;
    };
  };
  nssOrClassifiedDetected: boolean;
  nssEvidence: string;
  needsAnalystContextPrompt: boolean;
  inspectionSummary: string;
}

export type SeverityLevelCode =
  | 'EMERGENCY_BLACK'
  | 'SEVERE_RED'
  | 'HIGH_ORANGE'
  | 'MEDIUM_YELLOW'
  | 'LOW_GREEN'
  | 'BASELINE_MINOR_BLUE'
  | 'BASELINE_NEGLIGIBLE_WHITE'
  | 'UNSCORABLE_GRAY';

export type SeverityFloorTier =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Baseline'
  | 'Informational/Low';

export interface SeverityFloorInfo {
  floorTier: SeverityFloorTier;
  floorLevelCode: SeverityLevelCode;
  enforced: boolean;
  reasons: string[];
}

export interface SourceIpSummary {
  ip: string;
  count: number;
  failedLogins: number;
  succeededAfterFailure: boolean;
}

export interface BruteForceIpDetail {
  ip: string;
  failedCount: number;
  followedBySuccess: boolean;
}

export interface DeterministicTelemetrySummary {
  totalLinesParsed: number;
  totalEvents: number;
  failedLogins: number;
  successfulLogins: number;
  uniqueSourceIps: number;
  topSourceIps: SourceIpSummary[];
  blockedDeniedConnections: number;
  http4xxCount: number;
  http5xxCount: number;
  suspiciousPatterns: {
    sqliCount: number;
    pathTraversalCount: number;
    bruteForceIps: BruteForceIpDetail[];
    dnsTunnelingCount: number;
    portScanCount: number;
    exfiltrationCount: number;
    windowsEventIds: {
      event4625: number;
      event4720: number;
      event4732: number;
      event1102: number;
      event7045: number;
      event4624: number;
    };
  };
  computedSeverityFloor: {
    floorTier: SeverityFloorTier;
    floorLevelCode: SeverityLevelCode;
    reasons: string[];
  };
}

export type ContextProvenance =
  | 'Confirmed (Analyst)'
  | 'Confirmed (Observed in Logs)'
  | 'Assumed (Conservative Default — Missing Context)';

export interface ContextItemBreakdown {
  dimension:
    | 'Mission-Critical System'
    | 'Sensitive Data / PII (100,000+ Threshold)'
    | 'Authorized Activity Deconfliction';
  valueLabel: string;
  provenance: ContextProvenance;
  note: string;
}

export type PlaybookClassification =
  | 'Observable Event'
  | 'Confirmed Incident'
  | 'Breach'
  | 'Major Incident'
  | 'Major Incident Not Yet Ruled Out'
  | 'Exploited Vulnerability';

export type Table1TacticName =
  | 'Initial Access'
  | 'Execution'
  | 'Persistence'
  | 'Lateral Movement'
  | 'Credential Access'
  | 'C2'
  | 'Exfiltration';

export interface ObservedTactic {
  tactic: Table1TacticName;
  mitreTacticId: string;
  techniquesObserved: string;
  logSourcesUsed: string[];
  evidenceIndicators: string[];
  playbookCitation: string;
}

export interface KeyQuestionStatus {
  question: string;
  status: 'Answered' | 'Partially Answered' | 'Unanswered (Blind Spot)';
  finding: string;
  neededLogSources: string[];
}

export interface PlainLanguageWarningSign {
  technicalIndicator: string;
  isLivingOffTheLand: boolean;
  plainEnglishExplanation: string;
  whyItMatters: string;
}

export interface RoleHandoff {
  role: string;
  urgencyOrDeadline: string;
  actions: string[];
  playbookCitation: string;
}

export interface ClusterLogEntry {
  lineNumber?: number;
  timestamp: string;
  source: string;
  excerpt: string;
}

export type FingAttackVector =
  | 'Unknown'
  | 'Attrition'
  | 'Web'
  | 'Email/Phishing'
  | 'External/Removable Media'
  | 'Impersonation/Spoofing'
  | 'Improper Usage'
  | 'Loss or Theft of Equipment'
  | 'Other';

export interface FingNotificationAssessment {
  attackVectorCategory: FingAttackVector;
  attackVectorRationale: string;
  attackVectorCitation: string;
  functionalImpactCategory: string;
  functionalImpactRationale: string;
  informationImpactCategories: string[];
  informationImpactRationale: string;
  recoverabilityCategory: string;
  recoverabilityRationale: string;
  impactCitation: string;
  reportingTimeline: string;
  reportingChannelsAndRequiredData: string;
  reportingCitation: string;
}

export interface IncidentScorecard {
  clusterId: string;
  clusterTitle: string;
  connectionCertainty: 'unified' | 'uncertain_connection' | 'distinct';
  connectionNote: string;
  clusteringBasis: {
    hosts: string[];
    users: string[];
    ips: string[];
    timeframe: string;
  };
  nssOutOfScope: boolean;
  nssGuidance: string;
  vulnerabilityCrossover: {
    triggered: boolean;
    status: 'Compromised' | 'Susceptible' | 'Not Applicable';
    cveOrVulnerability: string;
    explanation: string;
    playbookCitation: string;
  };
  severity: {
    levelCode: SeverityLevelCode;
    ncissLevelName:
      | 'Emergency'
      | 'Critical'
      | 'High'
      | 'Medium'
      | 'Low'
      | 'Baseline – Minor'
      | 'Baseline – Negligible'
      | 'Unscorable';
    colorName: 'Black' | 'Red' | 'Orange' | 'Yellow' | 'Green' | 'Blue' | 'White' | 'Gray';
    ncissDefinitionQuote: string;
    ncissJustification: string;
    ncissCitation: string;
    unscorableReason: string | null;
    geminiInitialLevelCode?: SeverityLevelCode;
    severityFloorApplied?: SeverityFloorInfo;
    isProvisional: boolean;
    provisionalLabel: string | null;
    provisionalReason: string | null;
    recommendEscalate: boolean;
  };
  notificationAssessment: FingNotificationAssessment;
  contextSummary: ContextItemBreakdown[];
  shortRead: {
    classification: PlaybookClassification;
    playbookPhase: string;
    playbookCitation: string;
    summary: string;
    observedTactics: ObservedTactic[];
    affectedHosts: string[];
    affectedAccounts: string[];
    privilegeLevelsObserved: string[];
    knownFacts: string[];
    unknownFacts: string[];
  };
  warningSigns: {
    indicators: PlainLanguageWarningSign[];
    missingLogSources: string[];
    keyQuestions: KeyQuestionStatus[];
    playbookCitation: string;
  };
  nextSteps: {
    guardrailProminence: 'prominent' | 'reminder';
    guardrails: string[];
    guardrailsCitation: string;
    analystImmediateSteps: {
      deconfliction: string[];
      evidencePreservation: string[];
      keyQuestionInvestigation: string[];
      safeContainmentOptions: string[];
    };
    checklistCitations: string[];
    roleHandoffs: RoleHandoff[];
    ictContractorApplicable: boolean;
    ictContractorNote: string | null;
  };
  clusterLogs: ClusterLogEntry[];
}

export interface BenignLogEntry {
  lineNumber?: number;
  timestamp: string;
  source: string;
  excerpt: string;
  reason: string;
}

export interface TriageCounts {
  totalLinesParsed: number;
  evaluatedCount: number;
  clusteredCount: number;
  benignCount: number;
  clusterCount: number;
}

export interface ReferenceDocumentsStatus {
  playbookLoaded: boolean;
  ncissLoaded: boolean;
  fingLoaded: boolean;
}

export interface TriageAnalysisResponse {
  analyzedAtUtc: string;
  documentsStatus: ReferenceDocumentsStatus;
  geminiCallsMade: number;
  triageCounts: TriageCounts;
  telemetrySummary: DeterministicTelemetrySummary;
  globalScopeFlags: {
    nssOrClassifiedDetected: boolean;
    nssDetails: string;
    vulnerabilityPlaybookTriggered: boolean;
    vulnerabilityDetails: string;
    clusteringSummary: string;
  };
  scorecards: IncidentScorecard[];
  likelyBenign: BenignLogEntry[];
}
