import type { FingAttackVector, SeverityLevelCode } from '../types/triage';

export const PLAYBOOK_PDF_URL =
  '/assets/aistudio/CISA_Incident_Vulnerability_Response_Playbooks_ba8ab053.pdf';

export const NCISS_PDF_URL =
  '/assets/aistudio/CISA-NCISS_6cf528af.pdf';

export const FING_PDF_URL =
  '/assets/aistudio/CISA-Federal-Incident-Notification-Guidelines_049a1365.pdf';

export const MANDATORY_GUARDRAILS: string[] = [
  'Notify users of compromised systems via phone rather than email to avoid tipping off the attacker (Playbook pp. 9–10, 36).',
  'Do not submit malware samples to a public analysis service to avoid tipping off the attacker (Playbook pp. 9–10, 36).',
  'Capture memory and disk images and account for all evidence in a detailed log (chain of custody: how, when, and who acquired it) before wiping, re-imaging, or patching (Playbook p. 10 Step 3a–3b, p. 14, p. 36).',
];

export const NCISS_LEVEL_DEFINITIONS: Record<
  SeverityLevelCode,
  {
    levelName:
      | 'Emergency'
      | 'Critical'
      | 'High'
      | 'Medium'
      | 'Low'
      | 'Baseline – Minor'
      | 'Baseline – Negligible'
      | 'Unscorable';
    colorName: 'Black' | 'Red' | 'Orange' | 'Yellow' | 'Green' | 'Blue' | 'White' | 'Gray';
    definition: string;
    citation: string;
  }
> = {
  EMERGENCY_BLACK: {
    levelName: 'Emergency',
    colorName: 'Black',
    definition:
      'An Emergency priority incident poses an imminent threat to the provision of wide-scale critical infrastructure services, national government stability, or the lives of U.S. persons.',
    citation: 'CISA NCISS, Priority Levels — Emergency (Black), p. 4',
  },
  SEVERE_RED: {
    levelName: 'Critical',
    colorName: 'Red',
    definition:
      'A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties.',
    citation: 'CISA NCISS, Priority Levels — Severe (Red), p. 5',
  },
  HIGH_ORANGE: {
    levelName: 'High',
    colorName: 'Orange',
    definition:
      'A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels — High (Orange), p. 5',
  },
  MEDIUM_YELLOW: {
    levelName: 'Medium',
    colorName: 'Yellow',
    definition:
      'A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels — Medium (Yellow), p. 5',
  },
  LOW_GREEN: {
    levelName: 'Low',
    colorName: 'Green',
    definition:
      'A Low priority incident is unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels — Low (Green), p. 5',
  },
  BASELINE_MINOR_BLUE: {
    levelName: 'Baseline – Minor',
    colorName: 'Blue',
    definition:
      'A Baseline–Minor priority incident is an incident that is highly unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. The potential for impact, however, exists and warrants additional scrutiny.',
    citation: 'CISA NCISS, Priority Levels — Baseline – Minor (Blue), pp. 5–6',
  },
  BASELINE_NEGLIGIBLE_WHITE: {
    levelName: 'Baseline – Negligible',
    colorName: 'White',
    definition:
      'A Baseline–Negligible priority incident is an incident that is highly unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.',
    citation: 'CISA NCISS, Priority Levels — Baseline – Negligible (White), pp. 5–6',
  },
  UNSCORABLE_GRAY: {
    levelName: 'Unscorable',
    colorName: 'Gray',
    definition:
      'Cluster cannot be scored under CISA NCISS Priority Levels because required scoring evidence is absent or indeterminate.',
    citation: 'CISA NCISS, Priority Levels & Formula, pp. 3–6',
  },
};

export const FING_ATTACK_VECTORS: Array<{
  vector: FingAttackVector;
  description: string;
}> = [
  { vector: 'Unknown', description: 'Cause of attack is unidentified.' },
  {
    vector: 'Attrition',
    description:
      'An attack that employs brute force methods to compromise, degrade, or destroy systems, networks, or services.',
  },
  {
    vector: 'Web',
    description: 'An attack executed from a website or web-based application.',
  },
  {
    vector: 'Email/Phishing',
    description: 'An attack executed via an email message or attachment.',
  },
  {
    vector: 'External/Removable Media',
    description: 'An attack executed from removable media or a peripheral device.',
  },
  {
    vector: 'Impersonation/Spoofing',
    description:
      'An attack involving replacement of legitimate content/services with a malicious substitute.',
  },
  {
    vector: 'Improper Usage',
    description:
      'Any incident resulting from violation of an organization’s acceptable usage policies by an authorized user, excluding the above categories.',
  },
  {
    vector: 'Loss or Theft of Equipment',
    description: 'The loss or theft of a computing device or media used by the organization.',
  },
  {
    vector: 'Other',
    description: 'An attack method does not fit into any other vector.',
  },
];

export const PLAYBOOK_KEY_QUESTIONS: string[] = [
  'What was the initial attack vector? (How did the adversary gain initial access to the network?)',
  'How is the adversary accessing the environment?',
  'Is the adversary exploiting vulnerabilities to achieve access or privilege?',
  'How is the adversary maintaining command and control?',
  'Does the actor have persistence on the network or device, and what is the method?',
  'What accounts have been compromised and what privilege level (domain admin, local admin, user account, etc.)?',
  'What method is being used for reconnaissance?',
  'Is lateral movement suspected or known, and how is it conducted (RDP, network shares, malware, etc.)?',
  'Has data been exfiltrated and, if so, what kind and via what mechanism?',
];

export interface Table1Row {
  tactic: string;
  mitreId: string;
  commonTechniques: string;
  logSources: string;
  indicators: string;
}

export const PLAYBOOK_TABLE_1: Table1Row[] = [
  {
    tactic: 'Initial Access',
    mitreId: 'TA0001',
    commonTechniques:
      'Phishing [T1566], Drive-by Compromise [T1189], Exploit Public Facing Application [T1190], External Remote Services [T1133]',
    logSources: 'Email, web proxy, server application logs, IDS/IPS',
    indicators:
      'Phishing, redirect, and payload servers (domains and IP addresses), delivery mechanisms (lures, macros, downloaders, droppers, etc.), compromised credentials, web shells',
  },
  {
    tactic: 'Execution',
    mitreId: 'TA0002',
    commonTechniques:
      'Command and Script Interpreters [T1059], Exploitation for Client Execution [T1203]',
    logSources:
      'Host event logs, Windows event logs, Sysmon, anti-malware, EDR, PowerShell logs',
    indicators:
      'Invocation of command or scripting interpreter, exploitation, API calls, tools, malware, payloads',
  },
  {
    tactic: 'Persistence',
    mitreId: 'TA0003',
    commonTechniques:
      'Account Manipulation [T1098], Scheduled Task/Job [T1053], Valid Accounts [T1078]',
    logSources: 'Host event logs, Authentication logs, Registry',
    indicators: 'Scheduled Tasks, registry keys, autoruns, etc.',
  },
  {
    tactic: 'Lateral Movement',
    mitreId: 'TA0008',
    commonTechniques:
      'Exploitation of Remote Services [T1210], Remote Session Hijacking [T1563], Software Deployment Tools [T1072]',
    logSources: 'Internal network logs, host event logs, Application Logs',
    indicators:
      'Mismatch of users and applications/credentials, workstation to workstation communication, beaconing from hosts not intended to be internet accessible, etc.',
  },
  {
    tactic: 'Credential Access',
    mitreId: 'TA0006',
    commonTechniques:
      'Brute Force [T1110], Modify Authentication Process [T1556], Man-in-the-Middle [T1557]',
    logSources:
      'Authentication Logs, Domain Controller Logs, network traffic monitoring',
    indicators: 'LSASS reads, command or scripting interpreters accessing LSASS, etc.',
  },
  {
    tactic: 'C2',
    mitreId: 'TA0011',
    commonTechniques:
      'Application Layer Protocol [T1071], Protocol Tunneling [T1572]',
    logSources:
      'Firewall, Web Proxy, DNS, Network Traffic, Cloud activity logs, IDS/IPS',
    indicators: 'C2 domains, IP addresses',
  },
  {
    tactic: 'Exfiltration',
    mitreId: 'TA0010',
    commonTechniques:
      'Exfiltration Over C2 Channel [T1041], Exfiltration Over Alternative Protocol [T1048]',
    logSources:
      'Firewall, Web Proxy, DNS, Network Traffic, Cloud activity logs, IDS/IPS',
    indicators: 'Domains, URLs, IP addresses, IDS/IPS signatures',
  },
];

export const SEVERITY_STYLES: Record<
  SeverityLevelCode,
  {
    badgeBg: string;
    badgeText: string;
    badgeBorder: string;
    headerBg: string;
    headerText: string;
    surfaceTint: string;
    swatchColor: string;
  }
> = {
  EMERGENCY_BLACK: {
    badgeBg: 'bg-neutral-950',
    badgeText: 'text-white',
    badgeBorder: 'border-neutral-950',
    headerBg: 'bg-neutral-950',
    headerText: 'text-white',
    surfaceTint: 'bg-neutral-50',
    swatchColor: '#0A0A0A',
  },
  SEVERE_RED: {
    badgeBg: 'bg-red-700',
    badgeText: 'text-white',
    badgeBorder: 'border-red-700',
    headerBg: 'bg-red-700',
    headerText: 'text-white',
    surfaceTint: 'bg-red-50/60',
    swatchColor: '#B91C1C',
  },
  HIGH_ORANGE: {
    badgeBg: 'bg-orange-600',
    badgeText: 'text-white',
    badgeBorder: 'border-orange-600',
    headerBg: 'bg-orange-600',
    headerText: 'text-white',
    surfaceTint: 'bg-orange-50/60',
    swatchColor: '#EA580C',
  },
  MEDIUM_YELLOW: {
    badgeBg: 'bg-yellow-400',
    badgeText: 'text-yellow-950',
    badgeBorder: 'border-yellow-500',
    headerBg: 'bg-yellow-300',
    headerText: 'text-yellow-950',
    surfaceTint: 'bg-yellow-50/60',
    swatchColor: '#FACC15',
  },
  LOW_GREEN: {
    badgeBg: 'bg-emerald-700',
    badgeText: 'text-white',
    badgeBorder: 'border-emerald-700',
    headerBg: 'bg-emerald-700',
    headerText: 'text-white',
    surfaceTint: 'bg-emerald-50/50',
    swatchColor: '#15803D',
  },
  BASELINE_MINOR_BLUE: {
    badgeBg: 'bg-blue-700',
    badgeText: 'text-white',
    badgeBorder: 'border-blue-700',
    headerBg: 'bg-blue-700',
    headerText: 'text-white',
    surfaceTint: 'bg-blue-50/50',
    swatchColor: '#1D4ED8',
  },
  BASELINE_NEGLIGIBLE_WHITE: {
    badgeBg: 'bg-white',
    badgeText: 'text-slate-900',
    badgeBorder: 'border-slate-300',
    headerBg: 'bg-slate-100',
    headerText: 'text-slate-950',
    surfaceTint: 'bg-white',
    swatchColor: '#FFFFFF',
  },
  UNSCORABLE_GRAY: {
    badgeBg: 'bg-slate-600',
    badgeText: 'text-white',
    badgeBorder: 'border-slate-600',
    headerBg: 'bg-slate-700',
    headerText: 'text-white',
    surfaceTint: 'bg-slate-50',
    swatchColor: '#475569',
  },
};
