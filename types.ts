// types.ts - Định nghĩa TypeScript cho giao diện AI SOC Command Center

export type SeverityLevel = 'CAO' | 'TRUNG_BINH' | 'THAP';

export interface TimelineEvent {
  time: string;
  description: string;
  highlight?: string;
}

export interface ProposedAction {
  badge: string;
  description: string;
  checks: string[];
  primaryBtnText: string;
  secondaryBtnText: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: SeverityLevel;
  host: string;
  agentId: string;
  sourceIp: string;
  ipLabel?: string;
  targetUser: string;
  time: string;
  ruleId: string;
  alertRef: string;
  mitreId: string;
  mitreTactic: string;
  aiSummary: string;
  timeline: TimelineEvent[];
  rawSyslog: string;
  proposedAction: ProposedAction;
  status: 'OPEN' | 'APPROVED' | 'REVIEWED' | 'RESOLVED';
  blockedRemainingSeconds?: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'CRIT';
  agent: string;
  message: string;
  highlightIp?: string;
}
