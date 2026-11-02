export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type FindingStatus = 'Confirmed' | 'Suspected'
export type ScanStatus = 'Completed' | 'In progress' | 'Failed'

export interface Repository {
  id: string
  name: string
  owner: string
  language: string
  branch: string
  lastScan: string
  findings: number
  status: 'Secure' | 'Needs attention' | 'At risk'
}

export interface Vulnerability {
  id: string
  title: string
  severity: Severity
  repository: string
  file: string
  line: number
  source: string
  validation: FindingStatus
  remediation: 'Open' | 'In progress' | 'Resolved'
  description: string
  impact: string
  evidence: string
  reproduction: string
  explanation: string
  fix: string
  snippet: string
}

export interface SecurityScan {
  id: string
  repository: string
  branch: string
  commit: string
  status: ScanStatus
  startedAt: string
  duration: string
  findings: number
  critical: number
}

export interface ScanConfiguration {
  repository: string
  ref: string
  scope: string[]
  environment: string
  authorizationConfirmed: boolean
}

export interface ScanProgressEvent {
  type: 'progress' | 'activity' | 'finding' | 'complete' | 'error'
  stage?: number
  progress?: number
  message: string
  timestamp?: string
  data?: Record<string, unknown>
}

export interface ScanStartResponse {
  scan_id: string
  status: string
  events_url?: string
}
