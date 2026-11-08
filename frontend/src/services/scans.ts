import { api } from './api'

export interface ScanRecord {
  id: string
  repository_id: string
  commit_sha: string | null
  status: string
  scan_type: string
  summary: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface ScanFinding {
  id: string
  scan_id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  vulnerability_type: string
  file_path: string | null
  line_number: number | null
  evidence: string | null
  remediation: string | null
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive'
  created_at: string
}

export interface ScanRunResult {
  scan: ScanRecord
  findings: ScanFinding[]
  semgrep_findings: number
  files_analyzed: number
  limitations: string[]
}

export const scanService = {
  async run(
    repositoryId: string,
    scanType: 'full' | 'static' = 'full',
  ): Promise<ScanRunResult> {
    const { data } = await api.post<ScanRunResult>('/scans/run', {
      repository_id: repositoryId,
      scan_type: scanType,
    })
    return data
  },

  async list(): Promise<ScanRecord[]> {
    const { data } = await api.get<ScanRecord[]>('/scans/')
    return data
  },
}