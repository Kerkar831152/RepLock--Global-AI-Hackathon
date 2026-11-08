import { api } from './api'

export interface DashboardScan {
  scan_id: string
  repository_id: string
  repository_name: string
  status: string
  scan_type: string
  commit_sha: string | null
  created_at: string
  completed_at: string | null
  findings_count: number
}

export interface DashboardOverview {
  total_repositories: number
  total_scans: number
  scan_status_counts: Record<string, number>
  total_findings: number
  findings_by_severity: Record<string, number>
  findings_by_status: Record<string, number>
  security_score: number
  risk_level: 'low' | 'moderate' | 'high' | 'critical'
  risk_points: number
  latest_scan: DashboardScan | null
  recent_scans: DashboardScan[]
  most_affected_files: {
    file_path: string
    finding_count: number
    repository_count: number
  }[]
}

export const dashboardService = {
  async overview(): Promise<DashboardOverview> {
    const { data } = await api.get<DashboardOverview>(
      '/dashboard/overview',
    )
    return data
  },
}