import { api } from './api'

export interface MergeSecurityFinding {
  title: string
  vulnerability_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  file_path: string
  line_start: number
  line_end: number
  evidence: string
  description: string
  remediation: string
  references: { title: string; url: string }[]
}

export interface MergeAnalysis {
  repository: string
  branch_a: string
  branch_b: string
  comparison_status: string
  ahead_by: number
  behind_by: number
  changed_files: number
  files_analyzed: number
  summary: string
  findings: MergeSecurityFinding[]
  limitations: string[]
}

export const mergeIntelligenceService = {
  async analyze(
    repositoryId: string,
    branchA: string,
    branchB: string,
  ): Promise<MergeAnalysis> {
    const { data } = await api.post<MergeAnalysis>(
      `/repositories/${encodeURIComponent(repositoryId)}/merge-intelligence/analyze`,
      {
        branch_a: branchA,
        branch_b: branchB,
      },
    )
    return data
  },
}