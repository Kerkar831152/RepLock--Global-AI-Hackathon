import { api } from './api'

export interface SecurityReportFinding {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  vulnerability_type: string
  status: string
  file_path: string | null
  line_number: number | null
  evidence: string | null
  remediation: string | null
}

export interface SecurityReport {
  repository: {
    id: string
    name: string
    full_name: string
    description: string | null
    default_branch: string
    is_private: boolean
  }
  scan: {
    id: string
    status: string
    scan_type: string
    commit_sha: string | null
    pull_request_number: number | null
    changed_files: number | null
    files_analyzed: number | null
    semgrep_findings: number | null
    summary: string | null
    limitations: string[] | null
    started_at: string | null
    completed_at: string | null
    created_at: string
  }
  total_findings: number
  findings_by_severity: Record<string, number>
  findings: SecurityReportFinding[]
}

export const reportService = {
  async getRepositoryReport(
    repositoryId: string,
    scanId: string,
  ): Promise<SecurityReport> {
    const { data } = await api.get<SecurityReport>(
      `/reports/repositories/${encodeURIComponent(repositoryId)}`,
      { params: { scan_id: scanId } },
    )
    return data
  },
}

export function downloadReport(report: SecurityReport) {
  const { scan, repository, findings } = report
  const lines = [
    '# RepLock Security Assessment',
    '',
    `Repository: ${repository.full_name}`,
    `Description: ${repository.description || 'Not provided'}`,
    `Default branch: ${repository.default_branch}`,
    `Visibility: ${repository.is_private ? 'Private' : 'Public'}`,
    `Scan ID: ${scan.id}`,
    `Scan type: ${scan.scan_type}`,
    `Status: ${scan.status}`,
    `Commit: ${scan.commit_sha || 'Not recorded'}`,
    `Pull request: ${scan.pull_request_number ?? 'Not applicable'}`,
    `Changed files: ${scan.changed_files ?? 'Not recorded'}`,
    `Files analyzed: ${scan.files_analyzed ?? 'Not recorded'}`,
    `Semgrep findings: ${scan.semgrep_findings ?? 'Not recorded'}`,
    `Created: ${new Date(scan.created_at).toLocaleString()}`,
    `Completed: ${scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'Not recorded'}`,
    `Summary: ${scan.summary || 'Not recorded'}`,
    `Scan limitations: ${
      scan.limitations == null
        ? 'Not recorded'
        : scan.limitations.length
          ? scan.limitations.join('; ')
          : 'None reported'
    }`,
    '',
    '## Summary',
    `Total findings: ${report.total_findings}`,
    ...['critical', 'high', 'medium', 'low', 'info'].map(
      (severity) =>
        `${severity[0].toUpperCase()}${severity.slice(1)}: ${report.findings_by_severity[severity] ?? 0}`,
    ),
    '',
    '## Findings',
    ...findings.flatMap((finding, index) => [
      `### ${index + 1}. ${finding.title}`,
      `- Severity: ${finding.severity}`,
      `- Status: ${finding.status}`,
      `- Type: ${finding.vulnerability_type}`,
      `- Location: ${finding.file_path || 'Not specified'}${finding.line_number ? `:${finding.line_number}` : ''}`,
      `- Description: ${finding.description || 'Not provided'}`,
      `- Evidence: ${finding.evidence || 'Not provided'}`,
      `- Remediation: ${finding.remediation || 'Not provided'}`,
      '',
    ]),
  ]

  const blob = new Blob([lines.join('\n')], {
    type: 'text/markdown;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  const repositoryName = repository.full_name.replace(/[^a-z0-9-_]/gi, '-')

  link.href = url
  link.download = `replock-${repositoryName}-${scan.id.slice(0, 8)}.md`
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 0)
}
