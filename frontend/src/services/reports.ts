import type { ScanRecord, ScanFinding } from './scans'

export interface ReportData {
  scan: ScanRecord
  repositoryName: string
  findings: ScanFinding[]
}

export function downloadReport(report: ReportData) {
  const { scan, repositoryName, findings } = report

  const count = (severity: string) =>
    findings.filter((finding) => finding.severity === severity).length

  const lines = [
    '# RepLock Security Assessment',
    '',
    `Repository: ${repositoryName}`,
    `Scan ID: ${scan.id}`,
    `Scan type: ${scan.scan_type}`,
    `Status: ${scan.status}`,
    `Commit: ${scan.commit_sha || 'Not recorded'}`,
    `Created: ${new Date(scan.created_at).toLocaleString()}`,
    `Summary: ${scan.summary || 'Not recorded'}`,
    '',
    '## Summary',
    `Total findings: ${findings.length}`,
    `Critical: ${count('critical')}`,
    `High: ${count('high')}`,
    `Medium: ${count('medium')}`,
    `Low: ${count('low')}`,
    `Info: ${count('info')}`,
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

  link.href = url
  link.download = `replock-${repositoryName.replace(/[^a-z0-9-_]/gi, '-')}-${scan.id.slice(0, 8)}.md`

  document.body.appendChild(link)
  link.click()
  link.remove()

  window.setTimeout(() => URL.revokeObjectURL(url), 0)
}