import { api } from './api'
import axios from 'axios'

export interface ScanRecord {
  id: string
  repository_id: string
  commit_sha: string | null
  changed_files?: number | null
  status: string
  scan_type: string
  summary: string | null
  files_analyzed?: number | null
  semgrep_findings?: number | null
  limitations?: string[] | null
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
  status: 'open' | 'in_progress' | 'resolved' | 'ignored' | 'false_positive'
  created_at: string
}

export interface ScanRunResult {
  scan: ScanRecord
  findings: ScanFinding[]
  semgrep_findings: number | null
  files_analyzed: number | null
  limitations: string[] | null
}

export class ScanResponseError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ScanResponseError'
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isScanRecord(value: unknown): value is ScanRecord {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.repository_id === 'string' &&
    (typeof value.commit_sha === 'string' || value.commit_sha === null) &&
    typeof value.status === 'string' &&
    typeof value.scan_type === 'string' &&
    (typeof value.summary === 'string' || value.summary === null) &&
    typeof value.created_at === 'string'
  )
}

function isScanFinding(value: unknown): value is ScanFinding {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.scan_id === 'string' &&
    typeof value.title === 'string' &&
    typeof value.description === 'string' &&
    ['critical', 'high', 'medium', 'low', 'info'].includes(
      String(value.severity),
    ) &&
    typeof value.vulnerability_type === 'string' &&
    (typeof value.file_path === 'string' || value.file_path === null) &&
    (typeof value.line_number === 'number' || value.line_number === null) &&
    (typeof value.evidence === 'string' || value.evidence === null) &&
    (typeof value.remediation === 'string' || value.remediation === null) &&
    ['open', 'in_progress', 'resolved', 'ignored', 'false_positive'].includes(
      String(value.status),
    ) &&
    typeof value.created_at === 'string'
  )
}

export function parseScanRunResult(value: unknown): ScanRunResult {
  if (!isRecord(value) || !isScanRecord(value.scan)) {
    throw new ScanResponseError(
      'The API returned an invalid scan response. Refresh scan history to verify its status.',
    )
  }

  if (value.scan.status !== 'completed') {
    throw new ScanResponseError(
      `The API returned scan status "${value.scan.status}" instead of completed.`,
    )
  }

  if (!Array.isArray(value.findings) || !value.findings.every(isScanFinding)) {
    throw new ScanResponseError(
      'The API returned an invalid findings list. Refresh scan history to verify the persisted results.',
    )
  }

  if (
    typeof value.semgrep_findings !== 'number' ||
    !Number.isInteger(value.semgrep_findings) ||
    value.semgrep_findings < 0 ||
    typeof value.files_analyzed !== 'number' ||
    !Number.isInteger(value.files_analyzed) ||
    value.files_analyzed < 0 ||
    !Array.isArray(value.limitations) ||
    !value.limitations.every((item) => typeof item === 'string')
  ) {
    throw new ScanResponseError(
      'The API response is missing scan counts or limitations. Refresh scan history to verify the persisted results.',
    )
  }

  return {
    scan: value.scan,
    findings: value.findings,
    semgrep_findings: value.semgrep_findings,
    files_analyzed: value.files_analyzed,
    limitations: value.limitations,
  }
}

export function isScanRequestTimeout(error: unknown): boolean {
  return (
    axios.isAxiosError(error) &&
    (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT')
  )
}

export const scanService = {
  async start(
    repositoryId: string,
    scanType: 'full' | 'static' = 'full',
  ): Promise<ScanRecord> {
    const { data } = await api.post<ScanRecord>('/scans/background', {
      repository_id: repositoryId,
      scan_type: scanType,
    })
    if (!isScanRecord(data)) {
      throw new ScanResponseError(
        'The API returned an invalid scan record. Refresh scan history to verify whether the scan was created.',
      )
    }
    return data
  },

  async get(scanId: string): Promise<ScanRecord> {
    const { data } = await api.get<ScanRecord>(
      `/scans/${encodeURIComponent(scanId)}`,
    )
    if (!isScanRecord(data)) {
      throw new ScanResponseError('The API returned an invalid scan record.')
    }
    return data
  },

  async run(
    repositoryId: string,
    scanType: 'full' | 'static' = 'full',
  ): Promise<ScanRunResult> {
    const { data } = await api.post<unknown>(
      '/scans/run',
      {
        repository_id: repositoryId,
        scan_type: scanType,
      },
      {
        timeout: 480_000,
      },
    )
    return parseScanRunResult(data)
  },

  async list(): Promise<ScanRecord[]> {
    const { data } = await api.get<ScanRecord[]>('/scans/')
    return data
  },
}