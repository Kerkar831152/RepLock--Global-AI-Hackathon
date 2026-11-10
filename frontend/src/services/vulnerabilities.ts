import { api } from './api'
import type { ScanFinding } from './scans'

export interface FindingListResponse {
  items: ScanFinding[]
  total: number
  limit: number
  offset: number
}

export interface FindingSummary {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
}

export type FindingStatus =
  | 'open'
  | 'in_progress'
  | 'resolved'
  | 'ignored'
  | 'false_positive'

export const vulnerabilityService = {
  async list(
    params: {
      limit?: number
      offset?: number
      severity?: string
      status?: string
      search?: string
      scan_id?: string
      repository_id?: string
      vulnerability_type?: string
      date_from?: string
      date_to?: string
    } = {},
  ): Promise<FindingListResponse> {
    const { data } = await api.get<FindingListResponse>('/findings/', {
      params,
    })
    return data
  },

  async listAllForScan(scanId: string): Promise<ScanFinding[]> {
    let page = await this.list({ scan_id: scanId, limit: 100, offset: 0 })
    const items = [...page.items]
    let offset = page.items.length

    while (offset < page.total) {
      page = await this.list({ scan_id: scanId, limit: 100, offset })

      if (page.items.length === 0) {
        throw new Error('The findings API returned an incomplete report page.')
      }

      items.push(...page.items)
      offset += page.items.length
    }

    return items
  },

  async summary(): Promise<FindingSummary> {
    const { data } = await api.get<FindingSummary>('/findings/summary')
    return data
  },

  async updateStatus(
    findingId: string,
    status: FindingStatus,
  ): Promise<ScanFinding> {
    const { data } = await api.patch<ScanFinding>(
      `/findings/${encodeURIComponent(findingId)}/status`,
      { status },
    )
    return data
  },
}