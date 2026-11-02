import { api } from './api'
import type { Vulnerability } from '../types'

export const vulnerabilityService = {
  async list(): Promise<Vulnerability[]> {
    const { data } = await api.get<Vulnerability[]>('/vulnerabilities')
    return data
  },
  async retest(findingId: string): Promise<void> {
    await api.post(`/vulnerabilities/${encodeURIComponent(findingId)}/retest`)
  },
}
