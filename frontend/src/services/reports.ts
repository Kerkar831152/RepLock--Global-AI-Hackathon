import { api } from './api'

export interface SecurityReport {
  id: string
  repository: string
  commit: string
  date: string
  findings: number
  critical: number
  status: string
}

export const reportService = {
  async list(): Promise<SecurityReport[]> {
    const { data } = await api.get<SecurityReport[]>('/reports')
    return data
  },
}
