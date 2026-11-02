import { api } from './api'

export interface MergeAnalysis {
  id: string
  repository: string
  branchA: string
  branchB: string
  conflicts: number
  explanation: string
}

export const mergeIntelligenceService = {
  async list(): Promise<MergeAnalysis[]> {
    const { data } = await api.get<MergeAnalysis[]>('/merge-intelligence')
    return data
  },
  async analyze(repository: string, branchA: string, branchB: string): Promise<MergeAnalysis> {
    const { data } = await api.post<MergeAnalysis>('/merge-intelligence/analyze', {
      repository,
      branch_a: branchA,
      branch_b: branchB,
    })
    return data
  },
}
