import { api } from './api'

export interface PullRequest {
  id: string
  number: number
  title: string
  repository: string
  author: string
  source: string
  target: string
  files: number
  findings: number
  status: string
  diff: string
}

export const pullRequestService = {
  async list(): Promise<PullRequest[]> {
    const { data } = await api.get<PullRequest[]>('/pull-requests')
    return data
  },
}
