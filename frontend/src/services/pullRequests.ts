import { api } from './api'
import type { ScanFinding } from './scans'

export interface PullRequest {
  number: number
  title: string
  state: string
  html_url: string
  author: string | null
  head_sha: string
  base_branch: string
  changed_files: number
  additions: number
  deletions: number
}

export interface PullRequestReview {
  scan_id: string
  pull_request_number: number
  pull_request_url: string
  head_sha: string
  status: string
  summary: string
  files_analyzed: number
  findings: ScanFinding[]
  limitations: string[]
}

export const pullRequestService = {
  async list(repositoryId: string): Promise<PullRequest[]> {
    const { data } = await api.get<PullRequest[]>(
      `/repositories/${encodeURIComponent(repositoryId)}/pull-requests`,
    )
    return data
  },

  async review(
    repositoryId: string,
    number: number,
  ): Promise<PullRequestReview> {
    const { data } = await api.post<PullRequestReview>(
      `/repositories/${encodeURIComponent(repositoryId)}/pull-requests/${number}/review`,
    )
    return data
  },
}