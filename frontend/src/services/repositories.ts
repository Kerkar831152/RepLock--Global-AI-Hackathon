import { api } from './api'

export interface GithubRepository {
  github_repo_id: string
  name: string
  full_name: string
  description: string | null
  default_branch: string
  is_private: boolean
  html_url: string
  language: string | null
  updated_at: string | null
}

export interface ConnectedRepository {
  id: string
  github_repo_id: string
  name: string
  full_name: string
  description: string | null
  default_branch: string
  is_private: boolean
  owner_id: string
  created_at: string
}

export const repositoryService = {
  async listGithub(page = 1, perPage = 30): Promise<GithubRepository[]> {
    const { data } = await api.get<GithubRepository[]>('/repositories/github', {
      params: { page, per_page: perPage },
    })
    return data
  },

  async listConnected(): Promise<ConnectedRepository[]> {
    const { data } = await api.get<ConnectedRepository[]>('/repositories/')
    return data
  },

  async connect(githubRepoId: string): Promise<ConnectedRepository> {
    const { data } = await api.post<ConnectedRepository>('/repositories/', {
      github_repo_id: githubRepoId,
    })
    return data
  },
}