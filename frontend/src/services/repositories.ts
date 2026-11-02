import { api } from './api'
import type { Repository } from '../types'

export const repositoryService = {
  async list(): Promise<Repository[]> {
    const { data } = await api.get<Repository[]>('/repositories')
    return data
  },
  async disconnect(repositoryId: string): Promise<void> {
    await api.delete(`/repositories/${encodeURIComponent(repositoryId)}`)
  },
}
