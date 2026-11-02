import { api } from './api'

interface GithubAuthorizationResponse {
  authorization_url: string
}

export const authService = {
  async beginGithubOAuth(): Promise<void> {
    const { data } = await api.get<GithubAuthorizationResponse>('/auth/github')
    if (!data.authorization_url) throw new Error('The API did not return a GitHub authorization URL.')
    const destination = new URL(data.authorization_url, window.location.origin)
    if (!['http:', 'https:'].includes(destination.protocol)) {
      throw new Error('The API returned an invalid GitHub authorization URL.')
    }
    window.location.assign(destination.toString())
  },
}
