import { api, API_ROOT } from './api'

export interface CurrentUser {
  id: string
  github_id: string
  username: string
  email: string | null
  created_at: string
}

const TOKEN_KEY = 'replock_access_token'

export const authService = {
  beginGithubOAuth(): void {
    window.location.assign(`${API_ROOT}/api/v1/auth/github/login`)
  },

  getAccessToken(): string | null {
    return sessionStorage.getItem(TOKEN_KEY)
  },

  storeAccessToken(token: string): void {
    sessionStorage.setItem(TOKEN_KEY, token)
  },

  clearAccessToken(): void {
    sessionStorage.removeItem(TOKEN_KEY)
  },

  async getCurrentUser(): Promise<CurrentUser> {
    const { data } = await api.get<CurrentUser>('/auth/me')
    return data
  },
}