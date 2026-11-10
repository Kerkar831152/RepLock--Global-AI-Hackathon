import axios from 'axios'

export const API_ROOT = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '')

export const api = axios.create({
  baseURL: `${API_ROOT}/api/v1`,
  timeout: 20000,
  headers: { 'Content-Type': 'application/json' },
})

export const healthApi = axios.create({
  baseURL: API_ROOT,
  timeout: 10000,
})

api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('replock_access_token')

  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }

  return config
})

export function getApiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.response?.data && typeof error.response.data === 'object' && 'detail' in error.response.data) {
      return String(error.response.data.detail)
    }
    if (error.code === 'ECONNABORTED') return 'The API request timed out. Please try again.'
    if (!error.response) return 'Cannot reach the RepLock API. Check that the backend is running.'
    return `The API request failed with status ${error.response.status}.`
  }

  return error instanceof Error ? error.message : 'An unexpected error occurred.'
}