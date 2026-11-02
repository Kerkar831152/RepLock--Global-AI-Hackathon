import axios from 'axios'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

export function getApiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.response?.data && typeof error.response.data === 'object' && 'detail' in error.response.data) {
      return String(error.response.data.detail)
    }
    if (error.code === 'ECONNABORTED') return 'The API request timed out. Please try again.'
    if (!error.response) return 'Cannot reach the RepLock API. Check that the backend is running.'
    return `The API returned ${error.response.status}. This operation is not available yet.`
  }
  return error instanceof Error ? error.message : 'An unexpected error occurred.'
}
