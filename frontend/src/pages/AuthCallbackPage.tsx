import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { authService } from '../services/auth'
import { getApiErrorMessage } from '../services/api'

export default function AuthCallbackPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [message, setMessage] = useState('Completing GitHub sign-in...')

  useEffect(() => {
    let active = true

    async function completeLogin() {
      const error = searchParams.get('error')

      if (error) {
        authService.clearAccessToken()
        if (active) setMessage(error)
        return
      }

      const params = new URLSearchParams(window.location.hash.slice(1))
      const token = params.get('access_token')

      window.history.replaceState(
        {},
        document.title,
        window.location.pathname + window.location.search,
      )

      if (token) {
        authService.storeAccessToken(token)
      }

      if (!authService.getAccessToken()) {
        if (active) setMessage('No authentication token was received. Please try signing in again.')
        return
      }

      try {
        await authService.getCurrentUser()
        if (active) navigate('/repositories', { replace: true })
      } catch (error) {
        authService.clearAccessToken()
        if (active) setMessage(getApiErrorMessage(error))
      }
    }

    void completeLogin()

    return () => {
      active = false
    }
  }, [navigate, searchParams])

  return (
    <main className="min-h-screen flex items-center justify-center bg-[#09090b] px-6">
      <div className="max-w-md text-center">
        <div className="mx-auto mb-5 h-8 w-8 animate-spin rounded-full border-2 border-white/20 border-t-white" />
        <h1 className="text-xl font-semibold text-white">GitHub authentication</h1>
        <p className="mt-3 text-sm text-zinc-400">{message}</p>
        {message !== 'Completing GitHub sign-in...' && (
          <button
            onClick={() => navigate('/login', { replace: true })}
            className="mt-6 rounded-lg bg-white px-4 py-2 text-sm font-medium text-black"
          >
            Back to login
          </button>
        )}
      </div>
    </main>
  )
}