import { api } from './api'
import type { ScanConfiguration, ScanProgressEvent, ScanStartResponse } from '../types'

function isScanProgressEvent(event: unknown): event is ScanProgressEvent {
  if (!event || typeof event !== 'object') return false
  const candidate = event as Record<string, unknown>
  return (
    ['progress', 'activity', 'finding', 'complete', 'error'].includes(String(candidate.type)) &&
    typeof candidate.message === 'string' &&
    (candidate.stage === undefined || typeof candidate.stage === 'number') &&
    (candidate.progress === undefined || typeof candidate.progress === 'number') &&
    (candidate.timestamp === undefined || typeof candidate.timestamp === 'string')
  )
}

export const scanService = {
  async start(configuration: ScanConfiguration): Promise<ScanStartResponse> {
    const { data } = await api.post<ScanStartResponse>('/scans', configuration)
    if (!data?.scan_id?.trim()) throw new Error('The API accepted the request without returning a scan ID.')
    if (data.events_url) {
      const eventUrl = new URL(data.events_url, import.meta.env.VITE_API_URL || 'http://localhost:8000')
      if (!['http:', 'https:'].includes(eventUrl.protocol)) {
        throw new Error('The API returned an invalid scan event URL.')
      }
      return { ...data, events_url: eventUrl.toString() }
    }
    return data
  },
  subscribe(
    scanId: string,
    onEvent: (event: ScanProgressEvent) => void,
    onError: (error: Event) => void,
    eventsUrl?: string,
  ): () => void {
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
    const url = eventsUrl ? new URL(eventsUrl, baseUrl).toString() : `${baseUrl}/scans/${encodeURIComponent(scanId)}/events`
    const source = new EventSource(url)
    source.onmessage = (message) => {
      let event: unknown
      try {
        event = JSON.parse(message.data)
      } catch {
        onError(new Event('parseerror'))
        return
      }
      if (!isScanProgressEvent(event)) {
        onError(new Event('parseerror'))
        return
      }
      onEvent(event)
      if (event.type === 'complete') source.close()
    }
    source.onerror = onError
    return () => source.close()
  },
}
