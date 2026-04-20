import { useCallback, useEffect, useState } from 'react'
import { getDashboardSummary } from '../api/client'
import type { DashboardSummary } from '../types'

interface State {
  summary: DashboardSummary | null
  loading: boolean
  error: string | null
}

export function useDashboardSummary(refreshInterval = 10000) {
  const [state, setState] = useState<State>({
    summary: null,
    loading: true,
    error: null,
  })

  const refresh = useCallback(async () => {
    try {
      const data = await getDashboardSummary()
      setState({ summary: data, loading: false, error: null })
    } catch (e) {
      setState((s) => ({ ...s, loading: false, error: (e as Error).message }))
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, refreshInterval)
    return () => clearInterval(id)
  }, [refresh, refreshInterval])

  return { ...state, refresh }
}
