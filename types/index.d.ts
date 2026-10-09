export type Outcome = 'blocked' | 'allowed' | 'redacted' | 'error'
export type Incident = {
  id: number
  outcome: Outcome
  tool: string
  file?: string
  rules: string[]
  count: number
}
export type Dashboard = {
  sequence: number
  checking: boolean
  events: Incident[]
  view: 'latest' | 'history'
  selected: number | null
}

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { dashboard: Dashboard }
  }
}
