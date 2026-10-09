import type { Dashboard, Incident, Outcome } from '../types'
import { basename, redact, scan, type Skip } from './rules'

export type ObservedCall = {
  tool: string
  file_path?: string
  notebook_path?: string
  content?: unknown
  new_string?: unknown
  new_source?: unknown
  command?: unknown
}

export const INITIAL: Dashboard = { sequence: 0, checking: false, events: [], view: 'latest', selected: null }
export const HISTORY_LIMIT = 30
const TOOLS = new Set(['Write', 'Edit', 'NotebookEdit', 'Bash', 'PowerShell', 'WebFetch'])

/** Never retain a command, a finding preview, tool arguments or an output body. */
export function metadata(
  e: ObservedCall,
  skip: Skip = new Set(),
  withRules = true,
): Pick<Incident, 'tool' | 'file' | 'rules'> {
  const tool = TOOLS.has(e.tool) ? e.tool : e.tool.startsWith('mcp__') ? 'MCP' : 'Herramienta'
  const path = e.file_path ?? e.notebook_path
  const text = e.content ?? e.new_string ?? e.new_source ?? e.command
  // A passed call has no findings: skip a second full scan of its content.
  const rules = withRules && typeof text === 'string' ? [...new Set(scan(text, undefined, skip).map((f) => f.rule))] : []
  // Check the whole path before showing only its basename; never show known keys.
  const file =
    path === undefined
      ? undefined
      : scan(path).length || redact(path).count
        ? '[ruta ocultada]'
        : basename(path)
            .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
            .slice(0, 100)
  return { tool, ...(file ? { file } : {}), rules }
}

export function appendEvent(state: Dashboard, data: Omit<Incident, 'id'>): Dashboard {
  const entry = { ...data, id: state.sequence + 1 }
  // Routine passes would push incidents out of a 30-event history: keep only the latest pass.
  const kept = entry.outcome === 'allowed' ? state.events.filter((e) => e.outcome !== 'allowed') : state.events
  return {
    ...state,
    sequence: entry.id,
    checking: false,
    events: [entry, ...kept].slice(0, HISTORY_LIMIT),
  }
}

export const LABEL: Record<Outcome, string> = {
  blocked: 'Acción bloqueada',
  allowed: 'Comprobación superada',
  redacted: 'Resultado enmascarado',
  error: 'Bloqueada: revisión incompleta',
}

export function explanation(item: Incident): string {
  if (item.outcome === 'allowed')
    return 'Esta llamada superó las reglas aplicadas. No confirma su ejecución ni que el proyecto esté libre de secretos. Los bloqueos anteriores no se marcan como resueltos.'
  if (item.outcome === 'redacted')
    return 'Se ocultaron coincidencias en un mensaje cubierto. No deshace acciones previas ni limpia otros canales o registros.'
  if (item.outcome === 'error')
    return 'La comprobación no pudo completarse. Revisa el acceso a archivos, Git y los registros de diagnóstico; vuelve a intentar la operación después.'
  if (item.rules.includes('public-env-secret'))
    return 'Evita nombres públicos para secretos. Mantén la credencial en configuración del servidor, fuera del bundle del navegador.'
  if (item.tool === 'Write' || item.tool === 'Edit' || item.tool === 'NotebookEdit')
    return 'Usa una variable de entorno en el servidor. Si guardas el valor localmente, comprueba que Git ignore el archivo. No escribas marcadores REDACTED sobre credenciales reales.'
  return 'Consulta el motivo del bloqueo en la conversación. Revisa los archivos o el historial implicados. Si una credencial real ya se expuso, revócala o rótala.'
}
