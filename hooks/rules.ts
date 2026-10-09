// Pure detection, no `$`: what counts as a secret, a sensitive file or a
// command that ships code. Unit-tested directly in tests/rules.test.ts.

export type Finding = {
  rule: string
  label: string
  preview: string
  line: number
  file?: string
  hint?: string
}

type Rule = {
  id: string
  label: string
  /** Global + `d` (indices), so the secret's own span can be masked. */
  re: RegExp
  /** Capture group holding the secret; the whole match when absent. */
  group?: number
  /** Reports a name, not a value: never masked, never placeholder-checked. */
  isName?: true
  hint?: string
  isReal?: (secret: string, m: RegExpExecArray) => boolean
}

export const REDACTED = '[REDACTED:'
// Content cannot authorize exceptions. Allow markers are intentionally inert.

const PLACEHOLDER =
  /x{4,}|\*{4,}|\.{3}|<[^>]*>|\$\{|\{\{|example|placeholder|your[-_]|changeme|dummy|redacted|fake|sample/i
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|[^.]+)$/i
const WEAK_PASSWORD = /^(?:pass(?:word)?|postgres|root|admin|secret|test|guest|user|mysql|mongo|redis)$/i

const entropy = (s: string) => {
  const counts = new Map<string, number>()
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) bits -= (n / s.length) * Math.log2(n / s.length)
  return bits
}

const jwtRole = (payload: string): unknown => {
  try {
    const b64 = payload.replace(/-/g, '+').replace(/_/g, '/')
    return (JSON.parse(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='))) as { role?: unknown }).role
  } catch {
    return undefined
  }
}

// Provider-specific formats and generic entropy heuristics.
// Keep rule order stable: the first overlapping match owns the finding.
export const RULES: readonly Rule[] = [
  {
    id: 'private-key',
    label: 'Clave privada (PEM/SSH)',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/dg,
  },
  { id: 'aws-access-key', label: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/dg },
  {
    id: 'aws-secret-key',
    label: 'AWS secret access key',
    group: 1,
    re: /aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/dgi,
  },
  {
    id: 'github-token',
    label: 'Token de GitHub',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/dg,
  },
  { id: 'gitlab-token', label: 'Token de GitLab', re: /\bglpat-[A-Za-z0-9_-]{20,}/dg },
  { id: 'slack-token', label: 'Token de Slack', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/dg },
  {
    id: 'slack-webhook',
    label: 'Webhook de Slack',
    re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]{20,}/dg,
  },
  {
    id: 'discord-webhook',
    label: 'Webhook de Discord',
    re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/dg,
  },
  { id: 'stripe-secret', label: 'Clave secreta de Stripe (live)', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/dg },
  { id: 'stripe-webhook', label: 'Secreto de webhook de Stripe', re: /\bwhsec_[A-Za-z0-9+/=]{24,}/dg },
  {
    id: 'openai-key',
    label: 'API key de OpenAI',
    re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/dg,
  },
  { id: 'anthropic-key', label: 'API key de Anthropic', re: /\bsk-ant-[a-z]+\d*-[A-Za-z0-9_-]{20,}/dg },
  {
    id: 'google-api-key',
    label: 'API key de Google (Gemini, Maps, Firebase…)',
    re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/dg,
  },
  { id: 'google-oauth-secret', label: 'Client secret de Google OAuth', re: /\bGOCSPX-[A-Za-z0-9_-]{28}/dg },
  { id: 'huggingface-token', label: 'Token de Hugging Face', re: /\bhf_[A-Za-z]{34}\b/dg },
  { id: 'sendgrid-key', label: 'API key de SendGrid', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/dg },
  { id: 'npm-token', label: 'Token de npm', re: /\bnpm_[A-Za-z0-9]{36}\b/dg },
  { id: 'supabase-secret', label: 'Clave secreta de Supabase', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/dg },
  {
    id: 'supabase-service-role',
    label: 'JWT service_role de Supabase',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/dg,
    // the anon JWT is public by design; only an admin role is a secret
    isReal: (_s, m) => /service_role|supabase_admin/.test(String(jwtRole(m[1] ?? ''))),
  },
  {
    id: 'connection-string',
    label: 'Cadena de conexión con contraseña',
    group: 1,
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^:@\s/'"`]+:([^@\s'"`]+)@([^/\s:'"`?,]+)/dgi,
    // local dev databases (localhost, docker service names) are not leaks
    isReal: (pw, m) => !WEAK_PASSWORD.test(pw) && !LOCAL_HOST.test(m[2] ?? ''),
  },
  {
    id: 'bearer-token',
    label: 'Bearer token en claro',
    group: 1,
    re: /\bBearer\s+([A-Za-z0-9._~+/-]{24,}=*)/dg,
  },
  {
    id: 'public-env-secret',
    label: 'Secreto en una variable pública del frontend',
    isName: true,
    re: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD)[A-Z0-9_]*\b/dg,
    hint: 'todo lo que lleva prefijo público se incrusta en el JS que descarga el navegador: úsalo solo en el servidor',
  },
  {
    id: 'hardcoded-secret',
    label: 'Secreto escrito a mano en el código',
    group: 1,
    // bounded name prefix: an unbounded one backtracks quadratically on minified bundles
    re: /\b[\w.-]{0,40}(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key|credentials?)[\w.-]{0,40}["']?\s*(?::=|=>|[:=])\s*["'`]([^"'`\s]{12,})["'`]/dgi,
    isReal: (s) =>
      /[a-z]/i.test(s) &&
      /\d/.test(s) &&
      entropy(s) >= 3.5 &&
      !/^[A-Z0-9_]+$/.test(s) &&
      !/:\/\/|^[./]/.test(s),
  },
  {
    id: 'env-secret',
    label: 'Secreto en asignación sin comillas',
    group: 1,
    re: /(?:^|[;\s])(?:export\s+)?[\w.-]{0,40}(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key|credentials?)[\w.-]{0,40}\s*=\s*([^\s"'`;#]{12,})/dgi,
    isReal: (s) =>
      /[a-z]/i.test(s) &&
      /\d/.test(s) &&
      entropy(s) >= 3.5 &&
      !/^[A-Z0-9_]+$/.test(s) &&
      !/:\/\/|^[.$/]/.test(s),
  },
]

// A real masking marker names a known rule; prose or code about the format does not.
const MARKER = new RegExp(`${REDACTED.replace('[', '\\[')}(?:${RULES.map((r) => r.id).join('|')})\\]`)
export const hasMarker = (text: string) => MARKER.test(text)

type Span = { rule: Rule; start: number; end: number; secret: string }

/** Rule ids a person disabled through the plugin's `allowedRules` setting. */
export type Skip = ReadonlySet<string>
const NONE: Skip = new Set()

/** Parses the human-only `allowedRules` setting; unknown ids are ignored. */
export const allowedRules = (value: unknown): Skip => {
  const known = new Set(RULES.map((r) => r.id))
  return new Set(
    String(value ?? '')
      .split(/[\s,]+/)
      .filter((id) => known.has(id)),
  )
}

const spansIn = (line: string, only?: string, skip: Skip = NONE): Span[] => {
  // An allowed rule still claims its matches, so a generic rule cannot report the
  // same value again (an allowed Firebase key is also a high-entropy `apiKey`).
  const spans: (Span & { allowed: boolean })[] = []
  for (const rule of RULES) {
    if (only && rule.id !== only) continue
    for (const m of line.matchAll(rule.re)) {
      const g = rule.group ?? 0
      const secret = m[g]
      const at = m.indices?.[g]
      if (secret === undefined || at === undefined) continue
      if (!rule.isName && PLACEHOLDER.test(secret)) continue
      if (rule.isReal && !rule.isReal(secret, m)) continue
      const [start, end] = at
      if (spans.some((s) => start < s.end && s.start < end)) continue // one finding per secret
      spans.push({ rule, start, end, secret, allowed: skip.has(rule.id) })
    }
  }
  return spans.filter((s) => !s.allowed)
}

// Short secrets (a 10-character password) must not be half-revealed by the preview.
const preview = (s: Span) =>
  s.rule.isName
    ? s.secret
    : `${s.secret.slice(0, Math.min(4, Math.floor(s.secret.length / 4)))}… ${s.secret.length} caracteres`

const toFinding = (s: Span, line: number): Finding => ({
  rule: s.rule.id,
  label: s.rule.label,
  preview: preview(s),
  line,
  ...(s.rule.hint ? { hint: s.rule.hint } : {}),
})

/** Every secret in `text`, one finding per secret, line numbers from 1. */
export const scan = (text: string, only?: string, skip: Skip = NONE): Finding[] =>
  text.split('\n').flatMap((line, i) => spansIn(line, only, skip).map((s) => toFinding(s, i + 1)))

/** `text` with each secret's value replaced by `[REDACTED:<rule>]`. */
export const redact = (text: string, skip: Skip = NONE): { text: string; count: number } => {
  let count = 0
  // A complete block may contain wrapped key material. Without END, consume
  // only consecutive base64 body lines, never unrelated logs/source below it.
  let safe = ''
  let cursor = 0
  const blocks = skip.has('private-key') ? [] : text.matchAll(/-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----/g)
  for (const match of blocks) {
    const start = match.index!
    if (start < cursor) continue
    const after = start + match[0].length
    const tail = text.slice(after)
    const end = /^\r?\n/.test(tail) ? new RegExp('^-----END ' + match[1] + '-----', 'm').exec(tail) : null
    const completeLength = end ? end.index + end[0].length : undefined
    const body = /^(?:\r?\n[A-Za-z0-9+/=]{16,}(?=\r?\n|$))*/.exec(tail)?.[0] ?? ''
    safe += text.slice(cursor, start) + REDACTED + 'private-key]'
    cursor = after + (completeLength ?? body.length)
    count++
  }
  safe += text.slice(cursor)
  const lines = safe.split('\n').map((line) => {
    const spans = spansIn(line, undefined, skip)
      .filter((s) => !s.rule.isName)
      .sort((a, b) => b.start - a.start)
    count += spans.length
    for (const s of spans) line = `${line.slice(0, s.start)}${REDACTED}${s.rule.id}]${line.slice(s.end)}`
    return line
  })
  return { text: count ? lines.join('\n') : text, count }
}

/**
 * Reads a unified diff (`git diff -U0`, `git log -p -U0`) line by line and
 * scans only the added lines, with the file and new line number of each.
 */
export const diffScanner = (skip: Skip = NONE) => {
  const findings: Finding[] = []
  let file = ''
  let lineNo = 0
  let previous = ''
  return {
    findings,
    line(l: string) {
      if (l.startsWith('+++ ') && previous.startsWith('--- '))
        file = l
          .slice(4)
          .replace(/^"?b\//, '')
          .replace(/"$/, '')
      else if (l.startsWith('@@')) lineNo = Number(/\+(\d+)/.exec(l)?.[1] ?? 0)
      else if (l.startsWith('+')) {
        for (const s of spansIn(l.slice(1), undefined, skip)) findings.push({ ...toFinding(s, lineNo), file })
        lineNo++
      }
      previous = l
    },
  }
}

export const describe = (findings: readonly Finding[], max = 8): string =>
  findings
    .slice(0, max)
    .map(
      (f) =>
        `  - ${f.label}${f.file ? ` en ${f.file}:${f.line}` : ` (línea ${f.line})`}: ${f.preview}${f.hint ? ` (${f.hint})` : ''}`,
    )
    .join('\n') + (findings.length > max ? `\n  - …y ${findings.length - max} más` : '')

export const basename = (path: string) => path.split(/[\\/]/).pop() ?? path
export const dirname = (path: string) => {
  const cut = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  if (cut < 0) return '.'
  if (cut === 0 || (cut === 2 && /^[A-Za-z]:/.test(path))) return path.slice(0, cut + 1)
  return path.slice(0, cut)
}

/** A local env file: where secrets belong, as long as git ignores it. */
export const isLocalEnvFile = (path: string) => {
  const name = basename(path)
  return (
    name === '.dev.vars' ||
    (/^\.env(?:\..+)?$/.test(name) && !/\.(?:example|sample|template|dist|defaults?)$/.test(name))
  )
}

/** Files that hold credentials by their nature, whatever their content. */
export const isSensitiveFile = (path: string) =>
  isLocalEnvFile(path) ||
  /(?:^|[\\/])(?:id_(?:rsa|dsa|ecdsa|ed25519)|\.netrc|\.pgpass|\.htpasswd|credentials\.json|service[-_]?account[^\\/]*\.json|[^\\/]*firebase-adminsdk[^\\/]*\.json|[^\\/]+\.(?:p12|pfx|jks|keystore|tfstate))$/i.test(
    path,
  )

/** Files never worth reading for secrets: lockfiles and binaries. */
export const isSkippedFile = (path: string) =>
  /(?:^|[\\/])(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|composer\.lock|Cargo\.lock|poetry\.lock)$|\.(?:png|jpe?g|gif|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp[34]|webm|mov|wav|ogg|pdf|zip|t?gz|br|wasm|exe|dll|so|dylib)$/i.test(
    path,
  )

const DEPLOY = [
  /\bvercel(?:\s+deploy\b|\s+--prod\b|\s*$|\s*[;&|])/,
  /\bnetlify\s+deploy\b/,
  /\bwrangler\s+(?:deploy|publish|pages\s+deploy)\b/,
  /\bfirebase\s+deploy\b/,
  /\bfly(?:ctl)?\s+deploy\b/,
  /\brailway\s+up\b/,
  /\b(?:npm|pnpm|yarn|bun)\s+publish\b/,
  /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?deploy\b/,
  /\bgcloud\s+(?:app|run|functions)\s+deploy\b/,
  /\bsupabase\s+(?:functions\s+)?deploy\b/,
  /\bdocker\s+push\b/,
  /\bamplify\s+publish\b/,
  /\bheroku\s+(?:deploy|container:push)\b/,
]
export const isDeploy = (cmd: string) =>
  DEPLOY.some((re) => re.test(cmd)) ||
  (/(?:^|[;&|]\s*|\bnpx(?:\s+--(?:yes|no-install))*\s+|\bpnpm\s+dlx\s+|\bbunx\s+)vercel(?:\.exe)?(?:\s|$)/i.test(
    cmd,
  ) &&
    !/\bvercel(?:\.exe)?\s+(?:env|list|ls|inspect|logs|whoami|login|logout|help|--help|--version)\b/i.test(
      cmd,
    ))

const unquote = (s: string | undefined) => s?.replace(/^(["'])(.*)\1$/, '$2')

/** The directory a command runs git or a deploy in: `git -C <dir>` or a leading `cd <dir> &&`. */
export const commandDir = (cmd: string): string | undefined =>
  unquote(
    /\bgit\s+-C\s+("[^"]+"|'[^']+'|\S+)/.exec(cmd)?.[1] ??
      /^\s*cd\s+("[^"]+"|'[^']+'|\S+)\s*(?:&&|;)/.exec(cmd)?.[1],
  )
