import { gitCalls, commitPlan, pushPlan, words, resolveDir, vercelDirectory, isNonShipping } from './commands'
import type { EngineInterface, Register } from 'claude-code'
import { atom, read, update } from 'claude-code'
import type { Incident } from '../types'
import { INITIAL, LABEL, appendEvent, explanation, metadata, type ObservedCall } from './panel-model'
import {
  REDACTED,
  allowedRules,
  basename,
  commandDir,
  describe,
  diffScanner,
  dirname,
  hasMarker,
  isDeploy,
  isLocalEnvFile,
  isSensitiveFile,
  isSkippedFile,
  redact,
  scan,
  type Finding,
  type Skip,
} from './rules'

type $ = EngineInterface

const NAME = 'secret-guard'
const HOW =
  'Lee el valor de una variable de entorno (process.env.X en el servidor) y guárdalo en un .env que git ignore. ' +
  'Si es un falso positivo, pide una revisión humana de la regla; no introduzcas excepciones en el contenido.'
const ROTATE = 'Si la clave ya salió de esta máquina, rótala: borrarla del código no la invalida.'
const MAX_FILES = 10_000
const BUILD_DIRS = [
  'dist',
  'build',
  'out',
  '.next/static',
  '.output/public',
  '.vercel/output/static',
  '.svelte-kit/output/client',
]
const WALK_SKIP = new Set(['node_modules', '.git', '.cache', '.turbo', 'coverage'])
// Skip lockfiles consistently with the documented scan scope.
const DIFF_EXCLUDES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb'].map(
  (f) => `:(top,exclude,glob)**/${f}`,
)

/** Refuses with a reason the model reads, and tells the person at once. */
const deny = ($: $, why: string) => {
  try {
    $.ui.toast(`${NAME}: acción bloqueada, motivo en la conversación`)
  } catch {
    /* Cosmetic only. */
  }
  return { deny: `${NAME}: ${why}` }
}

const join = (dir: string | undefined, name: string) => (dir ? `${dir.replace(/[\\/]$/, '')}/${name}` : name)

// Rule ids the person disabled in the plugin settings (`allowedRules`); set on each load.
let SKIP: Skip = new Set()

// Never wait on a credential prompt (terminal or Git Credential Manager window), and never
// let a repository's own config run code while the guard inspects it.
const GIT_ENV = { GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never', GIT_OPTIONAL_LOCKS: '0' }
const GIT_SAFE = ['-c', 'core.fsmonitor=false']

// `$` calls do not count against the hook budget: these bound slow or stuck git, not the hook.
const git = ($: $, cwd: string | undefined, args: string[], init: { stdin?: string; timeoutMs?: number } = {}) =>
  $.process.run(['git', ...GIT_SAFE, ...args], {
    ...(cwd ? { cwd } : {}),
    env: GIT_ENV,
    timeoutMs: init.timeoutMs ?? 30_000,
    ...(init.stdin === undefined ? {} : { stdin: init.stdin }),
  })

/** Git metadata must be complete before it can authorize an action. */
async function checkedGit($: $, cwd: string | undefined, args: string[], timeoutMs?: number) {
  const result = await git($, cwd, args, timeoutMs === undefined ? {} : { timeoutMs })
  if (result.exitCode !== 0 || result.isStdoutTruncated || result.isStderrTruncated)
    throw new Error('Git inspection failed or returned incomplete output')
  return result
}

const isRepo = async ($: $, cwd: string | undefined) =>
  (await git($, cwd, ['rev-parse', '--git-dir'])).exitCode === 0

const nulList = (out: string) => out.split('\0').filter(Boolean)

/** Bounded diff output: truncation or subprocess timeout refuses the action. */
async function scanGitDiff($: $, cwd: string | undefined, args: string[]): Promise<Finding[]> {
  const result = await checkedGit($, cwd, args)
  const scanner = diffScanner(SKIP)
  for (const line of result.stdout.split('\n')) scanner.line(line)
  return scanner.findings
}

/** Reads and scans files 32 at a time; known binaries and lockfiles are excluded; read errors refuse the action. */
async function scanFiles($: $, paths: readonly string[], only?: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const todo = paths.filter((p) => !isSkippedFile(p))
  for (let i = 0; i < todo.length; i += 32) {
    const batch = todo.slice(i, i + 32)
    const texts = await Promise.all(batch.map((p) => $.fs.read(p)))
    texts.forEach((text, j) => {
      if (text.includes('\0')) return
      for (const f of scan(text, only, SKIP)) findings.push({ ...f, file: batch.at(j) ?? '' })
    })
  }
  return findings
}

async function walk($: $, dir: string, out: string[]): Promise<void> {
  const entries = await $.fs.list(dir)
  for (const entry of entries) {
    if (out.length > MAX_FILES) return
    const path = join(dir, entry.name)
    if (entry.kind === 'dir' && !WALK_SKIP.has(entry.name)) await walk($, path, out)
    else if (entry.kind === 'file' && !isLocalEnvFile(entry.name)) out.push(path)
  }
}

const tooMany = (n: number) =>
  `hay ${n} archivos que revisar (más de ${MAX_FILES}); revisa que .gitignore excluya dependencias y artefactos.`

function report(what: string, findings: Finding[], sensitive: string[]): string[] {
  const problems: string[] = []
  if (sensitive.length)
    problems.push(
      `${what} incluye archivos con credenciales: ${sensitive.join(', ')}. Añádelos a .gitignore` +
        ' (si ya están en git: git rm --cached <archivo>).',
    )
  if (findings.length) problems.push(`${what} contiene secretos:\n${describe(findings)}\n${HOW}\n${ROTATE}`)
  return problems
}

async function checkCommit($: $, cwd: string | undefined, args: string[]): Promise<string[]> {
  await checkedGit($, cwd, ['rev-parse', '--git-dir'])
  const hasHead = (await git($, cwd, ['rev-parse', '--verify', '-q', 'HEAD'])).exitCode === 0
  const plan = commitPlan(args)
  const addsAll = plan.all
  const base = (addsAll || plan.paths.length) && hasHead ? ['HEAD'] : ['--cached']
  if (plan.paths.length && !hasHead) throw new Error('Stage the initial commit before committing paths')
  const paths = plan.paths.length ? plan.paths : [':/']
  const findings = await scanGitDiff($, cwd, [
    'diff',
    ...base,
    '-U0',
    '--no-color',
    '--no-ext-diff',
    '--no-textconv',
    '--no-renames',
    '--',
    ...paths,
    ...DIFF_EXCLUDES,
  ])
  const added = await checkedGit($, cwd, [
    'diff',
    ...base,
    '--name-only',
    '--diff-filter=A',
    '-z',
    '--',
    ...paths,
  ])
  const names = nulList(added.stdout)
  return report('El commit', findings, names.filter(isSensitiveFile))
}

async function checkPush($: $, cwd: string, args: string[]): Promise<string[]> {
  await checkedGit($, cwd, ['rev-parse', '--git-dir'])
  const plan = pushPlan(args)
  if (plan.deletionOnly) return []
  let remote = plan.remote
  if (!remote) {
    const branch = (await checkedGit($, cwd, ['symbolic-ref', '--short', 'HEAD'])).stdout.trim()
    const pushRemote = await git($, cwd, ['config', '--get', 'branch.' + branch + '.pushRemote'])
    const defaultRemote = await git($, cwd, ['config', '--get', 'remote.pushDefault'])
    const tracking = await git($, cwd, ['config', '--get', 'branch.' + branch + '.remote'])
    remote =
      [pushRemote, defaultRemote, tracking].find((r) => r.exitCode === 0 && r.stdout.trim())?.stdout.trim() ??
      'origin'
  }
  // Refuse custom push mappings rather than inspect a different set silently.
  if (!plan.refs.length && !plan.all && !plan.tags && !plan.mirror) {
    const custom = await git($, cwd, ['config', '--get-all', 'remote.' + remote + '.push'])
    if (custom.exitCode === 0 && custom.stdout.trim())
      throw new Error('Use explicit push refspecs with configured remote.push')
    const mode = await git($, cwd, ['config', '--get', 'push.default'])
    if (mode.exitCode === 0 && !['simple', 'current', 'upstream', 'nothing'].includes(mode.stdout.trim()))
      throw new Error('Use explicit refs with push.default matching')
  }
  const refs = [...plan.refs]
  if (plan.all || plan.mirror)
    refs.push(
      ...(
        await checkedGit($, cwd, [
          'for-each-ref',
          '--format=%(refname)',
          ...(plan.mirror ? ['refs/'] : ['refs/heads/']),
        ])
      ).stdout
        .trim()
        .split('\n')
        .filter(Boolean),
    )
  if (plan.tags && !plan.mirror)
    refs.push(
      ...(await checkedGit($, cwd, ['for-each-ref', '--format=%(refname)', 'refs/tags/'])).stdout
        .trim()
        .split('\n')
        .filter(Boolean),
    )
  if (!refs.length) refs.push('HEAD')
  const tips: string[] = []
  if (refs.length > 100) throw new Error('Too many push refs for one inspection')
  for (const ref of [...new Set(refs)]) {
    if (ref.startsWith('-')) throw new Error('Invalid revision')
    tips.push((await checkedGit($, cwd, ['rev-parse', '--verify', ref + '^{commit}'])).stdout.trim())
  }
  // Query the actual push URL. No fetch, ref writes or credential value logging.
  const urls = (await git($, cwd, ['remote', 'get-url', '--push', '--all', remote])).stdout
    .trim()
    .split('\n')
    .filter(Boolean)
  if (urls.length > 1) throw new Error('Inspect each push URL separately')
  const url = urls[0] || remote
  // Network round trip: bounded on its own, and never prompts for credentials (GIT_ENV).
  const advertised = await git($, cwd, ['ls-remote', '--refs', '--', url], { timeoutMs: 20_000 }).catch(() => undefined)
  // Unreachable destination (offline, an SSH key that needs a passphrase): the push would
  // fail the same way. Fall back to what this repository last fetched from that remote, so
  // a slow network never turns into "incomplete check". Commits it already had are public.
  const known =
    advertised && advertised.exitCode === 0 && !advertised.isStdoutTruncated
      ? advertised.stdout
      : (await checkedGit($, cwd, ['for-each-ref', '--format=%(objectname) %(refname)', `refs/remotes/${remote}/`])).stdout
  const hashes = [
    ...new Set(
      known
        .split('\n')
        .map((l) => l.split(/\s/)[0]!)
        .filter((h) => /^[a-f0-9]{40,64}$/.test(h)),
    ),
  ]
  const exclusions: string[] = []
  if (hashes.length) {
    const objects = await git($, cwd, ['cat-file', '--batch-check=%(objectname) %(objecttype)'], {
      stdin: hashes.map((h) => h + '^{commit}').join('\n') + '\n',
    })
    if (objects.exitCode !== 0 || objects.isStdoutTruncated || objects.isStderrTruncated)
      throw new Error('Incomplete object inspection')
    for (const line of objects.stdout.split('\n')) {
      const [hash, type] = line.split(' ')
      if (type === 'commit' && /^[a-f0-9]{40,64}$/.test(hash ?? '')) exclusions.push('^' + hash)
    }
  }
  if (!tips.every((h) => /^[a-f0-9]{40,64}$/.test(h))) throw new Error('Invalid local tip')
  const range = [...tips, ...exclusions]
  const count = Number((await checkedGit($, cwd, ['rev-list', '--count', ...range, '--'])).stdout.trim())
  if (!Number.isFinite(count) || count > 500)
    return [
      'El push necesita revisar más de 500 commits nuevos; divide la operación o revisa el historial fuera del hook.',
    ]
  if (count === 0) return []
  const findings = await scanGitDiff($, cwd, [
    'log',
    '--root',
    '-m',
    '-p',
    '-U0',
    '--no-color',
    '--no-ext-diff',
    '--no-textconv',
    '--no-renames',
    '--format=%h',
    ...range,
    '--',
    ':/',
    ...DIFF_EXCLUDES,
  ])
  const added = await checkedGit($, cwd, [
    'log',
    '--root',
    '-m',
    '--name-only',
    '-z',
    '--diff-filter=A',
    '--format=',
    ...range,
    '--',
  ])
  const sensitive = [
    ...new Set(
      nulList(added.stdout)
        .map((s) => s.replace(/^\n+/, ''))
        .filter(isSensitiveFile),
    ),
  ]
  return report('El push', findings, sensitive)
}

async function checkDeploy($: $, cwd: string | undefined): Promise<string[]> {
  const files: string[] = []
  if (await isRepo($, cwd)) {
    // what a CLI uploads: tracked files plus new ones git does not ignore
    files.push(
      ...nulList((await checkedGit($, cwd, ['ls-files', '-co', '--exclude-standard', '-z'])).stdout).map(
        (n) => join(cwd, n),
      ),
    )
    for (const dir of BUILD_DIRS) {
      const build = join(cwd, dir)
      if (await $.fs.exists(build)) await walk($, build, files)
    }
  } else await walk($, cwd ?? '.', files)
  const uniqueFiles = [...new Set(files)]
  if (uniqueFiles.length > MAX_FILES) return [tooMany(uniqueFiles.length)]

  $.ui.status(`${NAME}: revisando ${uniqueFiles.length} archivos antes del deploy…`)
  try {
    const findings = await scanFiles(
      $,
      uniqueFiles.filter((f) => !isLocalEnvFile(f)),
    )
    // a secret behind a public prefix in a local .env ends up in the bundle
    const envs = (await $.fs.list(cwd ?? '.')).filter((e) => e.kind === 'file' && isLocalEnvFile(e.name))
    findings.push(
      ...(await scanFiles(
        $,
        envs.map((e) => join(cwd, e.name)),
        'public-env-secret',
      )),
    )
    return report('El deploy', findings, [])
  } finally {
    $.ui.status(undefined)
  }
}

/** Only exit 0 proves the file is ignored. A Git error is not permission. */
async function isIgnored($: $, path: string): Promise<boolean> {
  const { exitCode } = await git($, dirname(path), ['check-ignore', '-q', '--', basename(path)])
  return exitCode === 0
}

const PANE = 'secret-guard'
const state = atom({ plugin: 'secret-guard', key: 'dashboard' } as const, INITIAL)
const UNCHECKED = { deny: 'secret-guard: no he podido revisar esta acción, así que la bloqueo.' }

/** UI failures must not authorize an action or prevent a successful redaction. */
async function record($: EngineInterface, data: Omit<Incident, 'id'>) {
  try {
    await update($, state, (current) => appendEvent(current, data))
    // A pass clears the line; incidents stay visible until the next pass.
    $.ui.status(data.outcome === 'allowed' ? undefined : `secret-guard: ${LABEL[data.outcome].toLowerCase()} · /secret-guard`)
    if (data.outcome === 'blocked' || data.outcome === 'error') {
      // Do not wait for painting or steal the keyboard focus.
      void $.ui.open({ id: PANE, title: 'Secret Guard · revisión' }).catch(() => undefined)
    }
  } catch {
    /* The guard's result is independent from this optional display. */
  }
}

async function failed($: EngineInterface, e: ObservedCall, error?: unknown) {
  try {
    await record($, { ...metadata(e, SKIP), outcome: 'error', count: 0 })
  } catch {
    /* Error reporting cannot weaken a denial. */
  }
  // Say why, so the person can fix the cause (a timeout, a missing repo); masked and bounded.
  const why = error instanceof Error ? redact(error.message, SKIP).text.slice(0, 200) : ''
  return why ? { deny: `${UNCHECKED.deny} Motivo: ${why}` } : UNCHECKED
}

/** Slow checks (git, deploy) show progress; pure text scans are too quick to announce. */
async function busy($: EngineInterface, what: string) {
  try {
    await update($, state, (current) => ({ ...current, checking: true }))
    $.ui.status(`secret-guard: ${what}…`)
  } catch {
    /* Observability must not determine permission. */
  }
}

/** Record our decision BEFORE next; a later tool failure is not a guard failure. */
async function watch<T>(
  $: EngineInterface,
  e: ObservedCall,
  next: () => Promise<T>,
  check: (proceed: () => Promise<T>) => Promise<T | { deny: string }>,
): Promise<T | { deny: string }> {
  let passed = false
  try {
    const result = await check(async () => {
      passed = true
      await record($, { ...metadata(e, SKIP, false), outcome: 'allowed', count: 0 })
      return next()
    })
    if (!passed) await record($, { ...metadata(e, SKIP), outcome: 'blocked', count: 0 })
    return result
  } catch (error) {
    if (passed) throw error
    return failed($, e, error)
  }
}

const recordRedaction = ($: EngineInterface, count: number) =>
  record($, { outcome: 'redacted', tool: 'Resultado / adjunto', rules: [], count })

// Engine validation follows $ and on only within the hooks module.
// Keep engine-facing panel handlers here; pure display logic lives in panel-model.ts.
const registerPanel = (on: Parameters<Register>[0]) => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: PANE,
      immediate: true,
      description: 'Abre las comprobaciones e incidencias de Secret Guard',
    })
    return next(e)
  })

  on('command.run', { command: PANE }, async ($) => {
    const result = await $.ui.open({
      id: PANE,
      title: 'Secret Guard · revisión',
      focus: true,
      closeOnEscape: true,
    })
    return {
      text: result.isPlaced
        ? 'Panel de Secret Guard abierto.'
        : 'El panel no se pudo mostrar en esta superficie.',
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text, Button } = $.ui.resolve(e)
    const current = await read($, state)
    const latest = current.events[0]
    const selected = current.events.find((item) => item.id === current.selected) ?? latest
    const status = current.checking
      ? 'Revisando llamada cubierta…'
      : latest
        ? LABEL[latest.outcome]
        : 'Esperando llamadas cubiertas'
    const navigation = Box({
      flexDirection: 'row',
      columnGap: 1,
      children: [
        Button({
          key: 'latest',
          label: 'Última comprobación',
          hotkey: '1',
          onPress: async () => {
            await update($, state, (value) => ({ ...value, view: 'latest' as const, selected: null })).catch(
              () => undefined,
            )
          },
        }),
        Button({
          key: 'history',
          label: 'Ver historial',
          hotkey: '2',
          onPress: async () => {
            await update($, state, (value) => ({ ...value, view: 'history' as const })).catch(() => undefined)
          },
        }),
      ],
    })
    const content =
      current.view === 'history'
        ? current.events.map((item) =>
            Button({
              key: `event-${item.id}`,
              label: `#${item.id} · ${LABEL[item.outcome]} · ${item.tool}${item.file ? ` · ${item.file}` : ''}`,
              onPress: async () => {
                await update($, state, (value) => ({
                  ...value,
                  view: 'latest' as const,
                  selected: item.id,
                })).catch(() => undefined)
              },
            }),
          )
        : selected
          ? [
              Text({ bold: true, children: [`#${selected.id} · ${LABEL[selected.outcome]}`] }),
              Text({ children: [`Herramienta: ${selected.tool}`] }),
              Text({ children: [`Archivo: ${selected.file ?? 'No registrado'}`] }),
              Text({
                children: [`Reglas: ${selected.rules.join(', ') || 'Comprobación de política / contenido'}`],
              }),
              ...(selected.count ? [Text({ children: [`Coincidencias ocultadas: ${selected.count}`] })] : []),
              Text({ children: [explanation(selected)] }),
            ]
          : [Text({ children: ['Aún no hay comprobaciones registradas.'] })]
    return Box({
      flexDirection: 'column',
      rowGap: 1,
      children: [
        Text({ bold: true, children: ['SECRET GUARD'] }),
        Text({ children: [status] }),
        navigation,
        ...content,
        Text({
          dimColor: true,
          children: ['Últimos 30 eventos de esta sesión. No es una auditoría del proyecto.'],
        }),
      ],
    })
  })
}

// Exceptions are a person's decision: the agent may not change this mod's settings or
// switch it off to get past a block. Best effort; README says what remains out of reach.
const TAMPER = 'los ajustes y la instalación de secret-guard solo los cambia una persona, no el agente.'
const isSettingsFile = (path: string) => /^(?:settings(?:\.local)?|installed_plugins|known_marketplaces)\.json$/i.test(basename(path))
const touchesGuard = (cmd: string) =>
  /\ballowedRules\b|\bpluginConfigs\b/.test(cmd) ||
  /\bplugin\b[^;&|]*\b(?:disable|uninstall|remove|update|install|config)\b[^;&|]*secret-guard|secret-guard[^;&|]*\b(?:disable|uninstall)\b/i.test(cmd)
// Safety net: a `git commit`/`git push` in command position (start, after a separator, or
// inside a wrapper such as `sh -c "…"` / `env X=1 …`) that the parser did not turn into a
// call. Mentions inside strings (`grep "git push" README`) are not in command position.
const SHIPPING_AT_COMMAND = new RegExp(
  String.raw`(?:(?:^|[\n;&|(]\s*)|(?:^|[\s;&|(])(?:sh|bash|zsh|dash|cmd(?:\.exe)?|pwsh|powershell(?:\.exe)?|env|command|exec|xargs|nohup|time|nice|sudo|wsl|foreach)\b[^\n]*?["'\s])` +
    String.raw`git(?:\.exe)?["']?(?:\s+-[Cc]\s+\S+|\s+-\S+)*\s+(?:commit|push)\b`,
  'i',
)
const SHIPS = ['commit', 'push']

export const register: Register = (on, options) => {
  SKIP = allowedRules(options.allowedRules)
  registerPanel(on)

  on('tool.call', { tool: ['Write', 'Edit', 'NotebookEdit'] }, async ($, e, next) => {
    return watch(
      $,
      e,
      () => next(e),
      async (proceed) => {
        const path = e.tool === 'NotebookEdit' ? e.notebook_path : e.file_path
        const text = e.tool === 'Write' ? e.content : e.tool === 'Edit' ? e.new_string : e.new_source
        if (hasMarker(text))
          return deny(
            $,
            `el texto lleva marcadores ${REDACTED}…] de secretos que oculté en lo que leíste; escribirlo borraría los valores reales de ${basename(path)}. Edita solo las líneas que necesitas.`,
          )
        if (isSettingsFile(path) && /secret-guard|allowedRules/.test(text)) return deny($, TAMPER)
        const findings = scan(text, undefined, SKIP)
        if (findings.length === 0) return proceed()
        if (isLocalEnvFile(path) && findings.every((f) => f.rule !== 'public-env-secret')) {
          if (await isIgnored($, path)) return proceed()
          return deny($, `${basename(path)} no está en .gitignore: añádelo antes de guardar secretos en él.`)
        }
        return deny($, `no escribo secretos en ${basename(path)}:\n${describe(findings)}\n${HOW}`)
      },
    )
  }).catch(($, e, next) => (next.called ? next(e) : failed($, e)))

  on('tool.call', { tool: ['Bash', 'PowerShell'] }, async ($, e, next) => {
    return watch(
      $,
      e,
      () => next(e),
      async (proceed) => {
        const cmd = e.command
        const inline = scan(cmd, undefined, SKIP)
        if (inline.length)
          return deny(
            $,
            `el comando lleva un secreto en claro:\n${describe(inline)}\nUsa una variable de entorno ya definida ($VAR o $env:VAR) en vez del valor.`,
          )
        if (hasMarker(cmd))
          return deny(
            $,
            'el comando contiene marcadores de valores ocultados; no escribas esos marcadores de vuelta.',
          )
        if (touchesGuard(cmd)) return deny($, TAMPER)
        const cwd = await $.session.cwd()
        // Read-only git (status, log, diff…) needs no inspection at all, whatever its options.
        const calls = (/\bgit(?:\.exe)?\b/i.test(cmd) ? gitCalls(cmd, cwd) : []).filter((c) => !isNonShipping(c.action))
        if (SHIPPING_AT_COMMAND.test(cmd) && !calls.some((c) => SHIPS.includes(c.action)))
          return deny(
            $,
            'no he podido interpretar este git commit/push; ejecútalo directamente (git push …), sin envolverlo en otro comando.',
          )
        if (calls.length || isDeploy(cmd)) await busy($, 'revisando lo que se va a enviar')
        if (calls.length > 1 && calls.some((c) => SHIPS.includes(c.action)))
          return deny(
            $,
            'separa las operaciones Git en llamadas distintas para revisar el estado que realmente se enviará.',
          )
        const problems: string[] = []
        for (const call of calls) {
          // A commit or push (or an alias that may be one) we could not follow is refused.
          if (call.problem) throw new Error(call.problem)
          let action = call.action
          let args = call.args
          // Git aliases only (git ignores aliases named like built-in commands); shell
          // aliases/functions remain outside this parser.
          for (let depth = 0; depth < 5 && !SHIPS.includes(action); depth++) {
            const alias = await git($, call.cwd, ['config', '--get', 'alias.' + action])
            if (alias.exitCode === 1) break
            if (alias.exitCode !== 0 || alias.isStdoutTruncated) throw new Error('Cannot resolve Git alias')
            if (!alias.stdout.trim()) break
            if (alias.stdout.trim().startsWith('!'))
              throw new Error('Use the explicit Git operation instead of a shell alias')
            const expanded = words(alias.stdout.trim())
            action = expanded.shift() ?? ''
            args = [...expanded, ...args]
            if (depth === 4) throw new Error('Recursive alias')
          }
          if (calls.length > 1 && ['commit', 'push'].includes(action))
            return deny($, 'separa las operaciones Git para revisar cada estado real.')
          if (action === 'add' && args.some((a) => a === '--force' || /^-[^-]*f/.test(a)))
            problems.push(
              'git add --force requiere revisión manual de archivos ignorados; usa git add sin forzar.',
            )
          if (action === 'commit') problems.push(...(await checkCommit($, call.cwd, args)))
          if (action === 'push') problems.push(...(await checkPush($, call.cwd, args)))
        }
        if (isDeploy(cmd)) {
          const requestedDir = commandDir(cmd)
          const baseDir = requestedDir ? resolveDir(cwd, requestedDir) : cwd
          const deployDir = vercelDirectory(cmd, baseDir) ?? baseDir
          problems.push(...(await checkDeploy($, deployDir)))
        }
        return problems.length ? deny($, problems.join('\n\n')) : proceed()
      },
    )
  }).catch(($, e, next) => (next.called ? next(e) : failed($, e)))

  // anything sent out through an MCP server or a web fetch leaves the machine
  on('tool.call', { tool: [/^mcp__/, 'WebFetch'] }, async ($, e, next) => {
    return watch(
      $,
      e,
      () => next(e),
      async (proceed) => {
        const findings = scan(JSON.stringify(e, null, 2).replace(/\\n/g, '\n'), undefined, SKIP)
        return findings.length
          ? deny($, `no envío secretos a ${String(e.tool)}:\n${describe(findings)}`)
          : proceed()
      },
    )
  }).catch(($, e, next) => (next.called ? next(e) : failed($, e)))

  // what the model reads back (a cat .env, a printenv, a git diff, another hook's context)
  // is masked before it is stored or sent
  on('session.append', { door: ['tool-result', 'tool-message', 'attachment', 'hook-context'] }, async ($, e, next) => {
    let count = 0
    const clean = (text: string) => {
      const r = redact(text, SKIP)
      count += r.count
      return r.text
    }
    const content = e.message.content.map((block) => {
      if (block.type === 'text' && typeof block.text === 'string')
        return { ...block, text: clean(block.text) }
      if (block.type !== 'tool_result') return block
      const inner = block.content
      if (typeof inner === 'string') return { ...block, content: clean(inner) }
      if (!Array.isArray(inner)) return block
      return {
        ...block,
        content: inner.map((b: { type?: unknown; text?: unknown }) =>
          b?.type === 'text' && typeof b.text === 'string' ? { ...b, text: clean(b.text) } : b,
        ),
      }
    })
    if (count === 0) return next(e)
    await recordRedaction($, count)
    try {
      $.ui.toast(`${NAME}: oculté ${count} secreto(s) antes de que los leyera el modelo`)
    } catch {
      /* Cosmetic only. */
    }
    return next({ ...e, message: { ...e.message, content } })
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    // masking failed: hide the whole output rather than pass it on unread
    const hidden = `${NAME}: salida ocultada (no pude revisarla en busca de secretos)`
    const content = e.message.content.map((block) =>
      block.type === 'tool_result'
        ? { ...block, content: hidden }
        : block.type === 'text'
          ? { ...block, text: hidden }
          : block,
    )
    return next({ ...e, message: { ...e.message, content } })
  })
}
