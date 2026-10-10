/**
 * Deliberately bounded shell subset (Bash and PowerShell). What it cannot follow is
 * recorded as the call's `problem`: it refuses a commit or push, never a read-only command.
 */
export type GitCall = { action: string; args: string[]; cwd: string; options: string[]; problem?: string }

// PowerShell here-strings and quoted strings are single, opaque words.
const QUOTED = String.raw`@(['"])\r?\n[\s\S]*?\r?\n\1@|"(?:[^"\\]|\\.)*"|'[^']*'`
export const words = (text: string): string[] =>
  (text.match(new RegExp(`${QUOTED}|[^\\s]+`, 'g')) ?? []).map((s) =>
    s.replace(/^@(['"])\r?\n([\s\S]*?)\r?\n\1@$/, '$2').replace(/^(["'])([\s\S]*)\1$/, '$2'),
  )

export const resolveDir = (base: string, dir: string) => {
  if (/[$`~]/.test(dir)) throw new Error('Dynamic directory is not inspectable')
  // Git Bash spells C:\x as /c/x; the host process needs the Windows form.
  const msys = /^\/([A-Za-z])(?=\/|$)/.exec(dir)
  if (msys && /^[A-Za-z]:/.test(base)) return `${msys[1]!.toUpperCase()}:${dir.slice(2) || '/'}`
  if (/^(?:[A-Za-z]:[\\/]|\/)/.test(dir)) return dir
  return `${base.replace(/[\\/]$/, '')}/${dir}`
}

/** A heredoc body is data, not commands or words: drop it (an unterminated one is kept). */
const dropHeredocs = (text: string) => {
  let out = text
  let from = 0
  for (;;) {
    const m = /<<-?\s*(['"]?)([A-Za-z_][\w.-]*)\1/.exec(out.slice(from))
    if (!m) return out
    const start = from + m.index
    const lineEnd = out.indexOf('\n', start)
    const body = lineEnd < 0 ? null : new RegExp(String.raw`\n[\t ]*${m[2]!.replace(/[.-]/g, '\\$&')}[\t ]*(?:\r?\n|$)`).exec(out.slice(lineEnd))
    if (!body) {
      from = start + m[0].length
      continue
    }
    out = out.slice(0, start) + out.slice(start + m[0].length, lineEnd + 1) + out.slice(lineEnd + body.index + body[0].length)
    from = start
  }
}

// Git subcommands that never ship content: a parse problem in them is not worth a block.
const NON_SHIPPING = new Set(
  ('status log diff show branch fetch pull remote config rev-parse rev-list ls-files ls-remote ls-tree grep blame ' +
    'describe tag stash checkout switch restore reset init clone merge rebase cherry-pick revert version help ' +
    'cat-file for-each-ref reflog shortlog worktree clean mv rm apply am bisect archive gc fsck show-ref ' +
    'symbolic-ref check-ignore var name-rev count-objects range-diff format-patch sparse-checkout maintenance').split(' '),
)
export const isNonShipping = (action: string) => NON_SHIPPING.has(action)

// A `-c` that changes where or how a push goes would make the inspection look elsewhere.
const DESTINATION_CONFIG = /^(?:remote|url|push|branch|alias)\.|^core\.(?:sshcommand|hookspath)=/i
const PASS_OPTIONS = ['--no-pager', '--paginate', '-p', '--no-optional-locks', '--no-replace-objects', '--literal-pathspecs', '--noglob-pathspecs', '--icase-pathspecs']

export function gitCalls(command: string, cwd: string): GitCall[] {
  // Quoted text is opaque: a `;`, `|` or `&&` inside a commit message must not split the
  // command (it would turn message words into commit paths and narrow the scan).
  const quoted: string[] = []
  const masked = dropHeredocs(command).replace(new RegExp(QUOTED, 'g'), (q) => `\u0000${quoted.push(q) - 1}\u0000`)
  // Drop redirections before splitting, so 2>&1 cannot become a ref or separator.
  const clean = masked.replace(/\d*\s*(?:>>?|<)\s*(?:&\d+|[^\s;&|]+)/g, '')
  const chunks = clean
    .split(/\s*(?:&&|;|\|\||\||\r?\n)\s*/)
    .map((chunk) => chunk.replace(/\u0000(\d+)\u0000/g, (_, i: string) => quoted[Number(i)] ?? ''))
  const calls: GitCall[] = []
  // A directory change we cannot follow leaves every later call's directory unknown.
  let lost: string | undefined
  for (const chunk of chunks) {
    const args = words(chunk)
    if (args[0] === '&') args.shift() // PowerShell call operator: `& git push`
    const executable = (args.shift() ?? '').replaceAll('\\', '/').split('/').pop()?.toLowerCase()
    if (['cd', 'chdir', 'set-location', 'sl', 'pushd'].includes(executable ?? '')) {
      const target = args.filter((a) => !a.startsWith('-')) // Set-Location -Path X
      if (target.length !== 1) lost = 'Use a simple directory change before shipping'
      else
        try {
          cwd = resolveDir(cwd, target[0]!)
        } catch (error) {
          lost = (error as Error).message
        }
      continue
    }
    if (executable !== 'git' && executable !== 'git.exe') continue
    let dir = cwd
    let problem = lost
    const options: string[] = []
    while (args[0]?.startsWith('-')) {
      const option = args.shift()!
      if (option === '-C' || option === '-c') {
        const value = args.shift()
        if (value === undefined) problem ??= `Missing value for git ${option}`
        else if (option === '-c' && DESTINATION_CONFIG.test(value))
          problem ??= 'This git -c setting changes where the push goes; push without it'
        else if (option === '-c') options.push(option, value)
        else
          try {
            dir = resolveDir(dir, value)
          } catch (error) {
            problem ??= (error as Error).message
          }
      } else if (PASS_OPTIONS.includes(option)) options.push(option)
      else problem ??= `Unsupported Git global option ${option}; use a simple invocation`
    }
    calls.push({ action: args.shift() ?? '', args, cwd: dir, options, ...(problem ? { problem } : {}) })
  }
  return calls
}
export function commitPlan(args: string[]) {
  const paths: string[] = []
  let all = false
  let pathMode = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!
    if (pathMode) {
      paths.push(a)
      continue
    }
    if (a === '--') {
      pathMode = true
      continue
    }
    if (
      [
        '-m',
        '--message',
        '-F',
        '--file',
        '-C',
        '-c',
        '--reuse-message',
        '--reedit-message',
        '--author',
        '--date',
        '--trailer',
        '--fixup',
        '--squash',
      ].includes(a)
    ) {
      i++
      continue
    }
    if (a === '--all' || /^-[^-]*a/.test(a)) all = true
    if (/^-[^-]*m$/.test(a)) {
      i++
      continue
    }
    if (/^-[^-]*m./.test(a)) continue
    if (a.startsWith('-')) {
      if (
        !/^(?:-[amnqsv]+|-[mF].+|-S.*|--(?:amend|no-edit|all|allow-empty|allow-empty-message|no-verify|verify|quiet|verbose|signoff|no-gpg-sign|gpg-sign|status|no-status|no-post-rewrite)|--(?:message|author|date|trailer|fixup|squash|cleanup|gpg-sign)=.*)$/.test(
          a,
        )
      )
        throw new Error('Unsupported commit option; stage changes and use a plain commit')
    } else paths.push(a)
  }
  if (paths.some((p) => /[$`]/.test(p))) throw new Error('Dynamic commit paths')
  return { all, paths }
}
export function pushPlan(args: string[]) {
  let remote: string | undefined
  const refs: string[] = []
  let all = false
  let tags = false
  let mirror = false
  let remove = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!
    if (a === '--all') all = true
    else if (a === '--tags') tags = true
    else if (a === '--mirror') mirror = true
    else if (a === '--delete' || a === '-d') remove = true
    else if (['-o', '--push-option', '--receive-pack', '--exec', '--repo'].includes(a)) {
      const value = args[++i]
      if (!value) throw new Error('Missing push option')
      if (a === '--repo') remote = value
      else if (a === '--receive-pack' || a === '--exec')
        throw new Error('Custom receive program not supported')
    } else if (a.startsWith('--repo=')) remote = a.slice(7)
    else if (a.startsWith('-')) {
      if (
        // Options that change neither which commits nor which destination are let through.
        !/^(?:-[ufvqn46]+|--force|--force-with-lease(?:=.*)?|--force-if-includes|--no-force-with-lease|--set-upstream|--atomic|--no-atomic|--porcelain|--verbose|--quiet|--dry-run|--progress|--no-progress|--thin|--no-thin|--ipv4|--ipv6|--follow-tags|--no-follow-tags|--no-verify|--verify|--signed(?:=.*)?|--no-signed|--recurse-submodules=(?:no|check)|--no-recurse-submodules|--push-option=.*)$/.test(
          a,
        )
      )
        throw new Error('Unsupported push option')
      if (a === '--follow-tags') tags = true
    } else if (!remote) remote = a
    else refs.push(a)
  }
  if (remote?.startsWith('-') || (remote && /[$`]/.test(remote))) throw new Error('Invalid destination')
  if (refs.some((r) => /[$`*?\[\]]/.test(r))) throw new Error('Expand wildcard refspecs before pushing')
  return {
    remote,
    refs: remove ? [] : refs.map((r) => r.replace(/^\+/, '').split(':')[0]!).filter(Boolean),
    all,
    tags,
    mirror,
    deletionOnly: remove || (refs.length > 0 && refs.every((r) => r.startsWith(':'))),
  }
}
/** Directory explicitly selected by the supported Vercel deployment forms. */
export function vercelDirectory(command: string, cwd: string): string | undefined {
  const tokens = words(command)
  const at = tokens.findIndex((t) => /^(?:.*[\\/])?vercel(?:\.exe)?$/i.test(t))
  if (at < 0) return undefined
  let dir = cwd
  let positional: string | undefined
  for (let i = at + 1; i < tokens.length; i++) {
    const a = tokens[i]!
    if (['&&', ';', '|', '||'].includes(a)) break
    if (a === 'deploy') continue
    if (a === '--cwd') {
      if (!tokens[i + 1]) throw new Error('Missing Vercel directory')
      dir = resolveDir(cwd, tokens[++i]!)
    } else if (a.startsWith('--cwd=')) dir = resolveDir(cwd, a.slice(6))
    else if (
      [
        '--scope',
        '--token',
        '--name',
        '--target',
        '--archive',
        '--regions',
        '--build-env',
        '--env',
        '-e',
        '-b',
        '--local-config',
        '--global-config',
        '--meta',
        '-m',
      ].includes(a)
    ) {
      i++
    } else if (!a.startsWith('-')) {
      if (positional) throw new Error('Ambiguous Vercel paths')
      positional = a
    }
  }
  return positional ? resolveDir(dir, positional) : dir
}
