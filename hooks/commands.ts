/** Deliberately bounded shell subset. Unsupported shipping syntax is refused. */
export type GitCall = { action: string; args: string[]; cwd: string; options: string[] }
export const words = (text: string): string[] => {
  const matches = text.match(/"(?:[^"\\]|\\.)*"|'[^']*'|[^\s]+/g) ?? []
  return matches.map((s) => s.replace(/^(["'])(.*)\1$/, '$2'))
}
export const resolveDir = (base: string, dir: string) => {
  if (/[$`~]/.test(dir)) throw new Error('Dynamic directory is not inspectable')
  if (/^(?:[A-Za-z]:[\\/]|\/)/.test(dir)) return dir
  return `${base.replace(/[\\/]$/, '')}/${dir}`
}
export function gitCalls(command: string, cwd: string): GitCall[] {
  // Quoted text is opaque: a `;`, `|` or `&&` inside a commit message must not split the
  // command (it would turn message words into commit paths and narrow the scan).
  const quoted: string[] = []
  const masked = command.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, (q) => `\u0000${quoted.push(q) - 1}\u0000`)
  // Drop redirections before splitting, so 2>&1 cannot become a ref or separator.
  const clean = masked.replace(/\d*\s*(?:>>?|<)\s*(?:&\d+|[^\s;&|]+)/g, '')
  const chunks = clean
    .split(/\s*(?:&&|;|\|\||\|)\s*/)
    .map((chunk) => chunk.replace(/\u0000(\d+)\u0000/g, (_, i: string) => quoted[Number(i)] ?? ''))
  const calls: GitCall[] = []
  for (const chunk of chunks) {
    const args = words(chunk)
    const executable = (args.shift() ?? '').replaceAll('\\', '/').split('/').pop()?.toLowerCase()
    if (['cd', 'chdir', 'set-location'].includes(executable ?? '')) {
      if (chunks.length === 1) continue
      if (args.length !== 1 || !clean.includes('&&'))
        throw new Error('Use a separate directory change before shipping')
      cwd = resolveDir(cwd, args[0]!)
      continue
    }
    if (executable !== 'git' && executable !== 'git.exe') continue
    let dir = cwd
    const options: string[] = []
    while (args[0]?.startsWith('-')) {
      const option = args.shift()!
      if (option === '-C') {
        if (!args[0]) throw new Error('Missing directory')
        dir = resolveDir(dir, args.shift()!)
      } else if (['--no-pager', '--paginate', '--no-optional-locks'].includes(option)) options.push(option)
      else throw new Error('Unsupported Git global option; use an explicit simple invocation')
    }
    calls.push({ action: args.shift() ?? '', args, cwd: dir, options })
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
        !/^(?:-[am]+|-[mF].+|--(?:amend|no-edit|all|allow-empty|allow-empty-message|no-verify|quiet|verbose|signoff|no-gpg-sign)|--(?:message|author|date|trailer|fixup|squash)=.*)$/.test(
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
        !/^(?:-u|-f|--force|--force-with-lease(?:=.*)?|--set-upstream|--atomic|--porcelain|--verbose|--quiet|--dry-run|--follow-tags|--no-verify|--push-option=.*)$/.test(
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
