// Real-world Windows/Claude command forms that used to end as "incomplete check" (1.3.1).
import { expect, test } from 'claude-code/testing'
import { commitPlan, gitCalls, isNonShipping, pushPlan } from '../hooks/commands'

const CWD = 'C:\\work\\app'
const REPO = 'C:\\work\\repo'
const pushOf = (cmd: string) => gitCalls(cmd, CWD).find((c) => c.action === 'push')

test('PowerShell, Git Bash and plain forms of a push are all followed', () => {
  const forms: [string, string][] = [
    [`cd "${REPO}"; git push -u origin master`, REPO],
    [`Set-Location -Path "${REPO}"; git push -u origin master`, REPO],
    [`cd "${REPO}" && git push -u origin master`, REPO],
    ['cd /c/work/repo && git push -u origin master', 'C:/work/repo'],
    ['git -C /c/work/repo push -u origin master', 'C:/work/repo'],
    [`cd "${REPO}"\ngit push -u origin master`, REPO],
    [`& git -C "${REPO}" push origin master`, REPO],
  ]
  for (const [cmd, dir] of forms) {
    const push = pushOf(cmd)
    expect(push?.problem).toBeUndefined()
    expect(push?.cwd).toBe(dir)
  }
})

test('harmless options no longer make a push incomplete', () => {
  for (const cmd of [
    'git -c core.fsmonitor=false push origin master',
    'git push -u origin master --progress',
    'git push -v --no-thin origin master',
  ]) {
    const push = pushOf(cmd)
    expect(push?.problem).toBeUndefined()
    pushPlan(push?.args ?? [])
  }
  expect(commitPlan(['-s', '-v', '-m', 'msg']).paths).toEqual([])
})

test('a -c that redirects the push is still refused', () => {
  expect(pushOf('git -c remote.origin.pushurl=https://example.test/x.git push')?.problem).toMatch(/changes where/)
})

test('heredoc and here-string commit messages never become commit paths', () => {
  const heredoc = gitCalls("git commit -F - <<'EOF'\nfix: stuff; more | things\nEOF", CWD)
  expect(heredoc.length).toBe(1)
  expect(commitPlan(heredoc[0]?.args ?? []).paths).toEqual([])
  const hereString = gitCalls("git commit -m @'\nfix: stuff\nsecond line\n'@", CWD)
  expect(hereString.length).toBe(1)
  expect(commitPlan(hereString[0]?.args ?? []).paths).toEqual([])
})

test('an unterminated << is not taken as a heredoc that could hide a later push', () => {
  const calls = gitCalls('echo "a << b"\ngit push origin master', CWD)
  expect(calls.map((c) => c.action)).toEqual(['push'])
})

test('read-only git is never inspected, whatever its options', () => {
  for (const action of ['status', 'log', 'diff', 'show', 'fetch']) expect(isNonShipping(action)).toBe(true)
  for (const action of ['commit', 'push', 'add']) expect(isNonShipping(action)).toBe(false)
})

const ok = (stdout = '', exitCode = 0) => ({
  value: { stdout, exitCode, stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
})

test('odd read-only git and mentions of "git push" in text pass untouched', async ($, on) => {
  on('session.cwd', () => ({ value: CWD }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', () => ok('', 1))
  for (const command of [
    'git -c core.fsmonitor=false --bare log --oneline -3',
    'grep -n "git push" README.md',
    'echo "remember to git push later"',
    `cd "${REPO}"; git status`,
  ])
    expect((await $.tool.call({ tool: 'Bash', command })).deny).toBeUndefined()
})

test('a push hidden in a wrapper is refused with a clear message', async ($, on) => {
  on('session.cwd', () => ({ value: CWD }))
  on('tool.call', () => ({ result: {} as never }))
  for (const command of ['bash -lc "cd x && git push"', 'env GIT_TRACE=1 git commit -m wip'])
    expect((await $.tool.call({ tool: 'Bash', command })).deny).toMatch(/sin envolverlo/)
})

test('an unreachable remote falls back to the commits fetched from it', async ($, on) => {
  const tip = 'a'.repeat(40)
  const seen: string[] = []
  on('session.cwd', () => ({ value: REPO }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', ($, e) => {
    const args = e.argv.join(' ')
    seen.push(args)
    if (args.includes('ls-remote')) return ok('', 128) // ssh: Permission denied (publickey)
    if (args.includes('refs/remotes/origin/')) return ok(`${tip} refs/remotes/origin/master\n`)
    if (args.includes('cat-file')) return ok(`${tip} commit\n`)
    if (args.includes('rev-parse --verify')) return ok(`${tip}\n`)
    if (args.includes('symbolic-ref')) return ok('master\n')
    if (args.includes('rev-list --count')) return ok('0\n')
    if (args.includes('config --get')) return ok('', 1)
    return ok()
  })
  const r = await $.tool.call({ tool: 'Bash', command: 'git push origin master' })
  expect(r.deny).toBeUndefined()
  expect(seen.some((a) => a.includes(`^${tip}`))).toBe(true)
})
