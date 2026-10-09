import { expect, test } from 'claude-code/testing'
import { STRIPE, HARDCODED } from './fixtures'
const result = (stdout = '', exitCode = 0) => ({
  value: { stdout, exitCode, stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
})
const diff = `--- a/src/a.ts\n+++ b/src/a.ts\n@@ -0,0 +1 @@\n+const k = '${STRIPE}'\n`
for (const tool of ['WebFetch', 'mcp__demo__send'] as const)
  test(tool + ' cannot bypass scanning through unrelated allow field', async ($, on) => {
    on('tool.call', () => ({ result: {} as never }))
    const input =
      tool === 'WebFetch'
        ? { tool, url: 'https://acme.test', prompt: `secret-guard:allow ${STRIPE}` }
        : { tool, note: 'secret-guard:allow', token: STRIPE }
    expect((await $.tool.call(input as never)).deny).toMatch(/no envío secretos/)
    expect(
      (
        await $.tool.call(
          (tool === 'WebFetch'
            ? { tool, url: 'https://acme.test', prompt: 'clean' }
            : { tool, note: 'clean' }) as never,
        )
      ).deny,
    ).toBeUndefined()
  })
test('deploy sees real matches in an uploaded source and ignored build', async ($, on) => {
  on('session.cwd', () => ({ value: '/repo' }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', ($, e) => result(e.argv.includes('ls-files') ? 'src/a.ts\0' : ''))
  on('fs.exists', ($, e) => ({ value: true }))
  on('fs.list', () => ({ value: [{ name: 'bundle.js', kind: 'file', size: 1, mtimeMs: 0, isLink: false }] }))
  on('fs.read', () => ({ value: `const key='${STRIPE}'` }))
  expect((await $.tool.call({ tool: 'Bash', command: 'vercel --yes' })).deny).toMatch(
    /El deploy contiene secretos/,
  )
})
test('current session cwd after cd is used for Git and aliases', async ($, on) => {
  let cwd = '/first'
  const inspected: string[] = []
  on('session.cwd', () => ({ value: cwd }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', ($, e) => {
    inspected.push(e.init?.cwd ?? 'missing')
    if (e.argv.includes('alias.ci')) return result('commit')
    if (e.argv.includes('config')) return result('', 1)
    return result(e.argv.includes('-U0') ? diff : '')
  })
  cwd = '/second'
  expect((await $.tool.call({ tool: 'Bash', command: 'git.exe --no-pager ci -m check' })).deny).toMatch(
    /El commit contiene secretos/,
  )
  expect(inspected.every((p) => p === '/second')).toBe(true)
})
test('path commit scans working tree paths, not unrelated staged data', async ($, on) => {
  on('session.cwd', () => ({ value: '/repo' }))
  on('tool.call', () => ({ result: {} as never }))
  let args: readonly string[] = []
  on('process.run', ($, e) => {
    if (e.argv.includes('config')) return result('', 1)
    if (e.argv.includes('-U0')) {
      args = e.argv
      return result(diff)
    }
    return result()
  })
  expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m check -- src/a.ts' })).deny).toMatch(
    /El commit contiene secretos/,
  )
  expect(args.includes('HEAD')).toBe(true)
  expect(args.includes('--cached')).toBe(false)
  expect(args.includes('src/a.ts')).toBe(true)
})
test('forced add and masked writes from shell are refused', async ($, on) => {
  on('session.cwd', () => ({ value: '/repo' }))
  on('process.run', () => result('', 1))
  on('tool.call', () => ({ result: {} as never }))
  expect((await $.tool.call({ tool: 'Bash', command: 'git add -f .env' })).deny).toMatch(/force/)
  expect(
    (await $.tool.call({ tool: 'Bash', command: "echo '[REDACTED:env-secret]' > config" })).deny,
  ).toMatch(/marcadores/)
})
test('push excludes destination history, accepts stderr redirection and bounds new commits', async ($, on) => {
  on('session.cwd', () => ({ value: '/repo' }))
  on('tool.call', () => ({ result: {} as never }))
  const remote = 'b'.repeat(40)
  const local = 'a'.repeat(40)
  let log: readonly string[] = []
  let count = '1'
  on('process.run', ($, e) => {
    const a = e.argv
    if (a.includes('config')) return result('', 1)
    if (a.includes('ls-remote')) return result(remote + '\trefs/heads/main\n')
    if (a.includes('--verify')) return result(local)
    if (a.includes('cat-file')) return result(remote + ' commit\n')
    if (a.includes('rev-list')) return result(count)
    if (a.includes('-p')) log = a
    return result()
  })
  expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main 2>&1' })).deny).toBeUndefined()
  expect(log.includes('^' + remote)).toBe(true)
  expect(log.includes('--root')).toBe(true)
  expect(log.includes('-m')).toBe(true)
  count = '501'
  expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main' })).deny).toMatch(/500/)
})
test('unquoted generic value is masked by the real append hook', async ($, on) => {
  let content = ''
  on('session.append', ($, e, next) => {
    content = JSON.stringify(e.message.content)
    return next(e)
  })
  await $.session.append({
    door: 'tool-result',
    origin: { kind: 'tool', tool: 'Bash' } as never,
    uuid: 'env-test',
    message: {
      type: 'user',
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: 'x', content: `JWT_SECRET=${HARDCODED}\nOK=1` }],
    },
  })
  expect(content.includes(HARDCODED)).toBe(false)
  expect(content.includes('OK=1')).toBe(true)
})
