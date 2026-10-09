import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'
import { HARDCODED, STRIPE } from './fixtures'

// The test's own hooks sit beneath the plugin and stand for the engine: a
// tool that "ran", and a git whose answers each test chooses.
const toolRuns = (on: On) => {
  on('session.cwd', () => ({ value: '/app' }))
  return on('tool.call', () => ({ result: {} as never }))
}

const fakeGit = (on: On, answers: { checkIgnore?: number; diff?: string; isRepo?: boolean }) => {
  on('process.run', ($, e) => {
    const args = e.argv.join(' ')
    const exitCode = args.includes('config')
      ? 1
      : args.includes('check-ignore')
        ? (answers.checkIgnore ?? 1)
        : args.includes('rev-parse') && answers.isRepo === false
          ? 128
          : 0
    const stdout = args.includes('rev-parse --verify')
      ? 'a'.repeat(40)
      : args.includes('rev-list')
        ? '1'
        : args.includes('diff -') || args.includes('log --root -m -p')
          ? (answers.diff ?? '')
          : ''
    return { value: { exitCode, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })
  on('process.spawn', async function* () {
    if (answers.diff) yield { stream: 'stdout' as const, text: answers.diff }
    return { value: { code: 0, signal: null } }
  })
}

test('Write with a live Stripe key is refused, and the key is not echoed', async ($, on) => {
  toolRuns(on)
  const r = await $.tool.call({
    tool: 'Write',
    file_path: '/app/src/pay.ts',
    content: `const stripe = "${STRIPE}"`,
  })
  expect(r.deny).toMatch(/secret-guard: no escribo secretos en pay\.ts/)
  expect(r.deny?.includes(STRIPE)).toBe(false)
})

test('Edit with a hardcoded secret is refused; clean code goes through', async ($, on) => {
  toolRuns(on)
  const bad = await $.tool.call({
    tool: 'Edit',
    file_path: '/app/src/api.ts',
    old_string: 'a',
    new_string: `const apiKey = "${HARDCODED}"`,
  })
  expect(bad.deny).toMatch(/Secreto escrito a mano/)
  const ok = await $.tool.call({
    tool: 'Edit',
    file_path: '/app/src/api.ts',
    old_string: 'a',
    new_string: 'const apiKey = process.env.API_KEY',
  })
  expect(ok.deny).toBeUndefined()
})

test('a secret may go into a .env file only while git ignores it', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { checkIgnore: 0 })
  const ignored = await $.tool.call({
    tool: 'Write',
    file_path: '/app/.env.local',
    content: `STRIPE_KEY=${STRIPE}`,
  })
  expect(ignored.deny).toBeUndefined()
})

test('a .env file git would commit is refused', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { checkIgnore: 1 })
  const r = await $.tool.call({ tool: 'Write', file_path: '/app/.env', content: `STRIPE_KEY=${STRIPE}` })
  expect(r.deny).toMatch(/no está en \.gitignore/)
})

test('a Git error never authorizes writing a secret to an env file', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { checkIgnore: 128 })
  const r = await $.tool.call({ tool: 'Write', file_path: '.env', content: `STRIPE_KEY=${STRIPE}` })
  expect(r.deny).toMatch(/no está en \.gitignore/)
})

test('an unreadable deploy source refuses deployment', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { isRepo: false })
  on('fs.list', () => ({ value: [{ name: 'app.js', kind: 'file', size: 1, mtimeMs: 0, isLink: false }] }))
  on('fs.read', () => {
    throw new Error('access denied')
  })
  expect((await $.tool.call({ tool: 'Bash', command: 'vercel --prod' })).deny).toMatch(/no he podido revisar/)
})

test('a directory listing failure refuses deployment', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { isRepo: false })
  on('fs.list', () => {
    throw new Error('access denied')
  })
  expect((await $.tool.call({ tool: 'Bash', command: 'vercel --prod' })).deny).toMatch(/no he podido revisar/)
})

test('truncated Git metadata refuses a commit', async ($, on) => {
  toolRuns(on)
  on('process.run', ($, e) => ({
    value: {
      exitCode: 0,
      stdout: '',
      stderr: '',
      isStdoutTruncated: e.argv.includes('--name-only'),
      isStderrTruncated: false,
    },
  }))
  on('process.spawn', async function* () {
    return { value: { code: 0, signal: null } }
  })
  expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toMatch(
    /no he podido revisar/,
  )
})

test('writing back masked markers is refused so real values are not wiped', async ($, on) => {
  toolRuns(on)
  const r = await $.tool.call({
    tool: 'Write',
    file_path: '/app/.env',
    content: 'STRIPE_KEY=[REDACTED:stripe-secret]',
  })
  expect(r.deny).toMatch(/marcadores/)
})

test('a commit whose staged diff adds a secret is refused, naming file and line', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { diff: `--- a/src/pay.ts\n+++ b/src/pay.ts\n@@ -0,0 +7 @@\n+const k = "${STRIPE}"\n` })
  const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m "add payments"' })
  expect(r.deny).toMatch(/El commit contiene secretos/)
  expect(r.deny).toMatch(/src\/pay\.ts:7/)
})

test('a clean push goes through', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { diff: '--- a/a.ts\n+++ b/a.ts\n@@ -0,0 +1 @@\n+const a = 1\n' })
  expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main' })).deny).toBeUndefined()
})

test('a Git repository inspection error refuses a push', async ($, on) => {
  toolRuns(on)
  fakeGit(on, { isRepo: false })
  expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main' })).deny).toMatch(
    /no he podido revisar/,
  )
})

test('a secret typed inline in a shell command is refused', async ($, on) => {
  toolRuns(on)
  const r = await $.tool.call({
    tool: 'Bash',
    command: `curl https://api.stripe.com/v1/charges -u ${STRIPE}:`,
  })
  expect(r.deny).toMatch(/el comando lleva un secreto en claro/)
})

test('tool output is masked before the model reads it', async ($, on) => {
  let stored = ''
  on('session.append', { door: 'tool-result' }, ($, e, next) => {
    stored = JSON.stringify(e.message.content)
    return next(e)
  })
  await $.session.append({
    door: 'tool-result',
    origin: { kind: 'tool', tool: 'Bash' } as never,
    uuid: 'row-1',
    message: {
      type: 'user',
      role: 'user',
      content: [
        { type: 'tool_result', tool_use_id: 'call-1', content: `NODE_ENV=dev\nSTRIPE_KEY=${STRIPE}` },
      ],
    },
  })
  expect(stored.includes(STRIPE)).toBe(false)
  expect(stored).toMatch(/STRIPE_KEY=\[REDACTED:stripe-secret\]/)
})
