// Regressions found in the 1.3.0 release review.
import { expect, test } from 'claude-code/testing'
import { commitPlan, gitCalls } from '../hooks/commands'
import { allowedRules, hasMarker, redact, scan } from '../hooks/rules'
import { GOOGLE, STRIPE } from './fixtures'

const marker = (rule: string) => ['[REDACTED', `:${rule}]`].join('')
const allow = () => ({ result: {} as never })

test('a separator inside a commit message does not narrow the commit scan', () => {
  for (const message of ['fix: a; b', 'x | y && z']) {
    const [call, ...rest] = gitCalls(`git commit -m "${message}"`, '/repo')
    expect(rest.length).toBe(0)
    expect(call?.args).toEqual(['-m', message])
    expect(commitPlan(call?.args ?? []).paths).toEqual([])
  }
})

test('only a marker naming a known rule counts as a masked value', () => {
  expect(hasMarker(`KEY=${marker('stripe-secret')}`)).toBe(true)
  expect(hasMarker(`format: ${marker('<rule>')}`)).toBe(false)
  expect(hasMarker(marker('demo'))).toBe(false)
})

test('allowedRules keeps known ids only and switches those rules off everywhere', () => {
  const skip = allowedRules('google-api-key, bogus')
  expect([...skip]).toEqual(['google-api-key'])
  const line = `apiKey: "${GOOGLE}"`
  expect(scan(line).map((f) => f.rule)).toEqual(['google-api-key'])
  expect(scan(line, undefined, skip)).toEqual([])
  expect(redact(line, skip).count).toBe(0)
  expect(scan(`k = "${STRIPE}"`, undefined, skip).map((f) => f.rule)).toEqual(['stripe-secret'])
})

test('the preview never reveals a quarter or more of a short secret', () => {
  const password = ['Ab3d', 'Ef9h'].join('')
  const [finding] = scan(['postgres://app:', password, '@db.acme-prod.net/app'].join(''))
  expect(finding?.rule).toBe('connection-string')
  expect(finding?.preview.startsWith(password.slice(0, 3))).toBe(false)
})

test('a person can allow a rule through settings', { options: { allowedRules: 'google-api-key' } }, async ($, on) => {
  on('tool.call', allow)
  const r = await $.tool.call({ tool: 'Write', file_path: '/app/src/firebase.ts', content: `apiKey: "${GOOGLE}"` })
  expect(r.deny).toBeUndefined()
})

test('the agent cannot switch the guard off or allow its own rules', async ($, on) => {
  on('tool.call', allow)
  on('session.cwd', () => ({ value: '/repo' }))
  for (const command of [
    'claude plugin disable secret-guard@secret-guard',
    'claude plugin install secret-guard@secret-guard --config allowedRules=stripe-secret',
  ])
    expect((await $.tool.call({ tool: 'Bash', command })).deny).toMatch(/solo los cambia una persona/)
  const settings = await $.tool.call({
    tool: 'Write',
    file_path: '/home/u/.claude/settings.json',
    content: '{ "pluginConfigs": { "secret-guard": { "options": { "allowedRules": "stripe-secret" } } } }',
  })
  expect(settings.deny).toMatch(/solo los cambia una persona/)
})

test('git commit/push wrapped in another command is refused, not skipped', async ($, on) => {
  on('tool.call', allow)
  on('session.cwd', () => ({ value: '/repo' }))
  for (const command of ['sh -c "git push origin main"', 'env GIT_TRACE=1 git commit -m wip'])
    expect((await $.tool.call({ tool: 'Bash', command })).deny).toMatch(/sin envolverlo/)
  expect((await $.tool.call({ tool: 'Bash', command: 'echo "git log is fine"' })).deny).toBeUndefined()
})

test('an incomplete check says why it blocked', async ($, on) => {
  on('tool.call', allow)
  on('session.cwd', () => ({ value: '/repo' }))
  on('process.run', () => ({ deny: 'Git unavailable' }))
  const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m wip' })
  expect(r.deny).toMatch(/no he podido revisar esta acción, así que la bloqueo\. Motivo: /)
})
