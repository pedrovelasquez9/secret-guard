import { expect, test } from 'claude-code/testing'
import { RULES, scan, redact, isDeploy } from '../hooks/rules'
import { gitCalls, pushPlan, commitPlan } from '../hooks/commands'
import { STRIPE, HARDCODED, PEM, GOOGLE, jwt } from './fixtures'
const join = (...s: string[]) => s.join('')
const samples: Record<string, string> = {
  'private-key': PEM,
  'aws-access-key': join('AK', 'IA', 'A1B2C3D4E5F6G7H8'),
  'aws-secret-key': join('aws_secret_access_key=', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7d'),
  'github-token': join('gh', 'p_', 'aB3'.repeat(12)),
  'gitlab-token': join('gl', 'pat-', 'aB3'.repeat(8)),
  'slack-token': join('xox', 'b-', 'aB3'.repeat(8)),
  'slack-webhook': join('https://hooks.slack.com/', 'services/', 'aB3'.repeat(8)),
  'discord-webhook': join('https://discord.com/api/', 'webhooks/123456/', 'aB3'.repeat(8)),
  'stripe-secret': STRIPE,
  'stripe-webhook': join('wh', 'sec_', 'aB3'.repeat(8)),
  'openai-key': join('sk-', 'proj-', 'aB3'.repeat(8)),
  'anthropic-key': join('sk-', 'ant-api03-', 'aB3'.repeat(8)),
  'google-api-key': GOOGLE,
  'google-oauth-secret': join('GOC', 'SPX-', 'aB3'.repeat(9), 'q'),
  'huggingface-token': join('h', 'f_', 'aBcD'.repeat(8), 'Ef'),
  'sendgrid-key': join('SG.', 'aB3'.repeat(7), 'q.', 'aB3'.repeat(14), 'q'),
  'npm-token': join('n', 'pm_', 'aB3'.repeat(12)),
  'supabase-secret': join('sb_', 'secret_', 'aB3'.repeat(8)),
  'supabase-service-role': jwt('service_role'),
  'connection-string': join('postgres://app:', HARDCODED, '@db.acme.net/a'),
  'bearer-token': join('Bearer ', 'aB3'.repeat(8)),
  'public-env-secret': join('VITE_', 'ADMIN_PASSWORD=x'),
  'hardcoded-secret': `apiKey="${HARDCODED}"`,
  'env-secret': `JWT_SECRET=${HARDCODED}`,
}
for (const rule of RULES)
  test('positive provider/rule ' + rule.id, () => {
    expect(scan(samples[rule.id] ?? '').some((f) => f.rule === rule.id)).toBe(true)
  })
test('unquoted env secrets redact through cat and printenv text', () => {
  expect(redact(`JWT_SECRET=${HARDCODED}\nOK=1`).text).toBe('JWT_SECRET=[REDACTED:env-secret]\nOK=1')
  expect(scan('JWT_SECRET=$EXISTING_TOKEN')).toEqual([])
})
test('allow content never exempts any rule, including private keys', () => {
  expect(scan(PEM + ' # secret-guard:allow')[0]?.rule).toBe('private-key')
  expect(
    scan(JSON.stringify({ note: 'gitleaks:allow', key: STRIPE })).some((f) => f.rule === 'stripe-secret'),
  ).toBe(true)
})
test('a standalone key header does not swallow subsequent source or logs', () => {
  const text = PEM + '\nconst ok = true\noutput: finished'
  expect(redact(text).text).toBe('[REDACTED:private-key]\nconst ok = true\noutput: finished')
})
test('shell redirection, git.exe, global flags and commit paths', () => {
  const call = gitCalls('git.exe --no-pager push origin main 2>&1', '/actual')[0]!
  expect(call.action).toBe('push')
  expect(pushPlan(call.args).refs).toEqual(['main'])
  expect(commitPlan(['-m', 'message', 'src/a.ts']).paths).toEqual(['src/a.ts'])
  expect(gitCalls('git -C child commit -- src/a.ts', '/actual')[0]?.cwd).toBe('/actual/child')
  for (const cmd of ['vercel --yes', 'vercel ./dist', 'npx vercel deploy --prod', 'vercel.exe --prod'])
    expect(isDeploy(cmd)).toBe(true)
})
import { vercelDirectory } from '../hooks/commands'
test('Vercel upload paths and cwd options select the directory being uploaded', () => {
  expect(vercelDirectory('npx --yes vercel ./dist --yes', '/repo')).toBe('/repo/./dist')
  expect(vercelDirectory('vercel deploy --cwd child --prod', '/repo')).toBe('/repo/child')
  expect(isDeploy('npx --yes vercel ./dist --yes')).toBe(true)
  expect(commitPlan(['-am', 'message']).paths).toEqual([])
  expect(gitCalls('cd next', '/repo')).toEqual([])
})
