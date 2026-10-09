import { describe as group, expect, test } from 'claude-code/testing'
import {
  commandDir,
  diffScanner,
  dirname,
  isDeploy,
  isLocalEnvFile,
  isSensitiveFile,
  redact,
  scan,
} from '../hooks/rules'
import { DB_URL, GITHUB, GOOGLE, HARDCODED, OPENAI, PEM, STRIPE, jwt } from './fixtures'

const rules = (text: string) => scan(text).map((f) => f.rule)

group('scan', () => {
  test('finds provider keys by their prefix', () => {
    expect(rules(`const s = "${STRIPE}"`)).toEqual(['stripe-secret'])
    expect(rules(`token: ${GITHUB}`)).toEqual(['github-token'])
    expect(rules(`OPENAI_API_KEY=${OPENAI}`)).toEqual(['openai-key'])
    expect(rules(PEM)).toEqual(['private-key'])
  })

  test('reports a secret once even when two rules match it', () => {
    expect(rules(`const apiKey = "${STRIPE}"`)).toEqual(['stripe-secret'])
  })

  test('tells the Supabase service_role JWT from the public anon one', () => {
    expect(rules(`const key = '${jwt('service_role')}'`)).toEqual(['supabase-service-role'])
    expect(rules(`const key = '${jwt('anon')}'`)).toEqual([])
  })

  test('flags remote connection strings, not local dev databases', () => {
    expect(rules(`DATABASE_URL=${DB_URL}`)).toEqual(['connection-string'])
    expect(rules('DATABASE_URL=postgres://postgres:postgres@localhost:5432/app')).toEqual([])
    expect(rules('DATABASE_URL=postgres://app:Xk29fLq8Zr@db:5432/app')).toEqual([])
  })

  test('flags high-entropy values assigned to secret-looking names', () => {
    expect(rules(`const apiKey = "${HARDCODED}"`)).toEqual(['hardcoded-secret'])
    expect(rules('const apiKey = process.env.API_KEY')).toEqual([])
    expect(rules('const tokenUrl = "https://auth.acme.dev/oauth/token2"')).toEqual([])
    expect(rules('password: "correct horse battery staple"')).toEqual([])
    expect(rules('const secretName = "STRIPE_SECRET_KEY_2"')).toEqual([])
  })

  test('ignores placeholders but still scans lines marked secret-guard:allow', () => {
    // Assembled: even a placeholder in Stripe's exact format trips GitHub push protection.
    expect(rules(`STRIPE_KEY=${['sk', 'live', 'x'.repeat(24)].join('_')}`)).toEqual([])
    expect(rules('apiKey: "your-api-key-goes-here-123"')).toEqual([])
    expect(rules(`apiKey: "${GOOGLE}", // secret-guard:allow (Firebase web config)`)).toEqual([
      'google-api-key',
    ])
  })

  test('flags secrets behind a public frontend prefix, with a hint', () => {
    const [f] = scan(['VITE_', 'STRIPE_SECRET_KEY=abc'].join(''))
    expect(f?.rule).toBe('public-env-secret')
    expect(f?.hint).toMatch(/servidor/)
    expect(rules('VITE_SUPABASE_ANON_KEY=abc')).toEqual([])
  })

  test('never echoes the secret in a finding', () => {
    const [f] = scan(`x = "${STRIPE}"`)
    expect(f?.preview.includes(STRIPE)).toBe(false)
    expect(f?.line).toBe(1)
  })
})

group('redact', () => {
  test('masks values and keeps the rest of the text', () => {
    const r = redact(`A=1\nSTRIPE_KEY=${STRIPE}\nB=2`)
    expect(r.count).toBe(1)
    expect(r.text).toBe('A=1\nSTRIPE_KEY=[REDACTED:stripe-secret]\nB=2')
  })

  test('leaves clean text untouched and never masks a variable name', () => {
    expect(redact('hello').count).toBe(0)
    expect(redact(['VITE_', 'ADMIN_PASSWORD=x'].join('')).count).toBe(0)
  })
})

group('diffScanner', () => {
  test('scans added lines only, with file and new line number', () => {
    const s = diffScanner()
    const diff = [
      'diff --git a/src/pay.ts b/src/pay.ts',
      '--- a/src/pay.ts',
      '+++ b/src/pay.ts',
      '@@ -10,0 +11,2 @@',
      '+const ok = 1',
      `+const key = "${STRIPE}"`,
      `-const old = "${GITHUB}"`,
    ]
    diff.forEach(s.line)
    expect(s.findings.map((f) => [f.rule, f.file, f.line])).toEqual([['stripe-secret', 'src/pay.ts', 12]])
  })
})

group('files', () => {
  test('local env files vs committed templates', () => {
    expect(isLocalEnvFile('/app/.env')).toBe(true)
    expect(isLocalEnvFile('/app/.env.production.local')).toBe(true)
    expect(isLocalEnvFile('/app/.env.example')).toBe(false)
  })

  test('credential files by name', () => {
    expect(isSensitiveFile('keys/id_ed25519')).toBe(true)
    expect(isSensitiveFile('keys/id_ed25519.pub')).toBe(false)
    expect(isSensitiveFile('infra/terraform.tfstate')).toBe(true)
    expect(isSensitiveFile('my-app-firebase-adminsdk-x1.json')).toBe(true)
    expect(isSensitiveFile('src/firebase.ts')).toBe(false)
  })
})

group('commands', () => {
  test('deploys', () => {
    for (const cmd of [
      'npx vercel --prod',
      'vercel',
      'cd web && netlify deploy --prod',
      'npm run deploy',
      'pnpm publish',
      'wrangler deploy',
    ])
      expect(isDeploy(cmd)).toBe(true)
    for (const cmd of ['cat vercel.json', 'vercel env pull', 'npm run build', 'firebase emulators:start'])
      expect(isDeploy(cmd)).toBe(false)
  })

  test('the directory a command works in', () => {
    expect(commandDir('cd apps/web && vercel --prod')).toBe('apps/web')
    expect(commandDir('git -C "my repo" push')).toBe('my repo')
    expect(commandDir('git push')).toBeUndefined()
  })
})

group('regressions', () => {
  test('dirname handles a relative env path and drive roots', () => {
    expect(dirname('.env')).toBe('.')
    expect(dirname('/.env')).toBe('/')
    expect(dirname('C:\\.env')).toBe('C:\\')
    expect(dirname('src/config.ts')).toBe('src')
  })

  test('redacts a complete or truncated private key body', () => {
    const header = ['-----BEGIN ', 'PRIVATE KEY-----'].join('')
    const body = 'MIIE0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    expect(redact(`${header}\n${body}\n-----END PRIVATE KEY-----\nOK`).text).toBe(
      '[REDACTED:private-key]\nOK',
    )
    expect(redact(`${header}\n${body}`).text).toBe('[REDACTED:private-key]')
  })

  test('an allow comment does not send a secret back to the model', () => {
    expect(redact(`KEY=${STRIPE} # secret-guard:allow`).text.includes(STRIPE)).toBe(false)
  })
})
