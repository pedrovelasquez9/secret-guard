// Node.js 24: checks that synthetic fixtures and source don't trip this guard.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../hooks/rules.ts'
const root = fileURLToPath(new URL('../', import.meta.url))
const findings = []
// GitHub push protection matches provider formats without knowing a placeholder is fake
// (`sk_live_` + 24 x's is rejected): any contiguous provider-format literal fails the check.
const PROVIDER =
  /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{20,}|xox[abposr]-[\w-]{10,}|AIza[\w-]{35}|sk-(?:proj|ant)-[\w-]{20,}|glpat-[\w-]{20}|whsec_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z]{30,}/
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue
    const file = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(file)
    else if (/\.(ts|tsx|md|json|mjs)$/.test(file)) {
      const text = fs.readFileSync(file, 'utf8')
      for (const finding of scan(text))
        findings.push({ file: path.relative(root, file), line: finding.line, rule: finding.rule })
      text.split('\n').forEach((line, i) => {
        if (PROVIDER.test(line)) findings.push({ file: path.relative(root, file), line: i + 1, rule: 'provider-format-literal' })
      })
    }
  }
}
walk(root)
console.log(JSON.stringify(findings, null, 2))
process.exitCode = findings.length ? 1 : 0
