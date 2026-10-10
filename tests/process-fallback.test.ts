// A session whose process launcher broke (`$.process.run(git) failed to start: … this.#handle`).
import { expect, test } from 'claude-code/testing'

const BROKEN = "$.process.run(git) failed to start: undefined is not an object (evaluating 'this.#handle')"
const REPO = 'C:\\work\\repo'

const answer = (argv: readonly string[]) => {
  const args = argv.join(' ')
  if (args.includes('rev-parse --git-dir')) return { text: '.git\n', code: 0 }
  if (args.includes('rev-parse --verify')) return { text: 'a'.repeat(40) + '\n', code: 0 }
  return { text: '', code: 0 } // an empty staged diff: nothing to report
}

test('a broken process.run falls back to spawn and the check completes', async ($, on) => {
  let spawned = 0
  on('session.cwd', () => ({ value: REPO }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', () => ({ deny: BROKEN }))
  on('process.spawn', async function* ($, e) {
    spawned++
    const { text, code } = answer(e.argv)
    if (text) yield { stream: 'stdout' as const, text }
    return { value: { code, signal: null } }
  })
  const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m wip' })
  expect(r.deny).toBeUndefined()
  expect(spawned > 0).toBe(true)
})

test('when no process can start, the block says so and how to get out of it', async ($, on) => {
  on('session.cwd', () => ({ value: REPO }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', () => ({ deny: BROKEN }))
  on('process.spawn', async function* () {
    return { deny: BROKEN }
  })
  const r = await $.tool.call({ tool: 'Bash', command: 'git push origin master' })
  expect(r.deny).toMatch(/no consigue arrancar procesos en esta sesión/)
  expect(r.deny).toMatch(/Abre una sesión nueva/)
})

test('git running and failing is not mistaken for a launcher fault', async ($, on) => {
  let spawned = 0
  on('session.cwd', () => ({ value: REPO }))
  on('tool.call', () => ({ result: {} as never }))
  on('process.run', () => ({ deny: 'Git unavailable' }))
  on('process.spawn', async function* () {
    spawned++
    return { value: { code: 0, signal: null } }
  })
  const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m wip' })
  expect(r.deny).toMatch(/no he podido revisar/)
  expect(spawned).toBe(0)
})
