import { expect, test } from 'claude-code/testing'
import { gitCalls, commitPlan, pushPlan } from '../hooks/commands'

test('actual Git parser handles executable names, directories and stderr redirection', () => {
  const [call] = gitCalls('git.exe --no-pager -C "my repo" push -o ci.skip origin feature:main 2>&1', '/work')
  expect(call?.cwd).toBe('/work/my repo')
  expect(call?.action).toBe('push')
  expect(pushPlan(call!.args).refs).toEqual(['feature'])
})
test('commit plans distinguish all tracked changes, amendment and explicit paths', () => {
  expect(commitPlan(['-am', 'message']).all).toBe(true)
  expect(commitPlan(['--amend', '--no-edit']).all).toBe(false)
  expect(commitPlan(['-m', 'message', '--', 'src/app.ts']).paths).toEqual(['src/app.ts'])
})
test('push destination options never replace the intended source ref', () => {
  expect(pushPlan(['--repo', 'origin', 'feature:main']).refs).toEqual(['feature'])
  expect(pushPlan(['--repo=origin', '+feature:main']).refs).toEqual(['feature'])
  expect(pushPlan(['origin', '--tags']).tags).toBe(true)
  expect(pushPlan(['--mirror', 'origin']).mirror).toBe(true)
  expect(pushPlan(['origin', ':old']).deletionOnly).toBe(true)
  expect(() => pushPlan(['origin', 'refs/heads/*:refs/heads/*'])).toThrow()
})
