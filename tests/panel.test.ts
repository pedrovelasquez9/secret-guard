import { expect, test } from 'claude-code/testing'
import { INITIAL, HISTORY_LIMIT, appendEvent, metadata } from '../hooks/panel-model'
import { STRIPE } from './fixtures'

test('dashboard metadata excludes values, commands and sensitive path segments', () => {
  const entry = metadata({
    tool: 'Write',
    file_path: `/app/${STRIPE}.ts`,
    content: `const key = '${STRIPE}'`,
  })
  expect(JSON.stringify(entry).includes(STRIPE)).toBe(false)
  expect(entry.file).toBe('[ruta ocultada]')
  expect(entry.rules).toEqual(['stripe-secret'])
  expect(metadata({ tool: 'Bash', command: `echo ${STRIPE}` }).tool).toBe('Bash')
  expect(metadata({ tool: `mcp__${STRIPE}` }).tool).toBe('MCP')
})

test('history is bounded and keeps a block after a later allowed call', () => {
  const blocked = appendEvent(INITIAL, { outcome: 'blocked', tool: 'Write', rules: [], count: 0 })
  const allowed = appendEvent(blocked, { outcome: 'allowed', tool: 'Write', rules: [], count: 0 })
  expect(allowed.events.map((e) => e.outcome)).toEqual(['allowed', 'blocked'])
  // Routine passes never evict incidents: only the latest pass is kept.
  let state = allowed
  for (let i = 0; i < 40; i++)
    state = appendEvent(state, { outcome: 'allowed', tool: 'Bash', rules: [], count: 0 })
  expect(state.events.map((e) => e.outcome)).toEqual(['allowed', 'blocked'])
  expect(state.sequence).toBe(42)
  // Incidents themselves stay bounded.
  for (let i = 0; i < 40; i++)
    state = appendEvent(state, { outcome: 'blocked', tool: 'Write', rules: [], count: 0 })
  expect(state.events.length).toBe(HISTORY_LIMIT)
})

test('blocked call, correction and history render on terminal and desktop', async ($, on) => {
  let runs = 0
  on('tool.call', () => {
    runs++
    return { result: {} as never }
  })
  const blocked = await $.tool.call({
    tool: 'Write',
    file_path: '/demo/payments.ts',
    content: `const key = '${STRIPE}'`,
  })
  expect(blocked.deny).toMatch(/secret-guard/)
  expect(runs).toBe(0)
  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({
      plugin: 'secret-guard',
      surface,
      component: 'Pane',
      requestId: 'secret-guard',
      props: {
        title: 'Test',
        isFocused: true,
        bodyColumns: 100,
        placement: 'dock',
        scroll: { offset: 0, bodyRows: 50 },
        view: {},
      },
    })
    expect(await ui.find({ type: 'Text', text: /#1 · Acción bloqueada/ })).toBeDefined()
    expect(JSON.stringify(await ui.drawn()).includes(STRIPE)).toBe(false)
    expect(await ui.find({ type: 'Text', text: /payments.ts/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /stripe-secret/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: STRIPE })).toBeUndefined()
    await ui.press({ key: 'history' })
    expect(await ui.find({ key: 'event-1' })).toBeDefined()
    await ui.press({ key: 'event-1' })
    expect(await ui.find({ type: 'Text', text: /variable de entorno/ })).toBeDefined()
    await ui.unmount()
  }
  const allowed = await $.tool.call({
    tool: 'Write',
    file_path: '/demo/payments.ts',
    content: 'const key = process.env.STRIPE_SECRET_KEY',
  })
  expect(allowed.deny).toBeUndefined()
  expect(runs).toBe(1)
  const ui = await $.ui.mount({
    plugin: 'secret-guard',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'secret-guard',
    props: {
      title: 'Test',
      isFocused: true,
      bodyColumns: 100,
      placement: 'dock',
      scroll: { offset: 0, bodyRows: 50 },
      view: {},
    },
  })
  await ui.press({ key: 'latest' })
  expect(await ui.find({ type: 'Text', text: /Comprobación superada/ })).toBeDefined()
  await ui.press({ key: 'history' })
  await ui.press({ key: 'event-1' })
  expect(await ui.find({ type: 'Text', text: /Acción bloqueada/ })).toBeDefined()
  await ui.unmount()
})

test('failure to open a panel never permits a blocked write', async ($, on) => {
  let runs = 0
  on('tool.call', () => {
    runs++
    return { result: {} as never }
  })
  on('ui.open', () => ({ deny: 'no panel available' }))
  const result = await $.tool.call({ tool: 'Write', file_path: '/demo/a.ts', content: STRIPE })
  expect(result.deny).toMatch(/no escribo secretos/)
  expect(runs).toBe(0)
})

test('a dashboard state failure cannot disable the guard', async ($, on) => {
  let runs = 0
  on('state.set', () => ({ deny: 'dashboard unavailable' }))
  on('tool.call', () => {
    runs++
    return { result: {} as never }
  })
  const result = await $.tool.call({ tool: 'Write', file_path: '/demo/a.ts', content: STRIPE })
  expect(result.deny).toMatch(/no escribo secretos/)
  expect(runs).toBe(0)
})

test('Git inspection failures are visible as incomplete checks', async ($, on) => {
  on('process.run', () => ({ deny: 'Git unavailable' }))
  expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main' })).deny).toMatch(
    /no he podido revisar/,
  )
  const ui = await $.ui.mount({
    plugin: 'secret-guard',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'secret-guard',
    props: {
      title: 'Test',
      isFocused: true,
      bodyColumns: 100,
      placement: 'dock',
      scroll: { offset: 0, bodyRows: 50 },
      view: {},
    },
  })
  expect(await ui.find({ type: 'Text', text: /revisión incompleta/ })).toBeDefined()
  await ui.unmount()
})

test('redaction is recorded without retaining its content', async ($, on) => {
  let stored = ''
  on('session.append', ($, e, next) => {
    stored = JSON.stringify(e.message.content)
    return next(e)
  })
  await $.session.append({
    door: 'tool-result',
    origin: { kind: 'tool', tool: 'Bash' } as never,
    uuid: 'redaction-demo',
    message: {
      type: 'user',
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: 'call-1', content: STRIPE }],
    },
  })
  expect(stored.includes(STRIPE)).toBe(false)
  const ui = await $.ui.mount({
    plugin: 'secret-guard',
    surface: 'desktop',
    component: 'Pane',
    requestId: 'secret-guard',
    props: {
      title: 'Test',
      isFocused: true,
      bodyColumns: 100,
      placement: 'dock',
      scroll: { offset: 0, bodyRows: 50 },
      view: {},
    },
  })
  expect(await ui.find({ type: 'Text', text: /Resultado enmascarado/ })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: STRIPE })).toBeUndefined()
  await ui.unmount()
})

test('the slash command opens the panel and reports an unavailable surface honestly', async ($, on) => {
  on('ui.open', () => ({ value: { isPlaced: false, reason: 'test' } as never }))
  expect(
    (
      await $.command.run({
        command: 'secret-guard',
        args: '',
        origin: { kind: 'composer' },
        presentation: { isFullscreen: true, columns: 120 },
      })
    ).text,
  ).toMatch(/no se pudo mostrar/)
})
