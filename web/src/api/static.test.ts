import { describe, expect, it } from 'vitest'
import { narrow, slug, staticPath } from './static'
import type { RunRow, Runs } from './schemas'

const row = (over: Partial<RunRow>): RunRow => ({
  run_id: `sha256:${'a'.repeat(64)}`,
  case_id: 'A1-a-05',
  task_id: 'benign-13',
  config: 'undefended',
  dataset: 'batch_a',
  class: 'A1',
  technique: 'semantic_persuasion',
  batch: 'a',
  injection_point: 'product.description',
  attacker_win: true,
  task_success: false,
  poisoned: null,
  error: null,
  outcome: 'attacker_win',
  reason_codes: [],
  net_debit_paise: 4000,
  mandates_opened: 0,
  chain_entries: 0,
  chain_head: null,
  counterparts: {},
  ...over,
})

const body = (rows: RunRow[]): Runs => ({
  schema: 'mandate.web.runs/1',
  total: rows.length,
  limit: rows.length,
  cursor: 0,
  next_cursor: null,
  filters: {},
  sort: null,
  rows,
})

describe('staticPath', () => {
  it('maps each endpoint onto the file the export writes', () => {
    expect(staticPath('health', {})).toBe('api/health.json')
    expect(staticPath('results', { matrix: 'runs/m6', dataset: 'batch_a' })).toBe(
      'api/results/runs-m6/batch_a.json',
    )
    const id = `sha256:${'b'.repeat(64)}`
    expect(staticPath(`runs/${id}`, {})).toBe(`api/runs/sha256-${'b'.repeat(64)}.json`)
    expect(staticPath(`runs/${id}/chain`, {})).toBe(
      `api/runs/sha256-${'b'.repeat(64)}/chain.json`,
    )
  })

  it('has no static form for the live demo', () => {
    // There is no kernel behind a static file, and a demo that cannot get a
    // decision must not show one.
    expect(staticPath('demo/run', {})).toBeNull()
    expect(staticPath('tasks', {})).toBeNull()
    expect(staticPath('attacks', {})).toBeNull()
  })

  it('slugs a run id the same way the Python export does', () => {
    expect(slug('sha256:abc')).toBe('sha256-abc')
    expect(slug('runs/m6')).toBe('runs-m6')
  })
})

describe('narrow', () => {
  const rows = [
    row({ run_id: 'sha256:1', config: 'undefended', class: 'A1', outcome: 'attacker_win' }),
    row({ run_id: 'sha256:2', config: 'kernel', class: 'A1', outcome: 'blocked' }),
    row({ run_id: 'sha256:3', config: 'kernel', class: 'A2', outcome: 'blocked' }),
    row({ run_id: 'sha256:4', config: 'kernel', class: 'A2', outcome: 'poisoned' }),
  ]

  it('narrows to the view the video opens: one class, one arm', () => {
    const out = narrow(body(rows), { class: 'A1', config: 'undefended' })
    expect(out.rows.map((r) => r.run_id)).toEqual(['sha256:1'])
    expect(out.total).toBe(1)
  })

  it('ands every filter together', () => {
    expect(narrow(body(rows), { config: 'kernel' }).total).toBe(3)
    expect(narrow(body(rows), { config: 'kernel', class: 'A2' }).total).toBe(2)
    expect(narrow(body(rows), { config: 'kernel', class: 'A2', outcome: 'blocked' }).total).toBe(1)
  })

  it('does not fold a poisoned run into a blocked one', () => {
    // The static path must partition outcomes exactly as the server does.
    expect(narrow(body(rows), { outcome: 'poisoned' }).total).toBe(1)
    expect(narrow(body(rows), { outcome: 'blocked' }).total).toBe(2)
  })

  it('paginates with the same cursor contract as the API', () => {
    const first = narrow(body(rows), { limit: 2, cursor: 0 })
    expect(first.rows).toHaveLength(2)
    expect(first.next_cursor).toBe(2)
    const second = narrow(body(rows), { limit: 2, cursor: 2 })
    expect(second.rows).toHaveLength(2)
    expect(second.next_cursor).toBeNull()
  })

  it('returns everything when nothing is filtered', () => {
    expect(narrow(body(rows), {}).total).toBe(4)
  })
})
