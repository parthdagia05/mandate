import { describe, expect, it } from 'vitest'
import { buildHash, parseHash } from './router'

describe('the URL carries every filter', () => {
  it('round-trips a filtered run list', () => {
    // The exact view Shot 4 opens: "filter class A1, arm undefended".
    const hash = buildHash(['runs'], { config: 'undefended', class: 'A1' })
    expect(hash).toBe('#/runs?config=undefended&class=A1')
    expect(parseHash(hash)).toEqual({
      segments: ['runs'],
      params: { config: 'undefended', class: 'A1' },
    })
  })

  it('round-trips a run id without mangling its colon', () => {
    const runId = `sha256:${'a'.repeat(64)}`
    const hash = buildHash(['runs', runId])
    expect(parseHash(hash).segments).toEqual(['runs', runId])
  })

  it('round-trips a compare pair', () => {
    const left = `sha256:${'1'.repeat(64)}`
    const right = `sha256:${'2'.repeat(64)}`
    expect(parseHash(buildHash(['compare', left, right])).segments).toEqual([
      'compare',
      left,
      right,
    ])
  })

  it('drops empty filters rather than writing blank ones', () => {
    expect(buildHash(['runs'], { config: 'kernel', class: '', outcome: undefined })).toBe(
      '#/runs?config=kernel',
    )
  })

  it('treats an empty hash as the root', () => {
    expect(parseHash('')).toEqual({ segments: [], params: {} })
    expect(parseHash('#')).toEqual({ segments: [], params: {} })
    expect(parseHash('#/')).toEqual({ segments: [], params: {} })
  })
})
