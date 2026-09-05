/**
 * Reading the export from `file://`. Issue #90.
 *
 * A filesystem has no query strings, so `?matrix=runs/m6&dataset=batch_a` has no
 * static equivalent and `mk web --export` writes a file tree instead. This
 * module maps the API's endpoints onto that tree and, for the run list, filters
 * and paginates the exported list in the page.
 *
 * **That filtering is not a metric.** It selects which rows to show; it derives
 * no proportion, no interval and no count that appears as a figure. Every number
 * on every page still comes from `harness/metrics.py` through
 * `api/results/…json`, byte for byte the same object the server would have sent.
 *
 * Static mode is detected once, by asking for `export.json`. When it is absent
 * the app is being served by `mk web` and nothing here runs.
 */
import type { Runs } from './schemas'

/** `sha256:abc…` → `sha256-abc…`. Mirrors `_slug` in harness/web/export.py. */
export function slug(value: string): string {
  return value.replace(/:/g, '-').replace(/\//g, '-')
}

/**
 * The file an endpoint lives in, or `null` when it has no static form.
 *
 * `demo/run` is deliberately `null`: there is no kernel behind a static file,
 * and the export replaces that page with the reason it is absent.
 */
export function staticPath(
  path: string,
  params: Record<string, string | number | undefined>,
): string | null {
  if (path === 'health') return 'api/health.json'
  if (path === 'facets') return 'api/facets.json'
  if (path === 'matrices') return 'api/matrices.json'
  if (path === 'tasks' || path === 'attacks') return null
  if (path.startsWith('demo/')) return null

  if (path === 'results') {
    const matrix = params['matrix']
    const dataset = params['dataset']
    if (matrix === undefined || dataset === undefined) return null
    return `api/results/${slug(String(matrix))}/${String(dataset)}.json`
  }
  if (path === 'ablation') {
    const dir = params['dir']
    return dir === undefined ? null : `api/ablation/${slug(String(dir))}.json`
  }
  if (path === 'runs') return 'api/runs/all.json'

  const chain = /^runs\/(.+)\/chain$/.exec(path)
  if (chain?.[1]) return `api/runs/${slug(decodeURIComponent(chain[1]))}/chain.json`
  const run = /^runs\/(.+)$/.exec(path)
  if (run?.[1]) return `api/runs/${slug(decodeURIComponent(run[1]))}.json`

  return null
}

/** The filter dimensions the exported run list can be narrowed by. */
const DIMENSIONS = [
  'config',
  'dataset',
  'class',
  'technique',
  'injection_point',
  'batch',
  'outcome',
  'task_id',
  'case_id',
] as const

/**
 * Apply the run list's filters and cursor to the exported list.
 *
 * The served API does this in `RunIndex.filter`; doing it here for the export
 * keeps one page shape rather than two, and the rows are the API's own rows —
 * nothing is recomputed, only chosen.
 */
export function narrow(
  body: Runs,
  params: Record<string, string | number | undefined>,
): Runs {
  const wanted = DIMENSIONS.filter((key) => {
    const value = params[key]
    return value !== undefined && value !== ''
  })

  const matched = body.rows.filter((row) =>
    wanted.every((key) => String(row[key] ?? '') === String(params[key])),
  )

  const limit = Number(params['limit'] ?? 100) || 100
  const cursor = Number(params['cursor'] ?? 0) || 0
  const page = matched.slice(cursor, cursor + limit)

  return {
    ...body,
    total: matched.length,
    limit,
    cursor,
    next_cursor: cursor + limit < matched.length ? cursor + limit : null,
    filters: Object.fromEntries(wanted.map((key) => [key, String(params[key])])),
    rows: page,
  }
}
