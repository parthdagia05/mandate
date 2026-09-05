/**
 * Fetching, and the only place a URL is constructed.
 *
 * Every request is relative (`./api/...`), never absolute. Two reasons and both
 * are requirements: the static export has to work from `file://` (#90), and the
 * kernel is reached through `mk web`'s proxy rather than from the browser, so
 * the kernel's loopback peer guard is not widened for a page (#83, #89).
 *
 * Responses are parsed by a zod schema before they are returned. A response
 * that does not match is an error, not a partially rendered page: the run
 * record has near-identical sibling fields — `payee` and `checkout_payee`,
 * `amount_paise` and `captured_paise` — and a page that rendered whatever
 * happened to be there would put the merchant's address where the attacker's
 * belongs.
 */
import type { z } from 'zod'
import { narrow, staticPath } from './static'
import {
  Ablation,
  ApiError,
  Attacks,
  Chain,
  Demo,
  Facets,
  Health,
  Matrices,
  Results,
  RunDetail,
  Runs,
  Tasks,
} from './schemas'
import type { Runs as RunsBody } from './schemas'

/** A failed request, carrying enough to render the failure honestly. */
export class ApiFailure extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly field?: string,
  ) {
    super(message)
    this.name = 'ApiFailure'
  }
}

/**
 * Where the API lives, relative to the page.
 *
 * `import.meta.env.BASE_URL` is `./` in the export and `/` when served, so the
 * same code reaches `mk web` over a socket and the exported JSON on disk.
 */
function url(path: string, params?: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== '') search.set(key, String(value))
  }
  const query = search.toString()
  return `${base()}/api/${path}${query ? `?${query}` : ''}`
}

/**
 * Whether this page is the static export rather than a served build.
 *
 * Decided once, by asking for `export.json`, and remembered. Under `file://`
 * there is no server to answer a query string, so the endpoints resolve to the
 * files `mk web --export` wrote.
 */
let staticMode: Promise<boolean> | null = null

function isStatic(): Promise<boolean> {
  staticMode ??= fetch(`${base()}/export.json`, { headers: { Accept: 'application/json' } })
    .then((response) => response.ok)
    .catch(() => false)
  return staticMode
}

function base(): string {
  return import.meta.env.BASE_URL.replace(/\/$/, '')
}

async function get<T extends z.ZodTypeAny>(
  schema: T,
  path: string,
  params?: Record<string, string | number | undefined>,
): Promise<z.infer<T>> {
  const isExport = await isStatic()
  const file = isExport ? staticPath(path, params ?? {}) : null
  if (isExport && file === null) {
    throw new ApiFailure(
      501,
      `this page needs a running server. \`${path}\` is not in the static export — ` +
        'serve the same build with `mk web`.',
    )
  }

  let response: Response
  try {
    response = await fetch(file === null ? url(path, params) : `${base()}/${file}`, {
      headers: { Accept: 'application/json' },
    })
  } catch (cause) {
    // `mk web` is not running, or the export is missing its JSON. Say which,
    // rather than rendering an empty table that reads as "no attacks landed".
    throw new ApiFailure(0, `cannot reach the artifact API (${String(cause)})`)
  }

  const text = await response.text()
  let body: unknown
  try {
    body = text ? (JSON.parse(text) as unknown) : null // invariant-ok: the one parse, feeding zod below
  } catch {
    throw new ApiFailure(response.status, 'the API returned something that is not JSON')
  }

  if (!response.ok) {
    const parsed = ApiError.safeParse(body)
    throw new ApiFailure(
      response.status,
      parsed.success ? parsed.data.error : `request failed (${response.status})`,
      parsed.success ? parsed.data.field : undefined,
    )
  }

  const parsed = schema.safeParse(body)
  if (!parsed.success) {
    throw new ApiFailure(
      response.status,
      `the API's response does not match the contract: ${parsed.error.issues
        .slice(0, 3)
        .map((issue) => `${issue.path.join('.')} ${issue.message}`)
        .join('; ')}`,
    )
  }

  // The export writes one unfiltered run list, because a filesystem has no
  // query strings. Selecting the rows this view asked for is display, not
  // derivation: no figure on any page comes from here.
  if (isExport && path === 'runs') {
    return narrow(parsed.data as RunsBody, params ?? {}) as z.infer<T>
  }
  return parsed.data
}

/**
 * The one non-GET call. Same parsing discipline as `get`: a 503 carrying
 * `kernel_reachable: false` is a *valid* response the page must render, not an
 * error to swallow, so the body is parsed before the status is judged.
 */
async function post<T extends z.ZodTypeAny>(
  schema: T,
  path: string,
  body: unknown,
): Promise<z.infer<T>> {
  let response: Response
  try {
    response = await fetch(url(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    })
  } catch (cause) {
    throw new ApiFailure(0, `cannot reach the artifact API (${String(cause)})`)
  }

  const text = await response.text()
  let parsedBody: unknown
  try {
    parsedBody = text ? (JSON.parse(text) as unknown) : null // invariant-ok: feeds zod below
  } catch {
    throw new ApiFailure(response.status, 'the API returned something that is not JSON')
  }

  const parsed = schema.safeParse(parsedBody)
  if (parsed.success) return parsed.data

  const failure = ApiError.safeParse(parsedBody)
  throw new ApiFailure(
    response.status,
    failure.success ? failure.data.error : `request failed (${response.status})`,
    failure.success ? failure.data.field : undefined,
  )
}

export const api = {
  health: () => get(Health, 'health'),
  matrices: () => get(Matrices, 'matrices'),
  ablation: (dir: string) => get(Ablation, 'ablation', { dir }),
  facets: () => get(Facets, 'facets'),
  results: (matrix: string, dataset?: string) =>
    get(Results, 'results', { matrix, dataset }),
  runs: (params: {
    config?: string
    dataset?: string
    class?: string
    technique?: string
    injection_point?: string
    batch?: string
    outcome?: string
    task_id?: string
    case_id?: string
    sort?: string
    limit?: number
    cursor?: number
  }) => get(Runs, 'runs', params),
  run: (run_id: string) => get(RunDetail, `runs/${encodeURIComponent(run_id)}`),
  chain: (run_id: string) => get(Chain, `runs/${encodeURIComponent(run_id)}/chain`),
  tasks: () => get(Tasks, 'tasks'),
  attacks: () => get(Attacks, 'attacks'),
  demo: (body: { task_id: string; case_id?: string }) => post(Demo, 'demo/run', body),
}
