/**
 * Routing, in about eighty lines, because the dependency list is three packages
 * (#82) and a router would be a fourth.
 *
 * All view state is in the URL — arm, class, technique, injection point, batch,
 * outcome, and the compare pair (#86, invariant 12). Two reasons, and the second
 * is the real one: the video script has to arrive at an exact view with no
 * clicking on camera, and a shot that must be re-recorded has to land on the
 * identical view. A filter in `useState` makes both impossible.
 *
 * Hash routing, not history routing. The export opens from `file://` (#90),
 * where `history.pushState` to a path produces a URL the browser cannot reload.
 * A hash survives that, and survives being pasted into a script.
 */
import { useCallback, useEffect, useState } from 'react'

export interface Route {
  /** `['runs', 'sha256:...']` — the hash path, split and decoded. */
  readonly segments: readonly string[]
  /** `?arm=undefended&class=A1` — every filter, as strings. */
  readonly params: Readonly<Record<string, string>>
}

const EMPTY: Route = { segments: [], params: {} }

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#\/?/, '')
  if (!raw) return EMPTY
  const [path = '', query = ''] = raw.split('?', 2)
  const segments = path
    .split('/')
    .filter(Boolean)
    .map((segment) => decodeURIComponent(segment))
  const params: Record<string, string> = {}
  for (const [key, value] of new URLSearchParams(query)) params[key] = value
  return { segments, params }
}

export function buildHash(segments: readonly string[], params?: Record<string, string | undefined>): string {
  const path = segments.map((segment) => encodeURIComponent(segment)).join('/')
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== '') search.set(key, value)
  }
  const query = search.toString()
  return `#/${path}${query ? `?${query}` : ''}`
}

/** The current route, and a setter that writes it back to the URL. */
export function useRoute(): {
  route: Route
  go: (segments: readonly string[], params?: Record<string, string | undefined>) => void
  setParams: (next: Record<string, string | undefined>) => void
} {
  const [route, setRoute] = useState<Route>(() =>
    parseHash(typeof window === 'undefined' ? '' : window.location.hash),
  )

  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash))
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  const go = useCallback(
    (segments: readonly string[], params?: Record<string, string | undefined>) => {
      window.location.hash = buildHash(segments, params)
    },
    [],
  )

  const setParams = useCallback(
    (next: Record<string, string | undefined>) => {
      const current = parseHash(window.location.hash)
      window.location.hash = buildHash(current.segments, { ...current.params, ...next })
    },
    [],
  )

  return { route, go, setParams }
}

/** `href` for a link, so anchors are real anchors a reader can copy or open. */
export function href(segments: readonly string[], params?: Record<string, string | undefined>): string {
  return buildHash(segments, params)
}
