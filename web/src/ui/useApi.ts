/** Fetch once per key, with the three states a page has to distinguish. */
import { useEffect, useState } from 'react'

export type Async<T> =
  | { readonly state: 'loading' }
  | { readonly state: 'ok'; readonly value: T }
  | { readonly state: 'failed'; readonly error: unknown }

export function useApi<T>(load: () => Promise<T>, deps: readonly unknown[]): Async<T> {
  const [result, setResult] = useState<Async<T>>({ state: 'loading' })
  useEffect(() => {
    let live = true
    setResult({ state: 'loading' })
    load().then(
      (value) => live && setResult({ state: 'ok', value }),
      (error: unknown) => live && setResult({ state: 'failed', error }),
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return result
}
