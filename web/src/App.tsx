/**
 * The shell. Reads the route, picks a page, and shows what is being served.
 */
import type { ReactNode } from 'react'
import { api } from './api/client'
import { ChainPage } from './routes/Chain'
import { Compare } from './routes/Compare'
import { DemoPage } from './routes/Demo'
import { Results } from './routes/Results'
import { RunList } from './routes/RunList'
import { Trace } from './routes/Trace'
import { href, useRoute } from './routes/router'
import { Failure, Loading } from './ui/primitives'
import { useApi } from './ui/useApi'

export function App(): ReactNode {
  const { route } = useRoute()
  const [page] = route.segments
  return (
    <>
      <header className="masthead">
        <strong>Mandate</strong>
        <nav>
          <a href={href([])} aria-current={!page ? 'page' : undefined}>
            results
          </a>
          <a href={href(['runs'])} aria-current={page === 'runs' ? 'page' : undefined}>
            runs
          </a>
          <a href={href(['demo'])} aria-current={page === 'demo' ? 'page' : undefined}>
            live demo
          </a>
        </nav>
      </header>
      <main className="page">
        <Page page={page} route={route} />
      </main>
    </>
  )
}

function Page({
  page,
  route,
}: {
  page: string | undefined
  route: ReturnType<typeof useRoute>['route']
}): ReactNode {
  if (!page || page === 'results') {
    const matrix = route.params['matrix']
    if (matrix)
      return (
        <Results
          matrix={matrix}
          dataset={route.params['dataset']}
          ablation={route.params['ablation']}
        />
      )
    return <PickMatrix />
  }

  if (page === 'runs') {
    const [, run_id, section] = route.segments
    if (!run_id) return <RunList />
    if (section === 'chain') return <ChainPage run_id={run_id} />
    return <Trace run_id={run_id} />
  }

  if (page === 'compare') {
    const [, left, right] = route.segments
    if (!left || !right) {
      return (
        <div className="empty">
          <p>A comparison needs two run ids.</p>
          <p className="muted">
            Select two rows in the <a href={href(['runs'])}>run list</a>, or open a run
            and pick one of its counterpart arms.
          </p>
        </div>
      )
    }
    return <Compare left={left} right={right} />
  }

  if (page === 'demo') return <DemoPage />

  return (
    <div className="empty">
      <p>
        <code>{page}</code> is not a page.
      </p>
    </div>
  )
}

/**
 * Which matrix to read. Not a landing page — a picker, shown only because a
 * repository can hold several matrices and a results page that silently chose
 * one would be a results page whose provenance is a guess.
 */
function PickMatrix(): ReactNode {
  const matrices = useApi(() => api.matrices(), [])
  const health = useApi(() => api.health(), [])
  if (matrices.state === 'loading') return <Loading what="the matrices on disk" />
  if (matrices.state === 'failed') return <Failure error={matrices.error} />

  const ablations = matrices.value.ablations
  const usable = matrices.value.matrices.filter(
    (entry): entry is Extract<typeof entry, { matrix_id: string }> =>
      'matrix_id' in entry,
  )

  return (
    <>
      <h1>Mandate — trace viewer</h1>
      {health.state === 'ok' ? (
        <p className="muted">
          Serving {health.value.cases} runs from {health.value.suites} suites in{' '}
          <code>{health.value.runs_root}</code>. Kernel:{' '}
          {health.value.kernel.reachable ? 'reachable' : 'not reachable'}.
        </p>
      ) : null}

      {ablations.length > 0 ? (
        <p className="muted">
          Ablations on disk:{' '}
          {ablations.map((entry) => (
            <code key={entry.dir} style={{ marginRight: 8 }}>
              {entry.dir}
            </code>
          ))}
          . Append <code>&amp;ablation=&lt;dir&gt;</code> to a results link to render its
          per-check tables.
        </p>
      ) : null}

      {usable.length === 0 ? (
        <div className="empty">
          <p>No matrix directory found under the runs root.</p>
          <p className="muted">
            <code>mk matrix</code> leaves a <code>matrix.json</code> beside its JSONL.
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>matrix</th>
                <th>datasets</th>
                <th>seed</th>
                <th>model</th>
                <th>run</th>
              </tr>
            </thead>
            <tbody>
              {usable.map((entry) => (
                <tr key={entry.dir}>
                  <td>
                    <code>{entry.dir}</code>
                  </td>
                  <td>
                    {entry.datasets.map((dataset) => (
                      <span key={dataset} style={{ marginRight: 8 }}>
                        <a href={href(['results'], { matrix: entry.dir, dataset })}>
                          {dataset}
                        </a>
                      </span>
                    ))}
                  </td>
                  <td className="num">{entry.seed}</td>
                  <td>
                    <code>{entry.model}</code>
                  </td>
                  <td className="muted">{entry.started_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
