/**
 * The results page. Issue #85.
 *
 * Arms as rows, metrics as columns; per class and per evasion family as their
 * own tables; every proportion with its interval and its n; the corpus hash,
 * seed, model and arm at the top; and every cell one click from the runs behind
 * it.
 *
 * Nothing on this page is computed here. Every figure arrives from
 * `harness/metrics.py` through the API and is formatted (#91).
 */
import type { ReactNode } from 'react'
import { api } from '../api/client'
import type { Results as ResultsBody } from '../api/schemas'
import { formatMicros } from '../format/proportion'
import { Code, Failure, Loading, Prop, StandInBanner } from '../ui/primitives'
import { AblationTables } from './Ablation'
import { useApi } from '../ui/useApi'
import { href } from './router'

export function Results({
  matrix,
  dataset,
  ablation,
}: {
  matrix: string
  dataset?: string
  ablation?: string
}): ReactNode {
  const results = useApi(() => api.results(matrix, dataset), [matrix, dataset])
  if (results.state === 'loading') return <Loading what="the results" />
  if (results.state === 'failed') return <Failure error={results.error} />
  return (
    <>
      <ResultsBodyView body={results.value} />
      {ablation ? <AblationTables dir={ablation} /> : null}
    </>
  )
}

function ResultsBodyView({ body }: { body: ResultsBody }): ReactNode {
  const configs = body.arms.map((arm) => arm.config)
  return (
    <>
      <h1>Results — {body.dataset}</h1>

      {body.stand_in ? <StandInBanner model={body.matrix.model} /> : null}

      <Provenance body={body} />

      <p>
        Every proportion carries a Wilson 95% confidence interval and the counts it was
        computed from. Read the intervals, not the point estimates, and read the utility
        columns beside the ASR column: a defence with no attacks landing and no tasks
        completing has not defended anything.
      </p>

      <h2>The arms</h2>
      <dl className="provenance">
        {body.arms.map((arm) => (
          <div key={arm.config} style={{ display: 'contents' }}>
            <dt>
              <code>{arm.config}</code>
            </dt>
            <dd>{arm.blurb}</dd>
          </div>
        ))}
      </dl>

      <h2>The headline table</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>config</th>
              <th className="stat">targeted ASR</th>
              <th className="stat">utility under attack</th>
              <th className="stat">benign utility</th>
              <th className="stat">false block rate</th>
              <th className="stat">overhead p50</th>
              <th className="stat">overhead p99</th>
            </tr>
          </thead>
          <tbody>
            {body.headline.map((row) => (
              <tr key={row.config}>
                <td>
                  <a href={href(['runs'], { config: row.config, dataset: body.dataset })}>
                    <code>{row.config}</code>
                  </a>
                </td>
                <td className="stat">
                  <CellLink
                    dataset={body.dataset}
                    config={row.config}
                    outcome="attacker_win"
                  >
                    <Prop value={row.targeted_asr} />
                  </CellLink>
                </td>
                <td className="stat">
                  <Prop value={row.utility_under_attack} />
                </td>
                <td className="stat">
                  <Prop value={row.benign_utility} />
                </td>
                <td className="stat">
                  <CellLink
                    dataset={body.benign_dataset ?? body.dataset}
                    config={row.config}
                    outcome="blocked"
                  >
                    <Prop value={row.false_block_rate} />
                  </CellLink>
                </td>
                <td className="stat">
                  {row.overhead ? formatMicros(row.overhead.p50_delta_us) : <span className="muted">—</span>}
                </td>
                <td className="stat">
                  {row.overhead ? formatMicros(row.overhead.p99_delta_us) : <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">
        <em>Utility under attack is printed beside ASR on purpose.</em> A defence with a
        0% ASR and a 0% utility under attack has not defended anything — it has turned the
        agent off, and the ASR column alone cannot tell the two apart. Overhead is a
        difference against <code>undefended</code> over the benign suite, measured at the
        same boundary; it is not a level.
      </p>

      <Pivot
        title="By class"
        rows={body.by_class}
        configs={configs}
        dataset={body.dataset}
        param="class"
      />
      <Pivot
        title="By evasion family"
        rows={body.by_family}
        configs={configs}
        dataset={body.dataset}
        param="technique"
      />

      <h2>What refused, and why</h2>
      <p className="muted">
        An ASR that fell to zero with no refusals in the record would be an attack that
        stopped working rather than a defence that worked. These counts are how the two
        are told apart.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>config</th>
              <th>reason codes</th>
            </tr>
          </thead>
          <tbody>
            {configs.map((config) => {
              const codes = body.refusals[config] ?? []
              return (
                <tr key={config}>
                  <td>
                    <code>{config}</code>
                  </td>
                  <td style={{ whiteSpace: 'normal' }}>
                    {codes.length === 0 ? (
                      <span className="muted">nothing refused</span>
                    ) : (
                      codes.map((entry) => (
                        <span key={entry.reason_code} style={{ marginRight: 8 }}>
                          <Code code={entry.reason_code} />
                          <span className="muted"> ×{entry.count}</span>
                        </span>
                      ))
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <FalseBlocks body={body} />
    </>
  )
}

/**
 * The false-block table, and it is not optional.
 *
 * `harness/report.py`: the false-block column "is the column an author is most
 * tempted to leave out, so it is the one placed where a reader sees it before
 * the ASR." Every blocked benign case is named with the check that refused it,
 * because a false-block rate quoted without the case list is a number nobody
 * can argue with.
 */
function FalseBlocks({ body }: { body: ResultsBody }): ReactNode {
  const configs = Object.keys(body.false_blocks)
  const any = configs.some((config) => (body.false_blocks[config] ?? []).length > 0)
  return (
    <>
      <h2>The false block rate, case by case</h2>
      {!any ? (
        <p className="empty">
          No benign task was refused by any arm on this dataset. A zero here is a finding
          about the benign suite being too easy, not a perfect score.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>config</th>
                <th>task</th>
                <th>reason code</th>
                <th>step</th>
                <th>task still succeeded</th>
              </tr>
            </thead>
            <tbody>
              {configs.flatMap((config) =>
                (body.false_blocks[config] ?? []).map((block) => (
                  <tr key={`${config}:${block.run_id ?? block.task_id ?? ''}`}>
                    <td>
                      <code>{config}</code>
                    </td>
                    <td>
                      {block.run_id ? (
                        <a href={href(['runs', block.run_id])}>{block.task_id}</a>
                      ) : (
                        block.task_id
                      )}
                    </td>
                    <td>{block.reason_code ? <Code code={block.reason_code} /> : '—'}</td>
                    <td className="muted">{block.step ?? '—'}</td>
                    <td>{block.task_success ? 'yes' : 'no'}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

function Pivot({
  title,
  rows,
  configs,
  dataset,
  param,
}: {
  title: string
  rows: Record<string, Record<string, ReturnType<typeof Object> | null> | Record<string, never>>
  configs: string[]
  dataset: string
  param: 'class' | 'technique'
}): ReactNode {
  const keys = Object.keys(rows).sort()
  if (keys.length === 0) return null
  return (
    <>
      <h2>{title}</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{param}</th>
              {configs.map((config) => (
                <th key={config} className="stat">
                  <code>{config}</code>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key}>
                <td>
                  <a href={href(['runs'], { [param]: key, dataset })}>{key}</a>
                </td>
                {configs.map((config) => {
                  const cell = (rows[key] as Record<string, never> | undefined)?.[config]
                  return (
                    <td key={config} className="stat">
                      <CellLink
                        dataset={dataset}
                        config={config}
                        extra={{ [param]: key }}
                      >
                        <Prop value={(cell ?? null) as never} />
                      </CellLink>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

/** Every cell is one click from the runs that produced it (#85). */
function CellLink({
  dataset,
  config,
  outcome,
  extra,
  children,
}: {
  dataset: string
  config: string
  outcome?: string
  extra?: Record<string, string>
  children: ReactNode
}): ReactNode {
  return (
    <a
      href={href(['runs'], { dataset, config, outcome, ...extra })}
      style={{ textDecoration: 'none', color: 'inherit' }}
    >
      {children}
    </a>
  )
}

/** What a screenshot needs to be evidence rather than a picture (#85). */
function Provenance({ body }: { body: ResultsBody }): ReactNode {
  const m = body.matrix
  return (
    <dl className="provenance">
      <dt>corpus manifest</dt>
      <dd>{m.corpus_manifests[body.dataset] ?? m.corpus_manifest}</dd>
      <dt>matrix id</dt>
      <dd>{m.matrix_id}</dd>
      <dt>seed</dt>
      <dd>{m.seed}</dd>
      <dt>model</dt>
      <dd>{m.model}</dd>
      <dt>arms</dt>
      <dd>{m.configs.join(', ')}</dd>
      <dt>run</dt>
      <dd>
        {m.started_at} → {m.finished_at}
      </dd>
      <dt>batch B openings</dt>
      <dd>{m.batch_b_openings}</dd>
      {m.corpus_drift.length > 0 ? (
        <>
          <dt>corpus drift</dt>
          <dd>{m.corpus_drift.join('; ')}</dd>
        </>
      ) : null}
    </dl>
  )
}
