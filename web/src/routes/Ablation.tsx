/**
 * The per-check ablation, as its own tables. Issue #85.
 *
 * Two questions per check, because one is misleading on its own. **The checks
 * overlap on purpose:** a redirected payee changes the cart's hash, so check 4
 * refuses class A1 even with check 2 removed; turning off check 2 therefore
 * moves nothing, and a table with only that column would report check 2 as
 * worthless.
 *
 * So both are shown:
 *
 * - *necessary for* — classes whose ASR rose when this check alone was removed.
 *   "Given the other eight, this one is load-bearing."
 * - *sufficient for* — classes this check held down while every other ablatable
 *   check was off. "On its own, this one stops it."
 *
 * A check that answers neither is reported as answering neither. That is a
 * finding about the check, not a row to leave out.
 */
import type { ReactNode } from 'react'
import { api } from '../api/client'
import type { Ablation as AblationBody } from '../api/schemas'
import { Failure, Loading, Prop } from '../ui/primitives'
import { useApi } from '../ui/useApi'

export function AblationTables({ dir }: { dir: string }): ReactNode {
  const ablation = useApi(() => api.ablation(dir), [dir])
  if (ablation.state === 'loading') return <Loading what="the ablation" />
  if (ablation.state === 'failed') return <Failure error={ablation.error} />
  return <Body body={ablation.value} />
}

function Body({ body }: { body: AblationBody }): ReactNode {
  const classes = Object.keys(body.baseline.by_class).sort()
  const single = body.rows.filter((row) => row.mode === 'single')
  const isolated = body.rows.filter((row) => row.mode === 'isolated')
  const floor = body.rows.filter((row) => row.mode === 'floor')

  return (
    <>
      <h2>Per-check ablation</h2>
      <p className="muted">
        Dataset <code>{body.dataset}</code>, seed <code>{body.seed}</code>, model{' '}
        <code>{body.model}</code>.
      </p>

      <h3>Baseline — every check on</h3>
      <ByClass classes={classes} rows={[{ label: 'all checks', by_class: body.baseline.by_class, targeted_asr: body.baseline.targeted_asr }]} />

      <h3>One check off — is it necessary, given the others?</h3>
      <ByClass classes={classes} rows={single} />

      <h3>Only one check on — what does it stop by itself?</h3>
      <ByClass classes={classes} rows={[...floor, ...isolated]} />

      <h3>Does every check earn its row?</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">check</th>
              <th>necessary for</th>
              <th>sufficient for</th>
              <th>earns its row</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(body.verdicts)
              .sort((a, b) => Number(a[0]) - Number(b[0]))
              .map(([check, verdict]) => (
                <tr key={check}>
                  <td className="num">{check}</td>
                  <td>
                    {verdict.necessary_for.join(', ') || (
                      <span className="muted">nothing</span>
                    )}
                  </td>
                  <td>
                    {verdict.sufficient_for.join(', ') || (
                      <span className="muted">nothing</span>
                    )}
                  </td>
                  <td>{verdict.earns_row ? 'yes' : 'no'}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <p className="muted">
        A check that answers neither question is reported as answering neither — a
        finding about the check, not a row to leave out.
      </p>
    </>
  )
}

function ByClass({
  classes,
  rows,
}: {
  classes: string[]
  rows: {
    label: string
    targeted_asr: AblationBody['baseline']['targeted_asr']
    by_class: AblationBody['baseline']['by_class']
  }[]
}): ReactNode {
  if (rows.length === 0) return <p className="empty">No rows of this kind were run.</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>configuration</th>
            <th className="stat">targeted ASR</th>
            {classes.map((cls) => (
              <th key={cls} className="stat">
                {cls}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label}>
              <td>{row.label}</td>
              <td className="stat">
                <Prop value={row.targeted_asr} />
              </td>
              {classes.map((cls) => (
                <td key={cls} className="stat">
                  <Prop value={row.by_class[cls] ?? null} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
