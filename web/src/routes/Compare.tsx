/**
 * Two runs from the same seed, side by side, with the diverging step
 * highlighted. Issue #87, and it is the project's whole claim on one screen.
 *
 * "The two runs agree, step for step — until here." So this is a **diff**, not
 * two trace components next to each other. If the reader has to find the
 * divergence themselves, the component has not done its job.
 *
 * The alignment is by position and step name over `plan.steps`. Nothing
 * statistical happens here: the comparison is of recorded values, and the two
 * records were produced by the harness from one seed.
 */
import type { ReactNode } from 'react'
import { api } from '../api/client'
import type { RunDetail } from '../api/schemas'
import { align, firstDivergence } from './diff'
import { formatPaise } from '../format/money'
import { Code, Failure, Loading, OutcomeTag } from '../ui/primitives'
import { useApi } from '../ui/useApi'
import { href } from './router'

export function Compare({ left, right }: { left: string; right: string }): ReactNode {
  const pair = useApi(
    () => Promise.all([api.run(left), api.run(right)]),
    [left, right],
  )
  if (pair.state === 'loading') return <Loading what="both runs" />
  if (pair.state === 'failed') return <Failure error={pair.error} />
  const [a, b] = pair.value
  return <CompareBody a={a} b={b} />
}

function CompareBody({ a, b }: { a: RunDetail; b: RunDetail }): ReactNode {
  const rows = align(a.record.plan?.steps ?? [], b.record.plan?.steps ?? [])
  const divergence = firstDivergence(rows)
  const sameSeed = a.record.seed === b.record.seed
  const sameCase = a.record.case_id === b.record.case_id

  return (
    <>
      <h1>
        <code>{a.record.config}</code> <span className="muted">against</span>{' '}
        <code>{b.record.config}</code>
      </h1>

      {!sameCase || !sameSeed ? (
        <div className="banner">
          These two runs are <strong>not</strong> the same case at the same seed
          {sameCase ? '' : ` (${a.record.case_id ?? '—'} vs ${b.record.case_id ?? '—'})`}
          {sameSeed ? '' : ` (seed ${a.record.seed} vs ${b.record.seed})`}. A difference
          between them is not attributable to the arm.
        </div>
      ) : (
        <p className="muted">
          Same case <code>{a.record.case_id ?? a.record.task_id}</code>, same seed{' '}
          <code>{a.record.seed}</code>, same injected sentence. The only difference is
          what sits underneath.
        </p>
      )}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th />
              <th>
                <a href={href(['runs', a.record.run_id])}>
                  <code>{a.record.config}</code>
                </a>
              </th>
              <th>
                <a href={href(['runs', b.record.run_id])}>
                  <code>{b.record.config}</code>
                </a>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>outcome</td>
              <td>
                <OutcomeTag outcome={a.outcome} />
              </td>
              <td>
                <OutcomeTag outcome={b.outcome} />
              </td>
            </tr>
            <tr>
              <td>net debit</td>
              <td className="num">{formatPaise(netDebit(a))}</td>
              <td className="num">{formatPaise(netDebit(b))}</td>
            </tr>
            <tr>
              <td>refused with</td>
              <td>
                <Codes detail={a} />
              </td>
              <td>
                <Codes detail={b} />
              </td>
            </tr>
            <tr>
              <td>chain entries</td>
              <td className="num">{a.record.chain_entries ?? 0}</td>
              <td className="num">{b.record.chain_entries ?? 0}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>The plan, step for step</h2>
      {divergence === null ? (
        <p className="empty">
          The two plans are identical at every step. Whatever separates these runs
          happened below the planner — in the kernel, at the money call.
        </p>
      ) : (
        <p>
          They agree for {divergence} step{divergence === 1 ? '' : 's'}, and diverge at
          step {divergence + 1}.
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">#</th>
              <th>step</th>
              <th>
                <code>{a.record.config}</code>
              </th>
              <th>
                <code>{b.record.config}</code>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const isFirstDivergence = row.index === divergence
              return (
                <tr
                  key={row.index}
                  style={
                    isFirstDivergence
                      ? { background: 'var(--deny-bg)', borderTop: '2px solid var(--deny)' }
                      : row.same
                        ? undefined
                        : { background: 'var(--warn-bg)' }
                  }
                >
                  <td className="num">{row.index + 1}</td>
                  <td>
                    <code>{row.leftStep ?? row.rightStep ?? '—'}</code>
                    {isFirstDivergence ? (
                      <>
                        {' '}
                        <span className="code">diverges here</span>
                      </>
                    ) : null}
                  </td>
                  <td className="mono" style={{ whiteSpace: 'pre-wrap', maxWidth: '38ch' }}>
                    {row.leftOutput}
                  </td>
                  <td className="mono" style={{ whiteSpace: 'pre-wrap', maxWidth: '38ch' }}>
                    {row.rightOutput}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <h2>What each kernel said</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>
                <code>{a.record.config}</code>
              </th>
              <th>
                <code>{b.record.config}</code>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ whiteSpace: 'normal', verticalAlign: 'top' }}>
                <DecisionList detail={a} />
              </td>
              <td style={{ whiteSpace: 'normal', verticalAlign: 'top' }}>
                <DecisionList detail={b} />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </>
  )
}

function netDebit(detail: RunDetail): number {
  // Not a metric: the API already computed this over the ledger, in one place.
  // Read back from the row rather than re-added here.
  return detail.record.ledger === undefined
    ? 0
    : (detail.record.ledger[0]?.captured_paise ?? 0)
}

function Codes({ detail }: { detail: RunDetail }): ReactNode {
  const codes = (detail.record.decisions ?? [])
    .filter((decision) => decision.decision === 'deny' || decision.decision === 'escalate')
    .map((decision) => decision.reason_code)
  if (codes.length === 0) return <span className="muted">nothing refused</span>
  return (
    <>
      {codes.map((code, index) =>
        code ? (
          <span key={index} style={{ marginRight: 4 }}>
            <Code code={code} />
          </span>
        ) : null,
      )}
    </>
  )
}

function DecisionList({ detail }: { detail: RunDetail }): ReactNode {
  const decisions = detail.record.decisions ?? []
  if (decisions.length === 0) {
    return (
      <span className="muted">
        No kernel in front of the rail. The money moved without one being asked.
      </span>
    )
  }
  return (
    <ul style={{ margin: 0, paddingLeft: 18 }}>
      {decisions.map((decision, index) => (
        <li key={index}>
          <code>{decision.action ?? decision.step}</code> — {decision.decision}{' '}
          {decision.reason_code ? <Code code={decision.reason_code} /> : null}
        </li>
      ))}
    </ul>
  )
}
