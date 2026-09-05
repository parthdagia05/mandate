/**
 * One run, in the order it happened. Issue #87.
 *
 * The utterance and the intent it was bound to; the plan step by step with the
 * injection point marked where the payload sat; every kernel decision with its
 * reason code and the checks that ran; the ledger, refunds and mandates kept
 * apart the way the record keeps them; recoveries, because a crash that was
 * repaired has to be visible as a repair; and the chain, with the entry naming
 * the authorising utterance.
 *
 * No per-step duration is rendered anywhere. `latency_us` is in the record and
 * therefore in the response, but P8 established that it and `money_calls` are
 * the only fields that differ across machines — by more than an order of
 * magnitude — which is exactly why no duration reaches the event log or the
 * audit chain. Overhead is a difference between arms over one dataset and it
 * lives on the results page.
 */
import type { ReactNode } from 'react'
import { api } from '../api/client'
import type { CheckResult, KernelDecision, LedgerEntry, RunDetail } from '../api/schemas'
import { formatPaise } from '../format/money'
import { codeGloss } from '../format/codes'
import { Code, Failure, Hash, Loading, OutcomeTag, Payload } from '../ui/primitives'
import { useApi } from '../ui/useApi'
import { ChainPanel } from './Chain'
import { href } from './router'

export function Trace({ run_id }: { run_id: string }): ReactNode {
  const run = useApi(() => api.run(run_id), [run_id])
  if (run.state === 'loading') return <Loading what="the run" />
  if (run.state === 'failed') return <Failure error={run.error} />
  const detail = run.value
  return (
    <>
      <h1>
        {detail.record.case_id ?? detail.record.task_id}{' '}
        <span className="muted">under</span> <code>{detail.record.config}</code>
      </h1>
      <p>
        <OutcomeTag outcome={detail.outcome} />
      </p>

      <Counterparts detail={detail} />
      <Utterance detail={detail} />
      <Injection detail={detail} />
      <Plan detail={detail} />
      <ExtractorReads detail={detail} />
      <MoneyCalls calls={detail.record.money_calls ?? []} />
      <Decisions decisions={detail.record.decisions ?? []} />
      <Ledger ledger={detail.record.ledger ?? []} />
      <Apart title="Refunds" rows={detail.record.refunds ?? []} />
      <Apart title="Mandates" rows={detail.record.mandates ?? []} />
      <Recoveries rows={detail.record.recoveries ?? []} />

      <h2>The audit chain</h2>
      <ChainPanel run_id={run_id} />
    </>
  )
}

function Counterparts({ detail }: { detail: RunDetail }): ReactNode {
  const arms = Object.entries(detail.counterparts)
  if (arms.length === 0) return null
  return (
    <p>
      <span className="muted">The same case, same seed, under: </span>
      {arms.map(([config, other]) => (
        <span key={config} style={{ marginRight: 8 }}>
          <a href={href(['compare', detail.record.run_id, other])}>
            <code>{config}</code>
          </a>
        </span>
      ))}
    </p>
  )
}

/**
 * The sentence, and the proof the chain is bound to it.
 *
 * The chain carries `utterance_hash`, not the sentence, so printing the
 * utterance beside the chain would only *assert* the binding. The API
 * recomputes the hash with the kernel's own function and says whether it
 * matches; a mismatch is a finding and renders as one.
 */
function Utterance({ detail }: { detail: RunDetail }): ReactNode {
  const binding = detail.utterance_binding
  const utterance = detail.task?.utterance ?? null
  if (!utterance) return null
  return (
    <>
      <h2>What the human said</h2>
      <blockquote
        style={{
          margin: '0 0 16px',
          padding: '8px 16px',
          borderLeft: '3px solid var(--accent)',
          background: 'var(--paper-2)',
          maxWidth: '78ch',
        }}
      >
        {utterance}
      </blockquote>
      {binding === null ? (
        <p className="muted">
          This arm appended no audit chain, so there is no signed intent to bind the
          sentence to.
        </p>
      ) : binding.matches ? (
        <dl className="provenance">
          <dt>bound in the chain as</dt>
          <dd>{binding.utterance_hash}</dd>
          <dt>hash of the sentence above</dt>
          <dd>{binding.computed}</dd>
          <dt>match</dt>
          <dd>
            yes — the chain names this sentence, and the kernel can point at it for every
            charge it allowed
          </dd>
        </dl>
      ) : (
        <div className="failure">
          <p>
            <strong>The chain does not name this sentence.</strong>
          </p>
          <p className="hash">chain: {binding.utterance_hash}</p>
          <p className="hash">sentence: {binding.computed ?? 'could not be hashed'}</p>
        </div>
      )}
    </>
  )
}

function Injection({ detail }: { detail: RunDetail }): ReactNode {
  const attack = detail.attack
  if (!attack) {
    return (
      <>
        <h2>The injection</h2>
        <p className="empty">
          A benign task. No payload was placed anywhere in this run.
        </p>
      </>
    )
  }
  return (
    <>
      <h2>The injection</h2>
      <dl className="provenance">
        <dt>class</dt>
        <dd>{attack.class}</dd>
        <dt>technique</dt>
        <dd>{attack.technique}</dd>
        <dt>oracle</dt>
        <dd>{attack.oracle}</dd>
        <dt>injection point</dt>
        <dd>{attack.injection_point}</dd>
        <dt>expected undefended</dt>
        <dd>{attack.expected_undefended ?? '—'}</dd>
      </dl>
      <Payload
        text={attack.payload}
        point={attack.injection_point}
        held_out={attack.held_out}
      />
    </>
  )
}

function Plan({ detail }: { detail: RunDetail }): ReactNode {
  const plan = detail.record.plan
  if (!plan) return null
  const steps = plan.steps ?? []
  // Which steps actually read merchant content, from the extractor's own
  // record. Not inferred from the injection point: the mapping from a point to
  // a planner step lives in the simulator, and guessing it here would put a
  // confident marker on the wrong row in the arms that do not record reads.
  const read = new Set((detail.record.extractor?.reads ?? []).map((entry) => entry.step))
  const point = detail.attack?.injection_point ?? null
  return (
    <>
      <h2>The plan</h2>
      {plan.payee_was_redirected ? (
        <div className="banner">
          The agent was redirected: it chose{' '}
          <code>{plan.payee?.value}</code> where the checkout page named{' '}
          <code>{plan.checkout_payee?.value}</code>.
        </div>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">#</th>
              <th>step</th>
              <th>what it produced</th>
              <th>read merchant content</th>
            </tr>
          </thead>
          <tbody>
            {steps.map((step, index) => (
              <tr
                key={`${step.step}-${index}`}
                style={read.has(step.step) ? { background: 'var(--deny-bg)' } : undefined}
              >
                <td className="num">{index + 1}</td>
                <td>
                  <code>{step.step}</code>
                </td>
                <td style={{ whiteSpace: 'pre-wrap' }} className="mono">
                  {JSON.stringify(step.output ?? null)}
                </td>
                <td>
                  {read.has(step.step) ? (
                    <span className="code">{point ?? 'merchant content'}</span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">
        Cart total {plan.total_paise === undefined ? '—' : formatPaise(plan.total_paise)}.
        {point !== null && read.size === 0 ? (
          <>
            {' '}
            The payload sat at <code>{point}</code>. This arm&rsquo;s record does not
            attribute reads to steps, so no step is marked — the simulator knows which
            one, and the record does not.
          </>
        ) : null}
      </p>
    </>
  )
}

export function Decisions({ decisions }: { decisions: KernelDecision[] }): ReactNode {
  return (
    <>
      <h2>Kernel decisions</h2>
      {decisions.length === 0 ? (
        <p className="empty">
          No kernel decision was recorded. In the <code>undefended</code> and{' '}
          <code>model-only</code> arms there is no kernel in front of the rail, so the
          money moved without one being asked.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>action</th>
                <th>decision</th>
                <th>reason code</th>
                <th>why</th>
                <th>checks that ran</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((decision, index) => (
                <tr key={index}>
                  <td>
                    <code>{decision.action ?? decision.step ?? '—'}</code>
                  </td>
                  <td>{decision.decision ?? '—'}</td>
                  <td>
                    {decision.reason_code ? <Code code={decision.reason_code} /> : '—'}
                  </td>
                  <td className="muted" style={{ whiteSpace: 'normal' }}>
                    {decision.reason_code ? (codeGloss(decision.reason_code) ?? '') : ''}
                  </td>
                  <td style={{ whiteSpace: 'normal', maxWidth: '42ch' }}>
                    <Checks checks={decision.checks ?? []} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

/**
 * Which checks ran, and how each came out.
 *
 * A count would say a decision was reached without saying what reached it, and
 * "check 2 refused this and check 1 passed" is the whole substance of a denial —
 * the agent's signature was valid; the payee was not the signed one.
 */
function Checks({ checks }: { checks: CheckResult[] }): ReactNode {
  if (checks.length === 0) return <span className="muted">none recorded</span>
  return (
    <>
      {checks.map((check) => (
        <span key={check.id} style={{ marginRight: 6 }}>
          <span className={check.result === 'pass' ? 'tag' : 'code'}>
            {check.id} {check.name}
          </span>
        </span>
      ))}
    </>
  )
}

/**
 * The tool calls the agent made at the money boundary.
 *
 * Names only. The record carries a `latency_us` on each and it is deliberately
 * not shown: P8 found that field and `money_calls` to be the only ones that
 * differ across machines, by more than an order of magnitude, which is why no
 * duration reaches the event log or the audit chain. Overhead is a difference
 * between arms over one dataset and it belongs on the results page.
 */
function MoneyCalls({ calls }: { calls: { call: string }[] }): ReactNode {
  if (calls.length === 0) return null
  return (
    <>
      <h2>Money calls</h2>
      <p>
        {calls.map((call, index) => (
          <span key={index} style={{ marginRight: 6 }}>
            <code>{call.call}</code>
          </span>
        ))}
      </p>
      <p className="muted">
        Names only. The per-call duration on the record measures the hardware
        rather than the run, and comparing two of them across machines would be
        comparing the machines.
      </p>
    </>
  )
}

/**
 * What the quarantined extractor pulled out of merchant content, step by step.
 *
 * The closest thing on disk to "what the merchant returned": the simulator's
 * event log carries the served responses themselves, but the runner records
 * only its head hash and entry count, so the responses are not on disk for any
 * run already taken. Recorded by the agent-side arms only.
 */
function ExtractorReads({ detail }: { detail: RunDetail }): ReactNode {
  const reads = detail.record.extractor?.reads ?? []
  const refusals = detail.record.taint?.refusals ?? []
  if (reads.length === 0 && refusals.length === 0) return null
  return (
    <>
      <h2>What the agent read out of merchant content</h2>
      {reads.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>step</th>
                <th className="num">prose bytes</th>
                <th>extracted</th>
              </tr>
            </thead>
            <tbody>
              {reads.map((read, index) => (
                <tr key={`${read.step}-${index}`}>
                  <td>
                    <code>{read.step}</code>
                  </td>
                  <td className="num">{read.prose_bytes ?? '—'}</td>
                  <td className="mono" style={{ whiteSpace: 'pre-wrap', maxWidth: '52ch' }}>
                    {JSON.stringify(read.output ?? null)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {refusals.length > 0 ? (
        <>
          <h3>Fields the admission policy refused</h3>
          <p className="muted">
            A merchant-derived value was offered for a restricted field and the planner
            fell back to the user-provenance one. The run continued and the user still
            got their goods, which is why these are not counted as false blocks.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>field</th>
                  <th>provenance</th>
                  <th>admitted</th>
                </tr>
              </thead>
              <tbody>
                {refusals.map((refusal, index) => (
                  <tr key={index}>
                    <td>
                      <code>{refusal.field}</code>
                    </td>
                    <td>{refusal.provenance}</td>
                    <td className="muted">{(refusal.admitted ?? []).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </>
  )
}

function Ledger({ ledger }: { ledger: LedgerEntry[] }): ReactNode {
  return (
    <>
      <h2>The ledger</h2>
      {ledger.length === 0 ? (
        <p className="empty">Nothing was debited in this run.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>payment</th>
                <th>state</th>
                <th>payee</th>
                <th>source</th>
                <th className="num">amount</th>
                <th className="num">captured</th>
              </tr>
            </thead>
            <tbody>
              {ledger.map((entry, index) => (
                <tr key={entry.payment_id ?? index}>
                  <td className="mono">{entry.payment_id ?? '—'}</td>
                  <td>{entry.state ?? '—'}</td>
                  <td className="mono">{entry.payee?.value ?? '—'}</td>
                  <td className="mono">{entry.source?.value ?? '—'}</td>
                  <td className="num">
                    {entry.amount_paise === undefined ? '—' : formatPaise(entry.amount_paise)}
                  </td>
                  <td className="num">
                    {entry.captured_paise === undefined
                      ? '—'
                      : formatPaise(entry.captured_paise)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

/**
 * Refunds and mandates, each in their own section.
 *
 * Kept apart because the record keeps them apart: authority and money position
 * terminate independently, and a single merged "events" list would lose that.
 */
function Apart({ title, rows }: { title: string; rows: unknown[] }): ReactNode {
  if (rows.length === 0) return null
  return (
    <>
      <h2>{title}</h2>
      <div className="table-wrap">
        <table>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index}>
                <td className="mono" style={{ whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(row, null, 1)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

/** A crash that was repaired has to be visible as a repair, not as silence. */
function Recoveries({ rows }: { rows: unknown[] }): ReactNode {
  if (rows.length === 0) return null
  return (
    <>
      <h2>Recoveries</h2>
      <p className="muted">
        This run crashed mid-flight and the recovery scan resolved it. Exactly one debit
        is the claim; the ledger above is where it is counted.
      </p>
      <Apart title="" rows={rows} />
    </>
  )
}

export function TraceSummary({ detail }: { detail: RunDetail }): ReactNode {
  return (
    <>
      <p>
        <OutcomeTag outcome={detail.outcome} /> <Hash value={detail.record.run_id} />
      </p>
    </>
  )
}
