/**
 * The live demo. Issue #89.
 *
 * Pick a task, optionally an attack case, post the intent and then the payment,
 * and show what the kernel said: the decision, the reason code, the checks that
 * ran and the chain entry appended.
 *
 * **If the kernel is not reachable the page says so and renders nothing.** No
 * placeholder decision, no last answer kept around, no optimistic state. "A
 * demo that invents a decision when its backend is down is worse than a demo
 * that is down."
 *
 * And it is labelled a local demo rather than a measurement, every time. One
 * run is an anecdote; the results page is where the numbers live, with their
 * intervals and their n.
 */
import { useState, type ReactNode } from 'react'
import { ApiFailure, api } from '../api/client'
import type { Demo as DemoBody } from '../api/schemas'
import { Code, Failure, Loading } from '../ui/primitives'
import { useApi } from '../ui/useApi'

export function DemoPage(): ReactNode {
  const health = useApi(() => api.health(), [])
  const tasks = useApi(() => api.tasks(), [])
  const attacks = useApi(() => api.attacks(), [])

  const [task_id, setTask] = useState('')
  const [case_id, setCase] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<DemoBody | null>(null)
  const [error, setError] = useState<unknown>(null)

  const reachable = health.state === 'ok' ? health.value.kernel.reachable : null

  async function submit(): Promise<void> {
    setRunning(true)
    setError(null)
    // The previous answer is cleared before the new call, not after it. A
    // stale decision left on screen while a new one is in flight is the same
    // lie as an invented one, only slower.
    setResult(null)
    try {
      setResult(await api.demo(case_id ? { task_id, case_id } : { task_id }))
    } catch (cause) {
      setError(cause)
    } finally {
      setRunning(false)
    }
  }

  return (
    <>
      <h1>Live kernel demo</h1>
      <div className="banner">
        <strong>A local demo, not a measurement.</strong> One run says nothing about a
        rate. The <a href="#/">results page</a> carries the numbers, with their intervals
        and their n.
      </div>

      {health.state === 'loading' ? <Loading what="the kernel's status" /> : null}
      {reachable === false ? (
        <div className="failure">
          <p>
            <strong>The kernel is not reachable, so there is nothing to show.</strong>
          </p>
          <p>
            This page renders a decision only when a kernel gave it one. Start the kernel
            on <code>{health.state === 'ok' ? health.value.kernel.url : ':8080'}</code> and
            reload.
          </p>
        </div>
      ) : null}

      {reachable ? (
        <>
          <div className="filters">
            <label>
              task
              <select value={task_id} onChange={(event) => setTask(event.target.value)}>
                <option value="">choose a task</option>
                {tasks.state === 'ok'
                  ? tasks.value.tasks.map((task) => (
                      <option key={task.task_id} value={task.task_id}>
                        {task.task_id} — {task.utterance?.slice(0, 60) ?? ''}
                      </option>
                    ))
                  : null}
              </select>
            </label>
            <label>
              attack (optional)
              <select value={case_id} onChange={(event) => setCase(event.target.value)}>
                <option value="">none — a clean purchase</option>
                {attacks.state === 'ok'
                  ? attacks.value.attacks.map((attack) => (
                      <option key={attack.case_id} value={attack.case_id}>
                        {attack.case_id} — {attack.class} / {attack.technique}
                      </option>
                    ))
                  : null}
              </select>
            </label>
            <button type="button" disabled={!task_id || running} onClick={() => void submit()}>
              {running ? 'asking the kernel…' : 'run it'}
            </button>
          </div>
          {attacks.state === 'ok' ? (
            <p className="muted">{attacks.value.note}</p>
          ) : null}
        </>
      ) : null}

      {error !== null ? <Failure error={error} /> : null}
      {result !== null ? <Result result={result} /> : null}
    </>
  )
}

function Result({ result }: { result: DemoBody }): ReactNode {
  if (!result.kernel_reachable) {
    return (
      <div className="failure">
        <p>
          <strong>{result.error ?? 'The kernel went away.'}</strong>
        </p>
        <p>No decision is shown because none was given.</p>
      </div>
    )
  }
  return (
    <>
      <h2>What the kernel said</h2>
      {result.replayed && result.replay_note ? (
        <div className="banner">
          <strong>This is replay protection, not the attack being stopped.</strong>{' '}
          {result.replay_note}
        </div>
      ) : null}
      <dl className="provenance">
        <dt>decision</dt>
        <dd>{result.decision ?? '—'}</dd>
        <dt>reason code</dt>
        <dd>{result.reason_code ? <Code code={result.reason_code} /> : '—'}</dd>
        <dt>refused by check</dt>
        <dd>{(result.denied_by ?? []).join(', ') || '—'}</dd>
        {result.redirected_payee ? (
          <>
            <dt>payee the agent was told to use</dt>
            <dd className="mono">{result.redirected_payee.value}</dd>
          </>
        ) : null}
      </dl>

      <h3>The checks that ran</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">id</th>
              <th>check</th>
              <th>result</th>
            </tr>
          </thead>
          <tbody>
            {(result.checks ?? []).map((check) => (
              <tr key={check.id}>
                <td className="num">{check.id}</td>
                <td>
                  <code>{check.name}</code>
                </td>
                <td>{check.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3>Every call, and what came back</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>endpoint</th>
              <th className="num">status</th>
              <th>body</th>
            </tr>
          </thead>
          <tbody>
            {result.steps.map((step, index) => (
              <tr key={index}>
                <td>
                  <code>{step.endpoint}</code>
                </td>
                <td className="num">{step.status}</td>
                <td className="mono" style={{ whiteSpace: 'pre-wrap', maxWidth: '70ch' }}>
                  {JSON.stringify(step.body, null, 1)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">
        A policy refusal is a 200. A denial is not an HTTP error — a 403 would make a
        working defence look like a broken deployment.
      </p>

      {result.audit !== null && result.audit !== undefined ? (
        <>
          <h3>The chain entry appended</h3>
          <pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(result.audit, null, 1)}
          </pre>
        </>
      ) : null}

      <p className="muted">{result.note}</p>
    </>
  )
}

export { ApiFailure }
