/**
 * The audit chain, and what the verifier said about it. Issue #88.
 *
 * **The hash chain is not reimplemented here.** Verification is done by
 * `scripts/verify_chain.py`, server-side, and this page shows what it said. That
 * verifier imports nothing from the project and carries its own RFC 8785, which
 * is the whole reason REQ-9 asks reviewers to trust it; a second implementation
 * in TypeScript would be a bug factory, and the two disagreeing would tell a
 * reader nothing about which was right.
 *
 * So there is no `crypto.subtle` in this file, no SHA-256 and no canonical JSON
 * encoder. The per-row indicator is the verifier's verdict, not a local one.
 */
import { useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { Chain, ChainEntry } from '../api/schemas'
import { Failure, Loading } from '../ui/primitives'
import { useApi } from '../ui/useApi'

export function ChainPanel({ run_id }: { run_id: string }): ReactNode {
  const chain = useApi(() => api.chain(run_id), [run_id])
  if (chain.state === 'loading') return <Loading what="the chain" />
  if (chain.state === 'failed') return <Failure error={chain.error} />
  return <ChainBody chain={chain.value} />
}

function ChainBody({ chain }: { chain: Chain }): ReactNode {
  // No chain is not a failed verification. The undefended arm appends nothing,
  // and rendering that as "unverified" would be a different claim — and a false
  // one.
  if (chain.entries.length === 0) {
    return (
      <p className="empty">
        {chain.note ??
          'This arm appended no audit chain. That is not a failed verification.'}
      </p>
    )
  }

  const broken = chain.verify !== null && !chain.verify.ok
  return (
    <>
      <Verdict chain={chain} />
      {broken ? (
        <div className="failure">
          <p>
            <strong>
              BROKEN at seq {chain.verify?.broken_at ?? '?'} — this run is discarded.
            </strong>
          </p>
          <p>
            A run whose chain does not verify is not counted as a defended one. It is
            discarded, matching what the CLI does.
          </p>
          <p className="mono">{chain.verify?.message}</p>
        </div>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">seq</th>
              <th>ts</th>
              <th>actor</th>
              <th>action</th>
              <th>payload</th>
            </tr>
          </thead>
          <tbody>
            {chain.entries.map((entry) => (
              <Row key={entry.seq} entry={entry} broken_at={chain.verify?.broken_at ?? null} />
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

function Verdict({ chain }: { chain: Chain }): ReactNode {
  const verify = chain.verify
  return (
    <dl className="provenance">
      <dt>entries</dt>
      <dd>{chain.entries.length}</dd>
      <dt>head</dt>
      {/* In full, selectable, and with a button — #88 wants it copyable so it
          can be checked against the JSONL by hand, and selecting 71 characters
          of monospace by dragging is how a transcription error happens. */}
      <dd>
        <CopyableHash value={chain.head} />
      </dd>
      <dt>verified by</dt>
      <dd>{verify ? verify.verifier : '—'}</dd>
      <dt>verdict</dt>
      <dd>{verify ? verify.message : 'not run — this arm appends no chain'}</dd>
      {chain.path ? (
        <>
          <dt>file</dt>
          <dd>{chain.path}</dd>
        </>
      ) : null}
    </dl>
  )
}

/**
 * A hash, in full, with a copy button that degrades to plain text.
 *
 * `navigator.clipboard` is absent under `file://` in some browsers and on any
 * insecure origin, which is exactly where the static export runs. When it is
 * missing the value is still shown in full and still selectable — the button is
 * an affordance, never the only way to get the hash.
 */
function CopyableHash({ value }: { value: string | null }): ReactNode {
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="muted">—</span>
  const canCopy = typeof navigator !== 'undefined' && navigator.clipboard !== undefined
  return (
    <>
      <span className="hash">{value}</span>
      {canCopy ? (
        <>
          {' '}
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard.writeText(value).then(
                () => setCopied(true),
                () => setCopied(false),
              )
            }}
          >
            {copied ? 'copied' : 'copy'}
          </button>
        </>
      ) : null}
    </>
  )
}

function Row({
  entry,
  broken_at,
}: {
  entry: ChainEntry
  broken_at: number | null
}): ReactNode {
  const isBreak = broken_at !== null && entry.seq === broken_at
  // `intent.registered` carries the utterance hash — the sentence the whole
  // project is about — so it gets the emphasis rather than being row zero of a
  // uniform list.
  const isIntent = entry.action === 'intent.registered'
  return (
    <tr
      id={`seq-${entry.seq}`}
      style={
        isBreak
          ? { background: 'var(--deny-bg)' }
          : isIntent
            ? { background: 'var(--paper-2)' }
            : undefined
      }
    >
      <td className="num">{entry.seq}</td>
      <td className="muted">{entry.ts}</td>
      <td>{entry.actor}</td>
      <td>
        <code>{entry.action}</code>
      </td>
      <td style={{ whiteSpace: 'pre-wrap', maxWidth: '60ch' }} className="mono">
        {JSON.stringify(entry.payload, null, 1)}
      </td>
    </tr>
  )
}

export function ChainPage({ run_id }: { run_id: string }): ReactNode {
  return (
    <>
      <h1>Audit chain</h1>
      <p className="hash">{run_id}</p>
      <ChainPanel run_id={run_id} />
    </>
  )
}
