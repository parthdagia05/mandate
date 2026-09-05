/**
 * Presentational components. Props in, DOM out — no fetching, no arithmetic,
 * no formatting logic of their own beyond calling `format/`.
 */
import type { ReactNode } from 'react'
import type { Outcome, Proportion } from '../api/schemas'
import { formatProportion, proportionParts } from '../format/proportion'
import { codeGloss, isAllow, outcomeLabel } from '../format/codes'

/**
 * A proportion in a table cell: estimate, interval and counts, always all three.
 *
 * The interval and the counts are dimmed rather than dropped. Dimming is a
 * layout decision; dropping would be a claim, and it is the exact claim
 * `results.md` refuses to make.
 */
export function Prop({ value }: { value: Proportion | null }): ReactNode {
  if (value === null) return <span className="muted">—</span>
  const parts = proportionParts(value)
  if (parts === null) return <span className="muted">n/a (n=0)</span>
  return (
    <span title={formatProportion(value)}>
      <span className="prop-est">{parts.estimate}</span>{' '}
      <span className="prop-ci">{parts.interval}</span>{' '}
      <span className="prop-n">{parts.counts}</span>
    </span>
  )
}

/** One of the five outcomes (#86). `poisoned` and `error` are not defended runs. */
export function OutcomeTag({ outcome }: { outcome: Outcome }): ReactNode {
  return <span className={`tag tag-${outcome}`}>{outcomeLabel(outcome)}</span>
}

/** A reason code, in the kernel's own casing, with its gloss as a tooltip. */
export function Code({ code }: { code: string }): ReactNode {
  const gloss = codeGloss(code)
  return (
    <span className={isAllow(code) ? 'code code-ok' : 'code'} title={gloss ?? undefined}>
      {code}
    </span>
  )
}

/** A hash, shown in full and selectable, so it can be checked against the JSONL. */
export function Hash({ value }: { value: string | null }): ReactNode {
  if (!value) return <span className="muted">—</span>
  return <span className="hash">{value}</span>
}

export function Loading({ what }: { what: string }): ReactNode {
  return <p className="loading">Loading {what}…</p>
}

/**
 * A failure, stated. Never a blank table: an empty results page reads as "no
 * attacks landed", which is the most flattering possible way to be broken.
 */
export function Failure({ error }: { error: unknown }): ReactNode {
  const message = error instanceof Error ? error.message : String(error)
  return (
    <div className="failure">
      <p>
        <strong>This did not load, so nothing is shown for it.</strong>
      </p>
      <p className="mono">{message}</p>
      <p className="muted">
        If the artifact API is not running: <code>mk web</code> from the repository root.
      </p>
    </div>
  )
}

/**
 * Attacker-authored text. The only component that renders it.
 *
 * Always a text node — React escapes it, and `dangerouslySetInnerHTML` appears
 * nowhere in this codebase, because the corpus has an evasion family whose whole
 * technique is markup. Always labelled with where it sat, because Shot 4's point
 * is that the text is ordinary and the reader has to be told it is theirs.
 */
export function Payload({
  text,
  point,
  held_out,
}: {
  text: string | null
  point: string | null
  held_out: boolean
}): ReactNode {
  if (held_out) {
    return (
      <div className="payload payload-sealed">
        <span className="payload-label">
          held out — batch B is sealed and opening it is logged
        </span>
        <p className="payload-text muted">
          The payload is not shown and was not read. Its class, technique and oracle are
          above.
        </p>
      </div>
    )
  }
  if (text === null) return null
  return (
    <div className="payload">
      <span className="payload-label">
        attacker-authored{point ? ` · injected at ${point}` : ''}
      </span>
      <p className="payload-text">{text}</p>
    </div>
  )
}

/**
 * The stand-in banner. Rendered whenever the runs were driven by the
 * deterministic planner rather than a model, because `results.md` prints that
 * in bold and a page that dropped it would claim more than the document does.
 */
export function StandInBanner({ model }: { model: string }): ReactNode {
  return (
    <div className="banner">
      <strong>The deterministic stand-in drove these runs, not a model.</strong>{' '}
      <code>{model}</code> is a rule-based planner, so <strong>no ASR figure on this
      page is a model measurement</strong>. It exists so the rail, the merchant, the
      tools, the ledger and the kernel are measurable without an API key. Two
      consequences are visible and neither is hidden: the <code>base64</code> family
      scores an honest zero everywhere because the stand-in decodes nothing, and the{' '}
      <code>model-only</code> arm's classifier is a lexical rule standing in for a
      classifier model.
    </div>
  )
}
