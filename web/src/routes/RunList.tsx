/**
 * The run list. Issue #86.
 *
 * Filter by arm, class, technique, injection point, batch and outcome, and sort
 * by any column a header offers; a row opens the trace; two selected rows open
 * the compare view.
 *
 * Sorting happens in the service, not here. The page holds one window of a
 * corpus of thousands, and sorting a window sorts the wrong set — the top row
 * of a sort over 100 rows is not the top row of the corpus, and nothing on
 * screen would say so.
 *
 * **Outcome is not a boolean.** The five values come from the API, which decides
 * them in one place and in an order that matters: a poisoned run shows as
 * discarded and never as a defended one, and an errored run shows as an error
 * and not as a zero. Nothing here re-derives an outcome from `attacker_win`.
 *
 * Every filter is in the URL, so the view Shot 4 opens — class A1, arm
 * undefended — is a link, and a shot that has to be re-recorded lands on the
 * identical page.
 */
import { useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { Facets, RunRow } from '../api/schemas'
import { formatPaise } from '../format/money'
import { Code, Failure, Loading, OutcomeTag } from '../ui/primitives'
import { useApi } from '../ui/useApi'
import { href, useRoute } from './router'

/** The dimensions the API filters on, in the order the form shows them. */
const DIMENSIONS = [
  'config',
  'dataset',
  'class',
  'technique',
  'injection_point',
  'batch',
  'outcome',
] as const

type Dimension = (typeof DIMENSIONS)[number]

const PAGE = 100

export function RunList(): ReactNode {
  const { route, setParams } = useRoute()
  const facets = useApi(() => api.facets(), [])

  const filters: Partial<Record<Dimension, string>> = {}
  for (const dimension of DIMENSIONS) {
    const value = route.params[dimension]
    if (value) filters[dimension] = value
  }
  const cursor = Number(route.params['cursor'] ?? '0') || 0
  const sort = route.params['sort'] ?? ''

  const runs = useApi(
    () => api.runs({ ...filters, sort: sort || undefined, limit: PAGE, cursor }),
    [JSON.stringify(filters), cursor, sort],
  )

  // The compare selection is the one piece of state that is not a filter: it is
  // a transient two-click gesture, and the destination it produces *is* a URL.
  const [selected, setSelected] = useState<string[]>([])

  return (
    <>
      <h1>Runs</h1>

      {facets.state === 'ok' ? (
        <Filters
          facets={facets.value}
          filters={filters}
          onChange={(dimension, value) =>
            setParams({ [dimension]: value || undefined, cursor: undefined })
          }
          onClear={() =>
            setParams({
              ...Object.fromEntries(DIMENSIONS.map((d) => [d, undefined])),
              cursor: undefined,
            })
          }
        />
      ) : null}

      <CompareBar selected={selected} onClear={() => setSelected([])} />

      {runs.state === 'loading' ? <Loading what="the runs" /> : null}
      {runs.state === 'failed' ? <Failure error={runs.error} /> : null}
      {runs.state === 'ok' ? (
        <>
          <p className="muted">
            {runs.value.total} run{runs.value.total === 1 ? '' : 's'} match
            {runs.value.total === 1 ? 'es' : ''} these filters. Showing{' '}
            {runs.value.cursor + 1}–{runs.value.cursor + runs.value.rows.length}.
          </p>
          <Table
            rows={runs.value.rows}
            sort={sort}
            onSort={(column) =>
              setParams({
                // Third click clears the sort rather than cycling forever back
                // to ascending: "no ordering" is a real state and the corpus
                // order is the frozen one the harness ran in.
                sort: sort === column ? `-${column}` : sort === `-${column}` ? undefined : column,
                cursor: undefined,
              })
            }
            selected={selected}
            onSelect={(run_id) =>
              setSelected((current) =>
                current.includes(run_id)
                  ? current.filter((id) => id !== run_id)
                  : [...current, run_id].slice(-2),
              )
            }
          />
          <Pager
            cursor={runs.value.cursor}
            next={runs.value.next_cursor}
            onGo={(to) => setParams({ cursor: to === 0 ? undefined : String(to) })}
          />
        </>
      ) : null}
    </>
  )
}

function Filters({
  facets,
  filters,
  onChange,
  onClear,
}: {
  facets: Facets
  filters: Partial<Record<Dimension, string>>
  onChange: (dimension: Dimension, value: string) => void
  onClear: () => void
}): ReactNode {
  const active = DIMENSIONS.filter((dimension) => filters[dimension])
  return (
    <div className="filters">
      {DIMENSIONS.map((dimension) => {
        const options = facets.facets[dimension] ?? []
        if (options.length === 0) return null
        return (
          <label key={dimension}>
            {dimension}
            <select
              value={filters[dimension] ?? ''}
              onChange={(event) => onChange(dimension, event.target.value)}
            >
              <option value="">any</option>
              {options.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.value} ({option.runs})
                </option>
              ))}
            </select>
          </label>
        )
      })}
      <button type="button" onClick={onClear} disabled={active.length === 0}>
        clear {active.length > 0 ? `(${active.length})` : ''}
      </button>
    </div>
  )
}

function CompareBar({
  selected,
  onClear,
}: {
  selected: string[]
  onClear: () => void
}): ReactNode {
  if (selected.length === 0) {
    return (
      <p className="muted">
        Select two runs to compare them — the same case under two arms is the
        project&rsquo;s whole claim on one screen.
      </p>
    )
  }
  const [left, right] = selected
  return (
    <div className="filters">
      <span className="muted">
        {selected.length} selected{selected.length === 1 ? ' — pick one more' : ''}
      </span>
      {left && right ? (
        <a className="button" href={href(['compare', left, right])}>
          compare these two
        </a>
      ) : null}
      <button type="button" onClick={onClear}>
        clear selection
      </button>
    </div>
  )
}

/** Columns the service will order by. Mirrors `SORTABLE` in harness/web/api.py. */
const SORTABLE = new Set([
  'case_id',
  'task_id',
  'config',
  'class',
  'technique',
  'injection_point',
  'outcome',
  'net_debit_paise',
  'chain_entries',
])

function SortHeader({
  column,
  label,
  sort,
  onSort,
  numeric,
}: {
  column: string
  label: string
  sort: string
  onSort: (column: string) => void
  numeric?: boolean
}): ReactNode {
  if (!SORTABLE.has(column)) return <th className={numeric ? 'num' : undefined}>{label}</th>
  const active = sort === column ? 'ascending' : sort === `-${column}` ? 'descending' : undefined
  return (
    <th className={numeric ? 'num' : undefined} aria-sort={active ?? 'none'}>
      <button type="button" onClick={() => onSort(column)}>
        {label}
        {active === 'ascending' ? ' \u2191' : active === 'descending' ? ' \u2193' : ''}
      </button>
    </th>
  )
}

function Table({
  rows,
  sort,
  onSort,
  selected,
  onSelect,
}: {
  rows: RunRow[]
  sort: string
  onSort: (column: string) => void
  selected: string[]
  onSelect: (run_id: string) => void
}): ReactNode {
  if (rows.length === 0) {
    return <p className="empty">No run matches these filters.</p>
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th />
            <SortHeader column="case_id" label="case" sort={sort} onSort={onSort} />
            <SortHeader column="task_id" label="task" sort={sort} onSort={onSort} />
            <SortHeader column="config" label="arm" sort={sort} onSort={onSort} />
            <SortHeader column="class" label="class" sort={sort} onSort={onSort} />
            <SortHeader column="technique" label="technique" sort={sort} onSort={onSort} />
            <SortHeader
              column="injection_point"
              label="injection point"
              sort={sort}
              onSort={onSort}
            />
            <SortHeader column="outcome" label="outcome" sort={sort} onSort={onSort} />
            <th>refused with</th>
            <SortHeader
              column="net_debit_paise"
              label="lost"
              sort={sort}
              onSort={onSort}
              numeric
            />
            <SortHeader
              column="chain_entries"
              label="chain"
              sort={sort}
              onSort={onSort}
              numeric
            />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.run_id}>
              <td>
                <input
                  type="checkbox"
                  checked={selected.includes(row.run_id)}
                  onChange={() => onSelect(row.run_id)}
                  aria-label={`select ${row.case_id ?? row.task_id ?? row.run_id}`}
                />
              </td>
              <td>
                <a href={href(['runs', row.run_id])}>
                  {row.case_id ?? <span className="muted">benign</span>}
                </a>
              </td>
              <td>{row.task_id}</td>
              <td>
                <code>{row.config}</code>
              </td>
              <td>{row.class ?? <span className="muted">—</span>}</td>
              <td>{row.technique ?? <span className="muted">—</span>}</td>
              <td className="muted">{row.injection_point ?? '—'}</td>
              <td>
                <OutcomeTag outcome={row.outcome} />
              </td>
              <td>
                {row.reason_codes.length === 0 ? (
                  <span className="muted">—</span>
                ) : (
                  row.reason_codes.map((code) => (
                    <span key={code} style={{ marginRight: 4 }}>
                      <Code code={code} />
                    </span>
                  ))
                )}
              </td>
              <td className="num">
                {formatPaise(row.net_debit_paise)}
                {row.net_debit_paise === 0 && row.mandates_opened > 0 ? (
                  <>
                    {' '}
                    <span className="code">
                      {row.mandates_opened} mandate{row.mandates_opened === 1 ? '' : 's'}
                    </span>
                  </>
                ) : null}
              </td>
              <td className="num">
                {row.chain_entries > 0 ? (
                  <a href={href(['runs', row.run_id, 'chain'])}>{row.chain_entries}</a>
                ) : (
                  <span className="muted">none</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Pager({
  cursor,
  next,
  onGo,
}: {
  cursor: number
  next: number | null
  onGo: (to: number) => void
}): ReactNode {
  return (
    <div className="filters">
      <button type="button" disabled={cursor === 0} onClick={() => onGo(Math.max(0, cursor - PAGE))}>
        previous
      </button>
      <button type="button" disabled={next === null} onClick={() => next !== null && onGo(next)}>
        next
      </button>
    </div>
  )
}
