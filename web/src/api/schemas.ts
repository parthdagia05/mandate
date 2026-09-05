/**
 * The wire format, mirrored from the artifact API. One parse boundary for the
 * whole app: below this file everything is a checked type, above it there is no
 * `any` and no hand-read JSON.
 *
 * Field names are snake_case on purpose and all the way down. Issue #83: "a
 * field renamed on the way out is a field the reader cannot grep for in the
 * JSONL." It looks wrong in TypeScript and it is correct here — a reader who
 * sees `case_id` on a page can `grep case_id runs/*.jsonl` and find the line.
 *
 * The run record itself is deliberately NOT fully specified. It is the harness's
 * own record, it grows a field whenever a milestone adds one, and a schema that
 * enumerated all of them would fail closed on a new field rather than ignore it
 * — turning "the harness recorded something extra" into "the viewer is down".
 * The parts the pages actually read are typed; the rest passes through as
 * `unknown` and is rendered as raw JSON.
 */
import { z } from 'zod'

/**
 * `harness.metrics.Proportion.as_dict()`, verbatim.
 *
 * `p` is carried rather than derived, and `ci95` is Wilson from the one
 * implementation `results.md` uses. The frontend never recomputes either (#91).
 *
 * Both refinements catch a service that computed something wrong, and a failed
 * parse at the boundary is better than a table rendering `112.0%`.
 */
export const Proportion = z
  .object({
    label: z.string(),
    k: z.number().int().nonnegative(),
    n: z.number().int().nonnegative(),
    p: z.number().min(0).max(1),
    ci95: z.tuple([z.number().min(0).max(1), z.number().min(0).max(1)]),
  })
  .refine((x) => x.k <= x.n, { message: 'k exceeds n' })
  .refine((x) => x.ci95[0] <= x.ci95[1], { message: 'interval is inverted' })
export type Proportion = z.infer<typeof Proportion>

export const Overhead = z.object({
  dataset: z.string(),
  baseline_config: z.string(),
  arm_config: z.string(),
  baseline_us: z.record(z.string(), z.number()),
  arm_us: z.record(z.string(), z.number()),
  p50_delta_us: z.number(),
  p99_delta_us: z.number(),
})
export type Overhead = z.infer<typeof Overhead>

/**
 * The five outcomes of issue #86, closed.
 *
 * Closed for the reason `kernel/enums.py` gives about reason codes: "an open
 * enum is a place an attacker can put a value nobody wrote a branch for". An
 * unrecognised outcome fails the parse instead of falling through to a default
 * branch that would render it as something it is not.
 */
export const Outcome = z.enum([
  'poisoned',
  'error',
  'attacker_win',
  'blocked',
  'task_success',
  'no_result',
])
export type Outcome = z.infer<typeof Outcome>

export const Health = z.object({
  schema: z.literal('mandate.web.health/1'),
  ok: z.boolean(),
  runs_root: z.string(),
  suites: z.number().int(),
  cases: z.number().int(),
  skipped: z.array(z.string()),
  kernel: z.object({ reachable: z.boolean(), url: z.string() }),
})
export type Health = z.infer<typeof Health>

export const MatrixProvenance = z.object({
  dir: z.string(),
  matrix_id: z.string(),
  seed: z.string(),
  model: z.string(),
  corpus_manifest: z.string(),
  corpus_manifests: z.record(z.string(), z.string()),
  datasets: z.array(z.string()),
  configs: z.array(z.string()),
  started_at: z.string(),
  finished_at: z.string(),
  batch_b_openings: z.number().int(),
  corpus_drift: z.array(z.string()),
  out_dir: z.string(),
})
export type MatrixProvenance = z.infer<typeof MatrixProvenance>

export const Matrices = z.object({
  schema: z.literal('mandate.web.matrices/1'),
  matrices: z.array(
    z.union([MatrixProvenance, z.object({ dir: z.string(), error: z.string() })]),
  ),
  ablations: z.array(
    z.object({
      dir: z.string(),
      dataset: z.string().nullable(),
      seed: z.string().nullable(),
      model: z.string().nullable(),
      rows: z.number().int(),
    }),
  ),
})
export type Matrices = z.infer<typeof Matrices>

export const HeadlineRow = z.object({
  config: z.string(),
  targeted_asr: Proportion.nullable(),
  utility_under_attack: Proportion.nullable(),
  benign_utility: Proportion.nullable(),
  false_block_rate: Proportion.nullable(),
  recovered: Proportion.nullable(),
  overhead: Overhead.nullable(),
})
export type HeadlineRow = z.infer<typeof HeadlineRow>

export const FalseBlock = z.object({
  task_id: z.string().nullable(),
  run_id: z.string().nullable(),
  step: z.string().nullable().optional(),
  decision: z.string().nullable().optional(),
  reason_code: z.string().nullable().optional(),
  denied_by: z.array(z.unknown()).optional(),
  checks_run: z.array(z.unknown()).optional(),
  task_success: z.boolean().nullable().optional(),
})
export type FalseBlock = z.infer<typeof FalseBlock>

export const Results = z.object({
  schema: z.literal('mandate.web.results/1'),
  dataset: z.string(),
  is_attack_dataset: z.boolean(),
  benign_dataset: z.string().nullable(),
  stand_in: z.boolean(),
  matrix: MatrixProvenance.omit({ dir: true }).extend({ dir: z.string().optional() }),
  arms: z.array(z.object({ config: z.string(), blurb: z.string() })),
  headline: z.array(HeadlineRow),
  by_class: z.record(z.string(), z.record(z.string(), Proportion.nullable())),
  by_family: z.record(z.string(), z.record(z.string(), Proportion.nullable())),
  refusals: z.record(
    z.string(),
    z.array(z.object({ reason_code: z.string(), count: z.number().int() })),
  ),
  guard_refusals: z.record(
    z.string(),
    z.array(z.object({ refusal: z.string(), count: z.number().int() })),
  ),
  false_blocks: z.record(z.string(), z.array(FalseBlock)),
})
export type Results = z.infer<typeof Results>

export const Facets = z.object({
  schema: z.literal('mandate.web.facets/1'),
  facets: z.record(
    z.string(),
    z.array(z.object({ value: z.string(), runs: z.number().int() })),
  ),
})
export type Facets = z.infer<typeof Facets>

export const Ablation = z.object({
  schema: z.literal('mandate.web.ablation/1'),
  dataset: z.string(),
  seed: z.string(),
  model: z.string(),
  corpus_manifest: z.string(),
  baseline_suite_id: z.string(),
  started_at: z.string(),
  finished_at: z.string(),
  baseline: z.object({
    targeted_asr: Proportion.nullable(),
    by_class: z.record(z.string(), Proportion.nullable()),
  }),
  rows: z.array(
    z.object({
      check_ids: z.array(z.number().int()),
      check_id: z.number().int().nullable(),
      label: z.string(),
      mode: z.string(),
      suite_id: z.string(),
      targeted_asr: Proportion.nullable(),
      by_class: z.record(z.string(), Proportion.nullable()),
    }),
  ),
  verdicts: z.record(
    z.string(),
    z.object({
      necessary_for: z.array(z.string()),
      sufficient_for: z.array(z.string()),
      earns_row: z.boolean(),
    }),
  ),
})
export type Ablation = z.infer<typeof Ablation>

export const RunRow = z.object({
  run_id: z.string(),
  case_id: z.string().nullable(),
  task_id: z.string().nullable(),
  config: z.string(),
  dataset: z.string(),
  class: z.string().nullable(),
  technique: z.string().nullable(),
  batch: z.string().nullable(),
  injection_point: z.string().nullable(),
  attacker_win: z.boolean().nullable(),
  task_success: z.boolean().nullable(),
  poisoned: z.unknown().nullable(),
  error: z.unknown().nullable(),
  outcome: Outcome,
  reason_codes: z.array(z.string()),
  net_debit_paise: z.number().int(),
  mandates_opened: z.number().int(),
  chain_entries: z.number().int(),
  chain_head: z.string().nullable(),
  counterparts: z.record(z.string(), z.string()),
})
export type RunRow = z.infer<typeof RunRow>

export const Runs = z.object({
  schema: z.literal('mandate.web.runs/1'),
  total: z.number().int(),
  limit: z.number().int(),
  cursor: z.number().int(),
  next_cursor: z.number().int().nullable(),
  filters: z.record(z.string(), z.string()),
  sort: z.string().nullable(),
  rows: z.array(RunRow),
})
export type Runs = z.infer<typeof Runs>

/** A payee, a source, a refund destination. `value` is the address the money moved to. */
export const Account = z.object({
  type: z.string(),
  value: z.string(),
  merchant_id: z.string().optional(),
})
export type Account = z.infer<typeof Account>

export const LedgerEntry = z.object({
  payment_id: z.string().optional(),
  order_id: z.string().optional(),
  client_ref: z.string().optional(),
  state: z.string().optional(),
  currency: z.string().optional(),
  amount_paise: z.number().int().optional(),
  captured_paise: z.number().int().optional(),
  cart_hash: z.string().optional(),
  payee: Account.optional(),
  source: Account.optional(),
  line_items: z
    .array(
      z.object({
        sku: z.string(),
        qty: z.number().int(),
        unit_amount: z.number().int(),
      }),
    )
    .optional(),
})
export type LedgerEntry = z.infer<typeof LedgerEntry>

export const PlanStep = z.object({
  step: z.string(),
  output: z.unknown().optional(),
})
export type PlanStep = z.infer<typeof PlanStep>

/** One check the kernel ran, as it reported it. */
export const CheckResult = z.object({
  id: z.number().int(),
  name: z.string(),
  result: z.string(),
})
export type CheckResult = z.infer<typeof CheckResult>

export const KernelDecision = z.object({
  action: z.string().optional(),
  step: z.string().nullable().optional(),
  decision: z.string().optional(),
  reason_code: z.string().nullable().optional(),
  denied_by: z.array(z.unknown()).optional(),
  // Which checks ran, not how many. #87 asks for the checks; a count says a
  // decision was reached without saying what reached it.
  checks: z.array(CheckResult).nullable().optional(),
})
export type KernelDecision = z.infer<typeof KernelDecision>

/**
 * The run record. Only the fields the pages read are named; `passthrough`
 * carries the rest so a harness that records one more field does not take the
 * viewer down.
 */
export const RunRecord = z
  .object({
    run_id: z.string(),
    case_id: z.string().nullable().optional(),
    task_id: z.string().nullable().optional(),
    config: z.string().optional(),
    seed: z.string().optional(),
    model: z.string().optional(),
    attacker_win: z.boolean().nullable().optional(),
    task_success: z.boolean().nullable().optional(),
    poisoned: z.unknown().optional(),
    error: z.unknown().optional(),
    notes: z.array(z.string()).optional(),
    plan: z
      .object({
        total_paise: z.number().int().optional(),
        sku: z.string().optional(),
        payee: Account.optional(),
        checkout_payee: Account.optional(),
        payee_was_redirected: z.boolean().optional(),
        line_items: z
          .array(
            z.object({
              sku: z.string(),
              qty: z.number().int(),
              unit_amount: z.number().int(),
            }),
          )
          .optional(),
        steps: z.array(PlanStep).optional(),
      })
      .nullable()
      .optional(),
    decisions: z.array(KernelDecision).optional(),
    ledger: z.array(LedgerEntry).optional(),
    refunds: z.array(z.unknown()).optional(),
    mandates: z.array(z.unknown()).optional(),
    recoveries: z.array(z.unknown()).optional(),
    guard_events: z.array(z.unknown()).optional(),
    // The tool calls the agent made at the money boundary. `latency_us` rides
    // along on the record and is deliberately not in this shape: P8 found it
    // and `money_calls` to be the only fields that differ across machines, by
    // more than an order of magnitude, which is why no duration reaches the
    // event log or the chain. Rendering a per-call duration would invite a
    // comparison that was never valid.
    money_calls: z.array(z.object({ call: z.string() }).passthrough()).optional(),
    // The agent-side arms record what the quarantined extractor read out of
    // merchant content, step by step. This is the closest thing on disk to
    // "what the merchant returned"; the event log that holds the rest is
    // summarised to a head hash rather than persisted.
    extractor: z
      .object({
        has_tools: z.boolean().optional(),
        model: z.string().optional(),
        reads: z
          .array(
            z.object({
              step: z.string(),
              prose_bytes: z.number().int().optional(),
              output: z.unknown().optional(),
            }),
          )
          .optional(),
      })
      .passthrough()
      .optional(),
    taint: z
      .object({
        declared_kernel: z.number().int().optional(),
        declared_user: z.number().int().optional(),
        observed_merchant: z.number().int().optional(),
        refusals: z
          .array(
            z.object({
              field: z.string(),
              provenance: z.string(),
              admitted: z.array(z.string()).optional(),
              value: z.unknown().optional(),
            }),
          )
          .optional(),
      })
      .passthrough()
      .optional(),
    log_entries: z.number().int().optional(),
    log_head: z.string().nullable().optional(),
    chain_entries: z.number().int().optional(),
    chain_head: z.string().nullable().optional(),
    containment: z.unknown().optional(),
  })
  .passthrough()
export type RunRecord = z.infer<typeof RunRecord>

export const TaskDetail = z.object({
  task_id: z.string(),
  corpus: z.string(),
  merchant: z.string(),
  utterance: z.string().nullable(),
  query: z.string().nullable().optional(),
  wants: z.string().nullable().optional(),
  scope: z.unknown().nullable().optional(),
  expect: z.unknown().nullable().optional(),
})
export type TaskDetail = z.infer<typeof TaskDetail>

export const AttackDetail = z.object({
  case_id: z.string(),
  class: z.string(),
  batch: z.string(),
  task: z.string(),
  technique: z.string(),
  oracle: z.string(),
  injection_point: z.string(),
  expected_undefended: z.string().nullable().optional(),
  /** True for a held-out batch. `payload` is then absent — and that is not the same as empty. */
  held_out: z.boolean(),
  payload: z.string().nullable(),
})
export type AttackDetail = z.infer<typeof AttackDetail>

/**
 * Does the chain name the sentence being shown?
 *
 * The chain carries `utterance_hash`, not the sentence. `matches: false` is a
 * real finding and renders as one.
 */
export const UtteranceBinding = z.object({
  utterance_hash: z.string(),
  utterance: z.string().nullable(),
  computed: z.string().nullable(),
  matches: z.boolean(),
})
export type UtteranceBinding = z.infer<typeof UtteranceBinding>

export const RunDetail = z.object({
  schema: z.literal('mandate.web.run/1'),
  record: RunRecord,
  outcome: Outcome,
  counterparts: z.record(z.string(), z.string()),
  task: TaskDetail.nullable(),
  attack: AttackDetail.nullable(),
  utterance_binding: UtteranceBinding.nullable(),
})
export type RunDetail = z.infer<typeof RunDetail>

export const ChainEntry = z.object({
  seq: z.number().int().nonnegative(),
  ts: z.string(),
  actor: z.string(),
  action: z.string(),
  payload: z.unknown(),
  prev_hash: z.string(),
  entry_hash: z.string(),
})
export type ChainEntry = z.infer<typeof ChainEntry>

/**
 * The verifier's verdict, from `scripts/verify_chain.py`.
 *
 * There is no client-side recomputation to compare it against, deliberately
 * (#88): "the hash chain is not reimplemented in JavaScript. A second
 * implementation that disagrees with the first is a bug factory."
 */
export const ChainVerify = z.object({
  ok: z.boolean(),
  entries: z.number().int().nullable(),
  head: z.string().nullable(),
  broken_at: z.number().int().nullable(),
  message: z.string(),
  verifier: z.string(),
})
export type ChainVerify = z.infer<typeof ChainVerify>

export const Chain = z.object({
  schema: z.literal('mandate.web.chain/1'),
  run_id: z.string(),
  path: z.string().nullable(),
  entries: z.array(ChainEntry),
  head: z.string().nullable(),
  /** `null` when the arm appends no chain. Not the same as a failed verification. */
  verify: ChainVerify.nullable(),
  note: z.string().nullable(),
})
export type Chain = z.infer<typeof Chain>

export const Tasks = z.object({
  schema: z.literal('mandate.web.tasks/1'),
  corpus: z.string(),
  tasks: z.array(
    z.object({
      task_id: z.string(),
      merchant: z.string(),
      utterance: z.string().nullable(),
      scope: z.unknown().nullable().optional(),
    }),
  ),
})
export type Tasks = z.infer<typeof Tasks>

export const Attacks = z.object({
  schema: z.literal('mandate.web.attacks/1'),
  batch: z.string(),
  note: z.string(),
  attacks: z.array(
    z.object({
      case_id: z.string(),
      class: z.string(),
      batch: z.string(),
      task: z.string(),
      technique: z.string(),
      oracle: z.string(),
      injection_point: z.string(),
    }),
  ),
})
export type Attacks = z.infer<typeof Attacks>

/**
 * What the live kernel said. Issue #89.
 *
 * `kernel_reachable: false` means there is no decision, and the page renders
 * that fact and nothing else — every decision field is absent, not empty.
 */
export const Demo = z.object({
  schema: z.literal('mandate.web.demo/1'),
  kernel_reachable: z.boolean(),
  kernel_url: z.string(),
  error: z.string().optional(),
  task_id: z.string().optional(),
  case_id: z.string().nullable().optional(),
  redirected_payee: z.object({ type: z.string(), value: z.string() }).nullable().optional(),
  steps: z.array(
    z.object({
      endpoint: z.string(),
      status: z.number().int(),
      body: z.record(z.string(), z.unknown()),
    }),
  ),
  decision: z.string().nullable().optional(),
  reason_code: z.string().nullable().optional(),
  denied_by: z.array(z.number().int()).optional(),
  checks: z
    .array(z.object({ id: z.number().int(), name: z.string(), result: z.string() }))
    .optional(),
  audit: z.unknown().nullable().optional(),
  note: z.string(),
  replayed: z.boolean().optional(),
  replay_note: z.string().nullable().optional(),
})
export type Demo = z.infer<typeof Demo>

export const ApiError = z.object({
  error: z.string(),
  field: z.string().optional(),
})
export type ApiError = z.infer<typeof ApiError>
