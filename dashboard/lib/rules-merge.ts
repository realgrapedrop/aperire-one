/**
 * ADR 0020. Alert rules are two files, and this is where they become one set.
 *
 *   config/rules.yaml        the product's. Shipped, replaced by every
 *                            install and update, not edited on a host.
 *   config/rules.local.yaml  the operator's. Read, never written, excluded
 *                            from the deploy. Absent means the shipped rules
 *                            exactly.
 *
 * The merge happens on the RAW yaml entries, before the loader's own
 * per-rule validation runs, so the evaluator's inputs after the merge are the
 * same shape they were when one file fed it. Nothing here parses a threshold
 * or a duration; that stays in the one place that always did it.
 *
 * The key is metric + severity, which is the identity the evaluator already
 * uses: `ruleFingerprint()` is `${metric}:${severity}` and the firing_state
 * row is keyed on the same pair. So a local entry names exactly one rule
 * instance, and the thing it overrides is the thing that fires.
 *
 * Two rules this module exists to keep:
 *
 *   - **The local file can never take the alerting down.** Every fault in it
 *     is a named error handed back to the caller, with the shipped rules
 *     returned intact. Never a silent drop, never zero rules.
 *   - **An omitted `op` is never a `>=`.** The loader defaults a missing
 *     threshold op to `>=`. `peer_count` warns BELOW 5; a local
 *     `threshold: { value: 2 }` taking that default would fire at two peers
 *     or more, forever, meaning the opposite of what was written. An
 *     override inherits the shipped op; an addition has to say one.
 */

import yaml from 'js-yaml';

/** The operator's file, named in every message this module produces. */
export const LOCAL_RULES_FILENAME = 'rules.local.yaml';

type AnyObj = Record<string, unknown>;

/** A raw yaml rule entry, exactly as the loader's own validation will see it. */
export type RawRule = AnyObj;

export interface MergeCounts {
  /** Entries in the shipped file. */
  shipped: number;
  /** Local entries that replaced fields of a shipped rule. */
  overrides: number;
  /** Local entries for a key the shipped set does not have. */
  added: number;
  /** Local entries carrying `enabled: false`. */
  disabled: number;
}

export interface MergedRules {
  /** The merged raw entries: shipped order first, additions after. */
  rules: RawRule[];
  counts: MergeCounts;
  /** A local file was there to read, whether or not it could be used. */
  localPresent: boolean;
  /** Named reason the local file was not applied, or null. */
  localError: string | null;
}

/** A local file that cannot be used. Carried as a message, not thrown past
 *  the merge: the shipped rules still load. */
class LocalRulesError extends Error {}

const SEVERITIES = new Set(['warn', 'critical', 'page']);

/** metric + severity, lowercased. The evaluator's own fingerprint. */
export function ruleKey(metric: string, severity: string): string {
  return `${metric}:${severity.toLowerCase()}`;
}

/** The key of a raw entry, or null when it does not have one. */
function keyOf(raw: unknown): string | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as AnyObj;
  const metric = typeof r.metric === 'string' ? r.metric.trim() : '';
  const sev = String(r.severity ?? '').trim().toLowerCase();
  if (!metric || !SEVERITIES.has(sev)) return null;
  return ruleKey(metric, sev);
}

/** A human name for an entry that has no usable key. */
function describe(raw: unknown, index: number): string {
  const r = (raw && typeof raw === 'object') ? raw as AnyObj : {};
  const metric = typeof r.metric === 'string' ? r.metric : '';
  const sev = typeof r.severity === 'string' ? r.severity : '';
  if (metric || sev) return `${metric || '(no metric)'} ${sev || '(no severity)'}`;
  return `entry ${index + 1}`;
}

/**
 * The `rules:` array of a document, or null when there is no document at all.
 *
 * An empty file, or one that is nothing but comments, is a document of
 * `undefined` and reads as "no entries". The installer seeds exactly that, so
 * treating it as a fault would put every fresh install into a warn state.
 */
function rulesArray(text: string): RawRule[] {
  const doc = yaml.load(text) as AnyObj | undefined | null;
  if (doc === null || doc === undefined) return [];
  if (typeof doc !== 'object') throw new Error('not a yaml document of rules');
  const raw = (doc as AnyObj).rules;
  if (raw === null || raw === undefined) return [];
  if (!Array.isArray(raw)) throw new Error('top-level "rules" array missing');
  return raw as RawRule[];
}

/** Fields a local entry may set. `metric` and `severity` are the key and are
 *  taken from the shipped entry; `enabled` is an instruction, not a field. */
function applyOverride(shipped: RawRule, local: RawRule): RawRule {
  const out: RawRule = { ...shipped };
  for (const [field, value] of Object.entries(local)) {
    if (field === 'enabled' || field === 'metric' || field === 'severity') continue;
    if (field === 'threshold') {
      const base = (shipped.threshold && typeof shipped.threshold === 'object')
        ? shipped.threshold as AnyObj : {};
      out.threshold = { ...base, ...(value as AnyObj) };
      continue;
    }
    out[field] = value;
  }
  return out;
}

/**
 * Merge the two files into the raw rule set the loader validates.
 *
 * Throws only when the SHIPPED text is unusable, which is the existing
 * failure and keeps the existing message. Anything wrong with the local text
 * comes back as `localError` with the shipped rules returned whole.
 *
 * @param shippedText  contents of config/rules.yaml
 * @param localText    contents of config/rules.local.yaml, or null when absent
 */
export function mergeRuleFiles(shippedText: string, localText: string | null): MergedRules {
  const doc = yaml.load(shippedText) as AnyObj | undefined | null;
  const shipped = Array.isArray(doc?.rules) ? doc.rules as RawRule[] : null;
  if (!shipped) throw new Error('top-level "rules" array missing');

  const counts: MergeCounts = { shipped: shipped.length, overrides: 0, added: 0, disabled: 0 };
  if (localText === null) {
    return { rules: shipped, counts, localPresent: false, localError: null };
  }

  try {
    const local = rulesArray(localText);

    // Shipped keys first, so an override knows what it is overriding.
    const shippedByKey = new Map<string, RawRule[]>();
    shipped.forEach((raw) => {
      const k = keyOf(raw);
      if (!k) return;                     // the loader drops it; not our business
      const list = shippedByKey.get(k);
      if (list) list.push(raw); else shippedByKey.set(k, [raw]);
    });

    const overrides = new Map<string, RawRule>();
    const disabled = new Set<string>();
    const additions: RawRule[] = [];
    const seen = new Set<string>();

    local.forEach((raw, i) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new LocalRulesError(`${describe(raw, i)} is not a rule`);
      }
      const key = keyOf(raw);
      if (!key) {
        throw new LocalRulesError(
          `${describe(raw, i)} needs a metric and a severity of warn, critical or page`);
      }
      if (seen.has(key)) {
        throw new LocalRulesError(`${key.replace(':', ' ')} appears twice`);
      }
      seen.add(key);

      const enabled = (raw as AnyObj).enabled;
      if (enabled !== undefined && typeof enabled !== 'boolean') {
        throw new LocalRulesError(`${key.replace(':', ' ')}: enabled must be true or false`);
      }
      if (enabled === false) {
        disabled.add(key);
        counts.disabled++;
        return;
      }

      const base = shippedByKey.get(key);
      if (base) {
        const t = (raw as AnyObj).threshold;
        if (t !== undefined && (typeof t !== 'object' || t === null || Array.isArray(t))) {
          throw new LocalRulesError(`${key.replace(':', ' ')}: threshold must have op and value`);
        }
        overrides.set(key, raw);
        counts.overrides++;
        return;
      }

      // An addition inherits nothing, so it has to carry a whole threshold.
      // Without the op it would take the loader's `>=` default from silence.
      const t = (raw as AnyObj).threshold as AnyObj | undefined;
      const op = t && typeof t === 'object' ? t.op : undefined;
      const value = t && typeof t === 'object' ? t.value : undefined;
      if (typeof op !== 'string' || !op.trim() || !Number.isFinite(Number(value))) {
        throw new LocalRulesError(
          `${key.replace(':', ' ')} is not in the shipped rules, so it needs threshold op and value`);
      }
      additions.push(raw);
      counts.added++;
    });

    const rules: RawRule[] = [];
    for (const raw of shipped) {
      const k = keyOf(raw);
      if (k && disabled.has(k)) continue;
      const over = k ? overrides.get(k) : undefined;
      rules.push(over ? applyOverride(raw, over) : raw);
    }
    rules.push(...additions);

    return { rules, counts, localPresent: true, localError: null };
  } catch (err) {
    const message = err instanceof LocalRulesError
      ? `${LOCAL_RULES_FILENAME}: ${err.message}`
      : `${LOCAL_RULES_FILENAME}: ${(err as Error).message}`;
    return {
      rules: shipped,
      counts: { shipped: shipped.length, overrides: 0, added: 0, disabled: 0 },
      localPresent: true,
      localError: message,
    };
  }
}

/** The load line the dashboard writes, minus its `[insights] ` prefix.
 *
 *  One function so the line an operator greps for, the line the operational
 *  guide quotes and the line a test asserts are the same string. The prefix
 *  `rules.yaml parsed:` is kept from before ADR 0020: the guide names it and
 *  so does at least one operator's grep. */
export function describeRulesLoad(
  counts: { total: number; page: number; critical: number; warn: number },
  merged: MergedRules,
): string {
  return `rules.yaml parsed: ${counts.total} rules `
    + `(${counts.page}P · ${counts.critical}C · ${counts.warn}W); `
    + `shipped ${merged.counts.shipped}, ${describeMerge(merged)}`;
}

/** The tail of the load line, and of anything else reporting what is in force. */
export function describeMerge(m: MergedRules): string {
  if (m.localError) return `${LOCAL_RULES_FILENAME} not applied`;
  if (!m.localPresent) return `no ${LOCAL_RULES_FILENAME}`;
  const { overrides, added, disabled } = m.counts;
  if (!overrides && !added && !disabled) return `${LOCAL_RULES_FILENAME}: nothing overridden`;
  return `${LOCAL_RULES_FILENAME}: ${overrides} override${overrides === 1 ? '' : 's'}, `
    + `${added} added, ${disabled} disabled`;
}

// ─── The migration half (scripts/migrate-rules-local.sh) ──────────────
//
// The inverse of the merge: given a host's tuned rules.yaml and the shipped
// file it was tuned FROM, produce the local file that reproduces the host's
// set on top of the shipped one. Lives here so there is one implementation of
// what a key is and which fields an override carries.

/** Fields an override may carry. Everything else about a rule is its key. */
export const OVERRIDABLE_FIELDS = ['threshold', 'duration', 'channels', 'action', 'action_command'] as const;

export interface RulesDiff {
  /** Local entries to write, in the order they should appear. */
  entries: RawRule[];
  /** One line per entry, for the operator reading a dry run. */
  lines: string[];
  counts: { overrides: number; added: number; disabled: number };
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/** A file the migration reads, named in the error when it will not parse. */
function read(text: string, what: string): RawRule[] {
  try {
    return rulesArray(text);
  } catch (err) {
    throw new Error(`${what}: ${(err as Error).message}`, { cause: err });
  }
}

/**
 * What the host's file says that the baseline does not.
 *
 * @param hostText      the host's current rules.yaml
 * @param baselineText  the SHIPPED rules.yaml at the host's own deploy ref,
 *                      never the current one. A rule the product added since
 *                      that ref is not a rule the operator deleted, and
 *                      writing it back as `enabled: false` would disable
 *                      exactly what this migration exists to propagate.
 */
export function diffRulesForLocal(hostText: string, baselineText: string): RulesDiff {
  const host = read(hostText, 'rules.yaml');
  const baseline = read(baselineText, 'the baseline');

  const baseByKey = new Map<string, RawRule>();
  for (const raw of baseline) {
    const k = keyOf(raw);
    if (k && !baseByKey.has(k)) baseByKey.set(k, raw);
  }
  const hostKeys = new Set<string>();

  const entries: RawRule[] = [];
  const lines: string[] = [];
  const counts = { overrides: 0, added: 0, disabled: 0 };

  for (const raw of host) {
    const key = keyOf(raw);
    if (!key) continue;
    hostKeys.add(key);
    const base = baseByKey.get(key);
    const name = key.replace(':', ' ');

    if (!base) {
      entries.push(raw);
      counts.added++;
      lines.push(`added     ${name}`);
      continue;
    }

    const changed: RawRule = {};
    const what: string[] = [];
    for (const field of OVERRIDABLE_FIELDS) {
      if (sameValue(raw[field], base[field])) continue;
      changed[field] = raw[field];
      what.push(`${field} ${JSON.stringify(base[field] ?? null)} to ${JSON.stringify(raw[field] ?? null)}`);
    }
    if (what.length === 0) continue;
    entries.push({ metric: raw.metric, severity: raw.severity, ...changed });
    counts.overrides++;
    lines.push(`override  ${name}: ${what.join(', ')}`);
  }

  for (const [key, base] of baseByKey) {
    if (hostKeys.has(key)) continue;
    entries.push({ metric: base.metric, severity: base.severity, enabled: false });
    counts.disabled++;
    lines.push(`disabled  ${key.replace(':', ' ')} (the baseline has it, this host does not)`);
  }

  return { entries, lines, counts };
}

/**
 * What a set of local entries would still change about the CURRENT shipped
 * rules, and what it only repeats.
 *
 * The migration compares a host against the shipped file its own rules.yaml
 * descends from, which is old: on the lab hosts it is weeks old, because the
 * fleet deploy used to skip that file entirely. Every difference against that
 * baseline is a difference the host made, but not every one is a difference
 * the host still needs. Three of stock-node1's five overrides are the #128
 * action text, pasted onto the box by hand in August and shipped in the
 * release since; two of its "added" rules ship now as well. Written into
 * rules.local.yaml unpruned, each one pins today's wording or today's
 * threshold on that host for good, and the next correction to any of them
 * stops at the override. That is the drift ADR 0020 exists to end, recreated
 * by the tool that was supposed to end it.
 *
 * So: a field whose value the release already ships is dropped, an entry left
 * with no fields is dropped whole, and an "addition" the release now ships
 * becomes an override of it, pruned the same way. A disable is never pruned:
 * it says the host does not want a rule, which is not something a release can
 * say on its behalf.
 *
 * @param entries      local entries, from diffRulesForLocal or from a file
 * @param currentText  the shipped rules.yaml of the release being deployed
 */
export interface RulesPrune {
  /** The entries worth keeping, in their original order. */
  entries: RawRule[];
  /** One line per entry that changed, for the operator reading a dry run. */
  lines: string[];
  counts: { droppedEntries: number; droppedFields: number; kept: number };
}

export function pruneAgainstCurrent(entries: RawRule[], currentText: string): RulesPrune {
  const current = read(currentText, 'the current shipped rules');
  const curByKey = new Map<string, RawRule>();
  for (const raw of current) {
    const k = keyOf(raw);
    if (k && !curByKey.has(k)) curByKey.set(k, raw);
  }

  const out: RawRule[] = [];
  const lines: string[] = [];
  const counts = { droppedEntries: 0, droppedFields: 0, kept: 0 };

  for (const entry of entries) {
    const key = keyOf(entry);
    const name = key ? key.replace(':', ' ') : 'an entry with no key';

    // A disable is the host's own statement and is never pruned.
    if (!key || entry.enabled === false) {
      out.push(entry);
      counts.kept++;
      continue;
    }

    const cur = key ? curByKey.get(key) : undefined;
    if (!cur) {
      // The release does not ship this rule, so there is nothing to compare
      // it with. It stays, and if it is not a whole rule it is named: the
      // loader refuses an addition with no threshold, and an override of a
      // rule that has been withdrawn is exactly that.
      const t = entry.threshold as AnyObj | undefined;
      const complete = !!t && typeof t === 'object'
        && typeof t.op === 'string' && Number.isFinite(Number(t.value));
      out.push(entry);
      counts.kept++;
      if (!complete) {
        lines.push(`check     ${name}: the release does not ship this rule, and this entry has no `
          + `threshold of its own, so the loader will refuse it as an addition`);
      }
      continue;
    }

    const keptFields: RawRule = {};
    const dropped: string[] = [];
    for (const field of OVERRIDABLE_FIELDS) {
      if (!(field in entry)) continue;
      let same: boolean;
      if (field === 'threshold') {
        // A partial threshold inherits the rest, so what has to match the
        // release is the threshold this entry RESULTS in, not the fragment
        // written down. `{ value: 5 }` over a shipped `>= 5` changes nothing.
        const base = (cur.threshold && typeof cur.threshold === 'object') ? cur.threshold as AnyObj : {};
        const merged = { ...base, ...(entry.threshold as AnyObj ?? {}) };
        same = sameValue(merged, cur.threshold);
      } else {
        same = sameValue(entry[field], cur[field]);
      }
      if (same) {
        dropped.push(field);
        counts.droppedFields++;
      } else {
        keptFields[field] = entry[field];
      }
    }

    const remaining = Object.keys(keptFields);
    if (remaining.length === 0) {
      counts.droppedEntries++;
      lines.push(`dropped   ${name}: ${dropped.join(', ')} same as the release ships`);
      continue;
    }
    out.push({ metric: entry.metric, severity: entry.severity, ...keptFields });
    counts.kept++;
    if (dropped.length) {
      lines.push(`pruned    ${name}: dropped ${dropped.join(', ')} (same as the release ships), `
        + `kept ${remaining.join(', ')}`);
    }
  }

  return { entries: out, lines, counts };
}
