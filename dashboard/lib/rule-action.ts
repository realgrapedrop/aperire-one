// #128. The optional `action` / `action_command` fields on an alert rule.
//
// One or two plain sentences saying what to do about a rule firing and why
// it matters, plus an optional single command line to copy. Per-RULE rather
// than per-metric, because a warn and a critical on one metric usually want
// different answers; where a rule carries neither, the metric knowledge
// library (knowledge/metric-alerts.yaml) still answers as it always did.
//
// Instruction text and nothing else. The Insights security model is read,
// validate and instruct: Aperire never executes an action_command, and never
// substitutes a live value into either field. The alert already names the
// node, the threshold and the reading, so a static string is all this needs
// to be, and a static string is all it is allowed to be.
//
// Lives here rather than in server.ts so the acceptance a test asserts is
// the acceptance the server runs, rather than a copy of it that can drift.

/**
 * One or two sentences. Past this it is a malformed file rather than a long
 * answer, and the row tooltip it renders into is 320px wide.
 */
export const RULE_ACTION_MAX = 400;

/** A single command line. */
export const RULE_ACTION_COMMAND_MAX = 200;

export interface RuleActionWarning {
  metric: string;
  field: 'action' | 'action_command';
  reason: string;
}

/**
 * Optional, a string, non-empty once trimmed, and under the cap. Anything
 * else is not an action and is dropped.
 *
 * Dropped, never truncated, and never fatal to the rule. Half a sentence of
 * operator instruction is worse than none: it could read as a complete
 * thought while missing the part that mattered. And a rule that stopped
 * evaluating because its help text was malformed would take the alert down
 * with the advice, which is the wrong trade every time.
 *
 * Warnings are collected rather than swallowed, so a field that was thrown
 * away says so in the journal instead of just not appearing.
 */
export function parseRuleActionField(
  raw: unknown,
  cap: number,
  field: 'action' | 'action_command',
  metric: string,
  warnings?: RuleActionWarning[],
): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'string') {
    warnings?.push({ metric, field, reason: `expected a string, got ${typeof raw}` });
    return undefined;
  }
  const text = raw.trim();
  if (!text) return undefined;
  if (text.length > cap) {
    warnings?.push({ metric, field, reason: `${text.length} characters is over the ${cap} cap` });
    return undefined;
  }
  return text;
}
