/**
 * Reading the host verifier's report (scripts/verify-after-restart.sh, written
 * through scripts/verify-report-lib.sh) into two metrics.
 *
 * The rule this file exists to hold: an absent, unreadable or malformed report
 * yields NO reading at all. Never a zero. `verify_failed_checks: 0` means "a
 * run happened and found nothing wrong", and it is exactly the sentence a
 * missing file must not be allowed to say. This dashboard's characteristic bug
 * is a swallowed failure rendered as a healthy current value, and a verifier
 * that has never run reporting zero failures would be that bug with a new name.
 *
 * Age comes from the report's own `ts`, never the file's mtime. A copy, a
 * backup, a restore or an rsync rewrites mtime without any verifier having run,
 * so mtime answers "when did this file last move", and the question is "when
 * was this host last checked".
 *
 * Pure and free of I/O so every case below is a test rather than a fixture:
 * the caller reads the bytes, this decides what they mean.
 */

export interface VerifyReading {
  /** Checks that failed in the run that wrote this report. */
  failedChecks: number;
  /** Checks that passed. Not a metric, used to reject an empty run. */
  passedChecks: number;
  /** Seconds since the run, from the report's own stamp. Never negative. */
  ageS: number;
  /** The report's stamp, epoch seconds. */
  ts: number;
}

function isCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && Number.isInteger(v) && v >= 0;
}

/**
 * @param text  the file's contents, or null when it could not be read at all
 * @param nowMs the current time in milliseconds
 * @returns the reading, or null when there is nothing honest to report
 */
export function readVerifyReport(text: string | null | undefined, nowMs: number): VerifyReading | null {
  if (typeof text !== 'string' || text.trim() === '') return null;

  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return null; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const d = doc as Record<string, unknown>;

  // A report with no usable stamp is a report of unknown age. Age 0 would read
  // as "verified moments ago", which is the most dangerous thing it could say.
  const ts = d.ts;
  if (typeof ts !== 'number' || !Number.isFinite(ts) || ts <= 0) return null;

  if (!isCount(d.passed) || !isCount(d.failed)) return null;
  const passed = d.passed, failed = d.failed;

  // A run that recorded nothing. Every check skipped (no docker, no node, no
  // sudo) is a real outcome, and it is not evidence that the host is fine.
  if (passed + failed === 0) return null;

  // The counts and the list have to agree, because they come from one call
  // site and are only allowed to disagree if something wrote this file that
  // was not the verifier. Take neither in that case.
  if (!Array.isArray(d.checks) || d.checks.length !== passed + failed) return null;

  // Clamped rather than allowed negative: a host whose clock is ahead of this
  // process would otherwise produce a negative age, and no rule operator would
  // guess that "-40" means "the future". Zero is the honest floor, "as fresh
  // as it gets".
  const ageS = Math.max(0, nowMs / 1000 - ts);

  return { failedChecks: failed, passedChecks: passed, ageS, ts };
}

/**
 * Whether the absence of a report is worth saying, and what to say about it.
 *
 * The rule above holds absolutely: a missing report never produces a count of
 * failures. It also produced nothing at all, and that turned out to be a hole.
 * The verifier's timer only reaches its daily cadence after a first run, so on
 * a host where the first run never happened there was no report, no metric, no
 * age to age out, and nothing anywhere said the box had never been checked
 * (#143). Every piece behaving as designed, composing into silence.
 *
 * So the absence is measured, with the one distinction that keeps it honest.
 * A host that HAS the verifier installed and has no report from it is a fact
 * about that host, and a rule can fire on it. A host that has no verifier at
 * all (a dashboard run from a source tree, an aggregator installed another
 * way) is not faulty for lacking a report nothing was going to write, and it
 * gets no reading rather than a permanent alarm about a missing installer.
 *
 * @param reading            what readVerifyReport made of the file, or null
 * @param verifierInstalled  whether this host has the verifier's timer unit
 * @returns 1 when the verifier is installed and there is no usable report,
 *          0 when a report was read, and null when there is nothing to say
 */
export function verifyReportMissing(
  reading: VerifyReading | null,
  verifierInstalled: boolean,
): 0 | 1 | null {
  if (reading) return 0;
  return verifierInstalled ? 1 : null;
}
