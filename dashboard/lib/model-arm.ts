/**
 * Whether the host is armed for a seal, read without being able to read it.
 *
 * The sealer seals once per arming, and the arming is a root-owned, 0600,
 * empty file whose modification time is when root opened the window. The
 * dashboard cannot open that file and must not be able to write it; what it
 * can do is stat it, because /etc/aperire is searchable, and a stat is enough
 * to say "armed, twelve minutes left" or "not armed" truthfully.
 *
 * This is what the model form polls while it is open (the no-model takeover
 * on the Advisor tab, and Settings for each node),
 * so the Seal button is enabled only when pressing it could work, and the
 * operator who has not armed the host sees the one line to run instead of a
 * refusal after the passkey ceremony (#168).
 *
 * The window length here mirrors the sealer's own APERIRE_ARM_WINDOW_SEC
 * default. The sealer is the authority: a marker this reports as armed can
 * still be refused there, and the page treats that as the sealer's word.
 */

/** Where root puts the marker. The same path the sealer reads. */
export const ARM_MARKER = '/etc/aperire/model-key.arm';

/** The sealer's default window, in seconds. */
export const ARM_WINDOW_SEC = 900;

export interface ArmState {
  armed: boolean;
  /** Seconds left in the window. 0 when not armed. */
  remaining_s: number;
  /** Why it is not armed, for the page to choose words from. */
  reason?: 'no-marker' | 'expired' | 'future';
}

/** The stat the caller injects: the marker's mtime in ms, or null when the
 *  file is not there (or cannot be seen, which the page treats the same). */
export type MarkerStat = () => number | null;

export function armState(stat: MarkerStat, nowMs: number, windowSec = ARM_WINDOW_SEC): ArmState {
  const mtime = stat();
  if (mtime === null) return { armed: false, remaining_s: 0, reason: 'no-marker' };
  const ageS = Math.floor((nowMs - mtime) / 1000);
  // A marker from the future is not a fresh arming, and the sealer refuses it
  // for the same reason. Said as its own thing so an operator with a clock
  // problem is told about the clock, not sent to re-arm.
  if (ageS < 0) return { armed: false, remaining_s: 0, reason: 'future' };
  if (ageS > windowSec) return { armed: false, remaining_s: 0, reason: 'expired' };
  return { armed: true, remaining_s: windowSec - ageS };
}
