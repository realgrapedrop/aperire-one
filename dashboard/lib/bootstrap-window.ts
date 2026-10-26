// The bootstrap window: the only moment the browser may create an operator.
//
// #135 Step 1, under the operator's bootstrap-window ruling. A freshly
// installed box has an empty dashboard and nobody to sign in as. Until
// now the only way out was an SSH session and `aperire-auth add`. This is
// what lets the first admin be created in the browser instead.
//
// THE WINDOW IS OPEN WHILE ZERO OPERATORS EXIST, AND CLOSED FOREVER AFTER.
//
// "Operator" means a row in auth_users, NOT a row with a passkey attached.
// That distinction is the security of the thing. `aperire-auth add` creates
// the row first and issues an enrollment link second, so between those two
// moments an admin exists who has not enrolled yet. If the window keyed on
// credentials, that box would read as unowned and a stranger who reached it
// first could take the name of an admin the real operator had just created.
// A row is the claim; the passkey is only how the claim is later exercised.
//
// The cost of that choice, stated rather than hidden: an operator who names
// themselves and then abandons the ceremony leaves an admin with no passkey,
// and the window is shut behind them. They are not locked out. That is
// exactly the state `aperire-auth add` produces on purpose, and the existing
// enrollment link is how they finish. No reaper, no expiry, no second path.
//
// EMPTYING THE BOX DOES NOT REOPEN IT. That is the operator's ruling of
// 2026-09-17, given knowing the alternative, and it is what the whole feature
// buys: a box that has been owned once never accepts an unauthenticated write
// again, whatever happens to its operator rows afterwards. `aperire-auth del`
// runs a real DELETE FROM auth_users (scripts/aperire-auth.sh), and a box with
// nobody left on it is a box to recover from the host, not one for whoever
// reaches the port first to claim. The recovery is `aperire-auth add` in a
// shell ON that machine, which needs the host and not the network, and the
// wizard's own copy says so.
//
// So the window is open only when BOTH are true, and a durable record of the
// close is what makes it one-way:
//
//   1. the box has no operators now, and
//   2. nothing on record says it ever had one.
//
// The record is a row in `auth_events`, which the auth CLI's delete does not
// touch, which nothing in this product updates or deletes, and which survives
// a restore that brought back the audit and nothing else. It is also already
// outside the ADR 0008 read contract, so a read token cannot enumerate it. The
// alternative, a column beside the operator rows, dies with exactly the DELETE
// this has to outlive.
//
// Two shapes of row close it, because two things can own a box:
//
//   first_admin_created   the browser claimed it through this window.
//   setup_window_closed   this dashboard OBSERVED an operator it did not
//                         create, which is every box claimed with
//                         `aperire-auth add`, and every box that was already
//                         owned before this record existed.
//
// The second is written the first time an owned box is seen, so the fact is
// recorded once and read forever after. A box upgraded into this behaviour
// therefore records the day it was first seen owned, not the day it was
// claimed, and `setupStateFor` keeps those two apart rather than printing one
// as the other.

/** What the window is, as a value, so a caller cannot invent a third state. */
export type WindowState = 'open' | 'closed';

/** The durable close, as it is read back. Null means nothing on record. */
export interface WindowClosure {
  /** Unix seconds. */
  at: number;
  /** Which of the two rows closed it, and so which sentence is true. */
  why: 'first_admin_created' | 'observed_operator';
}

export function windowStateFor(input: {
  operatorCount: number;
  closure: WindowClosure | null;
}): WindowState {
  // A record of the close outranks the count, always. This is the whole
  // one-way property: the count can go back to zero, and this cannot.
  if (input.closure) return 'closed';
  // Defensive on a negative: a count that cannot be trusted is not a
  // reason to open a window that creates an administrator.
  return input.operatorCount === 0 ? 'open' : 'closed';
}

/**
 * The identity rule, ported from `aperire-auth.sh` (the `add` verb).
 *
 * Email IS the identity in this product: auth_users.username and .email are
 * both set to the same address, and the address is what an operator types at
 * the lock screen. The CLI's check is a local part, an @, and a dotted
 * domain, with no spaces, and it is deliberately loose because deliverability
 * is proven later by actually sending a link.
 *
 * Two implementations of one rule is the thing to be nervous about here. A
 * bash regex cannot be shared with TypeScript, so the shared owner is a test:
 * test/unit/bootstrap-window.test.ts runs a table of cases through this
 * function and through the CLI's own regex, and fails if they disagree.
 */
const OPERATOR_NAME_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** Length cap. Not in the CLI, which is bounded by a human typing an
 *  argument; a browser field is bounded by whatever is POSTed to it. */
export const OPERATOR_NAME_MAX = 254;   // RFC 5321 forward-path limit

export interface NameCheck { ok: boolean; value?: string; reason?: string }

export function checkOperatorName(raw: unknown): NameCheck {
  if (typeof raw !== 'string') return { ok: false, reason: 'a name is required' };
  const value = raw.trim();
  if (!value) return { ok: false, reason: 'a name is required' };
  if (value.length > OPERATOR_NAME_MAX) {
    return { ok: false, reason: `that is longer than ${OPERATOR_NAME_MAX} characters` };
  }
  if (!OPERATOR_NAME_RE.test(value)) {
    return { ok: false, reason: 'that does not look like an email address' };
  }
  return { ok: true, value };
}

/**
 * What the browser is told about the window, and nothing more.
 *
 * The wizard renders the server's answer every time it asks, rather than its
 * own memory of it: a page left open while somebody else claims the box from
 * another tab must not go on describing a window that shut minutes ago.
 *
 * `closed_at` and `closed_why` come off the durable record, so they still
 * answer on a box whose operator rows have all been deleted, which is the
 * case the ruling exists for. They are null for a caller with no session:
 * when the box was claimed is a fact about its history, and an
 * unauthenticated visitor on a closed box is being turned away, not briefed.
 * The page prints its sentence without a date in that case rather than
 * inventing one.
 *
 * `closed_why` is carried because the two rows mean different things and the
 * page says different sentences for them. A box claimed through this window
 * knows the day it was claimed; a box that was already owned knows only the
 * day this dashboard first saw that, and must not print the second as if it
 * were the first.
 */
export interface SetupState {
  state: WindowState;
  closed_at: number | null;
  closed_why: WindowClosure['why'] | null;
}

export function setupStateFor(input: {
  operatorCount: number;
  closure: WindowClosure | null;
  /** Whether the asker is signed in. Decides only whether the date is sent. */
  authed: boolean;
}): SetupState {
  const state = windowStateFor({ operatorCount: input.operatorCount, closure: input.closure });
  if (state === 'open') return { state, closed_at: null, closed_why: null };
  if (!input.authed || !input.closure) return { state, closed_at: null, closed_why: null };
  return { state, closed_at: input.closure.at, closed_why: input.closure.why };
}
