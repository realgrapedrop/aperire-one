/**
 * Handing a model API key to the one program allowed to seal it.
 *
 * The dashboard runs unprivileged and sealing needs root: `systemd-creds
 * encrypt` reads /var/lib/systemd/credential.secret, which is 0400 root:root.
 * So this does not seal anything, and it does not start anything either. It
 * cannot: the dashboard's unit sets NoNewPrivileges and an empty capability
 * bounding set, and nothing running under those can gain a privilege by
 * spawning a child.
 *
 * What it has instead is a socket. systemd listens on
 * /run/aperire/seal-model-key.sock, owned by this account and mode 0600, and
 * starts the sealer as root with the accepted connection as its standard
 * input, output and error. This file writes five lines into that connection,
 * half-closes it, reads what comes back and reports it.
 *
 * Three rules hold this file together, and each of them is a way the key
 * could leak that is closed here rather than hoped about:
 *
 *  1. The key goes on the connection, which is the sealer's STDIN. Never in
 *     argv, which is world-readable in /proc for as long as a process runs,
 *     and never in the environment, which is readable in the same places and
 *     inherited by every child. There is no argv here to put it in: this side
 *     names no program and no path.
 *  2. What comes back is read as data, never executed and never interpreted.
 *     The sealer's own words are the operator's message.
 *  3. Nothing here logs, throws or returns the key. The error paths are the
 *     dangerous ones: an exception carrying the payload it failed on is how a
 *     secret ends up in a log nobody meant to write.
 */

/** What the sealer reported, read back from its own output rather than
 *  assumed from the fact that it exited zero. */
export interface SealOutcome {
  ok: boolean;
  /** Machine-readable reason, for the browser to choose words from. `expired`
   *  and `unarmed` are the two an operator meets in normal use and they have
   *  different remedies, so they are never collapsed into one. */
  reason: 'sealed' | 'expired' | 'unarmed' | 'refused' | 'unavailable';
  /** One sentence, in the operator's terms, safe to render. Never carries a
   *  key: it comes from the sealer's own refusal text, which is written not
   *  to. */
  detail: string;
  /** What the sealer read back about the service afterwards: 'active' (the
   *  unit is up and its listener answered), 'not-answering' (the unit is up
   *  and nothing answered on its port, #1120) or 'inactive'. Absent when it
   *  never got that far. */
  service?: string;
  /** The credential it wrote, for the record. Not secret: it is a file name. */
  credential?: string;
  /** The model config it wrote, the file the Advisor reads its provider and
   *  model from. Read back from the sealer's own `config=` line. */
  config?: string;
}

export interface SealRequest {
  baseUrl: string;
  shape: 'openai' | 'anthropic';
  model: string;
  credentialName: string;
  /** Held for as long as it takes to write it to a socket, and cleared by the
   *  caller afterwards. */
  key: string;
}

/** The transport, injected so a test can watch what it was given without a
 *  real socket anywhere near it. Takes the payload and nothing else: there is
 *  no program to name and no arguments to pass.
 *
 *  Resolves rather than rejects on a refusal: that is an outcome, not an
 *  exception. It rejects only when the connection itself could not be made,
 *  and `sealModelKey` turns that into 'unavailable'. */
export interface SealRunner {
  (payload: string): Promise<{ code: number; stdout: string; stderr: string }>;
}

/** Where systemd listens on this host. Root owns the program behind it; this
 *  account owns the socket and may open it, which is the whole grant. */
export const SEALER_SOCKET = '/run/aperire/seal-model-key.sock';

/**
 * What each field may hold. One definition, imported by every place a field
 * arrives (the per-node handlers, the Settings ceremony, the node's fleet-write
 * gate) and mirrored by the sealer in bash.
 *
 * The rules are the frame. The sealer reads its payload positionally, one
 * field per line, and `sealPayload` is a bare join: a value carrying a line
 * break would shift every field after it by one slot, and the last slot is
 * the key. So no field may hold whitespace at all, and `base_url` (the one
 * the sealer writes into JSON) may not hold a quote or a backslash either.
 * Anchored at both ends: an unanchored loopback pattern was exactly how a
 * base_url once got four extra lines through (#179).
 */
export const SEAL_FIELD_RULES = {
  /** https, or loopback for a local runner: anything else is a key about to
   *  be posted in clear over the open internet. */
  baseUrl: (u: string): boolean =>
    /^https:\/\/[^\s"\\]+$/.test(u)
    || /^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?(\/[^\s"\\]*)?$/.test(u),
  model: (m: string): boolean => /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(m),
  /** A bare name: it becomes a file under the credential directory and a
   *  systemd credential name in the unit. */
  credentialName: (c: string): boolean =>
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(c) && !c.includes('..'),
  shape: (s: string): s is 'openai' | 'anthropic' => s === 'openai' || s === 'anthropic',
} as const;

/** The first field that breaks its rule, named the way an operator reads it,
 *  or null when the request would frame cleanly. The key is checked for line
 *  breaks only: its content is the provider's business. */
export function sealFieldRefusal(req: SealRequest): string | null {
  if (!SEAL_FIELD_RULES.baseUrl(req.baseUrl)) return 'the provider address must be https, or loopback for a local runner';
  if (!SEAL_FIELD_RULES.shape(req.shape)) return 'shape must be openai or anthropic';
  if (!SEAL_FIELD_RULES.model(req.model)) return 'that does not look like a model identifier';
  if (!SEAL_FIELD_RULES.credentialName(req.credentialName)) return 'the credential name must be a bare name';
  if (/[\r\n]/.test(req.key)) return 'the key carries a line break';
  return null;
}

/** The five lines the sealer reads, in its documented order, key last. Only
 *  ever called on a request `sealFieldRefusal` passed: that is the frame. */
export function sealPayload(req: SealRequest): string {
  return `${req.baseUrl}\n${req.shape}\n${req.model}\n${req.credentialName}\n${req.key}\n`;
}

/** The sentence added when a stream ends with no `exit=` line. Exported so a
 *  caller that reads `reported` can drop it rather than quote it back as the
 *  program's own last line (#848). */
export const SEALER_NO_REPORT = 'the sealer ended without reporting';

/**
 * One stream comes back, and it carries both of the sealer's.
 *
 * With a socket-activated service, standard output and standard error are the
 * same connection, and the exit code is not on it at all: when the program
 * ends the connection closes, carrying nothing about why. So the sealer prints
 * `exit=<code>` as its last line, and the two streams are told apart by shape.
 * Its fields are `name=value` with a lower-case name, which nothing it writes
 * for a human ever looks like: those all read `outcome: sentence`.
 */
export function splitSealerStream(raw: string): { code: number; stdout: string; stderr: string; reported: boolean } {
  const out: string[] = [];
  const err: string[] = [];
  let code: number | null = null;
  for (const line of raw.split('\n')) {
    const field = /^([a-z_]+)=(.*)$/.exec(line);
    if (field) {
      if (field[1] === 'exit') {
        // Only a plain number counts. Anything else is not the sealer's own
        // last line, and reading it as one would invent a success.
        if (/^\d+$/.test(field[2].trim())) code = Number(field[2].trim());
        continue;
      }
      out.push(line);
      continue;
    }
    if (line.trim() !== '') err.push(line);
  }
  // `reported` is the only way a caller can tell the program's own exit 1
  // from the 1 made up below. A caller whose verbs mean something by "the
  // program said nothing" (the fleet broker's) reads it; the sealer and the
  // trust sync keep reading `code` alone, as they always did.
  const reported = code !== null;
  if (code === null) {
    // No last line means the program did not reach its own exit handler: it
    // was killed, or it never started. Not a refusal, and not a success.
    err.push(SEALER_NO_REPORT);
    code = 1;
  }
  return { code, stdout: out.join('\n'), stderr: err.join('\n'), reported };
}

/** A connection that could not be made at all, told apart from one that was
 *  made and answered badly. ENOENT is the ordinary case: the socket unit is
 *  not installed on this host. */
export function isSocketUnreachable(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return code === 'ENOENT' || code === 'EACCES' || code === 'EPERM'
    || code === 'ECONNREFUSED' || code === 'ENOTDIR';
}

/** Classify a refusal from what the sealer said about itself.
 *
 *  The sealer prefixes every outcome with one word, and those words are the
 *  contract: an operator whose window lapsed twelve minutes ago must not be
 *  told the same thing as one who never armed at all, because the first is
 *  about to re-run one command and the second is about to go looking for a
 *  bug. */
export function classifyRefusal(stderr: string): { reason: SealOutcome['reason']; detail: string } {
  const line = stderr.split('\n').map((l) => l.trim()).filter(Boolean).pop() ?? '';
  if (/^expired:/.test(stderr) || /arming window closed/.test(stderr)) {
    return {
      reason: 'expired',
      detail: 'The arming window has closed. Arm this host again (the arm line on this page says how; the Advisor install command does it too), then seal.',
    };
  }
  if (/^unarmed:/.test(stderr) || /no arming marker/.test(stderr)) {
    return {
      reason: 'unarmed',
      detail: 'This host is not armed. Arm it first (the arm line on this page says how; the Advisor install command does it too), then seal.',
    };
  }
  return {
    reason: 'refused',
    // The sealer's own last line. It is written to be read by an operator and
    // is never given a key to put in it.
    detail: line.replace(/^[a-z]+:\s*/, '') || 'The host refused to seal the key, and said nothing about why.',
  };
}

/**
 * Seal a key, and report what was read back.
 *
 * The key is written to the connection and is not referenced again. The caller
 * clears its own copy; this function keeps none.
 */
export async function sealModelKey(req: SealRequest, run: SealRunner): Promise<SealOutcome> {
  // Whatever the caller checked. This is the one function that joins the
  // fields into the frame the sealer reads, so this is where the frame is
  // guaranteed, not in each of the three handlers in front of it.
  const framing = sealFieldRefusal(req);
  if (framing !== null) return { ok: false, reason: 'refused', detail: framing };

  let out: { code: number; stdout: string; stderr: string };
  try {
    out = await run(sealPayload(req));
  } catch (err) {
    // Deliberately not including the error's own message wholesale: it is the
    // one place a payload could ride out of here. The class of failure is what
    // the operator can act on anyway, and for the common one there is a
    // command that fixes it.
    if (isSocketUnreachable(err)) {
      return {
        ok: false,
        reason: 'unavailable',
        detail: 'This host has no sealing socket. Run the Advisor install command on it again; it installs the socket and opens a setup window.',
      };
    }
    return {
      ok: false,
      reason: 'unavailable',
      detail: 'The sealing program could not be reached on this host.',
    };
  }

  // The fields FIRST, whatever the exit code. The sealer exits non-zero when
  // the Advisor did not come back, and that is a run in which the key crossed:
  // it is sealed, it is wired in, and the window is spent. Classifying that as
  // a plain refusal told the operator nothing had happened when in fact
  // everything except the restart had, which is the one wrong answer here.
  const fields = new Map<string, string>();
  for (const line of out.stdout.split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) fields.set(line.slice(0, i).trim(), line.slice(i + 1).trim());
  }

  // Nothing was sealed: no `sealed=` line, so the program refused before it
  // wrote anything. Its own words are what the operator needs.
  if (!fields.has('sealed')) {
    if (out.code !== 0) {
      const { reason, detail } = classifyRefusal(out.stderr);
      return { ok: false, reason, detail };
    }
    return {
      ok: false, reason: 'refused',
      detail: 'The host reported neither a sealed key nor a reason.',
    };
  }

  const service = fields.get('service');
  if (service !== 'active') {
    return {
      ok: false,
      reason: 'refused',
      service,
      credential: fields.get('sealed'),
      config: fields.get('config'),
      detail: service === 'not-answering'
        ? 'The key was sealed and the Advisor\u2019s service started, but nothing answered on its port afterwards. The key is on this host; read the Advisor\u2019s log to find out why it is not listening.'
        : 'The key was sealed, but the Advisor did not come back afterwards. It is on this host; read its log to find out why.',
    };
  }
  return {
    ok: true,
    reason: 'sealed',
    service,
    credential: fields.get('sealed'),
    config: fields.get('config'),
    detail: 'Sealed to this host, and the Advisor came back with it.',
  };
}
