// A scratch dashboard goes when whatever started it is gone (#1084).
//
// Tests and walks start a dashboard of their own and stop it when they end.
// A runner killed outright (SIGKILL, a timeout, a session closing) runs no
// after() hook, no finally and no exit handler, so the server it started was
// adopted by init and kept its port, its database and a few hundred MB for
// days. Hundreds of them piled up on one box.
//
// So the launcher (tools/start-dashboard.mjs) names itself in
// APERIRE_EXIT_WITH_PARENT, and the server checks for it: once at start, so a
// launcher that died while the server was still compiling is caught, then
// every second. Two ways it can be gone: this process was re-parented away
// from it, or no process has that pid at all.
//
// Off unless the variable is set. No install, unit or update path sets it, so
// a production dashboard never watches anything.

export const EXIT_WITH_PARENT_ENV = 'APERIRE_EXIT_WITH_PARENT';

export interface ExitWithParentOptions {
  everyMs?: number;
  /** What to do once the launcher is gone. Default: say so and exit 0. */
  onGone?: (why: string) => void;
  /** For tests: this process's parent, read fresh each time. */
  ppid?: () => number;
  /** For tests: whether a pid exists. */
  alive?: (pid: number) => boolean;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM is a live process this user may not signal; only ESRCH is gone.
    return (e as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

/** Starts the watch when the variable names a pid. Returns the timer, or null
 *  when there is nothing to watch (or the launcher was already gone and the
 *  onGone hook returned instead of exiting). */
export function exitWithParent(
  env: NodeJS.ProcessEnv = process.env,
  opts: ExitWithParentOptions = {},
): ReturnType<typeof setInterval> | null {
  const raw = env[EXIT_WITH_PARENT_ENV];
  if (!raw) return null;
  const want = Number(raw);
  if (!Number.isInteger(want) || want <= 1) {
    console.warn(`[exit-with-parent] ${EXIT_WITH_PARENT_ENV}=${JSON.stringify(raw)} is not a pid; not watching`);
    return null;
  }
  const ppid = opts.ppid ?? (() => process.ppid);
  const alive = opts.alive ?? pidAlive;
  const onGone = opts.onGone ?? ((why: string) => {
    console.log(`[exit-with-parent] ${why}; this scratch dashboard is exiting`);
    process.exit(0);
  });
  // Re-parenting is the sharper test, and it cannot be fooled by the pid
  // being reused, but it only applies when the launcher really is the parent.
  const wasParent = ppid() === want;
  let timer: ReturnType<typeof setInterval> | null = null;
  const check = (): boolean => {
    let why = '';
    if (wasParent && ppid() !== want) why = `the process that started it (${want}) is gone`;
    else if (!alive(want)) why = `the process that started it (${want}) no longer exists`;
    if (!why) return false;
    if (timer) clearInterval(timer);
    onGone(why);
    return true;
  };
  if (check()) return null;
  timer = setInterval(check, opts.everyMs ?? 1000);
  timer.unref();
  return timer;
}
