// Graceful shutdown — punch #24.
//
// A fleet deploy stops this service to swap the binary. Before this file, that
// stop killed whatever it was in the middle of: on 2026-08-20 an operator's
// question died as "Post …/v1/messages: context canceled" because the deploy
// restarted the advisord that was answering it. The answer was most of the way
// done and there was nothing left of it anywhere.
//
// So a signal now means "stop taking new work", not "stop". The listener
// closes, whatever is in flight finishes, and only then does the process exit.
//
// What is deliberately NOT unbounded: the wait. systemd will SIGKILL after
// TimeoutStopSec regardless, and a deploy that hangs forever on one slow
// question is its own outage. drainWindow is the cap, and the units carry
// TimeoutStopSec=75 so systemd waits for it rather than through it.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// drainWindow is how long a shutdown will wait for work already started.
//
// It is shorter than either ceiling a question can run to — askBudget's 300s
// on the ordinary path, and 600s for a gated one (runGatedQuestionWithHost-
// Budget) — and that is a real tradeoff rather than an oversight. Waiting the
// full 600s would mean a ten-minute stop on every deploy, which nobody would
// use, so it would be turned off and the whole arrangement would be worth
// nothing.
//
// The two paths lose differently, and it is worth being plain about which:
//
//   - An ORDINARY ask cut off at 60s has usually lost nothing. Its POST
//     connection stays open through the drain, so if it finishes inside the
//     window the answer is delivered directly.
//   - A GATED question is the bad case. It runs behind a 202 and its answer
//     reaches the page only through the in-memory progress store, which dies
//     with this process — so a break-glass question cut off here is
//     unrecoverable, and the drawer's poll gets a 404 rather than an answer.
//     A deploy during a break-glass investigation is worth not doing;
//     fleet-update's quiet-check is what makes that avoidable rather than
//     a thing to remember.
const drainWindow = 60 * time.Second

// askStart marks one unit of question-shaped work as in flight and hands back
// the function that marks it finished.
//
// Called from the HANDLER, never from inside a goroutine the handler spawns.
// /v1/investigate/begin and /v1/investigate/continue answer 202 and run the
// question in the background: an Add(1) inside that goroutine leaves a window
// between the 202 and the scheduler where a quiet-check would read zero and a
// deploy would stop the service on top of the question.
//
// The returned function is safe to call more than once, so a handler can both
// `defer` it and hand it to a goroutine without double-counting.
// The counter BRACKETS the group rather than sitting inside it: up before
// Add, down after Done. That ordering is what makes a zero count proof that
// the group is empty, which is what the drain now decides on (#118). The
// other order leaves a window where the count reads zero while a Done has
// not landed yet.
func (s *server) askStart() func() {
	s.asksN.Add(1)
	s.asks.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			s.asks.Done()
			s.asksN.Add(-1)
		})
	}
}

// runStart is askStart for an executor run: same shape, same bracketing, and
// a separate group because the drain treats the two differently (an ask that
// is cut off loses an answer; a run that is cut off has left the node in a
// state somebody has to check).
//
// Called from the HANDLER, before the 202 that starts the run in the
// background, for the same reason askStart is: a count that only goes up once
// the goroutine is scheduled is a count a deploy would read as quiet.
func (s *server) runStart() func() {
	s.runsN.Add(1)
	s.runs.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			s.runs.Done()
			s.runsN.Add(-1)
		})
	}
}

// streamStopC is the channel a streaming handler selects on to learn that the
// service is shutting down. Closed exactly once, by closeStreams.
//
// Lazily created rather than initialised in a constructor because a
// zero-value &server{} is a real thing in this package's tests, and a nil
// channel here would be a receive that blocks forever, which is the correct
// behaviour for a server nobody is draining, but only if the drain side can
// still create and close it. Both sides go through streamMu so they cannot
// race on the creation.
func (s *server) streamStopC() <-chan struct{} {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.streamStop == nil {
		s.streamStop = make(chan struct{})
	}
	return s.streamStop
}

// streamStart marks one open stream and hands back the function that marks it
// closed. Counted only so the shutdown can say how many it released; nothing
// waits on this number.
func (s *server) streamStart() func() {
	s.streamsN.Add(1)
	var once sync.Once
	return func() { once.Do(func() { s.streamsN.Add(-1) }) }
}

// closeStreams releases every open stream and reports how many were holding
// the listener. Safe on a server that never served one, and safe to call
// twice.
func (s *server) closeStreams() int64 {
	// Read BEFORE closing: the question the log answers is how many streams
	// were holding this listener open, and by the time the close has
	// propagated the handlers have already decremented themselves away.
	n := s.streamsN.Load()
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.streamStop == nil {
		s.streamStop = make(chan struct{})
	}
	select {
	case <-s.streamStop:
		// Already closed. A second drain must not panic.
	default:
		close(s.streamStop)
	}
	return n
}

// askContext is the context a question runs under: bounded by its own budget,
// and deliberately NOT cancelled when the caller hangs up.
//
// It used to derive straight from r.Context(), and that is the second half of
// what happened on 2026-08-20. The first ask died because this service was
// restarted; the second died because the AGGREGATOR dashboard was restarted,
// which hung up the proxy connection carrying the question, which cancelled
// r.Context() 18 seconds in, which killed a model call on a host nobody had
// touched. Journal-proven on validator1, 15:03:52 → 15:04:10 UTC.
//
// The service already records every ask's terminal state in the progress
// store, and the drawer already recovers a dead POST by polling it. That
// recovery only ever finds something if the question outlives the connection
// that asked it — which is what this makes true. The gated path in the same
// handler has always worked this way (context.Background(), 600s); this is
// the ordinary path catching up.
//
// The cost is stated rather than hidden: a browser that closes its tab
// mid-question still spends the rest of that question's model budget. That is
// the trade — a few cents of tokens against losing an answer the operator was
// waiting on — and the budget is what stops it running away.
func askContext(r *http.Request, budget time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), budget)
}

// asksInFlight is what /v1/status publishes and what a deploy's quiet-check
// polls: ordinary asks, gated asks running synchronously on the ask path, and
// gated sessions running in the background behind a 202. One counter for all
// three, because the question a deploy must not interrupt is the same question
// whichever door it came through.
func (s *server) asksInFlight() int64 { return s.asksN.Load() }

// runsInFlight is the same reading for executor runs. Not published on
// /v1/status today; it exists so the drain can decide from a number rather
// than from a channel (#118).
func (s *server) runsInFlight() int64 { return s.runsN.Load() }

// drain stops the listener, waits out the work already started, and returns
// when the process may exit.
//
// srv.Shutdown is the load-bearing call and the subtle one. It closes the
// listener and waits for in-flight requests to finish — it does NOT cancel
// their r.Context(). That is why an ask already talking to the model provider
// survives this: its model call hangs off a context derived from the request,
// and nothing here cancels it.
// window is a parameter rather than a read of drainWindow so a test can prove
// the give-up path without taking a minute to do it.
func (s *server) drain(srv *http.Server, sig os.Signal, window time.Duration) {
	deadline := time.Now().Add(window)
	log.Printf("[shutdown] %v: not taking new work. %d ask(s) in flight; waiting up to %s",
		sig, s.asksInFlight(), window)

	// #116. Released BEFORE Shutdown, because Shutdown is what would otherwise
	// wait for them. A stream subscription is not work: nothing is computed
	// behind it, nothing is lost by ending it, and the page reattaches on its
	// own. Waiting for one meant every restart with a dashboard open burned
	// the whole window and then reported "the listener did not drain in time"
	// under a line saying nothing was running.
	//
	// This does NOT touch request contexts. An ask in flight still runs, still
	// holds its own r.Context(), and is still waited for below. That is the
	// guarantee TestDrainLetsASlowAskFinish exists to pin, and the reason a
	// server-wide BaseContext cancel was the wrong lever for this.
	if n := s.closeStreams(); n > 0 {
		log.Printf("[shutdown] closed %d open stream(s); a subscription is not work", n)
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		// Not fatal, and not a reason to skip what follows: Shutdown
		// returning ctx.Err() means it stopped WAITING, not that it stopped
		// the work. The background goroutines it never knew about are still
		// running, and the waits below are what account for them.
		log.Printf("[shutdown] the listener did not drain in time: %v", err)
	}

	// The number in the message is the one the decision was made on, not a
	// second load taken afterwards. #118: the old line read the counter again
	// on its way into the journal, so work that finished in between printed
	// "gave up on 0 ask(s)".
	if done, left := waitBy(&s.asks, s.asksInFlight, deadline); !done {
		log.Printf("[shutdown] gave up on %d ask(s) still running after %s; "+
			"their answers are lost", left, window)
	}

	// An execute RUN is different from an ask and is treated differently. It
	// is changing the node, so interrupting it is worse — but it can also run
	// far longer than any question (an upgrade waits for the node to come
	// back into sync), so waiting for it without a cap would mean a deploy
	// that never ends. Same deadline, and if it is not done by then the
	// transcript is told what happened rather than being left mid-sentence.
	if done, _ := waitBy(&s.runs, s.runsInFlight, deadline); !done {
		s.abandonRun(window)
	}

	log.Printf("[shutdown] drained; exiting")
}

// waitBy waits for wg, giving up at deadline. It reports whether the work
// finished and how much of it was left, and BOTH answers come from inFlight —
// the atomic count that brackets the group — never from a channel.
//
// #118. This used to answer an already-spent deadline with a non-blocking
// select on a channel closed by `go func() { wg.Wait(); close(done) }()`.
// A goroutine that has not been SCHEDULED yet has not closed anything, so on
// an empty group with the deadline already gone the default branch won and
// waitBy said false. The journal then carried "gave up on 0 ask(s) still
// running" and "a run was still going but had no open transcript to mark" on
// a service that had run nothing at all — a false statement printed at the
// exact moment an operator is reading the journal to find out what went
// wrong, and, with a transcript open, a spurious "pending" line the dashboard
// renders as "check the node before approving anything else".
//
// A count is the right thing to decide on because nothing can join either
// group here: the listener is closed before this is called, and both counters
// go up in the handler. So zero is final, and it is the same zero whichever
// goroutine the scheduler happens to be running.
func waitBy(wg *sync.WaitGroup, inFlight func() int64, deadline time.Time) (bool, int64) {
	if n := inFlight(); n == 0 {
		return true, 0
	}
	// Only now is there anything to wait for, and only if there is time left
	// to wait in. An expired window skips straight to the reading below
	// rather than arming a timer that has already fired.
	if left := time.Until(deadline); left > 0 {
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		t := time.NewTimer(left)
		defer t.Stop()
		select {
		case <-done:
			return true, 0
		case <-t.C:
		}
	}
	// One read, and it is the answer: work that finished while the timer was
	// firing is finished, and a caller that gives up gives up on this number.
	n := inFlight()
	return n == 0, n
}

// abandonRun writes the terminal line an interrupted run would otherwise not
// have.
//
// A transcript ends on done, halt or pending; a transcript that just stops is
// read by the dashboard as a run still going, and after the restart it would
// render an eight-month-old run as live.
//
// It is a stop, marked as an abandonment. It used to be "pending", and pending
// is a claim: the page renders it as "your node was restarted and is running
// the new version", which this process cannot know (#769). The step it was on
// may or may not have completed on the node, and the line says exactly that.
func (s *server) abandonRun(window time.Duration) {
	s.runMu.Lock()
	rl, label := s.runLog, s.runLabel
	s.runMu.Unlock()
	if rl == nil {
		log.Printf("[shutdown] a run was still going but had no open transcript to mark")
		return
	}
	rl.Abandon("abandoned by a service restart after " + window.String() +
		" — the step it was on may or may not have finished on the node. " +
		"Check the node before approving anything else.")
	log.Printf("[shutdown] abandoned run %s after %s; its transcript is marked stopped", label, window)
}
