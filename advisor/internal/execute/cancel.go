package execute

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/runbook"
)

// Cancel abandons a plan and leaves the deployment coherent.
//
// Not "undo everything". Backups and a pulled image are harmless and worth
// keeping — an operator who cancels at midnight may well proceed at nine, and
// throwing away work they will want again is its own unkindness.
//
// What cancel MUST fix is the deployment definition. Prepare's last step points
// compose at the new tag while the node still runs the old one, and a compose
// file naming a version the node is not running is a trap: the next unrelated
// `docker compose up` — a reboot, another service, someone tidying up —
// performs an unapproved upgrade at a time nobody chose. That is the state
// this exists to get out of.
//
// Deliberately not RB-002. Rollback is for a completed upgrade that went
// wrong. Cancel is for one that never finished. Different preconditions,
// different evidence, and they should not be confused because they feel
// similar under stress.
type CancelReport struct {
	Restored   string   `json:"restored,omitempty"`
	Kept       []string `json:"kept,omitempty"`
	Before     State    `json:"before"`
	After      State    `json:"after"`
	Refused    string   `json:"refused,omitempty"`
	NodeSafe   bool     `json:"node_safe"`
	Consistent bool     `json:"consistent"`
}

// State is the pair that has to agree: what the deployment says it will run,
// and what the node is actually running.
type State struct {
	ComposeTag     string `json:"compose_tag"`
	RunningVersion string `json:"running_version"`
	Consensus      string `json:"consensus"`
	ConsensusOK    bool   `json:"consensus_ok"`
}

// Canceller reads and repairs the deployment through the wrapper.
type Canceller struct {
	PlanID  string
	Stage   string
	Wrapper string
	// ApprovalDir is where the plan's approvals are. A claim on any of them
	// means a run is going, and the cancel refuses (#1074 review).
	ApprovalDir string
	Runner      Runner
	Ledger      *ledger.Ledger
	Log         *RunLog
	State       interface {
		RunningVersion() (string, error)
		ConsensusHealthy() (bool, string)
	}
	// ComposeFile is read directly — reading is not a privileged act, and the
	// wrapper's job is to be the only thing that WRITES.
	ComposeFile string
	ImageRepo   string
	// RunDir holds transcripts, used to tell a finished run from a live one.
	RunDir string

	// Actor is who cancelled, and it has a different provenance from a run's.
	//
	// Cancel never passes through RunStage and has no approval to read an
	// identity out of — there is no web route for it at all, so the only
	// caller is a person at a shell. Its actor is therefore the operating
	// system account, recorded as verified:"os" and source:"cli". Weaker than
	// a passkey and labelled as weaker, which is better than either pretending
	// it is the same thing or leaving the entry anonymous as it was.
	Actor ledger.Actor
}

// Cancel performs the whole sequence: refuse if unsafe, read, repair, re-read.
func (c *Canceller) Cancel(ctx context.Context) (*CancelReport, error) {
	rep := &CancelReport{}
	start := time.Now()

	// 1. Refuse while something is running. Restoring a compose file underneath
	// a step that is about to read it is how a tidy-up becomes an incident.
	// A run that holds an approval of this plan is live, however long its
	// transcript has been quiet (#1074 review): a long build writes nothing
	// for minutes, and the transcript's age alone let a cancel restore the
	// deployment under it.
	if c.ApprovalDir != "" {
		if held, ok := approval.HeldAny(c.ApprovalDir, c.PlanID, time.Now()); ok {
			why := "a run of this plan is still going: " + held.Error()
			rep.Refused = why
			c.record(ledger.KindRefusal, "cancel refused: "+why, rep)
			return rep, fmt.Errorf("%s", why)
		}
	}
	if live, why := c.runInFlight(); live {
		rep.Refused = why
		c.record(ledger.KindRefusal, "cancel refused: "+why, rep)
		return rep, fmt.Errorf("%s", why)
	}

	// 2. Read where things stand, before touching anything.
	rep.Before = c.read()
	rep.NodeSafe = rep.Before.ConsensusOK

	// 3. Repair only what is actually inconsistent.
	needsRestore := rep.Before.ComposeTag != "" &&
		rep.Before.RunningVersion != "" &&
		!strings.HasSuffix(rep.Before.ComposeTag, ":"+rep.Before.RunningVersion)

	if needsRestore {
		bak, err := c.newestBackup()
		if err != nil {
			rep.Refused = "compose names " + rep.Before.ComposeTag + " but the node runs " +
				rep.Before.RunningVersion + ", and no dated backup was found to restore from"
			c.record(ledger.KindRefusal, "cancel refused: "+rep.Refused, rep)
			return rep, fmt.Errorf("%s", rep.Refused)
		}
		c.Log.Printf("step", "cancel", "restoring %s", filepath.Base(bak))
		// By file name: the root socket takes no paths (ADR 0025), and the
		// wrapper resolves a name beside the compose file it knows.
		out, err := c.Runner.Run(ctx, c.Wrapper, "restore-compose", filepath.Base(bak))
		if err != nil {
			rep.Refused = "restore failed: " + err.Error()
			c.record(ledger.KindRunHalted, "cancel could not restore the deployment", rep)
			return rep, fmt.Errorf("%s", rep.Refused)
		}
		rep.Restored = bak
		c.Log.Write("out", "cancel", strings.TrimSpace(string(out)))
	} else {
		rep.Kept = append(rep.Kept, "deployment already names the running version; nothing to restore")
	}

	// Backups and any pulled image are left alone, deliberately.
	rep.Kept = append(rep.Kept,
		"dated backups kept — they are the rollback for a future attempt",
		"any pulled image kept — it costs disk, not safety, and saves the download next time")

	// 4. Read again. A repair that is not verified is a hope.
	rep.After = c.read()
	rep.NodeSafe = rep.After.ConsensusOK
	rep.Consistent = rep.After.ComposeTag == "" || rep.After.RunningVersion == "" ||
		strings.HasSuffix(rep.After.ComposeTag, ":"+rep.After.RunningVersion)

	if !rep.Consistent {
		c.record(ledger.KindRunHalted,
			"cancel left the deployment inconsistent — compose "+rep.After.ComposeTag+
				", node "+rep.After.RunningVersion, rep)
		return rep, fmt.Errorf("cancel did not reconcile the deployment; do not restart the node")
	}

	// The node's own reading beside the done (#769), judged against the
	// moment the cancel began: it restores a file and restarts nothing, and
	// the reading is what says so.
	var p *Proof
	if o, ok := c.State.(interface {
		Observe() (runbook.Observation, error)
	}); ok {
		obs, err := o.Observe()
		p = Judge(obs, err, start, time.Now(), rep.After.RunningVersion)
	}
	c.Log.StageDone(p, "cancelled; deployment and node agree")
	c.record(ledger.KindRunCancelled, "plan cancelled; deployment reconciled to "+rep.After.RunningVersion, rep)
	return rep, nil
}

// runInFlight reports whether a transcript has been written to recently. A
// finished run stops writing; a live one does not.
func (c *Canceller) runInFlight() (bool, string) {
	p := filepath.Join(c.RunDir, RunID(c.PlanID, c.Stage)+".ndjson")
	fi, err := os.Stat(p)
	if err != nil {
		return false, ""
	}
	if time.Since(fi.ModTime()) < 90*time.Second {
		return true, "a run for this plan wrote to its transcript " +
			fmt.Sprintf("%ds", int(time.Since(fi.ModTime()).Seconds())) +
			" ago; wait for it to finish or fail before cancelling"
	}
	return false, ""
}

func (c *Canceller) read() State {
	var s State
	if b, err := os.ReadFile(c.ComposeFile); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.Index(line, "image:"); i >= 0 && strings.Contains(line, c.ImageRepo) {
				s.ComposeTag = strings.TrimSpace(line[i+len("image:"):])
				break
			}
		}
	}
	if c.State != nil {
		if v, err := c.State.RunningVersion(); err == nil {
			s.RunningVersion = v
		}
		s.ConsensusOK, s.Consensus = c.State.ConsensusHealthy()
	}
	return s
}

// newestBackup finds the most recent dated copy of the compose file.
func (c *Canceller) newestBackup() (string, error) {
	dir := filepath.Dir(c.ComposeFile)
	base := filepath.Base(c.ComposeFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var best string
	var bestAt time.Time
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, base+".") || !strings.HasSuffix(n, ".bak") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().After(bestAt) {
			bestAt, best = fi.ModTime(), filepath.Join(dir, n)
		}
	}
	if best == "" {
		return "", fmt.Errorf("no dated backup of %s", base)
	}
	return best, nil
}

// spendGrant is approval.Spend, a variable so a test can make a spend fail the
// way a grant this account can neither remove nor rewrite does.
var spendGrant = approval.Spend

// SpendGrants retires every approval scope the plan can be granted for, and
// answers for each one (#1116). Cancel used to drop the result of the spend,
// so a grant that could be neither removed nor voided stayed live after the
// operator had been told the plan was cancelled, and nothing said so.
//
// The grant's own expiry is read before the spend, because that is the one
// moment it is certain to be on disk: a grant that could not be spent is the
// grant still there, and the operator needs to know until when. A grant that
// was voided in place authorises nothing more, and comes back as a note. A
// grant that stays live gets a refusal row in the ledger, as spendOwn writes
// for a run, and the returned error names it; the caller exits non-zero on it.
func (c *Canceller) SpendGrants(scopes []string) (notes []string, err error) {
	var others []error
	for _, scope := range scopes {
		a, found, perr := approval.Peek(c.ApprovalDir, c.PlanID, scope)
		serr := spendGrant(c.ApprovalDir, c.PlanID, scope)
		switch {
		case serr == nil:
		case errors.Is(serr, approval.ErrStillLive):
			until := "it expires"
			if perr == nil && found {
				until = a.ExpiresAt.UTC().Format("15:04 MST")
			}
			others = append(others, fmt.Errorf("the approval for this %s could not be spent, and it stays live until %s (%w)",
				scope, until, serr))
			if c.Ledger != nil {
				c.Ledger.AppendAs(ledger.KindRefusal, c.PlanID,
					"the approval could not be spent and stays live until "+until,
					map[string]any{"stage": c.Stage, "granted_scope": scope, "reason": "spend_failed",
						"error": serr.Error()}, c.Actor)
			}
		case errors.Is(serr, approval.ErrSpendFailed):
			notes = append(notes, "the "+scope+" approval could not be removed, so it was voided in place and "+
				"authorises nothing more: "+serr.Error())
		default:
			others = append(others, fmt.Errorf("the %s approval could not be spent: %w", scope, serr))
		}
	}
	return notes, errors.Join(others...)
}

func (c *Canceller) record(kind ledger.Kind, summary string, rep *CancelReport) {
	if c.Ledger == nil {
		return
	}
	c.Ledger.AppendAs(kind, c.PlanID, summary, map[string]any{
		"stage": c.Stage, "restored": rep.Restored, "kept": rep.Kept,
		"before": rep.Before, "after": rep.After,
		"node_safe": rep.NodeSafe, "consistent": rep.Consistent,
	}, c.Actor)
}
