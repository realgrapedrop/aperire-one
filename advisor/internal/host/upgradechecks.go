package host

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"aperire-advisor/internal/runbook"
)

// The checks the upgrade contract names and nothing else had: what the
// network's amendments are about to do, and whether the node that came back
// is the same node that went down.
//
// Both read the node's own admin RPC, the same endpoint and the same client
// server_info already uses, so neither widens what this process can reach.

// ── Amendments, and what they do to a rollback ────────────────────────────

// AmendmentClock is what the network's amendments mean for THIS node right
// now: whether it is already blocked, and what is on the clock.
type AmendmentClock struct {
	// BlockedNow is the node's own verdict: an amendment is enabled that
	// this build does not support. A rollback cannot fix that, and the
	// older build is at least as likely to be blocked by it.
	BlockedNow bool
	// BlockedBy names them, when the node says which.
	BlockedBy []string
	// EnabledHere counts the amendments the network has ENABLED and this
	// build supports. A real node reports about a hundred of them.
	EnabledHere int
	// Enabled is those amendments, by name and id, because the rollback
	// check has to ask about each one individually: whether the build being
	// rolled back TO supported it, read from that build's own reply.
	Enabled []EnabledAmendment
	// Enabling is every amendment that has reached majority and is not
	// enabled yet, with the moment it would enable.
	Enabling []EnablingAmendment
	// Read is false when the node would not answer. Absent is not zero: a
	// check that cannot read its evidence must not be the thing that stops
	// an operator recovering a node, so callers say "not measured" rather
	// than treating silence as "nothing pending".
	Read bool
}

// EnabledAmendment is one amendment the network has already enabled.
type EnabledAmendment struct {
	Name string
	ID   string
}

// EnablingAmendment is one amendment on the two-week clock.
type EnablingAmendment struct {
	Name          string
	ID            string
	MajoritySince time.Time
	// Enables is MajoritySince plus the network's own rule: an amendment
	// must hold more than 80% support for two weeks before it enables.
	Enables time.Time
}

// amendmentMajorityWindow is that rule, in one place.
const amendmentMajorityWindow = 14 * 24 * time.Hour

// featureResult is the subset of `feature`'s reply these checks read.
//
// `majority` is an INTEGER, in the ledger's own clock, and it is the field
// the daemon actually sends. An earlier version of this decoded a
// `majority_since` string, which xrpld has never had at any release: every
// amendment therefore read as having no clock at all, and the window half of
// this check was dead on a real node while its tests passed against a
// fixture nobody had taken from a node. The fixture beside this file is a
// real reply, 107 amendments, three of them inside their majority window.
//
// Absent on an amendment that has not reached majority, which is most of
// them, so it stays optional: a missing one means this has nothing to say
// about that amendment's clock, and it says so rather than guessing a date.
type featureResult struct {
	Result struct {
		Features map[string]struct {
			Enabled   bool   `json:"enabled"`
			Supported bool   `json:"supported"`
			Name      string `json:"name"`
			Majority  int64  `json:"majority"`
		} `json:"features"`
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"result"`
}

// rippleEpoch is the offset between the ledger's own clock and Unix time:
// the XRP Ledger counts seconds from 2000-01-01 UTC. Checked against the lab
// validator's own reply, where fixBatchV1_2 reads majority 843660771, which
// is 2026-09-25 14:12:51 UTC, the time the release announcement gives it.
const rippleEpoch = 946684800

// AmendmentClockNow reads the node's `feature` and reports what it means.
//
// An unreadable answer is Read=false with the reason, never an empty clock.
// featureReply is the one place this package asks the node about
// amendments. A real reply is about 22 KB and 107 amendments, so the read is
// bounded like every other.
func (s *State) featureReply() (featureResult, error) {
	var f featureResult
	body := strings.NewReader(`{"method":"feature","params":[{}]}`)
	req, err := http.NewRequestWithContext(s.context(), http.MethodPost, s.Profile.AdminRPC, body)
	if err != nil {
		return f, fmt.Errorf("could not ask the node about amendments: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return f, fmt.Errorf("could not ask the node about amendments: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return f, fmt.Errorf("could not read the node's amendment answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return f, fmt.Errorf("the node's admin rpc returned %s for feature", resp.Status)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("could not decode the node's amendment answer: %w", err)
	}
	if f.Result.Error != "" {
		return f, fmt.Errorf("the node refused the amendment read: %s", f.Result.Error)
	}
	return f, nil
}

func (s *State) AmendmentClockNow() (AmendmentClock, string) {
	var c AmendmentClock
	f, err := s.featureReply()
	if err != nil {
		return c, err.Error()
	}
	if len(f.Result.Features) == 0 {
		return c, "the node listed no amendments at all, so nothing here was measured"
	}
	c.Read = true
	for id, a := range f.Result.Features {
		name := a.Name
		if name == "" {
			name = shortID(id)
		}
		if a.Enabled && !a.Supported {
			c.BlockedNow = true
			c.BlockedBy = append(c.BlockedBy, name)
			continue
		}
		if a.Enabled {
			// Enabled, and this build supports it. That is the ordinary
			// state of every amendment on a healthy node, and it is what a
			// DOWNGRADE has to be measured against: the build being rolled
			// back to is older, and this cannot ask it what it supports.
			// Skipping these is what let a rollback to 3.3.0 read as safe
			// the day after fixBatchV1_2 enabled.
			c.EnabledHere++
			c.Enabled = append(c.Enabled, EnabledAmendment{Name: name, ID: id})
			continue
		}
		if a.Majority <= 0 {
			continue
		}
		since := time.Unix(a.Majority+rippleEpoch, 0).UTC()
		c.Enabling = append(c.Enabling, EnablingAmendment{
			Name: name, ID: id, MajoritySince: since, Enables: since.Add(amendmentMajorityWindow),
		})
	}
	sort.Strings(c.BlockedBy)
	sort.Slice(c.Enabled, func(i, j int) bool { return c.Enabled[i].Name < c.Enabled[j].Name })
	sort.Slice(c.Enabling, func(i, j int) bool { return c.Enabling[i].Enables.Before(c.Enabling[j].Enables) })
	return c, ""
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

// parseRippledTime reads the two stamp shapes this node's replies use: RFC
// 3339, and rippled's own "2026-Sep-25 14:12:51.000000000 UTC". Anything
// else is not a date this will guess at.
func parseRippledTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05 UTC",
		"2006-Jan-02 15:04:05 UTC",
		"2006-Jan-02 15:04:05.999999999 UTC",
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// ── What a build supports, kept from when it was the build running ───────

// supportRecord is one build's own answer to "which amendments do you
// support", taken while that build was running on this node.
//
// It is the one thing that can prove a rollback safe. An image cannot be
// asked without running it, and running a second copy of a validator's
// build against its own config is the one thing an operator must never do;
// this project carries no table of which release first supported which
// amendment either. But the node itself answered that question every time
// it was the version running, and that answer does not change for a given
// build, so it is worth keeping.
type supportRecord struct {
	Version string `json:"version"`
	// Build is the full build version that answered, with any -rc or -b
	// suffix (#1003). Empty on a record written before it was kept, which
	// was filed under the version with that suffix cut off, so an rc and
	// the release of the same number wrote one file.
	Build      string            `json:"build,omitempty"`
	CapturedAt time.Time         `json:"captured_at"`
	Supported  map[string]bool   `json:"supported"`
	Names      map[string]string `json:"names"`
}

// supportRecordName is the file one build's record lives in, beside the
// diagnostic snapshot. Keyed by build, because the point is to have the
// OLD build's answer available after a newer one is running, and an rc is
// not the release it precedes: an amendment added or dropped between them
// is exactly what this record exists to show.
func supportRecordName(build string) string {
	return "amendment-support-" + build + ".json"
}

// supportBuild is the key a build's record is filed under: the version the
// node reports with any fork prefix taken off and any "+" build metadata
// cut, and its -rc or -b suffix kept (#1003). NormalizeVersion cuts the
// suffix too, which is right for comparing a node with a tag and wrong
// here. Empty when what is left is not a version: it names a file, and it
// came from the node.
func supportBuild(raw string) string {
	v := strings.TrimSpace(raw)
	for _, p := range []string{"rippled-", "xrpld-", "xahaud-", "v"} {
		v = strings.TrimPrefix(v, p)
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if v == "" || len(v) > 40 || v[0] < '0' || v[0] > '9' || strings.Contains(v, "..") {
		return ""
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-') {
			return ""
		}
	}
	return v
}

// recordSupportedAmendments writes this build's own `feature` answer beside
// the snapshot. Best effort, and silent: an upgrade must not fail over a
// file that is only read much later, and the reader says "unproven" when it
// is missing, which is the honest answer rather than a wrong one.
func (s *State) recordSupportedAmendments(dir, rawVersion string) {
	build := supportBuild(rawVersion)
	v := NormalizeVersion(rawVersion)
	if dir == "" || build == "" || !versionish(v) {
		return
	}
	f, err := s.featureReply()
	if err != nil || len(f.Result.Features) == 0 {
		return
	}
	rec := supportRecord{
		Version: v, Build: build, CapturedAt: time.Now().UTC(),
		Supported: make(map[string]bool, len(f.Result.Features)),
		Names:     make(map[string]string, len(f.Result.Features)),
	}
	for id, a := range f.Result.Features {
		rec.Supported[id] = a.Supported
		if a.Name != "" {
			rec.Names[id] = a.Name
		}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, supportRecordName(build)), b, 0o640)
}

// readSupportRecord loads the record for one build, or says why not.
//
// The record that answers is the one that build wrote, named by its full
// build (#1003). A record written before builds were kept answers only for a
// release, and only when no record of that release's own exists: it was
// filed under the version with any -rc suffix cut off, so it cannot say
// whether the release or an rc of it wrote it, and the release's own record
// is the better answer whenever there is one. It never answers for an rc,
// which the old reader never matched either. A record whose build is
// another one never answers at all: an rc's support is not its release's.
func (s *State) readSupportRecord(version string) (supportRecord, error) {
	var rec supportRecord
	if s.EvidencePath == "" {
		return rec, fmt.Errorf("this host keeps no diagnostic snapshots, so nothing recorded what %s supports", version)
	}
	build := supportBuild(version)
	if build == "" {
		return rec, fmt.Errorf("nothing on this host records which amendments %s supports", version)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(s.EvidencePath), supportRecordName(build)))
	if err != nil {
		return rec, fmt.Errorf("nothing on this host records which amendments %s supports", version)
	}
	if err := json.Unmarshal(b, &rec); err != nil || len(rec.Supported) == 0 {
		return rec, fmt.Errorf("the record of what %s supports could not be read", version)
	}
	switch {
	case rec.Build == build:
		return rec, nil
	case rec.Build == "" && build == NormalizeVersion(build):
		// The old format, for a release, and the release wrote no record of
		// its own since: the one answer this host has.
		return rec, nil
	case rec.Build == "":
		return supportRecord{}, fmt.Errorf("nothing on this host records which amendments %s supports", version)
	}
	return supportRecord{}, fmt.Errorf("the record filed for %s was written by %s, which is another build, "+
		"so nothing on this host records which amendments %s supports", version, rec.Build, version)
}

// RollbackSafeFromAmendments answers the contract's step 2 for a rollback:
// can the version this rolls back TO be shown not to come up amendment
// blocked?
//
// The rule is provable rather than cautious, and it rests on one fact: the
// node answered "which amendments do I support" every time it was the
// version running, and this keeps that answer beside the diagnostic
// snapshot, keyed by version. A build's support set does not change, so a
// record taken while 3.3.0 was running is exactly what 3.3.0 supports
// today.
//
// So: a rollback is safe when every amendment the network has ENABLED now
// was supported by the target build's own reply. It is refused, naming the
// amendment, when one was not. And it is "unproven" when nothing on this
// host recorded what that build supports, which is what a host that has
// never run an upgrade through this Advisor looks like.
//
// Two other refusals stay, and both come before the record is consulted:
// the node is blocked right now (a rollback cannot fix that, and the older
// build is at least as likely to lack what blocked this one), and an
// amendment has passed its two-week window so it is enabled or about to be.
//
// A node that would not answer produces "not measured", never a pass
// disguised as one.
func (s *State) RollbackSafeFromAmendments(target string) runbook.Measurement {
	// Memoised for the life of this State, which is one request. The gate
	// renders this answer twice, once as a precondition and once as the
	// concern above the approve button, and two reads of a moving
	// amendment clock could put two different sentences on one screen
	// (#676). A State is rebuilt per request, so this is a shared reading,
	// never a cached one.
	if m, ok := s.amendmentSafety[target]; ok {
		return m
	}
	m := s.rollbackSafeFromAmendments(target)
	if s.amendmentSafety == nil {
		s.amendmentSafety = map[string]runbook.Measurement{}
	}
	s.amendmentSafety[target] = m
	return m
}

func (s *State) rollbackSafeFromAmendments(target string) runbook.Measurement {
	c, why := s.AmendmentClockNow()
	if !c.Read {
		// Unmeasured, and deliberately NOT a refusal. A node that will not
		// answer `feature` is often exactly the node an operator is rolling
		// back, and taking the remedy away from a sick node is a worse
		// outcome than an unproven gate an operator reads and decides on.
		// It reads "not measured" now rather than "pass" (#679), which is
		// the part that was wrong.
		return runbook.FailedToMeasure(why + ". Read `feature` on this node before approving a rollback")
	}
	if c.BlockedNow {
		return runbook.Measured(false, fmt.Sprintf(
			"this node is amendment blocked right now (%s). A rollback cannot fix that, and %s is at "+
				"least as likely to lack it, so there is no safe automatic rollback here: upgrade to a "+
				"build that supports it, or escalate",
			strings.Join(c.BlockedBy, ", "), target))
	}
	now := s.now()
	var due []string
	for _, a := range c.Enabling {
		if now.Before(a.Enables) {
			continue
		}
		due = append(due, fmt.Sprintf("%s (majority since %s, enabling from %s)",
			a.Name, a.MajoritySince.Format("2006-01-02"), a.Enables.Format("2006-01-02")))
	}
	if len(due) > 0 {
		return runbook.Measured(false, fmt.Sprintf(
			"%s has held majority past its two-week window, so it is enabled or about to be, and nothing "+
				"here can prove %s supports it. A node that comes back blocked is a worse outcome than the "+
				"one this rollback is for: roll back to a release whose own record shows it supports it, "+
				"or escalate",
			strings.Join(due, "; "), target))
	}
	if c.EnabledHere == 0 {
		return runbook.Measured(true, "nothing is enabled that this node does not support, and no amendment is inside its majority window")
	}

	rec, rerr := s.readSupportRecord(target)
	if rerr != nil {
		// Unproven, not a measured "no": nothing here says the target
		// lacks anything, only that nothing says it doesn't. It still
		// refuses, and the gate's concern renders it as undetermined from
		// this same field (#676).
		return runbook.Unproven(fmt.Sprintf(
			"unproven: %v, and the network has %d amendment%s enabled. An older build that lacks one comes "+
				"back amendment blocked, which stops it participating altogether. A rollback this Advisor "+
				"has a record for is the one it can vouch for; for this one, check the release notes against "+
				"what is enabled, or escalate",
			rerr, c.EnabledHere, plural1(c.EnabledHere)))
	}
	var lacks []string
	for _, a := range c.Enabled {
		if supported, known := rec.Supported[a.ID]; known && supported {
			continue
		}
		name := a.Name
		if n := rec.Names[a.ID]; n != "" {
			name = n
		}
		lacks = append(lacks, name)
		if len(lacks) >= 4 {
			break
		}
	}
	if len(lacks) > 0 {
		return runbook.Measured(false, fmt.Sprintf(
			"%s %s enabled on the network and %s did not support %s when it last ran here (recorded %s). "+
				"It would come back amendment blocked: roll back to a release that supports %s, or escalate",
			strings.Join(lacks, ", "), plural2(len(lacks)), target, plural3(len(lacks)),
			rec.CapturedAt.Format("2006-01-02"), plural3(len(lacks))))
	}
	return runbook.Measured(true, fmt.Sprintf(
		"every one of the %d amendments enabled now was supported by %s's own reply when it last ran here "+
			"(recorded %s), so it comes back able to follow the network",
		c.EnabledHere, target, rec.CapturedAt.Format("2006-01-02")))
}

func plural2(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func plural3(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// now is the clock, injectable for the tests that have to stand on both
// sides of an enablement date.
func (s *State) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func plural1(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ── The node that came back is the node that went down ────────────────────

// IdentityUnchanged compares the node answering now with the diagnostic
// snapshot taken before the change: contract step 8.
//
// The snapshot is the one this package already writes before any state
// change (CaptureEvidence), so this needs no new reading and no new file.
// What it compares is what an operator would check by hand and what a
// version number cannot tell them: a node can report the target build and
// still be the wrong node, or the same node with its validator identity
// gone, or one the publisher lists no longer reach.
//
// Peers are compared with a tolerance, because a node that has just come
// back is still rebuilding them, and the caller only reaches this once the
// node is back in full sync.
func (s *State) IdentityUnchanged() (bool, string) {
	if s.EvidencePath == "" {
		return true, "no diagnostic snapshot was configured, so there is nothing to compare against"
	}
	raw, err := os.ReadFile(s.EvidencePath)
	if err != nil {
		return true, fmt.Sprintf("the diagnostic snapshot could not be read (%v), so nothing was compared", err)
	}
	var snap struct {
		ServerInfo serverInfoFields `json:"server_info"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		return true, fmt.Sprintf("the diagnostic snapshot could not be decoded (%v), so nothing was compared", err)
	}
	info, err := s.serverInfo()
	if err != nil {
		return false, fmt.Sprintf("the node would not say what it is: %v", err)
	}
	before, after := snap.ServerInfo, info.Result.Info

	var bad, said []string
	if before.PubkeyNode != "" {
		if after.PubkeyNode != before.PubkeyNode {
			bad = append(bad, fmt.Sprintf("this node's key was %s before the change and is %s now",
				before.PubkeyNode, after.PubkeyNode))
		} else {
			said = append(said, "same node key")
		}
	}
	if before.PubkeyValidator != "" {
		if after.PubkeyValidator != before.PubkeyValidator {
			bad = append(bad, fmt.Sprintf("the validator key was %s before the change and is %s now",
				before.PubkeyValidator, after.PubkeyValidator))
		} else {
			said = append(said, "same validator key")
		}
	}
	if after.AmendmentBlocked {
		bad = append(bad, "the node is amendment blocked")
	}
	if before.ValidatorList != nil {
		switch {
		case after.ValidatorList == nil:
			bad = append(bad, "the node no longer reports a validator list at all")
		case after.ValidatorList.Status != "active":
			bad = append(bad, fmt.Sprintf("the validator list reads %q, not active", after.ValidatorList.Status))
		case after.ValidatorList.Count != before.ValidatorList.Count:
			bad = append(bad, fmt.Sprintf("the validator list holds %d publishers and held %d before",
				after.ValidatorList.Count, before.ValidatorList.Count))
		default:
			said = append(said, fmt.Sprintf("validator list active, %d publishers", after.ValidatorList.Count))
		}
	}
	// Peers are reported and never the thing that halts a run. A validator's
	// peer count moves on its own, the contract's "back to within 2" is a
	// reading an operator judges rather than a threshold worth rolling a
	// node back over, and a node that came back with the right keys and an
	// active UNL is the node that went down whatever its peer count is this
	// second.
	if before.Peers > 0 {
		if after.Peers < before.Peers-peerTolerance {
			said = append(said, fmt.Sprintf("peers %d, below the %d before this (still rebuilding, or worth a look)",
				after.Peers, before.Peers))
		} else {
			said = append(said, fmt.Sprintf("peers %d (were %d)", after.Peers, before.Peers))
		}
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	if len(said) == 0 {
		return true, "the snapshot carried none of these readings, so nothing was compared"
	}
	return true, strings.Join(said, ", ")
}

// peerTolerance is how far below its own baseline a node may sit and still
// count as back: the contract's "within 2".
const peerTolerance = 2

// ── The recipe a container node builds its image from ────────────────────

// ImageRecipeReady asks the wrapper whether it would build from the recipe
// installed on this host, through the wrapper's own checks rather than by
// looking at the files from here.
//
// It exists because an update placed nothing (#675): `get-aperire.sh` ran
// the recipe installer in --refresh-only, which exits 0 without writing on
// a host that has no copy, so every container node installed before 17w
// had a card that showed eleven green preconditions and then refused at
// the build step, after the operator had approved. The refusal was right;
// its timing was not. This is the same question, asked before the gate.
//
// Asked through the wrapper on purpose. The build refuses on what the
// WRAPPER sees (root-owned, no symlinks, nothing group-writable, the whole
// chain above it), and a second implementation of those rules here would
// be free to disagree with the one that matters.
func (s *State) ImageRecipeReady() runbook.Measurement {
	const fix = "Install it on this host: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
	if s.Wrapper == "" {
		return runbook.FailedToMeasure(
			"no privilege wrapper is configured, so whether this host can build an image was not read")
	}
	name := s.Wrapper
	args := []string{"recipe-state"}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		// A wrapper too old to know the verb is the common case on a host
		// that has not been updated yet, and it is exactly the host this
		// check is about, so it says what to do rather than reporting a
		// bare exit status.
		return runbook.FailedToMeasure(fmt.Sprintf(
			"whether this host has the image recipe could not be read: %v. %s", err, fix))
	}
	var state, reason, path string
	for _, ln := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "AperireRecipe":
			state = v
		case "AperireRecipeReason":
			reason = v
		case "AperireRecipePath":
			path = v
		}
	}
	switch state {
	case "present":
		return runbook.Measured(true, "the image recipe root builds from is installed at "+path)
	case "absent":
		if reason == "" {
			reason = "no image recipe is installed on this host"
		}
		return runbook.Measured(false, reason+". This node builds its own image from the signed "+
			"package, so without the recipe the upgrade would refuse at the build step. "+fix)
	}
	return runbook.FailedToMeasure(
		"the wrapper did not say whether the image recipe is installed. " + fix)
}

// ── Where docker keeps its images ─────────────────────────────────────────

// ImageHeadroomBytes is free space on the filesystem docker keeps its images
// on, through the wrapper's image-headroom verb: contract step 3.
//
// Not the node's data path. On this project's own hosts they are often the
// same filesystem and often not, and a build writes its layers where docker
// lives rather than where the ledger does. A build that runs out of room
// there fails in the middle, which is survivable, and it is still better to
// know before the node's operator has approved anything.
func (s *State) ImageHeadroom() (avail int64, path string, err error) {
	if s.Wrapper == "" {
		return 0, "", fmt.Errorf("no privilege wrapper is configured, so docker's own disk was not measured")
	}
	name := s.Wrapper
	args := []string{"image-headroom"}
	out, rerr := s.Runner.Run(s.context(), name, args...)
	if rerr != nil {
		return 0, "", fmt.Errorf("could not measure docker's own disk: %w", rerr)
	}
	var reason string
	for _, ln := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "AperireImagePath":
			path = v
		case "AperireImageAvailBytes":
			avail, _ = strconv.ParseInt(v, 10, 64)
		case "AperireImageReason":
			reason = v
		}
	}
	if path == "" || avail == 0 {
		if reason == "" {
			reason = "the wrapper answered nothing this could read"
		}
		return 0, path, fmt.Errorf("%s", reason)
	}
	return avail, path, nil
}

// ── The store's own rotation clock ────────────────────────────────────────

// RotationWindow is how far this node is from its next store rotation, in
// ledgers and in the time those ledgers take: contract step 6.
type RotationWindow struct {
	// Until is how many ledgers until the next rotation is due. Negative
	// means it is already due, which happens on a node that rotates on its
	// own schedule.
	Until int
	// Known is false when any of the three readings behind it is missing,
	// and Reason says which. A node whose store never rotates (no
	// online_delete) is Known=false with that as the reason, not a zero.
	Known  bool
	Reason string
	// Failed separates the two ways Known can be false, and the separation
	// is the whole of #679's first defect. A node that answered and had
	// nothing to report is ordinary and must still be offered an upgrade; a
	// wrapper that ERRORED means the Advisor never got to look, and a
	// safety check it could not take must not read as a pass. Without this
	// bit both arrive as "not measured" and the caller has to guess.
	Failed bool
	// OnlineDelete is the configured interval in ledgers, set whenever
	// Known is. It is the most quiet time a rotation can ever leave.
	OnlineDelete int
	// SinceLast is how long ago the last rotation finished, by the finish
	// line's own stamp, and SinceKnown says whether the wrapper reported
	// it (#833). Added to the time left, it is the quiet stretch between a
	// rotation finishing and the next one starting, which is the most a
	// swap can ever be given on this node. A wrapper from before #833 does
	// not report it.
	SinceLast  time.Duration
	SinceKnown bool
}

// ledgerSeconds is how long a ledger takes, for turning a count into a
// window. Three to four seconds is the network's own figure; the larger one
// is used, because over-estimating the time to the next rotation is the
// direction that refuses a swap it could have allowed, and under-estimating
// is the direction that stops a node mid-rotation.
const ledgerSeconds = 4

// ledgerDigits is the only shape a rotation reading may take.
var ledgerDigits = regexp.MustCompile(`^[0-9]{1,10}$`)

// maxLedgerSeq is the largest ledger sequence there is: they are 32-bit.
const maxLedgerSeq = 1<<32 - 1

// maxUntilLedgers is the most ledgers whose time still fits a Duration.
// Anything further off is far enough for any swap, so it is clamped here
// rather than overflowing into a negative window that reads as "inside it".
const maxUntilLedgers = int64(math.MaxInt64 / int64(ledgerSeconds*time.Second))

// RotationWindowNow reads the wrapper's rotation-window verb.
func (s *State) RotationWindowNow() RotationWindow {
	if s.Wrapper == "" {
		return RotationWindow{
			Reason: "no privilege wrapper is configured, so the store's rotation clock was not read",
			Failed: true,
		}
	}
	name := s.Wrapper
	args := []string{"rotation-window"}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		return RotationWindow{
			Reason: fmt.Sprintf("the store's rotation clock could not be read: %v", err),
			Failed: true,
		}
	}
	var last, online, validated, age int
	var reason string
	var sawAge bool
	// Three states come out of this parse, not two, and the third is the
	// one #679 left open on this path. An answer the wrapper could not
	// take, an answer nobody can read, and an answer that says "nothing to
	// report" are different things, and only the last of them is benign.
	var (
		readErr   string // the wrapper named its own failure
		sawReason bool   // the wrapper said, in words, that it has nothing
		sawKey    bool   // anything recognisable came back at all
	)
	// Strict, because the wrapper is: each key at most once, and a reading
	// is plain digits, at most ten (ledger sequences are 32-bit). Atoi alone
	// takes "+12", "-5" and "12 " in its own ways, and a repeated key would
	// be read last-wins here whatever the wrapper meant. Either is an answer
	// this code cannot vouch for, so it fails to measure rather than sums.
	seen := map[string]bool{}
	var malformed string
	for _, ln := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "AperireLastRotatedSeq", "AperireOnlineDelete", "AperireValidatedSeq",
			"AperireRotationReason", "AperireRotationError", "AperireLastRotatedAge":
			if seen[k] && malformed == "" {
				malformed = fmt.Sprintf("the rotation clock named %s more than once", k)
			}
			seen[k] = true
		}
		n := 0
		switch k {
		case "AperireLastRotatedSeq", "AperireOnlineDelete", "AperireValidatedSeq", "AperireLastRotatedAge":
			// The age is seconds, not ledgers, but the same shape: ten
			// digits is three centuries, and the wrapper only ever prints
			// digits. Held to the same strictness on purpose: it only
			// shapes a sentence, but an answer this code cannot read is
			// not one to half-trust.
			if !ledgerDigits.MatchString(v) {
				if malformed == "" {
					malformed = fmt.Sprintf("the rotation clock's %s reads %q, which is not a ledger count", k, v)
				}
				continue
			}
			n, _ = strconv.Atoi(v)
		}
		switch k {
		case "AperireLastRotatedSeq":
			last, sawKey = n, true
		case "AperireOnlineDelete":
			online, sawKey = n, true
		case "AperireValidatedSeq":
			validated, sawKey = n, true
		case "AperireRotationReason":
			reason, sawReason, sawKey = v, true, true
		case "AperireRotationError":
			readErr, sawKey = v, true
		case "AperireLastRotatedAge":
			age, sawAge = n, true
		}
	}
	switch {
	case malformed != "":
		return RotationWindow{Reason: malformed, Failed: true}
	case readErr != "":
		// The wrapper ran and told us it could not read the node's log:
		// a logging driver it cannot read, a container it cannot reach.
		// The guard is blind, which is not the same as a quiet node.
		return RotationWindow{Reason: readErr, Failed: true}
	case last > maxLedgerSeq || online > maxLedgerSeq || validated > maxLedgerSeq:
		// Ledger sequences are 32-bit. A longer number is not a reading of
		// this node, and summed it would overflow the time below.
		return RotationWindow{
			Reason: fmt.Sprintf("the rotation clock reported a number past any ledger sequence "+
				"(last %d, online_delete %d, validated %d), so it was not used", last, online, validated),
			Failed: true,
		}
	case last > 0 && online > 0 && validated > 0 && last > validated:
		// A rotation after the newest validated ledger is a log and a node
		// describing two different stores. The sum would put the next
		// rotation further off than it is, which is the unsafe direction.
		return RotationWindow{
			Reason: fmt.Sprintf("the rotation clock reported a last rotation at ledger %d, past the "+
				"validated ledger %d, so the log and the node are not describing the same store", last, validated),
			Failed: true,
		}
	case last > 0 && online > 0 && validated > 0:
		return RotationWindow{Until: last + online - validated, Known: true, OnlineDelete: online,
			SinceLast: time.Duration(age) * time.Second, SinceKnown: sawAge}
	case sawReason:
		// The one benign shape: the wrapper answered, and its answer is
		// that this node has nothing to report.
		return RotationWindow{Reason: reason}
	case !sawKey:
		return RotationWindow{
			Reason: "the rotation clock came back empty: nothing this Advisor recognises was in the answer",
			Failed: true,
		}
	}
	// Recognisable keys, no reason, and not all three readings: the answer
	// is not one this code knows how to read, and guessing which way it
	// leans is how a safety check becomes decoration.
	return RotationWindow{
		Reason: "the rotation clock's answer could not be read: it named no reason and did not report a " +
			"last rotation, an online_delete and a validated ledger",
		Failed: true,
	}
}

// FarFromRotation answers the contract's step 6: is the next rotation
// further off than the time this swap needs?
//
// A stop inside a rotation is how a store gets emptied (issue #79), and the
// wrapper already refuses one it can SEE in the log. This is the other half:
// a rotation that has not started yet but would start during the swap.
//
// An unknown clock comes back unmeasured, and which KIND of unknown decides
// what the gate does with it (#679). A node that answered and has nothing
// to report is still offered the upgrade, because plenty of healthy nodes
// look like that (advisory_delete off is a first-class choice here) and the
// wrapper's log-based guard still refuses a stop inside a rotation it can
// see. A wrapper that errored is different: nothing looked, and a safety
// check nobody took must not render as a pass.
//
// This form takes the rotation reading fresh from the wrapper, and only when
// the store is at or past its window. The service hands its own cached
// reading in through FarFromRotationWith instead, so a check does not read
// the log twice.
func (s *State) FarFromRotation(need time.Duration) runbook.Measurement {
	return s.FarFromRotationWith(need, s.RotationStateNow)
}

// shippedOnlineDelete is what the node template this software installs sets
// online_delete to (scripts/templates/rippled.stock.cfg), named in the one
// sentence that tells an operator to raise theirs (#833).
const shippedOnlineDelete = 32768

// FarFromRotationWith is FarFromRotation with the rotation reading supplied:
// the wrapper's state word, its one line about it, and whether it could be
// read. It is asked only when the store is at or past its window, which is
// the one case the clock alone cannot answer.
func (s *State) FarFromRotationWith(need time.Duration, rotation func() (string, string, error)) runbook.Measurement {
	w := s.RotationWindowNow()
	if !w.Known {
		if w.Failed {
			return runbook.FailedToMeasure(w.Reason)
		}
		return runbook.NotMeasured(w.Reason)
	}
	until := int64(w.Until)
	if until > maxUntilLedgers {
		until = maxUntilLedgers
	}
	have := time.Duration(until) * ledgerSeconds * time.Second
	tooOften := rotatesTooOften(w, have, need)
	if w.Until <= 0 {
		// At or past the window. On a node with advisory_delete on, that
		// is ordinary: the store is due and waits for the daily window to
		// let it rotate. On any node it is also what a rotation RUNNING
		// looks like, and that used to pass here, handing off to the
		// rotation reading (#833): a node whose rotations run long against
		// their interval passed this check only while one was running. So
		// the rotation reading decides it, inside this verdict.
		var state, detail string
		var err error
		if rotation != nil {
			state, detail, err = rotation()
		}
		switch {
		case err != nil:
			// The reading fails open everywhere else, and the wrapper's own
			// refusal is still in front of the stop. Not measured, then,
			// rather than a pass nobody looked behind.
			return runbook.NotMeasured(fmt.Sprintf(
				"the store is at or past its rotation window (%d ledgers), and whether a rotation is "+
					"running right now could not be read: %v", -w.Until, err))
		case state == "rotating" && tooOften != "":
			return runbook.Measured(false, "a store rotation is running now, and "+tooOften)
		case state == "rotating":
			return runbook.Measured(false, fmt.Sprintf(
				"a store rotation is running now (%s), so the swap would land inside it. "+
					"Let it finish, then run this again", orNoDetail(detail)))
		case state == "idle":
			return runbook.Measured(true, fmt.Sprintf(
				"the store is at or past its rotation window (%d ledgers), and no rotation is running now (%s)",
				-w.Until, orNoDetail(detail)))
		}
		// Only "idle" says nothing is running. "unknown" is a read that ran
		// out or could not see the log, "stale" a rotation that started
		// hours ago and never said it finished, and an empty word is no
		// answer at all. None of them is a pass with "no rotation is
		// running" in it (PR #1049 review): not measured, which still
		// offers the swap, and the wrapper's unbounded guard still stands
		// in front of the stop.
		word := state
		if word == "" {
			word = "no answer"
		}
		return runbook.NotMeasured(fmt.Sprintf(
			"the store is at or past its rotation window (%d ledgers), and whether a rotation is "+
				"running right now is not known (the rotation reading says %s: %s)",
			-w.Until, word, orNoDetail(detail)))
	}
	if have < need {
		if tooOften != "" {
			return runbook.Measured(false, tooOften)
		}
		return runbook.Measured(false, fmt.Sprintf(
			"the next store rotation is about %s away (%d ledgers) and this needs about %s, so the swap "+
				"would land inside it. Let it rotate, then run this again",
			have.Round(time.Minute), w.Until, need.Round(time.Minute)))
	}
	return runbook.Measured(true, fmt.Sprintf(
		"the next store rotation is about %s away (%d ledgers), past the %s this needs",
		have.Round(time.Minute), w.Until, need.Round(time.Minute)))
}

// RotationEvery is how often a store with this online_delete rotates, as an
// operator reads it: "about every 34 minutes (online_delete=512 ledgers)".
// The same arithmetic the rotation precondition holds against a swap's need
// (ledgers at ledgerSeconds each), so chat and the check give one number. It
// is empty for an online_delete that is not a count (#1058).
func RotationEvery(onlineDelete int) string {
	if onlineDelete <= 0 || int64(onlineDelete) > maxUntilLedgers {
		return ""
	}
	every := time.Duration(onlineDelete) * ledgerSeconds * time.Second
	return fmt.Sprintf("about every %s (online_delete=%d ledgers)", plainMinutes(every), onlineDelete)
}

// RotationSchedule is how often the store rotates on a host with this
// online_delete, as one clause for chat (#1058, review of #1101).
// online_delete alone is the whole answer only on a node that rotates on its
// own. With advisory delete enabled and the daily window
// (aperire-can-delete.timer) enabled, each timer run authorises exactly one
// rotation (scripts/aperire-can-delete.sh), so the store rotates at most once
// a day, and no sooner than online_delete ledgers after the last one.
//
// What decides it is the RUNNING node, not the file. fileValue is the config
// file's advisory_delete ("" when not read); live is the node's own answer
// (AdvisoryLive*); timer is a CanDeleteTimer* state. A file that says 1 beside
// a node that reports it is not enabled is a node that has not restarted since
// the edit (scripts/enable-advisory-delete.sh does not restart it), and it
// still rotates on its own. When a rotation is running, a sentence that nothing
// lets one begin would contradict the screen, so a window that is not enabled
// is reported as what it is and not as a ban.
func RotationSchedule(onlineDelete int, fileValue, live, timer string) string {
	every := RotationEvery(onlineDelete)
	if every == "" {
		return ""
	}
	span := time.Duration(onlineDelete) * ledgerSeconds * time.Second
	fileOn := strings.TrimSpace(fileValue) == "1"
	switch live {
	case AdvisoryLiveNotEnabled:
		if fileOn {
			return "the node reports advisory delete is not enabled, although its configuration file says " +
				"advisory_delete=1 (the node has not restarted since), so it rotates on its own: " + every
		}
		return "the store rotates " + every
	case AdvisoryLiveEnabled:
		switch timer {
		case CanDeleteTimerEnabled:
			return fmt.Sprintf("the node reports advisory delete enabled and the daily rotation window "+
				"(aperire-can-delete.timer) is enabled, so the store rotates at most once a day, when the window "+
				"lets one begin, and no sooner than about %s (online_delete=%d ledgers) after the last one",
				plainMinutes(span), onlineDelete)
		case CanDeleteTimerAbsent, CanDeleteTimerDisabled:
			return fmt.Sprintf("the node reports advisory delete enabled and the daily rotation window is %s, "+
				"so a rotation begins only when something else calls can_delete (online_delete=%d ledgers)",
				timer, onlineDelete)
		}
		return fmt.Sprintf("the node reports advisory delete enabled and whether the daily rotation window is "+
			"enabled was not measured, so how often the store rotates is not known (online_delete=%d ledgers)",
			onlineDelete)
	}
	// The node's own state was not read.
	if fileOn {
		return fmt.Sprintf("the configuration file says advisory_delete=1 but the node's own state was not read, "+
			"so whether the store rotates on its own or only through the daily window is not known "+
			"(online_delete=%d ledgers)", onlineDelete)
	}
	return "the store rotates " + every + " if it rotates on its own (the node's own advisory delete state was not read)"
}

// rotatesTooOften is the sentence for a node whose rotations never leave a
// swap enough room, or "" when they do (#833, ruling 2026-10-04). On such a
// node "let it rotate, then run this again" never helps: a lab node, at
// online_delete=512, started a rotation every 32 minutes and each ran about
// 20, so the quiet stretch was about 11 minutes against the 30 a swap needs,
// every time.
//
// The quiet stretch is the time from the last finish to the next start: how
// long ago the finish was, plus the time left. A rotation's own running time
// is in it, which online_delete alone cannot show. A wrapper from before
// #833 reports no age, and then only the interval itself is held against the
// need, which misses that node (512 ledgers at four seconds is 34 minutes) and
// still catches anything shorter.
func rotatesTooOften(w RotationWindow, have, need time.Duration) string {
	every := time.Duration(w.OnlineDelete) * ledgerSeconds * time.Second
	fix := fmt.Sprintf("so waiting for the next one will not help. Raise online_delete in the node's "+
		"[node_db] (the template Aperire installs sets %d; the Advisor's configuration change can set it, "+
		"and the node restarts to apply it), then run this again", shippedOnlineDelete)
	if !w.SinceKnown {
		if every >= need {
			return ""
		}
		return fmt.Sprintf("this node's store rotates about every %s (online_delete=%d ledgers), shorter "+
			"than the %s this swap needs even before a rotation's own running time, %s",
			plainMinutes(every), w.OnlineDelete, plainMinutes(need), fix)
	}
	// have is the clamped time left; past the window it is negative, and
	// the sum is then the stretch before the rotation now due or running.
	quiet := w.SinceLast + have
	if w.Until <= 0 {
		quiet = w.SinceLast + time.Duration(w.Until)*ledgerSeconds*time.Second
	}
	if quiet >= need {
		return ""
	}
	if quiet < 0 {
		quiet = 0
	}
	return fmt.Sprintf("this node's store rotates about every %s (online_delete=%d ledgers), and a "+
		"rotation leaves only about %s between finishing and the next one starting, under the %s this "+
		"swap needs, %s",
		plainMinutes(every), w.OnlineDelete, plainMinutes(quiet), plainMinutes(need), fix)
}

// plainMinutes is a duration as an operator reads one: "12 minutes", or
// "1h05m" past the hour, never "12m0s".
func plainMinutes(d time.Duration) string {
	m := int64(d.Round(time.Minute) / time.Minute)
	if m < 60 {
		if m == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", m)
	}
	return fmt.Sprintf("%dh%02dm", m/60, m%60)
}

// orNoDetail is the wrapper's own line, or a plain word for its absence.
func orNoDetail(d string) string {
	if strings.TrimSpace(d) == "" {
		return "the rotation reading gave no detail"
	}
	return d
}

// ── Which software is this, before offering it a release ──────────────────

// xrpldFamily is the set of binary names the package repository at
// packages.xrplf.org publishes releases for. rippled is here because the
// 3.2.0 release renamed the binary and a node on an older build still
// reports the old name; it is the same software and the same repository.
var xrpldFamily = map[string]bool{"xrpld": true, "rippled": true}

// ForkFamily names the software this node runs, from what the node and its
// deployment say rather than from an assumption.
//
// It exists because the release index this Advisor reads is xrpld's. A fork
// with its own repository, its own releases and its own amendment set would
// otherwise be offered an xrpld release, which is not an upgrade: it is a
// different program. Nothing here claims to recognise every fork. It
// recognises the one the evidence NAMES, and anything it cannot name is
// read as the xrpld family, because that is what this software installs and
// what every node it deploys is.
//
// Evidence, in order:
//
//  1. The build version the node reports. A fork that renames its binary
//     says so there (xahaud-2.0.0), and that is the node's own word.
//  2. The image repository or package name the deployment carries, which is
//     what the operator chose to run.
func (s *State) ForkFamily() (name, evidence string) {
	if info, err := s.serverInfo(); err == nil {
		raw := strings.TrimSpace(info.Result.Info.BuildVersion)
		if i := strings.Index(raw, "-"); i > 0 {
			if prefix := strings.ToLower(raw[:i]); isBinaryName(prefix) {
				return prefix, fmt.Sprintf("the node reports %q", raw)
			}
		}
	}
	return s.profileFork()
}

// profileFork is ForkFamily from the recorded profile alone, with no call
// to the node: what the image or the package is called.
func (s *State) profileFork() (name, evidence string) {
	from := s.Profile.ImageRepo
	label := "image"
	if s.Kind() == "native" {
		from, label = s.Profile.Package, "package"
	}
	if i := strings.LastIndex(from, "/"); i >= 0 {
		from = from[i+1:]
	}
	if i := strings.Index(from, ":"); i > 0 {
		from = from[:i]
	}
	from = strings.ToLower(strings.TrimSpace(from))
	if isBinaryName(from) {
		return from, fmt.Sprintf("this node's %s is %q", label, from)
	}
	return "xrpld", "nothing here names another fork, so this is read as xrpld"
}

// isBinaryName is a word that could be a program's name: lower-case letters
// and digits, nothing else, and short. It keeps a version, a registry host
// or an empty string from being read as a fork.
func isBinaryName(v string) bool {
	if v == "" || len(v) > 24 {
		return false
	}
	letters := 0
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			letters++
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return letters > 0
}

// xrpldFamilyOrRefusal is the gate in front of every read of the xrpld
// package index: this node has to BE an xrpld node before a release from
// that index means anything to it.
func (s *State) xrpldFamilyOrRefusal() error {
	name, evidence := s.ForkFamily()
	if xrpldFamily[name] {
		return nil
	}
	return fmt.Errorf(
		"this node runs %s, not xrpld (%s), and %s publishes xrpld releases. Offering one here would "+
			"name a different program as an upgrade, so this says nothing rather than the wrong thing",
		name, evidence, PackagesIndexSource)
}
