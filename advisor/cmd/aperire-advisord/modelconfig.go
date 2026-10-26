package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/model"
)

// Publishing and watching which language model this Advisor uses.
//
// Two gaps, one file. The status block said only that a model was configured,
// so the tab had to learn the model's name from the reply to a question — a
// fact about this host, discovered by spending a call to the provider. And a
// model change left no trace anywhere: the sealer rewrites model.json and
// restarts the service, and nothing on either side recorded that the thing
// answering an operator's questions had been changed.
//
// The watcher below is watchTrustStore's shape, deliberately and line for
// line, because the three properties that shape has are the ones this needs
// too: the component performing the change does not write the record of it,
// the record is written from an observation so an unsanctioned rewrite is
// caught as well as a sanctioned one, and a change made while the service was
// stopped is still noticed at startup and reported as something noticed
// rather than something seen.

// modelFingerprint reduces a model configuration to one comparable string.
//
// Every field is hex-encoded before joining, for the reason
// host.CredentialStore.Fingerprint sets out at length: base_url and model are
// operator-typed and may contain the delimiter, so a model named "a|b" read
// with credential "c" would otherwise hash identically to model "a" with
// credential "b|c" — the exact drift this exists to catch. Hex output is
// [0-9a-f] only, so no value can carry a delimiter.
//
// A configuration that cannot be read, or that reads and does not validate,
// is "none". No model is a supported state, not an error state, and moving
// into or out of it is a real change worth a record.
func modelFingerprint(cfg model.Config, err error) string {
	if err != nil || cfg.Validate() != nil {
		return "none"
	}
	fields := []string{string(cfg.Shape), cfg.BaseURL, cfg.Model, cfg.CredentialName, cfg.KeyHint}
	enc := make([]string, 0, len(fields))
	for _, f := range fields {
		enc = append(enc, hex.EncodeToString([]byte(f)))
	}
	sum := sha256.Sum256([]byte(strings.Join(enc, "|")))
	return hex.EncodeToString(sum[:])
}

// modelBaseline is what the ledger last recorded about this Advisor's model
// choice and its credential, read together from the SAME entry so the two
// facts can never be taken from two different moments in the record.
//
// credentialPresent is nil when that entry predates the field (#516's own
// migration gap: every entry on disk before this shipped has no opinion on
// this). nil is a real third state, never read as false, because a host
// whose last entry has never heard of this field has not told this service
// its credential is absent; it has told it nothing at all.
type modelBaseline struct {
	fingerprint       string
	credentialPresent *bool
	// lastNoteAt is the watermark a note's own "at" must be strictly newer
	// than to be trusted again (P2-084). It is the "at" of the most recent
	// model entry that actually quoted a note, read back from the ledger
	// wherever that entry is, even if a later entry recorded something else
	// with no note beside it. When no entry anywhere has ever quoted one, it
	// falls back to the newest model entry's own timestamp, so a note older
	// than the last time this service looked at all is still refused on a
	// host that has never quoted a note before.
	lastNoteAt time.Time
}

// lastLedgeredModelBaseline walks the ledger backwards for the most recent
// model entry this service recorded, and reads both facts off it, plus the
// note watermark described above.
//
// The ledger IS the durable baseline, for the reason lastLedgeredFingerprint
// gives for the trust store: a marker in its own mutable file would sit
// outside the tamper-evident record and could be edited to make a swap look
// like no change at all, which is precisely the alarm it would be there to
// raise. That is exactly as true of the credential half as of the
// fingerprint, which is why this reads the pair rather than the fingerprint
// alone (#516 P1-077): a marker anywhere else could be reset by whatever
// reset the fingerprint's own marker would have to survive. The note
// watermark (P2-084) needs the same property for the same reason: a marker
// of "the last note consumed" kept anywhere but the ledger could be reset by
// whatever wiped out the evidence that a note had already been used once.
func lastLedgeredModelBaseline(path string) modelBaseline {
	es, err := ledger.Entries(path)
	if err != nil && len(es) == 0 {
		return modelBaseline{}
	}
	var b modelBaseline
	haveLatest := false
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Kind != ledger.KindModelConfigured {
			continue
		}
		fp, ok := es[i].Data["fingerprint"].(string)
		if !ok || fp == "" {
			continue
		}
		if !haveLatest {
			b.fingerprint = fp
			if v, ok := es[i].Data["credential_present"].(bool); ok {
				b.credentialPresent = &v
			}
			// The fallback watermark: this entry's own recorded time,
			// overwritten below the moment an entry with a real note_at is
			// found, wherever it is.
			b.lastNoteAt = es[i].At
			haveLatest = true
		}
		if raw, ok := es[i].Data["note_at"].(string); ok {
			if t, terr := time.Parse(time.RFC3339, raw); terr == nil {
				b.lastNoteAt = t
				break
			}
		}
	}
	return b
}

// lastLedgeredModelFingerprint is the fingerprint half of the pair above,
// kept as its own name for the callers, tests included, that only ever
// needed that half.
func lastLedgeredModelFingerprint(path string) string {
	return lastLedgeredModelBaseline(path).fingerprint
}

// modelKnown is what this service currently believes about its own model
// choice and its credential, threaded from one check to the next (startup,
// then every tick) so a check that observes no change does not have to
// re-read the ledger to know what it already knows. Mirrors modelBaseline
// exactly, because it is the same pair, held in memory between checks
// instead of read back from disk on every one of them.
type modelKnown struct {
	fingerprint       string
	credentialPresent *bool
}

// modelSummary is what an entry says about a configuration, and it never says
// it with the key: where the questions go, which model answers them, which
// credential is read, and the sealer's hint for which key that is, and
// whether that credential can currently be read at all.
//
// A configuration of "none" carries the fingerprint alone. Empty strings for
// provider and model would read as a provider named nothing rather than as no
// provider at all, and the record is worth more without them.
//
// credentialPresent is taken as a parameter rather than computed here
// (P3-087): CredentialPresent is a file read now, not a stat, and a caller
// that read it once for its own decision and then let this function read it
// again a moment later could see two different answers if the credential
// changed hands in between. A departure entry whose own data then claimed
// `credential_present: true` would hide the arrival that just happened. One
// read per check, passed down, closes that window.
func modelSummary(cfg model.Config, fp string, credentialPresent bool) map[string]any {
	d := map[string]any{"fingerprint": fp}
	if fp == "none" {
		return d
	}
	d["provider"] = cfg.Provider()
	d["model"] = cfg.Model
	if cfg.CredentialName != "" {
		d["credential_name"] = cfg.CredentialName
	}
	if cfg.KeyHint != "" {
		d["key_hint"] = cfg.KeyHint
	}
	// The other half of the pair every entry now carries (#516 P1-077):
	// whether the credential this configuration names can actually be read
	// on this host, at the moment this check was made. Every entry from here
	// on gives the next comparison a real baseline instead of the ledger's
	// old silence on the question.
	d["credential_present"] = credentialPresent
	return d
}

// modelLabel is the human half of a log line: the destination and the model,
// or the plain fact that there is neither.
func modelLabel(cfg model.Config, fp string) string {
	if fp == "none" {
		return "no model"
	}
	return cfg.Provider() + " " + cfg.Model
}

// modelChangeSummary is the sentence an entry leads with, for a move from
// one configuration to another.
//
// One table, read by both paths, so the trail reads the same whether the
// change happened while this service was up or while it was down. The three
// moves are not one sentence with a different subject: "changed" for a model
// that is gone reads as a swap, and "changed" for a node that had none hides
// the single event this record most needs to carry (#447).
//
// `before` is empty when nothing was ever recorded and "none" when what was
// recorded is that there is no model. Both mean the same thing here: what
// this Advisor has now, it did not have before.
func modelChangeSummary(before, after string, atStartup bool) string {
	switch {
	case after == "none":
		if atStartup {
			return "the language model was removed while this service was not running, " +
				"observed at startup"
		}
		return "the language model was removed"
	case before == "" || before == "none":
		return "a language model was configured on this Advisor, which had none"
	default:
		if atStartup {
			return "the language model configuration changed while this service was not running, " +
				"observed at startup"
		}
		return "the language model configuration changed"
	}
}

// modelChangeFileName is what the sealer leaves beside the model config
// when it has just changed it: who asked, and under whose arming.
//
// The sealer does not write the ledger and must not: the record of a model
// change is this service's observation of its own configuration, so that a
// rewrite nobody sanctioned is caught as readily as one that came through the
// sealer (see internal/ledger on KindModelConfigured). What a note carries is
// the half an observer cannot see. A file that changed says nothing about
// who changed it, and "a key landed on this node at 14:20" is worth much less
// than "it was pushed from the aggregator".
const modelChangeFileName = "model-change.json"

// peekModelChangeNote reads that note WITHOUT removing it.
//
// P1-078: the caller decides whether an entry gets written from what is
// here, and only removeModelChangeNote, called after a SUCCESSFUL append
// that used it, takes it off disk. The previous shape read and deleted in
// one step, before the ledger was ever opened, so a failed Open or AppendAs
// (logged and nothing more) lost the note and the entry in the same moment,
// with no way to tell afterward that anything had even been attempted.
//
// A duplicate ENTRY on a crash between a successful append and the removal
// that follows it is the safe direction for a record like this one, and it
// no longer costs a duplicate: acceptNote refuses to consume the same note
// twice regardless of why it is still on disk (P2-084), by checking its own
// "at" against the ledger's own watermark for the last note a model entry
// actually consumed. A re-read of an already-consumed note is a no-op, not
// a second entry, however the removal that should have followed it failed.
//
// Nothing here trusts it further than it deserves. It is a root-owned file
// beside a root-owned config, the fields are copied by name, each is capped
// and has to be printable, and an unreadable note is no note at all. The
// entry says `verified: "os"` either way, which is exactly how strong a
// claim about a file's author this service can make.
func peekModelChangeNote(configPath string) map[string]any {
	path := filepath.Join(filepath.Dir(configPath), modelChangeFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var got map[string]any
	if jerr := json.Unmarshal(raw, &got); jerr != nil {
		log.Printf("[model] the note beside the configuration could not be read: %v", jerr)
		return nil
	}
	out := map[string]any{}
	// "at" is the note's identity (P2-084): read here alongside the
	// attribution fields, capped and validated the same tolerant way, but
	// never quoted onto an entry by name. acceptNote parses it, decides
	// whether the note is trusted at all, and if so carries it onto the
	// entry as its own field, `note_at`, never as a raw "at" that could be
	// mistaken for the entry's own timestamp.
	for _, k := range []string{"via", "by", "issuer", "credential_name", "at"} {
		v, ok := got[k].(string)
		if !ok || v == "" || len(v) > 64 {
			continue
		}
		if strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// removeModelChangeNote takes the note off disk. Called in two cases, and
// two only: once this service has appended an entry that quoted the note,
// and once acceptNote has decided a note is genuine but too old to trust
// (P2-085). That one is removed on sight, whether or not anything else is
// written this check, because waiting longer will not make it useful. A
// note acceptNote refused outright (an already-consumed replay, or one
// naming a different credential than the config now does) is neither of
// these: it stays exactly where it was, for the next check to find, or for
// an operator to find by hand.
func removeModelChangeNote(configPath string) {
	path := filepath.Join(filepath.Dir(configPath), modelChangeFileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("[model] could not remove %s after recording it: %v", path, err)
	}
}

// quoteModelNote adds the note's attribution fields to an entry, and never
// over the top of what was observed. The observation is the stronger claim
// of the two wherever they overlap. Never called with the note's own "at";
// quoteModelNoteWithTime below is the one path that ever reaches an entry,
// and it adds that separately, under its own name.
func quoteModelNote(d, note map[string]any) {
	for k, v := range note {
		if _, taken := d[k]; !taken {
			d[k] = v
		}
	}
}

// quoteModelNoteWithTime is quoteModelNote plus the one field it does not
// carry: when the note itself was written (P2-085), as `note_at`, beside
// the entry's own timestamp. A reader comparing the two sees directly
// whether the attribution is fresh or trails the observation it is
// attached to; never called with a note that failed acceptNote, and never
// with a stale one, which carries no attribution at all.
func quoteModelNoteWithTime(d, note map[string]any, at time.Time) {
	quoteModelNote(d, note)
	d["note_at"] = at.UTC().Format(time.RFC3339)
}

// noteMaxAge bounds how old a note may be and still be trusted as
// attribution (P2-085). A seal that lands a real credential also restarts
// the service, so a note this service is still looking at more than a day
// after it was written was never consumed by the restart that should have
// happened at the time; whatever this service observes now is unrelated to
// it, and quoting it would misattribute the observation to that old
// attempt. 24 hours: long enough that a seal made right before an operator
// stepped away for the night is still trusted the next morning, short
// enough that a note left over from a genuinely different event has long
// since stopped looking like today's.
const noteMaxAge = 24 * time.Hour

// acceptNote decides whether a peeked note is trusted at all this check
// (P2-084, P2-085), and, separately, whether it is fresh enough to quote as
// attribution.
//
// ok is false, and attribution nil, when the note is not evidence of
// anything this check may act on: its own "at" is missing or unreadable;
// it is not strictly newer than watermark, the ledger's own record of the
// last note a model entry actually consumed (P2-084, this is what makes a
// note that could not be deleted a no-op on the next read rather than a
// second, false entry); or the config currently names a credential and the
// note names a different one (P2-085), which is what an unrelated or
// superseded seal attempt looks like, and quoting it would misattribute
// whatever this check observes to a seal that was about a different
// credential entirely. Checked only when the config HAS a name to disagree
// with: a reset's own note names the credential that was just taken away,
// which the post-reset config, having none at all, cannot be expected to
// still agree with, and that is the note this record most needs to keep.
// A refused note is left on disk exactly as P1-078 already requires.
//
// A note that clears both is real, but stale is true when it is older than
// noteMaxAge: it is not quoted, and the caller removes it regardless of
// whether anything else this check writes (P2-085), because a note this
// old is not going to become useful by waiting longer.
func acceptNote(
	note map[string]any, cfg model.Config, watermark, now time.Time,
) (attribution map[string]any, at time.Time, stale, ok bool, reason string) {
	if note == nil {
		return nil, time.Time{}, false, false, ""
	}
	raw, _ := note["at"].(string)
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, time.Time{}, false, false, "carries no readable timestamp"
	}
	if !t.After(watermark) {
		return nil, time.Time{}, false, false, "already consumed"
	}
	if cfg.CredentialName != "" {
		if cn, has := note["credential_name"].(string); has && cn != "" && cn != cfg.CredentialName {
			return nil, time.Time{}, false, false, "names a different credential than the config does now"
		}
	}
	attribution = make(map[string]any, len(note))
	for k, v := range note {
		if k != "at" {
			attribution[k] = v
		}
	}
	return attribution, t, now.Sub(t) > noteMaxAge, true, ""
}

// modelAnomalyThrottle bounds how often a recurring, unresolved model-note
// journal line reaches the log (P3-086). A refused note, or an accepted one
// that still has nothing to justify, stays on disk (P1-078) and is
// re-examined on the model watcher's own cadence, so logging it every time
// is once every 30 seconds forever until an operator notices and clears it
// by hand.
type modelAnomalyThrottle struct {
	lastLoggedAt time.Time
	silentSince  int
}

// modelAnomalyLogInterval is how long a repeat of the same anomaly stays
// quiet after it has been said once. An hour: frequent enough that a
// problem left overnight is still in the journal from a few hours ago
// whenever anyone looks, sparse enough that thirty-second polling does not
// bury the one line that matters under thousands of copies of itself.
const modelAnomalyLogInterval = time.Hour

// logf prints on the first sight of a given anomaly and then at most once
// per modelAnomalyLogInterval, naming how many checks were silent in
// between so the gap this throttle creates is never itself hidden.
func (t *modelAnomalyThrottle) logf(format string, args ...any) {
	now := time.Now()
	if !t.lastLoggedAt.IsZero() && now.Sub(t.lastLoggedAt) < modelAnomalyLogInterval {
		t.silentSince++
		return
	}
	silent := t.silentSince
	t.silentSince = 0
	t.lastLoggedAt = now
	msg := fmt.Sprintf(format, args...)
	if silent > 0 {
		msg = fmt.Sprintf("%s (and %d check(s) silently since the last time this was said)", msg, silent)
	}
	log.Print(msg)
}

// recordModelConfig appends one entry, attributed the way watchTrustStore
// attributes its own. The change was made by something with write access to a
// file this account reads, so naming the account is the strongest honest
// claim available, and verified:"os" on the entry says exactly how strong
// that is.
//
// Reports whether the append actually landed. Every caller uses this to
// decide whether a note it quoted may now be removed (P1-078): a write that
// failed leaves the note in place, so the fact it would have recorded is not
// lost along with the attempt.
func (s *server) recordModelConfig(path, summary string, d map[string]any) bool {
	l, err := ledger.Open(path)
	if err != nil || l == nil {
		log.Printf("[model] could not open the ledger to record the change: %v", err)
		return false
	}
	if _, aerr := l.AppendAs(ledger.KindModelConfigured, "", summary, d,
		ledger.Actor{Operator: osOwner(), Source: ledger.SourceService, Verified: ledger.VerifiedOS}); aerr != nil {
		log.Printf("[model] could not record the change: %v", aerr)
		return false
	}
	return true
}

// recordModelConfigAndNote appends the entry and, only once that succeeds,
// removes the note it quoted (P1-078). A nil note is fine and common: not
// every entry this file writes has one to quote or to remove.
func (s *server) recordModelConfigAndNote(configPath, ledgerPath, summary string, d, note map[string]any) bool {
	ok := s.recordModelConfig(ledgerPath, summary, d)
	if ok && note != nil {
		removeModelChangeNote(configPath)
	}
	return ok
}

// credentialArrivalSummary, credentialDepartureSummary and
// credentialResealSummary are the three sentences a credential-only entry
// can lead with (#516 P1-077/P2-081/P3-082). None of them say "the
// configuration changed": the fingerprint has not moved in any of these,
// which is exactly why they need their own words rather than
// modelChangeSummary's.
func credentialArrivalSummary(atStartup bool) string {
	if atStartup {
		return "a credential for the configured language model arrived on this host, observed at startup"
	}
	return "a credential for the configured language model arrived on this host"
}

func credentialDepartureSummary(atStartup bool) string {
	if atStartup {
		return "the configured language model's credential is no longer present on this host, observed at startup"
	}
	return "the configured language model's credential is no longer present on this host"
}

func credentialResealSummary(atStartup bool) string {
	if atStartup {
		return "the configured language model's credential was resealed on this host, observed at startup"
	}
	return "the configured language model's credential was resealed on this host"
}

// recordCredentialTransition is the credential half of the comparison this
// service makes when its declared configuration has NOT moved: the choice
// of model is the same as last recorded, but whether this Advisor can reach
// it may not be (#516). baselineCred is read together with the fingerprint
// by lastLedgeredModelBaseline, so the two never come from two different
// moments in the record; it is nil when the last entry predates this field.
//
// The transitions a known baseline decides on its own, note or no note:
//
//	false -> true   a credential arrived. The restore drill's own defect: a
//	                fleet push or a local reseal put a working key where
//	                there was none, the declared choice unchanged
//	                throughout.
//	true  -> false  the credential is gone (P2-081). Never through the
//	                reset verb, which changes the fingerprint and is
//	                handled by the caller's other branches; this is a
//	                credential file or a drop-in removed some other way,
//	                with the config still naming one.
//	true  -> true, with a note   a deliberate reseal of a credential that
//	                was already there (P3-082), worth its own word,
//	                "resealed", never "arrived": arriving is what a
//	                credential does exactly once.
//
// baselineCred == nil is not a transition, because an old ledger has no
// opinion on this yet, and treating an observed `true` as "arrived" would
// fire once on every host in the fleet the day this ships. A note tips it:
// the note is evidence a real event just happened even when the ledger
// cannot speak to what came before it, so nil, current true, note present
// is still recorded as an arrival. Without a note, nothing is recorded and
// nothing is claimed either way; the entry the NEXT real transition writes
// carries credential_present on its own, so the baseline heals itself the
// first time anything actually happens.
//
// note is always the OUTPUT of acceptNote, never a raw peek: nil unless it
// is fresh, unreplayed, and named for the credential the config currently
// has (P2-084, P2-085). The one case that records nothing and is not
// silent about it: current false with a trusted note present and a
// baseline that is not true (nil or false). The sealer says it sealed and
// the credential is still not readable, which is a real anomaly this
// cannot resolve into a claim either way, so it is logged, throttled
// (P3-086), for as long as the note is never deleted for a check it was
// not used on (P1-078).
func (s *server) recordCredentialTransition(
	lPath string, cfg model.Config, fp string, cur bool, baselineCred *bool,
	note map[string]any, noteAt time.Time, atStartup bool,
) bool {
	var summary string
	switch {
	case baselineCred != nil && !*baselineCred && cur:
		summary = credentialArrivalSummary(atStartup)
	case baselineCred == nil && cur && note != nil:
		summary = credentialArrivalSummary(atStartup)
	case baselineCred != nil && *baselineCred && !cur:
		summary = credentialDepartureSummary(atStartup)
	case baselineCred != nil && *baselineCred && cur && note != nil:
		summary = credentialResealSummary(atStartup)
	default:
		if note != nil {
			s.modelNoteUnjustified.logf("[model] a note was left beside the configuration, and the credential it "+
				"names reads no differently from what this service already knows (%s); nothing to record", abbrevID(fp))
		}
		return false
	}
	d := modelSummary(cfg, fp, cur)
	if atStartup {
		d["observed"] = "at startup"
	} else {
		d["observed"] = "while running"
	}
	if note != nil {
		quoteModelNoteWithTime(d, note, noteAt)
	}
	wrote := s.recordModelConfigAndNote(s.modelPath, lPath, summary, d, note)
	if wrote {
		log.Printf("[model] %s (%s)", summary, abbrevID(fp))
	}
	return wrote
}

// resolveNote runs a note this service has already peeked through
// acceptNote, folding in the two side effects a rejected or stale note
// carries (P2-084, P2-085, P3-086): a note this service declines to trust
// as a replay or a credential mismatch is logged, throttled, and left in
// place; a note that is real but too old is removed on sight and logged
// once, plainly, since removing it is itself the resolution and there is
// nothing left to repeat. The note this returns is nil unless it is fresh
// and trustworthy, ready to hand straight to modelSummary's callers and to
// recordCredentialTransition without either needing to know why.
//
// Takes the already-peeked note rather than peeking itself, and the
// watermark rather than computing it, so the caller decides when a ledger
// re-read is worth paying for: recordModelAtStartup already has both on
// hand for its own comparison; recordModelTick only reads the ledger again
// at all when a note is actually there to judge.
func (s *server) resolveNote(raw map[string]any, cfg model.Config, watermark time.Time, fp string) (note map[string]any, at time.Time) {
	if raw == nil {
		return nil, time.Time{}
	}
	note, at, stale, ok, reason := acceptNote(raw, cfg, watermark, time.Now())
	switch {
	case ok && stale:
		removeModelChangeNote(s.modelPath)
		log.Printf("[model] a note beside the configuration was older than %s and has been removed, unused (%s)",
			noteMaxAge, abbrevID(fp))
		return nil, time.Time{}
	case !ok:
		s.modelNoteRejected.logf("[model] a note beside the configuration was not trusted (%s); left in place (%s)",
			reason, abbrevID(fp))
		return nil, time.Time{}
	}
	return note, at
}

// recordModelAtStartup is the comparison this service makes against its own
// record the moment it comes up: what the configuration says now, against
// what it last wrote down.
//
// Split out of watchModelConfig so it can be exercised on its own. The loop
// below it runs forever by design and a test cannot call it.
func (s *server) recordModelAtStartup(lPath string) modelKnown {
	cfg, err := model.LoadConfig(s.modelPath)
	if err != nil {
		log.Printf("[model] cannot read the model configuration: %v", err)
	}
	known := modelFingerprint(cfg, err)
	cur := cfg.CredentialPresent()
	baseline := lastLedgeredModelBaseline(lPath)
	// Peeked once, here; resolveNote decides whether it is trusted at all
	// and folds in whatever that decision costs (removed if stale, logged
	// and left alone if refused). What comes back is nil unless it is fresh
	// and trustworthy, and only then is it ever removed on a successful
	// write, never on a check that declined it (P1-078).
	note, noteAt := s.resolveNote(peekModelChangeNote(s.modelPath), cfg, baseline.lastNoteAt, known)

	switch {
	case known != "none" && (baseline.fingerprint == "none" || (baseline.fingerprint == "" && note != nil)):
		// A key landing on a node that had none, which is the single event
		// this record most needs to carry and the one it used to skip
		// (#447). Two ways to be sure of it, and both are evidence rather
		// than inference: the last thing recorded WAS "none", or there is
		// nothing recorded at all and a trustworthy note says it has just
		// put one there.
		//
		// A ledger with nothing in it and NO note is the third case, below:
		// a host that has been running with a model since before this
		// service recorded anything. Calling that "configured on an Advisor
		// which had none" would be a claim nobody observed.
		d := modelSummary(cfg, known, cur)
		d["from"] = "none"
		d["observed"] = "at startup"
		if note != nil {
			quoteModelNoteWithTime(d, note, noteAt)
		}
		summary := modelChangeSummary("none", known, true)
		if s.recordModelConfigAndNote(s.modelPath, lPath, summary, d, note) {
			log.Printf("[model] configured from none: %s (%s)", modelLabel(cfg, known), abbrevID(known))
		}
	case baseline.fingerprint != "" && baseline.fingerprint != known:
		// The startup case, and the honest wording for it. This service was
		// not running when the change happened, so it cannot say when it
		// happened, only that the configuration no longer matches what it
		// last recorded. A model that is GONE gets its own sentence out of
		// the table above: a reset takes the key, the credential directive
		// and the configuration together, and "changed" reads as a swap.
		summary := modelChangeSummary(baseline.fingerprint, known, true)
		d := modelSummary(cfg, known, cur)
		d["fingerprint_before"] = baseline.fingerprint
		d["observed"] = "at startup"
		if note != nil {
			quoteModelNoteWithTime(d, note, noteAt)
		}
		if s.recordModelConfigAndNote(s.modelPath, lPath, summary, d, note) {
			log.Printf("[model] changed while stopped: %s (%s → %s)",
				modelLabel(cfg, known), abbrevID(baseline.fingerprint), abbrevID(known))
		}
	case baseline.fingerprint == "" && known != "none":
		// Nothing recorded yet, and a model is already configured. Record the
		// baseline so the FIRST later change has something to be a change
		// FROM, and label it as a baseline rather than as a change.
		d := modelSummary(cfg, known, cur)
		d["observed"] = "first observation"
		if s.recordModelConfig(lPath, "first record of which language model this Advisor uses", d) {
			log.Printf("[model] first record: %s (%s)", modelLabel(cfg, known), abbrevID(known))
		}
	default:
		// The fingerprint has not moved. Whatever there is to say about the
		// credential behind it, arrived, gone or resealed, is the other
		// comparison's job.
		if known != "none" {
			s.recordCredentialTransition(lPath, cfg, known, cur, baseline.credentialPresent, note, noteAt, true)
		} else if note != nil {
			log.Printf("[model] a note was left beside the configuration, "+
				"which is unchanged (%s); nothing to record", abbrevID(known))
		}
	}
	if known == "none" {
		return modelKnown{fingerprint: known}
	}
	return modelKnown{fingerprint: known, credentialPresent: &cur}
}

// recordModelTick is one iteration of watchModelConfig's comparison, split
// out for the same reason recordModelAtStartup is: the loop it serves runs
// forever by design and a test cannot call it directly.
func (s *server) recordModelTick(lPath string, known modelKnown) modelKnown {
	next, nerr := model.LoadConfig(s.modelPath)
	if nerr != nil {
		// A partial write mid-seal; the next tick sees the finished file.
		//
		// The cost of this line, stated plainly: a model.json that stays
		// unreadable is recorded at the next start rather than now.
		// Recording it here instead would append "the language model was
		// removed" to a tamper-evident record every time the sealer
		// rewrote the file, which is a false alarm in the one place a
		// false alarm is expensive. A MISSING file is not this case:
		// LoadConfig reports that as no model and no error, so a deleted
		// configuration is still caught on the very next tick.
		return known
	}
	fp := modelFingerprint(next, nil)
	cur := next.CredentialPresent()
	// Peeked once per tick, and the ledger is asked for the note watermark
	// only when there is a note to judge: `known` never carries it (its
	// whole point is surviving a restart this in-memory state does not),
	// and a note only ever exists right after a seal, so on the overwhelming
	// majority of ticks this costs nothing more than the file read
	// peekModelChangeNote was already doing.
	var note map[string]any
	var noteAt time.Time
	if raw := peekModelChangeNote(s.modelPath); raw != nil {
		watermark := lastLedgeredModelBaseline(lPath).lastNoteAt
		note, noteAt = s.resolveNote(raw, next, watermark, fp)
	}
	if fp == known.fingerprint {
		if fp == "none" {
			if note != nil {
				log.Printf("[model] a note was left beside the configuration, "+
					"which is unchanged (%s); nothing to record", abbrevID(fp))
			}
			return known
		}
		s.recordCredentialTransition(lPath, next, fp, cur, known.credentialPresent, note, noteAt, false)
		return modelKnown{fingerprint: fp, credentialPresent: &cur}
	}
	summary := modelChangeSummary(known.fingerprint, fp, false)
	d := modelSummary(next, fp, cur)
	if known.fingerprint == "none" {
		// The same event as the startup branch above, and by the table
		// above the same sentence for it, so the trail reads the same
		// whether the key landed while this service was up or down.
		d["from"] = "none"
	}
	d["fingerprint_before"] = known.fingerprint
	d["observed"] = "while running"
	if note != nil {
		quoteModelNoteWithTime(d, note, noteAt)
	}
	if s.recordModelConfigAndNote(s.modelPath, lPath, summary, d, note) {
		log.Printf("[model] changed: %s (%s → %s)",
			modelLabel(next, fp), abbrevID(known.fingerprint), abbrevID(fp))
	}
	if fp == "none" {
		return modelKnown{fingerprint: fp}
	}
	return modelKnown{fingerprint: fp, credentialPresent: &cur}
}

// watchModelConfig records which model this Advisor uses at startup, and
// every observed change afterwards. Runs for the life of the process.
func (s *server) watchModelConfig() {
	lPath := s.ledgerPath()
	known := s.recordModelAtStartup(lPath)

	// The trust store's cadence, and one small file read like it. Fast enough
	// that a change is on the record long before an operator can act on an
	// answer from the new model, cheap enough to be invisible; there is no
	// reason for a second number.
	for range time.Tick(trustCheckInterval) {
		known = s.recordModelTick(lPath, known)
	}
}

// modelStatus is the /v1/status "model" block: whether this Advisor can ask a
// language model anything, and which one it would ask.
//
// The tab used to find out whether a model was configured by POSTing an empty
// question to /v1/ask, which answers 200 with configured:false when there is
// no model, and 400 "the question is empty" when there is one. So a correctly
// configured host logged a failed request in the browser console on every
// single load, which is exactly the shape of a real bug and cost the operator
// a diagnosis. Status is fetched anyway; this costs nothing.
//
// `configured` is present either way, including false — the tab keys its
// no-model form on it being false, and a field only present when true cannot
// be told apart from a field the caller failed to read. `config_path` is
// unconditional for the same reason: an operator whose model will not load
// needs the path of the file to fix.
//
// `configured: true` is a conjunction, not a read of one file. A config that
// validates says which model this Advisor is SET to; whether it can actually
// ask that model a question also needs the credential the config names, and
// those are two different facts a restore can pull apart. #516: a host
// rebuilt from a backup gets `advisor/state/model.json` back (an ordinary
// file, copied like any other) but never gets `/etc/aperire/creds` back (a
// credential sealed to the host that made it, and it is not this Advisor's
// business to move one across hosts). Before this, that host answered
// `configured: true` from the restored file alone, and a rebuilt aggregator's
// catch-up verdict read every such node as already on the fleet's setting,
// which is exactly the node a catch-up push exists for.
//
// So the identity fields below (`name` through `configured_at`) are
// published whenever the CONFIG validates, whether or not the credential is
// there, and `configured` is true only when both are. A reader that sees
// `configured: false` alongside a `name` is looking at a model this Advisor
// is set to but cannot currently reach; `credential_present` says which of
// the two facts is missing, and a reader that predates this field cannot
// tell the difference and degrades to the old, conservative reading (no
// model at all), which under-claims what the host holds and never
// over-claims it. `key_hint` is published verbatim from what the sealer
// wrote and is nowhere derived here, see model.Config.KeyHint. Omitted when
// the sealer wrote none, because a host sealed before that field existed
// has no hint, and an invented one would be worse than none.
func (s *server) modelStatus() map[string]any {
	m := map[string]any{"configured": false, "config_path": s.modelPath}

	cfg, err := model.LoadConfig(s.modelPath)
	if err != nil {
		m["error"] = err.Error()
		return m
	}
	if verr := cfg.Validate(); verr != nil {
		m["error"] = verr.Error()
		return m
	}

	m["name"] = cfg.Model
	m["shape"] = string(cfg.Shape)
	m["base_url"] = cfg.BaseURL
	m["provider"] = cfg.Provider()
	// Empty on a host that reads its key from a key_file rather than a
	// systemd credential, which Validate allows. Published as it stands
	// rather than omitted: the field is part of the block whenever a model
	// is configured, and the reader decides what an empty one means.
	m["credential_name"] = cfg.CredentialName
	if cfg.KeyHint != "" {
		m["key_hint"] = cfg.KeyHint
	}
	// When the choice was last written, from the file's own mtime. Omitted
	// when the stat fails, because a timestamp this service could not read is
	// not a timestamp it may guess at.
	if fi, serr := os.Stat(s.modelPath); serr == nil {
		m["configured_at"] = fi.ModTime().UTC().Format(time.RFC3339)
	}

	if !cfg.CredentialPresent() {
		m["credential_present"] = false
		m["error"] = credentialMissingError(cfg)
		return m
	}
	m["credential_present"] = true
	m["configured"] = true
	return m
}

// credentialMissingError is the sentence for a config that names a
// credential this host does not currently hold, a restore's own shape, and
// the one #516 was filed from. Names whichever of the two ways the config can
// point at a key, because an operator reading this on the config the tab
// still shows needs to know which file to look for.
func credentialMissingError(cfg model.Config) string {
	if cfg.CredentialName != "" {
		return "the model is configured, but its credential (" + cfg.CredentialName +
			") is not present on this host"
	}
	return "the model is configured, but its key_file is not present on this host"
}
