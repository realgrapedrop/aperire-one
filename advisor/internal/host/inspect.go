package host

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Inspection is the read-only half of the privilege wrapper, reached the same
// way every other verb is.
//
// It exists because the Advisor could describe a validator in general but
// could not answer "what does MY config say" or "why is MY box touching swap"
// — it had to ask the operator to paste something, which is the moment most
// people stop. Nothing here changes anything; every verb is a read, runs
// through the root-owned wrapper, and is logged there with its arguments.
//
// What it deliberately cannot do: see the validator's key material. The node
// config arrives already redacted, stripped inside the wrapper before a byte
// reaches this process. That is §7 enforced by the filesystem and a separate
// account rather than by this code remembering not to look.

// Probe is one read-only verb and the question it answers.
type Probe struct {
	Verb  string
	Arg   string
	Title string
	// When returns true if the operator's question is plausibly about this.
	When *regexp.Regexp
}

// Probes are matched against the question and attached when they hit. Ordered
// roughly by how often they answer something, since the budget below cuts from
// the end.
var Probes = []Probe{
	{Verb: "show-config", Title: "NODE CONFIGURATION (key material removed by the privilege wrapper)",
		When: regexp.MustCompile(`(?i)\b(config(uration)?s?|rippled\.cfg|xrpld\.cfg|cfg|settings?|configured|node_size|ledger_history|online_delete|peers_max|ports?|ssl)\b`)},
	// node_size and sizing questions belong here too: "is node_size right for
	// this box" cannot be answered from the config alone, and without this the
	// Advisor correctly but uselessly replies that it has no hardware figures.
	{Verb: "resources", Title: "MEMORY, SWAP, LOAD AND UPTIME",
		When: regexp.MustCompile(`(?i)\b(memory|ram|swap(ping|ped)?|load|uptime|resources?|free|node_size|sizing|siz(e|ed)|hardware|cpu|cores?|box|spec)\b`)},
	{Verb: "sysctl-relevant", Title: "KERNEL SETTINGS THAT AFFECT A VALIDATOR",
		When: regexp.MustCompile(`(?i)\b(sysctl|kernel|swappiness|somaxconn|rmem|wmem|backlog|file-max|tcp|buffer|tune|tuning)\b`)},
	{Verb: "disk", Title: "DISK ON THE NODE'S DATA PATH",
		When: regexp.MustCompile(`(?i)\b(disks?|space|storage|full|df|nudb|database size|online_delete)\b`)},
	{Verb: "limits", Title: "THE NODE PROCESS'S ACTUAL RESOURCE LIMITS",
		When: regexp.MustCompile(`(?i)\b(limits?|ulimits?|file descriptors?|open files|nofile|too many)\b`)},
	{Verb: "show-validators", Title: "CONFIGURED VALIDATOR LIST SITES",
		When: regexp.MustCompile(`(?i)\b(unls?|validator lists?|validators\.txt|list sites?|vl\.|quorum)\b`)},
	{Verb: "show-toml", Title: "THE DOMAIN VERIFICATION FILE THIS NODE PUBLISHES",
		When: regexp.MustCompile(`(?i)\b(toml|domain|well-known|verif)\w*\b`)},
	{Verb: "unit-status", Title: "SYSTEMD STATE OF THE APERIRE UNITS",
		When: regexp.MustCompile(`(?i)\b(systemd|units?|services?|restart(ed|ing)?|running|relay|advisord|dashboard)\b`)},
	{Verb: "node-log", Arg: "80", Title: "THE LAST 80 LINES THE NODE EMITTED",
		When: regexp.MustCompile(`(?i)\b(logs?|errors?|warnings?|wrn|exceptions?|crash(ed|ing)?|stack|why did)\b`)},
	{Verb: "journal", Arg: "60", Title: "THE LAST 60 JOURNAL LINES FOR THE APERIRE UNITS",
		When: regexp.MustCompile(`(?i)\b(journal|journalctl|advisor log|dashboard log|relay log)\b`)},
}

// aboutThisHost separates "what is a UNL" from "what UNLs am I using".
//
// Subject alone is not enough. A question can be entirely about validator
// configuration and want nothing from this machine, and running a privileged
// command to answer it is both wasted work and reference material that buries
// the actual question. A probe fires only when the operator is asking about
// their own host — which is exactly when they would otherwise have to go and
// paste something.
var aboutThisHost = regexp.MustCompile(`(?i)(\bmy\b|\bmine\b|\bour\b|\bi\b|\bme\b|\bthis (node|host|box|server|validator|machine)\b|\bam i\b|\bdo i\b|\bshould i\b|\bhere\b|\bcurrent(ly)?\b|\bwe\b)`)

// Inspect runs the probes whose subject the question mentions and returns them
// as prompt material. Output per probe is capped, because a log tail can be
// larger than everything else in the prompt combined.
//
// budget is the question's shared privileged-read counter — see Budget and
// MaxPrivilegedHostReads in readverb.go. Callers that also let the model
// request further host_read items later in the same question must pass the
// same *Budget in, so a run of Inspect's seed probes and a subsequent menu
// read draw from one three-read ceiling rather than each getting their own.
//
// allow decides which verbs this asker may have read on their behalf. Nil
// means every verb, which is what a caller with no role to apply passes.
//
// It exists because these probes are matched from the question's own words
// and spliced into the prompt as "treat as Measured", BEFORE the model is
// ever asked anything — so a role rule enforced only on the model's own
// host_read requests would be a rule the seed reads walk straight past. A
// monitor asking what their config says would have had the config read to
// them by the service itself. The predicate is
// interrogate.RoleAllowsVerb(role); this package does not import that one, so
// it takes the answer rather than the rule.
func Inspect(ctx context.Context, r Runner, wrapper string, question string, budget *Budget, allow func(verb string) bool) string {
	var b strings.Builder
	// One check for the whole question rather than per probe: if nothing here
	// refers to this host, nothing below should run a command on it.
	if !aboutThisHost.MatchString(question) {
		return ""
	}
	for _, p := range Probes {
		if budget.Remaining() <= 0 {
			break
		}
		if !p.When.MatchString(question) {
			continue
		}
		// Skipped silently, and this is the one place in this file where
		// silence is right: the refusal belongs to the asker's question, not
		// to a probe they never asked for by name, and the loop's own
		// host_read refusal is what states it in the step trace where they
		// can read it.
		if allow != nil && !allow(p.Verb) {
			continue
		}
		out, err := ReadVerb(ctx, r, wrapper, budget, p.Verb, p.Arg)
		if err != nil {
			// Said plainly rather than dropped. "I could not check" is a real
			// answer; silence reads as "there was nothing to find".
			fmt.Fprintf(&b, "\n\n%s\nCould not read this: %v\n", p.Title, err)
			continue
		}
		fmt.Fprintf(&b, "\n\n%s (read from this host just now — treat as Measured)\n%s\n",
			p.Title, Clamp(out, 6000))
	}
	if b.Len() > 0 {
		b.WriteString("\nThe readings above are from this operator's own host. " +
			"Use them rather than describing what a validator usually looks like.\n")
	}
	return b.String()
}

// Clamp keeps one probe from crowding out the question — a log tail can be
// larger than everything else in the prompt combined. Exported so the
// interrogative loop's step renderer can recognise a truncation by this
// function's own trailing line rather than building a second truncator that
// could disagree with this one about what "truncated" means (§7.2: one
// redactor, one truth — the same discipline applies to clamps).
func Clamp(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n… truncated; ask for a narrower range if you need more."
}
