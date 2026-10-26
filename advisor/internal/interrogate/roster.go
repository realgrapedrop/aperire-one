package interrogate

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The fleet roster a question is resolved against, and the three answers it
// can produce, #59.
//
// The defect this closes: asked on one node about another node in the same
// fleet, the Advisor said it had no registered peer by that name. It was
// telling the truth about its own peer table and the wrong thing about the
// fleet. advisord's peer table (internal/fleet, advisor/state/fleet.json) is
// generated from the dashboard's fleet.yaml, and a row whose read token this
// host holds no copy of is deliberately LEFT OUT of it rather than guessed
// at (dashboard/lib/advisor-registry-gen.ts). So two different facts,
// "nobody registered that name" and "that host is in the fleet and I hold no
// way to read it", arrived here as one, and both rendered as the first.
//
// The roster is the dashboard's answer to "who is in this fleet", read
// through the ADR 0008 contract's `fleet` route. It is layered over the peer
// table rather than replacing it: the peer table still decides what can
// actually be READ, and the roster decides what can be NAMED. Every peer
// read still goes through the client built at boot from an origin and a
// token path; nothing here opens a channel.
//
// This file is stdlib-only, like the rest of this package: the roster is
// data a caller supplies, exactly as the read parameters are.

// RosterNode is one member of the fleet, as the dashboard on this host knows
// it, plus the one fact only advisord knows: whether this process holds a
// read client for it.
type RosterNode struct {
	// Label is the node's exact label. The ONLY string that ever reaches a
	// dispatch, an operator's informal spelling resolves to one of these
	// and is then discarded, on the same reasoning internal/fleet's labelRe
	// gives for bounding a label at the parser: what travels onward into
	// service-authored text is the service's own value, never the asker's.
	Label string
	// Role is "aggregator", "node", "validator", "relay", or "" for a row
	// that does not say. Never inferred.
	Role string
	// Self marks the one row that is this host.
	Self bool
	// Readable reports whether this advisord holds a read client for this
	// node. False on every node whose token path this host has no copy of,
	// which is every peer on an ordinary node and none on the aggregator.
	Readable bool
	// LastAnsweredMs is when the dashboard on this host last polled this
	// node and got an answer. Zero means it never has since that dashboard
	// started, a different fact from "a long time ago", and said
	// differently.
	LastAnsweredMs int64
	// Detail is the dashboard's own short reason for a row that is not ok,
	// carried verbatim so the Advisor and the FLEET card say the same words
	// about the same node.
	Detail string
}

// Roster is the fleet as the host this question was asked on knows it.
//
// The zero value is a host that was never told anything, and resolves every
// name to Unregistered with nothing to list, which is exactly the behaviour
// a build with no roster had before this existed.
type Roster struct {
	// Registered is false on a host with no fleet registry at all. Nodes
	// then holds one row, this host. It is not an empty fleet: a host with
	// no registry has no standing to make a claim about a fleet, and the
	// refusal says so.
	Registered bool
	// NowMs is the dashboard's clock when it built this roster. Every age
	// stated below is computed against it and never against this process's
	// own clock: two hosts' clocks can disagree, one body's cannot disagree
	// with itself.
	NowMs int64
	Nodes []RosterNode
}

// ResolutionKind is which of the answers a named node produced. Three of
// them are refusals the operator reads; two are a read that goes ahead.
type ResolutionKind int

const (
	// ResolvedPeer: the name is a registered node, it is not this host, and
	// this process can read it. The read goes to that peer.
	ResolvedPeer ResolutionKind = iota
	// ResolvedSelf: the name is this host. The read goes to this node's own
	// data, which is what the operator asked for even though they named it.
	ResolvedSelf
	// Unregistered: no node by that name is registered here. The refusal
	// lists the ones that are.
	Unregistered
	// Ambiguous: the name fits more than one registered node. Nothing is
	// read and both are named, because picking one is a guess and a guess
	// about which host a question concerns is the worst kind.
	Ambiguous
	// Unreachable: the node IS registered here and cannot be read from
	// here. The refusal says when it last answered.
	Unreachable
)

// Resolution is what Resolve decided. Label is set on the two kinds that go
// ahead and on Unreachable (which knows exactly which node it means);
// Refusal is the operator-facing sentence on the three that do not.
type Resolution struct {
	Kind ResolutionKind
	// Label is the roster's own exact label, never the asker's spelling.
	Label string
	// Close is true when the name was matched by a close form rather than
	// exactly, so a caller can say which node it took them to mean.
	Close bool
	// Refusal is the sentence for Unregistered, Ambiguous and Unreachable.
	Refusal string
}

// Known reports whether anything is in this roster at all.
func (r Roster) Known() bool { return len(r.Nodes) > 0 }

// Labels lists every registered label in roster order.
func (r Roster) Labels() []string {
	out := make([]string, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		out = append(out, n.Label)
	}
	return out
}

// Peers lists every registered node that is not this host.
func (r Roster) Peers() []RosterNode {
	out := make([]RosterNode, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		if !n.Self {
			out = append(out, n)
		}
	}
	return out
}

// SelfLabel is this host's own label, or "" if the roster has no self row.
func (r Roster) SelfLabel() string {
	for _, n := range r.Nodes {
		if n.Self {
			return n.Label
		}
	}
	return ""
}

// normaliseName folds the spellings an operator actually types into one
// form: case, surrounding space, and the two separators that get swapped for
// a hyphen in speech and in typing. Nothing else, this is a lookup key, not
// a fuzzy matcher, and every rule here has to be one a person could predict.
func normaliseName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

// segmentsOf splits a label on hyphens.
func segmentsOf(label string) []string { return strings.Split(label, "-") }

// Resolve turns a name the operator (or the model, quoting them) used into
// one registered node, or into one of the three refusals.
//
// Matching is deliberately small and explainable. Exact first. Then two
// close forms, and only two:
//
//   - a whole hyphen-delimited segment of the label ("node2" for
//     "stock-node2", "validator1" for "validator1"),
//   - the label with its hyphens removed ("stocknode2", "stock-node-2").
//
// There is no edit distance and no prefix matching. A name that fits more
// than one node is refused with both named rather than resolved to the
// first, because the failure mode of guessing here is an answer about the
// wrong validator, which reads exactly like an answer about the right one.
func (r Roster) Resolve(name string) Resolution {
	want := normaliseName(name)
	if want == "" {
		return Resolution{Kind: Unregistered, Refusal: r.unregisteredRefusal(name)}
	}

	for _, n := range r.Nodes {
		if n.Label == want {
			return r.decide(n, false)
		}
	}

	var hits []RosterNode
	wantTight := strings.ReplaceAll(want, "-", "")
	for _, n := range r.Nodes {
		matched := false
		for _, seg := range segmentsOf(n.Label) {
			if seg == want {
				matched = true
				break
			}
		}
		if !matched && wantTight != "" && strings.ReplaceAll(n.Label, "-", "") == wantTight {
			matched = true
		}
		if matched {
			hits = append(hits, n)
		}
	}

	switch len(hits) {
	case 0:
		return Resolution{Kind: Unregistered, Refusal: r.unregisteredRefusal(name)}
	case 1:
		return r.decide(hits[0], true)
	default:
		labels := make([]string, 0, len(hits))
		for _, n := range hits {
			labels = append(labels, n.Label)
		}
		sort.Strings(labels)
		return Resolution{
			Kind: Ambiguous,
			Refusal: fmt.Sprintf("%q fits more than one registered node, %s. Name one.",
				name, joinWithOr(labels)),
		}
	}
}

// decide is the second half of Resolve: the name landed on a node, and this
// says which of the three things that means.
func (r Roster) decide(n RosterNode, close bool) Resolution {
	switch {
	case n.Self:
		return Resolution{Kind: ResolvedSelf, Label: n.Label, Close: close}
	case !n.Readable:
		return Resolution{Kind: Unreachable, Label: n.Label, Close: close,
			Refusal: r.unreachableRefusal(n)}
	default:
		return Resolution{Kind: ResolvedPeer, Label: n.Label, Close: close}
	}
}

// unregisteredRefusal is the first honest answer: nobody by that name is
// registered HERE. It always lists what is, because "no" without a roster
// leaves the operator guessing whether they mistyped or asked the wrong box.
//
// A host with no registry gets a different sentence. It has one node in its
// roster, itself, and saying "the fleet registered here is: stock-node1"
// would dress a single-node install up as a fleet of one.
func (r Roster) unregisteredRefusal(name string) string {
	if !r.Registered {
		self := r.SelfLabel()
		if self == "" {
			return fmt.Sprintf("no node named %q is registered on this host, and this host has no fleet "+
				"registry at all, it knows only itself. A question about another node is answered from "+
				"the dashboard that holds the fleet.", name)
		}
		return fmt.Sprintf("no node named %q is registered on this host. This host has no fleet registry "+
			"and knows only itself, %s. A question about another node is answered from the dashboard "+
			"that holds the fleet.", name, self)
	}
	if !r.Known() {
		return fmt.Sprintf("no node named %q is registered on this host.", name)
	}
	return fmt.Sprintf("no node named %q is registered on this host. Registered here: %s.",
		name, strings.Join(r.describeAll(), ", "))
}

// unreachableRefusal is the second honest answer: that node IS registered
// here and cannot be read from here, with the last time it was.
//
// The age is the dashboard's last SUCCESSFUL poll of that node, dated
// against the roster's own clock. It is not the age of this refusal and not
// the age of the last attempt: a failed poll never advances it, which is
// what makes "last answered 6m ago" mean six minutes of silence rather than
// six minutes since somebody tried.
func (r Roster) unreachableRefusal(n RosterNode) string {
	var when string
	switch {
	case n.LastAnsweredMs <= 0:
		when = "it has not answered this host's dashboard since that dashboard started"
	case r.NowMs > 0 && r.NowMs >= n.LastAnsweredMs:
		when = "it last answered this host's dashboard " + humanAge(r.NowMs-n.LastAnsweredMs) + " ago"
	default:
		when = "this host's dashboard has an answer from it on record"
	}
	detail := strings.TrimSpace(n.Detail)
	if detail == "" {
		detail = "this host holds no read credential for it"
	}
	return fmt.Sprintf("%s is registered on this host but cannot be read from here right now (%s); %s.",
		n.Label, detail, when)
}

// describeAll renders the roster for a refusal: every label, this host
// marked as this host, and a node that cannot be read marked as such, so a
// second question does not walk into the same wall.
func (r Roster) describeAll() []string {
	out := make([]string, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		switch {
		case n.Self:
			out = append(out, n.Label+" (this host)")
		case !n.Readable:
			out = append(out, n.Label+" (registered, not readable from here)")
		default:
			out = append(out, n.Label)
		}
	}
	return out
}

// HumanAge renders a duration the way an operator reads one. Coarse on
// purpose: the question this answers is "is that recent", and a figure to
// the millisecond invites precision the reading does not have.
//
// Exported so the menu's own fleet description dates a node the same way a
// refusal does. Two vocabularies for one clock is how "last answered" comes
// to mean two things on one page.
func HumanAge(ms int64) string { return humanAge(ms) }

func humanAge(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// joinWithOr renders a candidate list as prose: "a or b", "a, b or c".
func joinWithOr(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
	}
}
