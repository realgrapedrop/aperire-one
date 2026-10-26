// Package compact is the standing agreement between the operator and the
// Advisor — ADR 0007.
//
// Two layers, and the compact never approves anything. It sets a ceiling: the
// classes of operation the Advisor may ever propose to perform, and the
// privilege option under which it performs them. Every individual action still
// needs its own approval. An operator who has accepted the compact has not
// consented to an upgrade; they have consented to being ASKED about upgrades.
//
// The terms are versioned by the hash of their own text. The ledger records
// that hash, so "what did I actually agree to" is answerable months later even
// if the wording has since changed.
package compact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/runbook"
)

// PrivilegeOption is how the executor reaches the node — ADR 0007 §2.
type PrivilegeOption string

const (
	// OptionAdvise is the tier below all of them: the Advisor prints, the
	// operator runs. Nothing is granted because nothing is executed.
	OptionAdvise PrivilegeOption = "advise"
	// OptionN1 is a sudoers rule allow-listing exact commands, for a natively
	// installed node.
	OptionN1 PrivilegeOption = "N1"
	// OptionD1 is a wrapper script performing exact compose operations, called
	// by an executor with no docker socket access.
	OptionD1 PrivilegeOption = "D1"
	// OptionD3 is an executor in the docker group. Root-equivalent.
	OptionD3 PrivilegeOption = "D3"
)

// Terms is the agreement text. Kept as data rather than prose in a doc so the
// thing the operator accepted and the thing the executor enforces cannot drift
// apart.
type Terms struct {
	Version string
	Body    []string
}

// V1 is the accepted wording.
func V1() Terms {
	return Terms{
		Version: "v1",
		Body: []string{
			"The Advisor reads your node, forms a view, and proposes a named operation from a fixed list. It cannot invent an operation, and it cannot express a shell command — the type it emits has no field that can carry one.",
			"Nothing runs without your approval. Accepting these terms sets a ceiling on what may ever be proposed; it approves nothing by itself.",
			"Every approval is for one plan, on one node, and expires. An approval that goes unused becomes worthless rather than lingering.",
			"The executor checks the node itself before every operation, and again before the step that interrupts validation. It does not trust what the plan claimed, including its own earlier checks.",
			"The Advisor never reads or writes validator key material, never edits the amendments section or validators.txt, and never restarts the node while consensus looks anomalous.",
			"Everything is recorded — what was proposed, what was approved, what the executor observed, and what it refused to do. The record is append-only and hash-chained, so an alteration is visible.",
			"You can withdraw the compact at any time by deleting the acceptance file. The Advisor falls back to advising, which needs no privilege at all.",
		},
	}
}

// V2 adds the break-glass paragraph — plan-interrogative-loop §11.6.
//
// This is the operator-facing cost of Phase B2, and it is deliberate rather
// than accidental: V1's wording describes a system that proposes operations
// from a fixed list, and says nothing about reading this host's logs and
// configuration into a model provider's context. An operator who accepted V1
// agreed to being asked about upgrades; they did not agree to a deeper read
// of their host leaving the box. Because Hash() gates Load, publishing this
// text invalidates every V1 acceptance on every host — see the remedy this
// package's callers print, and CHANGELOG.md.
//
// The wording below is the operator's to edit before release; this is the
// one place it lives, so a review of the clause is a review of this
// function and nothing else.
func V2() Terms {
	v1 := V1()
	return Terms{
		Version: "v2",
		Body: append(append([]string{}, v1.Body...),
			"A deeper investigation you approve reads more of this host — configuration, logs, resource state, and system settings, with key material already removed on the privileged side — and sends that material to the model provider you configured. It never includes validator key material, at any tier, with or without your approval.",
		),
	}
}

// Hash identifies exactly this wording.
func (t Terms) Hash() string {
	h := sha256.Sum256([]byte(t.Version + "\n" + strings.Join(t.Body, "\n")))
	return hex.EncodeToString(h[:])
}

func (t Terms) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "OPERATOR COMPACT %s\n\n", t.Version)
	for i, line := range t.Body {
		fmt.Fprintf(&b, "%d. %s\n\n", i+1, wrapAt(line, 74, "   "))
	}
	fmt.Fprintf(&b, "terms hash %s\n", t.Hash()[:16])
	return b.String()
}

// Acceptance is what the operator agreed to, and the ceiling it sets.
type Acceptance struct {
	TermsVersion string            `json:"terms_version"`
	TermsHash    string            `json:"terms_hash"`
	AcceptedBy   string            `json:"accepted_by"`
	AcceptedAt   time.Time         `json:"accepted_at"`
	Node         string            `json:"node"`
	Privilege    PrivilegeOption   `json:"privilege"`
	Classes      []runbook.Class   `json:"classes"`
	Notes        map[string]string `json:"notes,omitempty"`
}

// Permits reports whether a runbook class is inside the ceiling. An operator
// can allow configuration edits while refusing restarts, and that distinction
// is enforced here rather than described in a document.
func (a Acceptance) Permits(c runbook.Class) bool {
	for _, x := range a.Classes {
		if x == c {
			return true
		}
	}
	return false
}

// Peek reads an acceptance without checking whether it still applies.
//
// For one caller and one purpose: an operator whose compact no longer applies
// needs the command that accepts it again, and that command should carry the
// privilege and the classes they already chose rather than a wider default
// somebody else picked (#466). Those two values are in the file Load just
// refused, and they are readable.
//
// It grants nothing and is never a gate. Every path that decides whether an
// act may happen calls Load, which checks the terms hash and the node. This
// returns what was written, for printing.
func Peek(path string) (Acceptance, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Acceptance{}, err
	}
	var a Acceptance
	if err := json.Unmarshal(raw, &a); err != nil {
		return Acceptance{}, fmt.Errorf("compact %s: %w", path, err)
	}
	return a, nil
}

// Load reads an acceptance and checks it still applies.
//
// A compact accepted against different terms does not carry forward. If the
// wording changes, the operator agreed to something else and has to agree
// again — which is the whole point of hashing the text.
func Load(path string, node string) (Acceptance, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Acceptance{}, fmt.Errorf("no compact has been accepted for this host")
	}
	if err != nil {
		return Acceptance{}, err
	}
	var a Acceptance
	if err := json.Unmarshal(raw, &a); err != nil {
		return Acceptance{}, fmt.Errorf("compact %s: %w", path, err)
	}
	// V2 is the current wording. A V1 acceptance — or any hash that is not
	// V2's — fails closed here: `ask` reports no compact, execute refuses,
	// and the Advisor falls back to advising, which needs no privilege at
	// all. That is the safe direction, and it is visible rather than
	// silent — see /v1/status's `compact` block and the tab that renders it.
	if a.TermsHash != V2().Hash() {
		return Acceptance{}, fmt.Errorf(
			"the accepted compact was for different terms (%s); accept the current terms again",
			short(a.TermsHash))
	}
	if a.Node != node {
		return Acceptance{}, fmt.Errorf(
			"the compact was accepted for node %q, not %q", a.Node, node)
	}
	if a.Privilege == "" {
		return Acceptance{}, fmt.Errorf("the compact records no privilege option")
	}
	return a, nil
}

// Save writes the acceptance.
func Save(path string, a Acceptance) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o640)
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func wrapAt(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	line := 0
	for i, w := range words {
		if line > 0 && line+1+len(w) > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}
