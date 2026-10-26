// Package actionplan defines the only thing the agent may emit, and the rules
// that decide whether it is well formed.
//
// The security property this type exists to create: an ActionPlan names a
// runbook and parameters. It cannot express a command. There is no field here
// that carries a shell string, an argv, a path to execute, or anything an
// executor could be tricked into running. No runbook, no action.
//
// Everything in this file is about *shape*. Whether the named runbook exists,
// whether the operator permitted it, and whether the host is currently in a
// state where it may run are all separate questions answered elsewhere and
// deliberately not here — see ADR 0001 and ADR 0007.
package actionplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is carried on every plan. An executor that does not recognise
// the version refuses the plan rather than guessing at its meaning.
const SchemaVersion = 1

// Plan is what the agent proposes. It is data, never behaviour.
type Plan struct {
	SchemaVersion int    `json:"schema_version"`
	PlanID        string `json:"plan_id"`
	RunbookID     string `json:"runbook_id"`
	NodeID        string `json:"node_id"`

	// Params are runbook-defined. The registry declares each parameter's type
	// and bounds; this package only checks that the names and scalar shapes
	// are sane, because a plan that is structurally wrong should be rejected
	// before anything looks up what the values are supposed to mean.
	Params map[string]any `json:"params"`

	// Rationale is the agent's reasoning in plain language. It is shown to the
	// operator and recorded. It is never parsed and never influences control
	// flow — treating model prose as instructions is the failure mode the
	// whole design exists to prevent.
	Rationale string `json:"rationale"`

	// Hypothesis is what this action is expected to change, in terms that can
	// be measured afterward. ADR 0004 makes this a schema requirement rather
	// than a convention: a plan with no measurable expectation cannot be
	// verified, so it does not validate.
	Hypothesis Hypothesis `json:"hypothesis"`

	// Citations are what makes the plan reviewable. A proposal without them is
	// an assertion, and an assertion is not something an operator should
	// approve an action on.
	Citations []Citation `json:"citations"`

	CreatedAt time.Time `json:"created_at"`
}

// Hypothesis states the expected effect and how long to wait before judging it.
type Hypothesis struct {
	Statement      string   `json:"statement"`
	Signals        []string `json:"signals"`
	VerifyAfterSec int      `json:"verify_after_sec"`
}

// Source classifies where a citation came from. The names are the operator
// facing ones deliberately: the lettered scheme collided with the design doc's
// Tier 1-4 model escalation, which is an unrelated idea.
type Source string

const (
	// SourceDocumented is authored corpus: the Field Guide, xrpl.org, the
	// dashboard's own knowledge files. Citable as evidence.
	SourceDocumented Source = "documented"
	// SourceMeasured is this operator's own data. Citable as evidence.
	SourceMeasured Source = "measured"
	// SourceExternal is retrieved from outside the node. It may propose a
	// hypothesis and can never stand as evidence on its own — see ADR 0006.
	SourceExternal Source = "external"
)

// Citation points at what supports a claim.
type Citation struct {
	Source Source `json:"source"`
	Ref    string `json:"ref"`
	Note   string `json:"note,omitempty"`
	// RetrievedAt pins when an external source was read, because live
	// retrieval can answer differently tomorrow and a citation that cannot be
	// re-checked is not a citation.
	RetrievedAt *time.Time `json:"retrieved_at,omitempty"`
}

var (
	ErrSchemaVersion = errors.New("unrecognised schema_version")
	ErrMalformed     = errors.New("malformed action plan")
)

// idPattern is deliberately tight. IDs end up in log lines, file names and
// audit records, so anything that could carry a path traversal, a shell
// metacharacter or a newline is rejected at the door.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidationError collects every problem found rather than stopping at the
// first. An operator debugging a rejected plan should see all of it at once.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%v: %s", ErrMalformed, strings.Join(e.Problems, "; "))
}
func (e *ValidationError) Is(target error) bool { return target == ErrMalformed }

// Validate checks the plan's shape. It answers "is this a well formed plan",
// not "may this run" — that is the executor's question and it is asked later
// against the registry, the compact, and live host state.
func (p *Plan) Validate() error {
	var probs []string
	add := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }

	if p.SchemaVersion != SchemaVersion {
		// Version is fatal on its own: if we do not know the dialect, every
		// other complaint below is guesswork.
		return fmt.Errorf("%w: got %d, expected %d", ErrSchemaVersion, p.SchemaVersion, SchemaVersion)
	}
	if !idPattern.MatchString(p.PlanID) {
		add("plan_id %q is not a valid identifier", p.PlanID)
	}
	if !idPattern.MatchString(p.RunbookID) {
		add("runbook_id %q is not a valid identifier", p.RunbookID)
	}
	if !idPattern.MatchString(p.NodeID) {
		add("node_id %q is not a valid identifier", p.NodeID)
	}
	if strings.TrimSpace(p.Rationale) == "" {
		add("rationale is empty")
	}
	if p.CreatedAt.IsZero() {
		add("created_at is unset")
	}

	// Params must be flat scalars. Nested structures are where an executor
	// starts interpreting rather than looking up, and interpretation is how a
	// parameter becomes a command.
	for _, k := range sortedKeys(p.Params) {
		if !idPattern.MatchString(k) {
			add("param name %q is not a valid identifier", k)
			continue
		}
		switch p.Params[k].(type) {
		case string, bool, float64, int, int64, json.Number, nil:
		default:
			add("param %q must be a scalar, got %T", k, p.Params[k])
		}
	}

	if strings.TrimSpace(p.Hypothesis.Statement) == "" {
		add("hypothesis.statement is empty; a plan with no measurable expectation cannot be verified")
	}
	if len(p.Hypothesis.Signals) == 0 {
		add("hypothesis.signals is empty; verification needs something to measure")
	}
	if p.Hypothesis.VerifyAfterSec < 0 {
		add("hypothesis.verify_after_sec is negative")
	}

	if len(p.Citations) == 0 {
		add("citations is empty; an uncited proposal is an assertion")
	}
	evidence := 0
	for i, c := range p.Citations {
		switch c.Source {
		case SourceDocumented, SourceMeasured:
			evidence++
		case SourceExternal:
			if c.RetrievedAt == nil {
				add("citation %d is external and has no retrieved_at", i)
			}
		default:
			add("citation %d has unknown source %q", i, c.Source)
		}
		if strings.TrimSpace(c.Ref) == "" {
			add("citation %d has an empty ref", i)
		}
	}
	// ADR 0006: external sources generate hypotheses, they are never the
	// evidence. A plan resting only on what something on the internet said has
	// nothing of the operator's own behind it.
	if len(p.Citations) > 0 && evidence == 0 {
		add("every citation is external; a plan needs at least one documented or measured source")
	}

	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Parse decodes and validates in one step. Unknown fields are rejected: a plan
// carrying something this build does not understand is a plan we cannot reason
// about, and silently dropping it is how a field that matters goes missing.
func Parse(b []byte) (*Plan, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var p Plan
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}
