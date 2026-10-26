package host

import (
	"fmt"
	"regexp"
	"strings"

	"aperire-advisor/internal/runbook"
)

// The node's own configuration, read for the one purpose of computing a diff
// — ADR 0018.
//
// It goes through the privilege wrapper's `show-config` verb, which is where
// the redaction happens: [validator_token] and every other secret stanza is
// removed on the privileged side, before a byte reaches this process. That is
// the same boundary artefactHashes relies on, and the reason this file never
// opens the config directly even when it could.
//
// What this is FOR is worth stating, because it decides what it may not do.
// The operator is about to approve a change to a file, and the only honest
// way to show them what would change is to read the file. The lines here are
// the service's own reading; they travel into the gate and into the ledger,
// and they do NOT travel into the model's context — the assessment gives the
// model the current value of a key, not the file.

// NodeConfig is one reading of the node configuration.
type NodeConfig struct {
	// File is the path the wrapper reports, verbatim from its own header
	// line. Never assembled here: the point of showing it is that it names
	// the file that would actually change, on the machine that holds it.
	File string
	// Host is the machine the wrapper reports. An operator running more than
	// one node reads "your rippled.cfg" as ambiguous, and has twice.
	Host string
	// Lines is every line the wrapper emitted after the header — comments and
	// blanks already dropped by it, redactions already applied.
	Lines []string
}

var showConfigHeader = regexp.MustCompile(`^# configuration read from (\S+) on (\S+) at `)

// NodeConfiguration reads the node config through the wrapper.
//
// This is the service's own read and does not spend the question's privileged
// read budget: it happens when a change is being validated, not when a model
// asks to look. The model's route to the same file is host_read show-config,
// which is budgeted and role-gated exactly as before.
func (s *State) NodeConfiguration() (NodeConfig, error) {
	if s.Wrapper == "" {
		return NodeConfig{}, fmt.Errorf("no privilege wrapper is configured, so the node's configuration cannot be read")
	}
	name := s.Wrapper
	rest := []string{"show-config"}
	out, err := s.Runner.Run(s.context(), name, rest...)
	if err != nil {
		return NodeConfig{}, fmt.Errorf("reading the node configuration through the wrapper: %w", err)
	}
	return parseNodeConfig(string(out))
}

func parseNodeConfig(out string) (NodeConfig, error) {
	var c NodeConfig
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if m := showConfigHeader.FindStringSubmatch(ln); m != nil && c.File == "" {
			c.File, c.Host = m[1], m[2]
			continue
		}
		if strings.HasPrefix(ln, "#") {
			// The wrapper's own trailing note about dropped comments, and its
			// second header line. Neither is configuration.
			continue
		}
		c.Lines = append(c.Lines, ln)
	}
	if c.File == "" {
		return NodeConfig{}, fmt.Errorf("the wrapper's show-config output did not name the file it read")
	}
	// A header with (almost) nothing under it is a failed read wearing a
	// passing face: mawk standing in for gawk panicked mid-redaction and the
	// output was the two header lines plus a fragment (2026-08-20, stock
	// Ubuntu rootfs). Every real rippled.cfg has dozens of setting lines, and
	// "the config is empty" downstream reads as "every setting is absent" —
	// an error nobody sees. Refuse it by name instead.
	nonEmpty := 0
	for _, ln := range c.Lines {
		if strings.TrimSpace(ln) != "" {
			nonEmpty++
		}
	}
	if nonEmpty < 2 {
		return NodeConfig{}, fmt.Errorf("show-config returned only %d configuration lines for %s — the read failed (is gawk installed on the node's host?)", nonEmpty, c.File)
	}
	return c, nil
}

// assignmentOf matches the wrapper's own grep, byte for byte in effect:
// ^[[:space:]]*key[[:space:]]*= . The two must agree, because the wrapper
// rewrites exactly the lines it finds this way and the diff shown to the
// operator promises exactly those lines. A looser match here shows a line
// that will not change; a tighter one hides a line that will.
func assignmentOf(line, key string) bool {
	t := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(t, key) {
		return false
	}
	t = strings.TrimLeft(t[len(key):], " \t")
	return strings.HasPrefix(t, "=")
}

// Assignments returns every line assigning key, in file order.
//
// Every one of them, not the first. This node has two online_delete lines,
// which is precisely why the wrapper rewrites them all — replacing only the
// first would leave the second to win and the change would appear to do
// nothing.
func (c NodeConfig) Assignments(key string) []string {
	var out []string
	for _, ln := range c.Lines {
		if assignmentOf(ln, key) {
			out = append(out, ln)
		}
	}
	return out
}

// Value is what a key=value setting resolves to right now: the LAST
// assignment, because that is the one that wins.
//
// Only the kv shape. A stanza-shaped setting has no assignment line at all and
// this returns false for it, correctly and uselessly — Setting is the reading
// that answers "what is this set to" for either shape.
func (c NodeConfig) Value(key string) (string, bool) {
	a := c.Assignments(key)
	if len(a) == 0 {
		return "", false
	}
	last := a[len(a)-1]
	_, v, _ := strings.Cut(last, "=")
	return strings.TrimSpace(v), true
}

// ── the stanza shape ─────────────────────────────────────────────────────
//
// rippled writes two of the four changeable settings as a section whose value
// is the line under its header:
//
//	[node_size]
//	huge
//
// Everything above this line reads the other shape, a key=value inside a
// section. Reading only that one is what produced the 2026-08-19 report: an
// operator asked to lower node_size and the assessment said the setting was
// not present in the config the node was running huge from. Which shape a key
// takes is in runbook's table, mirrored from the wrapper's own case arms.

var stanzaHeader = regexp.MustCompile(`^[[:space:]]*\[([A-Za-z0-9_]+)\][[:space:]]*$`)

// StanzaHeaders counts the headers named `name`. More than one and there is no
// single answer to what the setting holds — the wrapper refuses that case, and
// this side has to refuse it in the same words, before a ceremony rather than
// during one.
func (c NodeConfig) StanzaHeaders(name string) int {
	n := 0
	for _, ln := range c.Lines {
		if m := stanzaHeader.FindStringSubmatch(ln); m != nil && m[1] == name {
			n++
		}
	}
	return n
}

// StanzaValue is the first value line under the named header, trimmed.
//
// Blank and comment lines between the header and the value are skipped; the
// next section header ends the search, because a stanza with no value line of
// its own has no value rather than borrowing the following section's. Both
// rules match the wrapper's stanza_value, which is the thing that will do the
// writing.
//
// show-config has already dropped comments and blanks, so in practice the
// value is the very next line. The skipping is here because this same reading
// has to hold if that ever changes, and because a wrapper and a reader that
// disagree about which line is the value is the whole failure mode.
func (c NodeConfig) StanzaValue(name string) (string, bool) {
	in := false
	for _, ln := range c.Lines {
		if m := stanzaHeader.FindStringSubmatch(ln); m != nil {
			if m[1] == name {
				in = true
				continue
			}
			if in {
				return "", false
			}
			continue
		}
		if !in {
			continue
		}
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return t, true
	}
	return "", false
}

// ConfigChange is what a set-config would do to the file, measured from the
// file. It is what the operator is shown before they are asked for a passkey,
// and it is derived from a reading rather than from anything a model wrote.
type ConfigChange struct {
	// Stanza is the section header this change sits under, bare — "node_size"
	// for the stanza shape, empty for a key=value line. The gate renders it
	// as context above the change, uncoloured, because the header does not
	// change and colouring it would claim it does.
	Stanza string
	// Before is the line, or lines, that would change. Verbatim.
	Before []string
	// After is what they become, one for one.
	After []string
	// Current is the value in force now — the last assignment for a kv key,
	// the stanza's value line for a stanza key.
	Current string
}

// ChangeFor works out what changing key to value would do to this config, and
// refuses in the same terms the wrapper does when it cannot be done.
//
// Every refusal here is one the wrapper would also make. That is the point: a
// diff the operator approves and a wrapper that then declines to write it is
// the gap between the page and the file this whole design exists to close.
func (c NodeConfig) ChangeFor(key, value string) (ConfigChange, error) {
	meta, known := runbook.LookupConfigKey(key)
	if !known {
		return ConfigChange{}, fmt.Errorf("%s is not a setting the Advisor may change", key)
	}
	if meta.Shape == runbook.ShapeStanza {
		switch n := c.StanzaHeaders(key); {
		case n == 0:
			return ConfigChange{}, fmt.Errorf("there is no [%s] section in %s, so there is "+
				"nothing to change — the Advisor rewrites a setting the file already has and "+
				"never adds one, because which part of the file it belongs in is not something "+
				"it can decide", key, c.File)
		case n > 1:
			return ConfigChange{}, fmt.Errorf("%s has %d [%s] sections, and which one is in "+
				"force is rippled's decision rather than the Advisor's — this needs a person to "+
				"look at the file", c.File, n, key)
		}
		current, ok := c.StanzaValue(key)
		if !ok {
			return ConfigChange{}, fmt.Errorf("the [%s] section in %s has no value line under "+
				"it, so there is nothing to replace", key, c.File)
		}
		return ConfigChange{
			Stanza: key, Before: []string{current}, After: []string{value}, Current: current,
		}, nil
	}
	before := c.Assignments(key)
	if len(before) == 0 {
		return ConfigChange{}, fmt.Errorf("there is no %s= line in %s, so there is nothing to "+
			"change — the Advisor rewrites a setting the file already has and never adds one, "+
			"because which section it belongs in is not something it can decide", key, c.File)
	}
	after := make([]string, len(before))
	for i := range after {
		after[i] = key + "=" + value
	}
	current, _ := c.Value(key)
	return ConfigChange{Before: before, After: after, Current: current}, nil
}

// Setting is what a key holds right now, whichever shape it takes. This is the
// reading the assessment gives the model, and the one that used to say a
// stanza-shaped setting was absent.
func (c NodeConfig) Setting(key string) (string, bool) {
	if meta, ok := runbook.LookupConfigKey(key); ok && meta.Shape == runbook.ShapeStanza {
		if c.StanzaHeaders(key) != 1 {
			return "", false
		}
		return c.StanzaValue(key)
	}
	return c.Value(key)
}
