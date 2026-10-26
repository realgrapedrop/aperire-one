package runbook

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The configuration allow-list — ADR 0018, RB-003.
//
// This table MIRRORS the privilege wrapper's `set-config` case arms. The
// wrapper is the enforcing copy: it refuses a key or a value outside these
// bands whatever this file says, because it is the thing running as root and
// the thing an auditor reads. This copy exists so the refusal reaches the
// operator BEFORE a ceremony rather than as a failed run afterwards, and so
// the gate can show the band it would have to satisfy.
//
// Two copies of a rule is how one of them rots, so a test greps the wrapper
// for these exact keys, bands and SHAPES and fails when they part company.
// The shape was the omission that made this a bug report rather than a
// refactor: it lived only in the wrapper's grep, as an assumption that every
// setting is a key=value line, and rippled writes two of these four as
// stanzas. Widening a
// band is a deliberate change to the wrapper with its own review; this table
// then follows it, and the test is what makes "then" not optional.
//
// Every key here is read by the node at startup. That is not a coincidence of
// the four — it is why they are the four: a setting that takes effect while
// the node runs would not need the compound approval the restart half of this
// runbook exists to carry, and would be a different decision.

// ConfigShape is how a setting is written in the node configuration. rippled
// has two, and which one a setting takes is not derivable from its name.
type ConfigShape string

const (
	// ShapeKV is a key=value line inside a section: `online_delete=32768`
	// under [node_db]. The wrapper rewrites every assignment of the key.
	ShapeKV ConfigShape = "kv"
	// ShapeStanza is a section whose VALUE is the line under its header:
	// `[node_size]` and then `huge`. The wrapper replaces that one line and
	// leaves the header alone.
	//
	// This is the distinction that produced the 2026-08-19 report: an operator
	// asked to lower node_size and was told it was not a setting this config
	// has, because everything on both sides of the wrapper went looking for a
	// `node_size=` line on a node that was running `[node_size]` / `huge`.
	ShapeStanza ConfigShape = "stanza"
)

// ConfigKey is one permitted setting.
type ConfigKey struct {
	// Name is the key as it appears in the node configuration.
	Name string `json:"name"`
	// Shape is how it is written there. Mirrors the wrapper's own shape case
	// arms, and the drift test reads those arms to prove it.
	Shape ConfigShape `json:"shape"`
	// Band is the operating range, in the words the refusal uses. Shown in
	// the gate beside the proposed value.
	Band string `json:"band"`
	// What the setting does, in one line, for the assessment the model reads.
	What string `json:"what"`
	// StartupRead records that the node reads this at startup only, so a
	// change does nothing until it restarts. True for all four in v1; carried
	// as a field rather than assumed, because the compound approval and the
	// gate's amber line are both derived from it and an assumption would make
	// a fifth key silently claim a restart it does not need.
	StartupRead bool `json:"startup_read"`

	// accepts is the band, as code. Mirrors the wrapper's own value check.
	accepts func(string) bool
}

var configDigits = regexp.MustCompile(`^[0-9]+$`)

// configKeys is the table. Declaration order is the order the gate and the
// prompt list them in.
var configKeys = []ConfigKey{
	{
		Name:  "online_delete",
		Shape: ShapeKV,
		Band:  "a whole number between 16384 and 131072",
		What:  "how many ledgers the node keeps online before rotating the store",
		// Below 16384 is the I/O-storm band NuDB rotation misbehaves in —
		// the wrapper's own words for the same floor.
		StartupRead: true,
		accepts: func(v string) bool {
			if !configDigits.MatchString(v) {
				return false
			}
			n, err := strconv.Atoi(v)
			return err == nil && n >= 16384 && n <= 131072
		},
	},
	{
		Name:        "advisory_delete",
		Shape:       ShapeKV,
		Band:        "0 or 1",
		What:        "whether online deletion waits to be asked rather than rotating on its own",
		StartupRead: true,
		accepts:     func(v string) bool { return v == "0" || v == "1" },
	},
	{
		Name:        "node_size",
		Shape:       ShapeStanza,
		Band:        "tiny, small, medium, large or huge",
		What:        "how much memory and cache the node sizes itself for",
		StartupRead: true,
		accepts: func(v string) bool {
			switch v {
			case "tiny", "small", "medium", "large", "huge":
				return true
			}
			return false
		},
	},
	{
		Name:        "ledger_history",
		Shape:       ShapeStanza,
		Band:        "a whole number, or full",
		What:        "how much history the node keeps and will serve",
		StartupRead: true,
		accepts:     func(v string) bool { return v == "full" || configDigits.MatchString(v) },
	},
}

// ConfigKeys returns the table.
func ConfigKeys() []ConfigKey { return append([]ConfigKey(nil), configKeys...) }

// ConfigKeyNames is the enum, in declaration order — what the runbook's own
// Param.Allowed is built from, so the parameter and this table cannot name
// different sets.
func ConfigKeyNames() []string {
	out := make([]string, 0, len(configKeys))
	for _, k := range configKeys {
		out = append(out, k.Name)
	}
	return out
}

// LookupConfigKey finds a key by name.
func LookupConfigKey(name string) (ConfigKey, bool) {
	for _, k := range configKeys {
		if k.Name == name {
			return k, true
		}
	}
	return ConfigKey{}, false
}

// ValidateConfigChange checks one key and value against the table and returns
// the sentence the operator should read when it refuses.
//
// The error text IS the refusal detail — it travels into the action block's
// `invalid_change` reason and is rendered verbatim. So it names the band
// rather than saying the value was rejected, which is the difference between
// a refusal an operator can act on and one they have to guess at.
func ValidateConfigChange(key, value string) error {
	k, ok := LookupConfigKey(key)
	if !ok {
		return fmt.Errorf("%q is not a setting the Advisor may change — the allow-list is %s",
			key, strings.Join(ConfigKeyNames(), ", "))
	}
	if value == "" {
		return fmt.Errorf("%s needs a value: %s", key, k.Band)
	}
	if !k.accepts(value) {
		return fmt.Errorf("%s must be %s, and %q is not", key, k.Band, value)
	}
	return nil
}

// ConfigKeysSorted is the allow-list as a sorted set, for a test comparing it
// against the wrapper's case arms without depending on either order.
func ConfigKeysSorted() []string {
	out := ConfigKeyNames()
	sort.Strings(out)
	return out
}
