package interrogate

// Role policy — what a monitor may read through the Advisor.
//
// The rules themselves are written down in advisor/knowledge/role-policy.md,
// which the service injects into every system prompt so the model can explain
// them. This file is the enforcement, and the two are deliberately not the
// same artefact: a prompt tells the model what to say, and a model that is
// talked out of saying it is still refused here.
//
// It lives in this package for the same reason hostVerbs does. This is the
// package that carries the security properties, it imports nothing outside
// the standard library, and it is meant to be reviewable on its own. Two
// enforcement points consult ONE list (the concrete menu's host_read handler,
// and the seed probes the service runs from the question's own words before
// the loop starts); a second copy of the list somewhere else is how a verb
// quietly becomes readable again.

// RoleMonitor is the one role that may not act and may not make the seven
// sensitive host reads below. Stamped on every question by the dashboard
// proxy, from the signed-in session, never typed by the browser.
const RoleMonitor = "monitor"

// sensitiveHostVerbs are the seven wrapper reads that describe the host in
// the ways an attacker would want: the configuration (ports, fixed peers,
// paths, feature flags), the logs and the journal (peer addresses, file
// paths, error text), kernel settings and process limits, the validator list
// sites and the domain file.
//
// None of them is secret in the cryptographic sense — key material never
// leaves the host at any tier, for any role, and the wrapper strips it before
// a byte reaches this process. Together, though, they are the threat surface
// of one validator, and a monitor session is meant to watch the node rather
// than to map it.
//
// The other three verbs — resources, disk, unit-status — are memory, swap,
// load, disk on the data path, and whether the Aperire units are up. They
// name nothing about where the host is or how it is reached, and a monitor
// keeps them.
var sensitiveHostVerbs = map[string]bool{
	"show-config":     true,
	"node-log":        true,
	"journal":         true,
	"sysctl-relevant": true,
	"limits":          true,
	"show-validators": true,
	"show-toml":       true,
}

// SensitiveHostVerb reports whether a verb is one of the seven a monitor may
// not read. Exported for the seed-probe filter, which walks host.Probes
// rather than this package's own request path.
func SensitiveHostVerb(verb string) bool { return sensitiveHostVerbs[verb] }

// RoleMayReadVerb is the whole rule, in one place.
//
// An EMPTY role is treated as an admin, deliberately. The dashboard proxy
// stamps the role on every question it forwards — local and peer, ordinary
// and gated — so an absent role does not mean "a session that did not say".
// It means the caller is not the proxy at all: the CLI, a test, or the host
// operator with the service token in their hand. That person already holds
// the token this service authenticates with, which is the same authority the
// wrapper runs under; refusing them the config on a machine they are root on
// would be theatre, and rendering them as the least-privileged role would
// teach every non-browser caller that the Advisor lies about what it can see.
//
// Anything that is neither empty nor "monitor" is an admin. The dashboard has
// exactly two roles and the enum is checked at the session layer; a value
// this service does not recognise is a dashboard newer than it is, and
// refusing a role it has never heard of would fail closed on an upgrade
// rather than on an attack.
func RoleMayReadVerb(role, verb string) bool {
	if role != RoleMonitor {
		return true
	}
	return !sensitiveHostVerbs[verb]
}

// RoleAllowsVerb is the predicate form, bound to one role — for a caller
// filtering a fixed list of verbs (the seed probes) rather than answering one
// request at a time.
func RoleAllowsVerb(role string) func(verb string) bool {
	return func(verb string) bool { return RoleMayReadVerb(role, verb) }
}
