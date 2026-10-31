// Command aperire-executor evaluates and, once approved, performs a runbook
// against the live node.
//
//	check    evaluate the preconditions; change nothing
//	advise   the same evaluation, rendered as steps for a person to run
//	compact  show the operator compact, or accept it
//	approve  refuses: an approval needs a passkey, which a flag cannot supply
//	execute  perform an approved stage through the privilege wrapper
//	ledger   read back the record, verifying its chain
//
// The plan identifier is derived from the runbook, the node and the
// parameters, so an approval and `execute` agree on what was approved without
// passing an identifier between them — and changing a parameter after
// approval produces a different plan, which the approval does not cover.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aperire-advisor/internal/advise"
	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/execute"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/memory"
	"aperire-advisor/internal/outage"
	"aperire-advisor/internal/runbook"
)

type opts struct {
	container, adminRPC, target, book, evidence string
	stateDir, wrapper                           string
	// wrapperSocket is the root socket the node wrapper is reached through
	// (ADR 0025). Empty means "work it out" (see wrapperSocketFor).
	wrapperSocket string
	// socketSettled is set once withSocket has decided; see there.
	socketSettled                              bool
	stage, reason, privilege, classes, confirm string
	// retract is memory's second verb (#1012): withdraw a note the Advisor
	// wrote that is wrong. reason, when given, is recorded with it.
	retract string
	// intent is RB-002's bound parameter, and it is deliberately a separate
	// flag from reason. reason is the operator's own words, free text, kept
	// with the approval and outside the fingerprint; intent is one of four
	// declared values and is INSIDE it. One flag serving both would either
	// fail parameter binding or bind nothing, and binding nothing is what
	// makes every confirm code on a node identical.
	intent string
	// key and value are RB-003's bound parameters — ADR 0018. Separate flags
	// for the same reason intent is separate from reason: both are inside the
	// fingerprint, and a value the runbook does not bind produces a confirm
	// code for a plan nobody evaluated.
	cfgKey, cfgValue string
	// change and runAs are RB-005's bound parameters (ADR 0023), and source
	// is the upgrade's build override (#682). Separate flags for the reason
	// key and value are separate: all three are inside the fingerprint, so a
	// run started without one is a run against a plan nobody approved.
	change, runAs, source       string
	ttl, timeout                time.Duration
	accept, asJSON, verify, yes bool
	// repair is ledger's way out of a forked chain (#1091).
	repair bool
}

// version is stamped at build time via -ldflags -X main.version=<commit>,
// the same way the daemon's is (#266). Three build sites stamp this binary
// and every one of them was writing into a symbol that did not exist, so
// the stamp was silently dropped and an executor run beside a stamped
// daemon could not be told apart from one built by hand (#695). A symbol
// that is not declared is not a build error, which is why this went
// unnoticed; scripts/test-build-stamps.sh is what notices now.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]

	var o opts
	fs := newFlagSet(cmd, &o, flag.ExitOnError)
	fs.Parse(os.Args[2:])

	switch cmd {
	case "version":
		fmt.Println(version)
	case "compact":
		doCompact(o)
	case "ledger":
		doLedger(o)
	case "memory":
		doMemory(o)
	case "cancel":
		doCancel(o)
	case "check", "advise":
		doEvaluate(cmd, o)
	case "approve":
		doApprove(o)
	case "execute":
		doExecute(o)
	default:
		usage()
	}
}

// newFlagSet registers every flag the executor's commands read, onto o. One
// set for all commands, as it always was; pulled out of main so a test can
// prove a verb's flag is actually registered (#1012: --confirm was read and
// documented but never registered).
func newFlagSet(cmd string, o *opts, onErr flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd, onErr)
	fs.StringVar(&o.container, "container", defaultContainer(), "container running the node")
	fs.StringVar(&o.adminRPC, "admin-rpc", "http://127.0.0.1:5005", "node admin JSON-RPC endpoint")
	fs.StringVar(&o.target, "target", "", "target version, e.g. 3.2.1")
	fs.StringVar(&o.book, "runbook", "upgrade-xrpld", "runbook")
	fs.StringVar(&o.evidence, "evidence", "", "write a diagnostic snapshot to this path first")
	fs.StringVar(&o.stateDir, "state", defaultStateDir(), "compact, approvals and ledger live here")
	fs.StringVar(&o.wrapper, "wrapper", defaultWrapper(), "privilege wrapper script")
	fs.StringVar(&o.wrapperSocket, "wrapper-socket", os.Getenv("APERIRE_WRAPPER_SOCKET"),
		"reach the node wrapper through this root socket (ADR 0025); worked out from the "+
			"installed wrapper when this account can use exactly one")
	fs.StringVar(&o.stage, "stage", "", "prepare | cutover | restart | config | rollback | normalise")
	fs.StringVar(&o.reason, "reason", "", "your words, recorded with the approval")
	fs.StringVar(&o.intent, "intent", "",
		"restart-node: apply-config | resource-pressure | planned-maintenance | operator-judgement; "+
			"rollback-node: planned-rollback | regression-suspected | operator-judgement")
	fs.StringVar(&o.cfgKey, "key", "",
		"config-change: "+strings.Join(runbook.ConfigKeyNames(), " | "))
	fs.StringVar(&o.cfgValue, "value", "", "config-change: the value to set, inside that key's safe band")
	fs.StringVar(&o.change, "change", "",
		"normalise-deployment: "+strings.Join(runbook.NormaliseChanges(), " | "))
	fs.StringVar(&o.runAs, "user", "", "normalise-deployment runtime-user: the uid:gid to write")
	fs.StringVar(&o.source, "source", "",
		"upgrade-xrpld: build, to build the image here when an official one also exists")
	fs.StringVar(&o.privilege, "privilege", "D1", "advise | N1 | D1 | D3")
	fs.StringVar(&o.classes, "classes", "upgrade", "comma-separated runbook classes to permit")
	fs.DurationVar(&o.ttl, "ttl", 15*time.Minute, "how long an approval is valid")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Minute, "how long to wait for the node to come back")
	fs.BoolVar(&o.accept, "accept", false, "compact: record acceptance")
	fs.BoolVar(&o.asJSON, "json", false, "emit JSON")
	fs.BoolVar(&o.verify, "verify", false, "ledger: verify the chain only")
	fs.BoolVar(&o.repair, "repair", false,
		"ledger: move a forked chain's extra rows into a sidecar, keeping a copy of the file; refuses any other break")
	fs.BoolVar(&o.yes, "yes", false, "execute: do not ask about an unconfirmed step")
	// Both memory verbs. --confirm was read by doMemory and printed in its
	// own help, but never registered, so the flag parser refused it before
	// doMemory ran (found with #1012).
	fs.StringVar(&o.confirm, "confirm", "", "memory: agree with the conclusion that has this id")
	fs.StringVar(&o.retract, "retract", "", "memory: withdraw the note that has this id; --reason says why")
	return fs
}

// exitUnconfirmed is execute's status for a stage the node restarted from
// on the right build and has not been confirmed back in full sync (#769).
const exitUnconfirmed = 3

func usage() {
	fmt.Fprint(os.Stderr, `aperire-executor <command> [flags]

  check    evaluate preconditions against the live node; change nothing
  advise   the same, rendered as steps for a person to run
  compact  show the operator compact, or --accept it
  approve  refuses — approve from the Advisor tab, which can ask for a passkey
  execute  perform an approved stage: --target --stage
           a restart is --runbook=restart-node --stage=restart --intent=<one of four>
           a config change is --runbook=config-change --stage=config --key= --value=
           a rollback is --runbook=rollback-node --stage=rollback --target=<derived> --intent=
  ledger   read back the record (--verify to check the chain only)
           --repair moves the extra rows of a forked chain into a sidecar file,
           keeps a copy of the ledger as it was, and records what it did. It
           refuses any break that is not a fork. Run it as the Advisor's account.
  memory   what the Advisor remembers; --confirm <id> to agree with a conclusion,
           --retract <id> --reason "<why>" to withdraw a note that is wrong
  cancel   abandon a plan and leave the deployment coherent: --target --stage
  version  the commit this binary was built from, or "dev" when unstamped

The node wrapper is reached through its root socket when this account can use
one: --wrapper-socket=<path> (or APERIRE_WRAPPER_SOCKET) names it; with
neither, the installed wrapper's socket is used if this account can reach
exactly one. A named socket that cannot be reached is an error, never a
fallback to docker.

execute exits 0 only when the node proved the stage finished, 1 when it
stopped or failed, and 3 when the node restarted onto the right build but
has not reached full sync yet: not a failure, not complete.
`)
	os.Exit(2)
}

func defaultStateDir() string {
	if d := os.Getenv("APERIRE_ADVISOR_STATE"); d != "" {
		return d
	}
	wd, _ := os.Getwd()
	// Run from advisor/, "state" is right. Run from the repository root —
	// which is where the Advisor tab's own instructions land an operator —
	// it named a directory that does not exist, and accepting the compact
	// failed with a permission error on a path nobody recognised. Prefer the
	// real one when it is there. Choosing a directory that exists cannot
	// make an unaccepted host look accepted: a compact written anywhere the
	// service does not read simply leaves it unaccepted, which is the safe
	// direction.
	if st, err := os.Stat(filepath.Join(wd, "state")); err == nil && st.IsDir() {
		return filepath.Join(wd, "state")
	}
	if st, err := os.Stat(filepath.Join(wd, "advisor", "state")); err == nil && st.IsDir() {
		return filepath.Join(wd, "advisor", "state")
	}
	return filepath.Join(wd, "state")
}

// The node this host actually runs, from the wrapper's own configuration —
// which was written from the discovered deployment at install. Hardcoded,
// the default named a container that exists on exactly one machine, and an
// operator accepting the compact recorded their consent against a node that
// was not theirs: the acceptance is per-node by design, so it read back as
// "not accepted" with nothing to say why.
func defaultContainer() string {
	b, err := os.ReadFile("/etc/aperire/node-wrapper.conf")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SERVICE="); ok && v != "" {
				return v
			}
		}
	}
	return "rippledvalidator"
}

func defaultWrapper() string {
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "scripts", "aperire-node-wrapper.sh"))
}

// wrapperRunDir is where the installed wrapper's sockets live (ADR 0025). A
// variable so a test never looks at the real one.
var wrapperRunDir = "/run/aperire"

// socketUsable says whether this account can connect to the socket at path:
// it is a socket, and the account may write to it, which is what connecting
// needs. Nothing is connected to, so asking costs the broker nothing.
var socketUsable = func(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false
	}
	return syscall.Access(path, 2) == nil
}

// wrapperSocketFor is the socket this command reaches the wrapper through, or
// "" when it reaches it directly.
//
// On a host where the Advisor runs as its own account there is no docker
// group and no sudo; the only way to the node is the root socket, and the
// documented command line names neither it nor an installed wrapper. So, in
// order:
//
//  1. --wrapper-socket (or APERIRE_WRAPPER_SOCKET), taken as given. A socket
//     named here that cannot be reached is an error that names it. It never
//     falls back to docker: the account that was told to use the socket is
//     the one that has no docker.
//  2. The socket that belongs to --wrapper, when that names an installed
//     wrapper and this account can use the socket.
//  3. The one wrapper socket in the run directory this account can use. Two
//     usable ones is ambiguous, and guessing would run one node's plan
//     through another node's wrapper, so it stops and says to choose.
//
// An operator on their own account with docker cannot use the Advisor's
// socket: it is root:<the Advisor's own group>, mode 0660, the installer keeps
// every other account out of that group, and the broker behind it checks the
// caller's uid as well. So for them 2 and 3 find nothing and nothing changes.
// Root is the one account the file mode does not stop, and the broker would
// refuse it, so a run as root never looks (it has docker anyway).
func wrapperSocketFor(o opts) (string, error) {
	if o.wrapperSocket != "" {
		return o.wrapperSocket, nil
	}
	if geteuid() == 0 {
		return "", nil
	}
	if sock := host.SocketForWrapper(o.wrapper); sock != "" && socketUsable(sock) {
		return sock, nil
	}
	var usable []string
	found, _ := filepath.Glob(filepath.Join(wrapperRunDir, "node-wrapper*.sock"))
	for _, c := range found {
		if socketUsable(c) {
			usable = append(usable, c)
		}
	}
	switch len(usable) {
	case 0:
		return "", nil
	case 1:
		return usable[0], nil
	}
	return "", fmt.Errorf("this account can use more than one wrapper socket (%s); "+
		"name the one for this node with --wrapper-socket", strings.Join(usable, ", "))
}

// installedWrapperFor is the installed wrapper that belongs to a socket, the
// inverse of host.SocketForWrapper: /run/aperire/node-wrapper-node2.sock is
// /usr/local/sbin/aperire-node-wrapper-node2. "" for any other socket.
func installedWrapperFor(sock string) string {
	base := filepath.Base(sock)
	rest, ok := strings.CutPrefix(base, "node-wrapper")
	if !ok || !strings.HasSuffix(rest, ".sock") {
		return ""
	}
	return "/usr/local/sbin/aperire-node-wrapper" + strings.TrimSuffix(rest, ".sock")
}

// withSocket settles, once, how a command that reaches the node will do it:
// the socket in o.wrapperSocket, and the wrapper's name to match. Reaching the
// node through a socket makes the wrapper a name, not a file this account can
// open, so a wrapper nobody chose is called by its installed name, the one the
// ledger and the by-hand instructions should show. Idempotent. The commands
// that never touch the node (compact, ledger, memory) never call it, so a
// host with two sockets only asks them to choose when they need one.
func withSocket(o opts) opts {
	if o.socketSettled {
		return o
	}
	sock, err := wrapperSocketFor(o)
	if err != nil {
		fail("%v", err)
	}
	o.socketSettled = true
	o.wrapperSocket = sock
	if sock != "" && o.wrapper == defaultWrapper() {
		if w := installedWrapperFor(sock); w != "" {
			o.wrapper = w
		}
	}
	return o
}

// runnerFor is how this command reaches the host: through the wrapper's root
// socket when there is one, the way advisord does, and directly otherwise.
// Every command that reads the deployment or runs a step builds its Runner
// here, so no command can reach docker on a host that has given this account
// none (#1090).
func runnerFor(o opts) host.Runner {
	o = withSocket(o)
	if o.wrapperSocket == "" {
		return host.ExecRunner{}
	}
	return host.ViaWrapper{Wrapper: o.wrapper, Socket: o.wrapperSocket}
}

func whoami() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

// osActor attributes a command-line act to the account that ran it.
//
// Deliberately weaker than a run's actor and labelled as such: whoami() is
// the shell's identity, not a passkey, and verified:"os" says so. It is the
// strongest thing available here — there is no ceremony on this path — and
// recording it is strictly better than the anonymous entries these acts used
// to leave behind.
func osActor() ledger.Actor {
	a := ledger.Actor{
		Operator: whoami(),
		Source:   ledger.SourceCLI,
		Verified: ledger.VerifiedOS,
	}
	// Run as `sudo -u <advisor account>`, the form every printed command
	// uses, whoami() is the service account on every act. sudo names the
	// person in SUDO_USER, and that is recorded beside it as a claim, never
	// as Operator: the environment is the account's own to set, so it is
	// what sudo said, not what this process proved (#1012 review, L3).
	if su := sudoUser(); su != "" && su != a.Operator {
		a.ClaimedOperator, a.ClaimedBy = su, "SUDO_USER"
	}
	return a
}

func sudoUser() string { return strings.TrimSpace(os.Getenv("SUDO_USER")) }

// operatorName is who a memory verdict is recorded as: the person sudo names
// and the account it ran as, or the account alone, saying there was no sudo.
func operatorName() string {
	acct := whoami()
	if su := sudoUser(); su != "" && su != acct {
		return su + " (through sudo, as " + acct + ")"
	}
	return acct + " (no SUDO_USER: run directly as this account)"
}

func newClient() *http.Client {
	// HTTP/1.1 only: Go's HTTP/2 fingerprint trips Cloudflare's bot challenge
	// on Docker's endpoints, which arrives as a 403 and is indistinguishable
	// from "this release does not exist".
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
}

type plan struct {
	rb      runbook.Runbook
	params  runbook.Params
	profile host.Profile
	// node is the identity this plan is signed against, the container name
	// on a compose host, the systemd unit on a native one (#398). Held beside
	// the profile rather than re-derived at each use, so the fingerprint, the
	// approval record and the approval check cannot come to disagree.
	node        string
	state       *host.State
	planID      string
	fingerprint string
}

func build(ctx context.Context, o opts) plan {
	o = withSocket(o)
	runner := runnerFor(o)
	sock := o.wrapperSocket
	profile, err := host.DiscoverProfile(ctx, runner, o.container, o.adminRPC)
	if err != nil {
		if sock != "" {
			fail("could not read the deployment through the wrapper socket %s: %v", sock, err)
		}
		fail("could not read the deployment: %v", err)
	}
	st := host.New(ctx, profile, runner, newClient())
	if sock != "" {
		// What reads the node's own files has to go to the wrapper too, as it
		// does in the service; an empty Wrapper reads them directly, which an
		// account with no access to them cannot do.
		st.Wrapper = o.wrapper
	}
	st.LedgerPath = filepath.Join(o.stateDir, "ledger.jsonl")
	rb, err := runbook.V1().Lookup(o.book)
	if err != nil {
		fail("%v", err)
	}
	if rb.DeclaresParam("target_version") && o.target == "" && rb.ID == "upgrade-xrpld" {
		// Derive the recommendation the same way the service does. approve and
		// execute still deserve an explicit target — consenting to "whatever is
		// newest" is not consenting to a plan — and their fingerprint check
		// enforces that the derived value matches what was approved anyway.
		//
		// Only for a runbook that HAS a version. RB-002 restarts the node on
		// the image it is already running, so deriving the newest release
		// here would fetch a number nothing in that plan uses, and fail the
		// whole command on a host with no registry access.
		latest, lerr := st.LatestRelease()
		if lerr != nil {
			fail("--target not given and the latest release could not be determined: %v", lerr)
		}
		o.target = latest
		fmt.Fprintf(os.Stderr, "target not given; the registry's newest release is %s\n\n", latest)
	}
	// RB-004 declares target_version too, and the registry is the wrong place
	// to get it: "the newest published release" is the opposite of a rollback.
	// Its target is derived from this node's own deployment backups and run
	// history — advisord does that; the command line is told.
	if rb.ID == "rollback-node" && o.target == "" {
		fail("--target is required for a rollback: it is the version this node was running " +
			"before, and it is never the registry's newest release. The Advisor derives it " +
			"from the node's dated deployment copies and its own run history")
	}

	if o.evidence != "" {
		if err := st.CaptureEvidence(o.evidence); err != nil {
			fail("could not capture the evidence snapshot: %v", err)
		}
	} else {
		// Same convention and same self-service as the web service: the
		// snapshot is a read the Advisor takes for itself. The precondition
		// only fails when the read does.
		st.EvidencePath = host.ConventionalEvidencePath(o.stateDir)
		if err := st.EnsureEvidence(); err != nil {
			fmt.Fprintf(os.Stderr, "note: could not refresh the evidence snapshot: %v\n", err)
		}
	}
	raw := map[string]any{}
	if rb.DeclaresParam("target_version") {
		raw["target_version"] = o.target
	}
	if rb.DeclaresParam("intent") {
		raw["intent"] = o.intent
	}
	if rb.DeclaresParam("key") {
		raw["key"] = o.cfgKey
		raw["value"] = o.cfgValue
	}
	if rb.DeclaresParam("change") {
		raw["change"] = o.change
		raw["user"] = o.runAs
	}
	// Where the image comes from, resolved HERE and never taken from the
	// command line as a digest. #682: the two doors have to reach one plan,
	// and a fingerprint computed without the pin is a different plan than
	// the one the card shows, so this asks the same reader the service asks
	// and asks it before the plan id is minted.
	//
	// One registry read, the one the service's run door takes (#1033). A
	// read that fails binds the unpinned plan, as the service does, and is
	// said: that plan runs only if it is the one approved, which is what a
	// card on a host the registry does not answer offers.
	if rb.DeclaresParam("digest") && o.source != "build" && o.target != "" {
		src, digest, err := st.RunSource(o.target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "note: could not read where %s comes from (%v); binding the build, "+
				"which runs only if that is the plan you approved\n", o.target, err)
		}
		if err == nil && src == host.OfficialImageSource && digest != "" {
			raw["source"], raw["digest"] = "official", digest
		}
	} else if rb.DeclaresParam("source") && o.source != "" {
		raw["source"] = o.source
	}
	// Which dated copy a rollback puts back, resolved HERE for the same
	// reason the digest above is: the fingerprint is computed from the
	// bound parameters, so the file the approval covers and the file the
	// run restores are the same file only if the name is in the plan
	// (#682, second review).
	if rb.DeclaresParam("restore_path") && o.target != "" {
		if err := bindRestoreCopy(st, raw); err != nil {
			fail("could not read the node to name the copy this rollback restores: %v", err)
		}
	}
	params, err := rb.BindParams(raw)
	if err != nil {
		fail("%v", err)
	}
	node, err := profile.IdentityKey()
	if err != nil {
		fail("%v", err)
	}
	fp := approval.Fingerprint(rb.ID, node, params)
	return plan{rb, params, profile, node, st, "plan-" + fp[:12], fp}
}

// bindRestoreCopy puts the dated copy a rollback restores, and the digest it
// pins, into the parameters a plan id is minted from. The same call the
// service makes at every door (#1029), with this node's run history read off
// the ledger at the state directory: a command line that read no history
// could bind a copy the service refuses as ambiguous, and the two doors would
// mint different plans for one rollback. A read that fails is an error, not
// an empty copy: an empty copy is another plan.
func bindRestoreCopy(st *host.State, raw map[string]any) error {
	name, digest, err := st.PlannedRestoreCopy()
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	raw["restore_path"] = name
	if digest != "" {
		raw["restore_digest"] = digest
	}
	return nil
}

// ── compact ───────────────────────────────────────────────────────────────

func doCompact(o opts) {
	terms := compact.V2()
	path := filepath.Join(o.stateDir, "compact.json")

	if !o.accept {
		fmt.Print(terms.String())
		if a, err := compact.Load(path, o.container); err == nil {
			fmt.Printf("\nACCEPTED by %s on %s\n  privilege %s, classes %v\n",
				a.AcceptedBy, a.AcceptedAt.Format(time.RFC3339), a.Privilege, a.Classes)
		} else {
			fmt.Printf("\nNOT ACCEPTED — %v\n\nAccept with:\n  aperire-executor compact --accept --privilege=D1 --classes=upgrade,investigate,restart,config\n", err)
		}
		return
	}

	var classes []runbook.Class
	for _, c := range strings.Split(o.classes, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Checked against the known set at accept time — B2 adds a class
		// with no runbook behind it (`investigate`), which makes a typo
		// here a bigger papercut than it used to be: nothing else in this
		// path validates a class against the registry (plan-interrogative-
		// loop §11.6). `investigate` is explicitly allowed even though no
		// runbook declares it.
		if !runbook.KnownClass(runbook.Class(c)) {
			fail("--classes: %q is not a known class (%v)", c, runbook.KnownClasses())
		}
		classes = append(classes, runbook.Class(c))
	}
	if len(classes) == 0 {
		fail("--classes may not be empty; a compact permitting nothing is not a compact")
	}

	a := compact.Acceptance{
		TermsVersion: terms.Version, TermsHash: terms.Hash(),
		AcceptedBy: whoami(), AcceptedAt: time.Now().UTC(),
		Node: o.container, Privilege: compact.PrivilegeOption(o.privilege), Classes: classes,
	}
	// Say plainly what this privilege option is and is not on this host.
	if a.Privilege == compact.OptionD1 {
		a.Notes = map[string]string{
			"boundary": "The wrapper is the only path the executor uses. If the account running " +
				"the executor is in the docker group, that is an allow-list and an audit trail, " +
				"not containment: docker group membership is root-equivalent. Full D1 means a " +
				"dedicated user with no docker group, reaching the wrapper only through its root " +
				"socket (ADR 0025), never sudo.",
		}
	}
	if err := compact.Save(path, a); err != nil {
		fail("%v", err)
	}
	l := openLedger(o)
	// The actor moves out of the summary prose and into a field. It used to be
	// readable only by parsing the sentence, which is not a record.
	l.AppendAs(ledger.KindCompactAccepted, "",
		fmt.Sprintf("compact %s accepted by %s for %s under %s", terms.Version, a.AcceptedBy, a.Node, a.Privilege),
		map[string]any{"terms_hash": a.TermsHash, "privilege": string(a.Privilege),
			"classes": a.Classes, "notes": a.Notes}, osActor())

	fmt.Print(terms.String())
	fmt.Printf("\nAccepted by %s for %s.\n  privilege %s\n  classes   %v\n  recorded  %s\n",
		a.AcceptedBy, a.Node, a.Privilege, classes, filepath.Join(o.stateDir, "ledger.jsonl"))
	if a.Notes != nil {
		fmt.Printf("\n  %s\n", a.Notes["boundary"])
	}
}

func openLedger(o opts) *ledger.Ledger {
	path := filepath.Join(o.stateDir, "ledger.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		fail("ledger: %v\n%s", err, brokenChainHint(path))
	}
	return l
}

// ── check / advise ────────────────────────────────────────────────────────

func doEvaluate(mode string, o opts) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p := build(ctx, o)

	var verdicts []runbook.Verdict
	blocked := false
	for _, pc := range p.rb.Preconditions {
		v := pc.Check(p.params, p.state)
		verdicts = append(verdicts, v)
		if !v.Passed {
			blocked = true
		}
	}
	// The manual rendering is the upgrade's. There is no hand-run sequence to
	// print for a restart: it is one wrapper call, and `advise` would
	// otherwise print five upgrade steps under a restart's heading.
	var steps []advise.Step
	if p.rb.DeclaresParam("target_version") {
		steps = advise.UpgradeSteps(p.profile, o.target)
	}
	pl := advise.Plan{RunbookID: p.rb.ID, Summary: p.rb.Summary, Profile: p.profile,
		Verdicts: verdicts, Blocked: blocked, Steps: steps}

	if o.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{"plan_id": p.planID, "fingerprint": p.fingerprint,
			"runbook": p.rb.ID, "target": o.target, "profile": p.profile,
			"verdicts": verdicts, "blocked": blocked})
	} else {
		var b strings.Builder
		b.WriteString("DRY RUN — nothing on this host was changed.\n\n")
		fmt.Fprintf(&b, "Plan      %s\n", p.planID)
		fmt.Fprintf(&b, "Confirm   %s\n", approval.ConfirmCode(p.fingerprint))
		if mode == "check" {
			renderChecks(&b, pl)
		} else {
			pl.Render(&b)
		}
		fmt.Print(b.String())
	}
	if blocked {
		os.Exit(1)
	}
}

func renderChecks(b *strings.Builder, p advise.Plan) {
	fmt.Fprintf(b, "%s on %s\n\n", p.RunbookID, p.Profile.Container)
	for _, v := range p.Verdicts {
		fmt.Fprintf(b, "[%s] %s\n       %s\n", v.Word(), v.Name, v.Detail)
	}
	if f := p.Failures(); len(f) > 0 {
		fmt.Fprintf(b, "\n%d of %d preconditions refused.\n", len(f), len(p.Verdicts))
	} else {
		fmt.Fprintf(b, "\nAll %d preconditions pass.\n", len(p.Verdicts))
	}
}

// ── approve ───────────────────────────────────────────────────────────────

// doApprove no longer grants anything, and says so.
//
// It used to write an approval and print "Approved:" with a confirm code. That
// approval could never be spent: execute verifies the passkey assertion behind
// an approval through CheckSigned, and one written here carries none, so it is
// refused as ErrUnsigned every time. The command reported success for something
// that was guaranteed to fail — the worst shape a security tool can have,
// because the operator believes a step is done.
//
// Kept rather than deleted so anyone with it in their notes gets an
// explanation instead of "unknown command", and kept refusing rather than
// fixed because there is nothing to fix: an approval means a person touched a
// key, and a command-line flag is not a person touching a key. That is the
// property, not a limitation of the implementation. The grant path it used to
// run is in the history if anyone needs to see what it wrote.
func doApprove(o opts) {
	fmt.Fprintf(os.Stderr, `This command cannot grant an approval, and never could.

An approval is a passkey signature over a challenge this host issued, bound to
one plan and one stage. Executing spends it and verifies the signature; an
approval without one is refused as unsigned. This command has no way to
produce a signature, so what it used to write was rejected every time — after
printing that it had worked.

Approve from the Advisor tab: it asks for the confirm code and then for your
passkey, per stage. Nothing else can stand in for that, here or anywhere.

To see what would run without approving anything:
  aperire-executor plan --target=%s
`, o.target)
	os.Exit(64)
}

// ── execute ───────────────────────────────────────────────────────────────

func doExecute(o opts) {
	// Never as root (#1074 review, L1). The approvals, their lock and their
	// claims belong to the Advisor's own account, and every documented way
	// to run this is `sudo -u <advisor account>`. Root writing there is how
	// a link that account planted becomes its copy of a root file.
	if err := refuseRoot("execute"); err != nil {
		fail("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	o = withSocket(o)
	p := build(ctx, o)
	// Which stages exist is the runbook's to say, not this command's. It
	// used to name prepare and cutover as a constant, so a one-stage runbook
	// was refused by the tool that was supposed to run it.
	if !stageIn(p.rb.Stages, o.stage) {
		fail("--stage must be one of %v for %s", p.rb.Stages, p.rb.ID)
	}

	acc, err := compact.Load(filepath.Join(o.stateDir, "compact.json"), o.container)
	if err != nil {
		fail("%v", err)
	}
	if !acc.Permits(p.rb.Class) {
		fail("the compact does not permit the %q class", p.rb.Class)
	}
	// Through the root socket the wrapper is the broker's to find, not this
	// account's: the copy it runs is root-owned and may be unreadable here.
	if o.wrapperSocket == "" {
		if _, err := os.Stat(o.wrapper); err != nil {
			fail("privilege wrapper not found at %s", o.wrapper)
		}
	}

	// A grant another run holds (#1063): the service shares no lock with
	// this tool, so its run is found by the claim on the grant. Asked BEFORE
	// anything is written to the ledger (#1091): the refusal used to come
	// after a plan.created row, and that row, written while the run that held
	// the grant was mid-stage, forked the chain. A refused run leaves no
	// trace in a ledger it cannot join. Refused before the transcript is
	// opened as well, because the two runs would share one.
	if c, held := approval.HeldBy(filepath.Join(o.stateDir, "approvals"), p.planID, o.stage,
		time.Now()); held {
		fail("%v. Nothing was done", c)
	}

	l := openLedger(o)
	l.AppendAs(ledger.KindPlanCreated, p.planID,
		fmt.Sprintf("%s to %s on %s", p.rb.ID, o.target, p.profile.Container),
		map[string]any{"runbook": p.rb.ID, "target": o.target, "fingerprint": p.fingerprint,
			"profile": p.profile, "privilege": string(acc.Privilege), "wrapper": o.wrapper},
		osActor())

	// The executor verifies the passkey behind an approval itself. Without a
	// credential store there is nothing to verify against, and CheckSigned
	// refuses rather than waving it through — an unverifiable approval and an
	// unverified one look identical from outside.
	creds, err := host.LoadCredentials(filepath.Join(o.stateDir, "credentials.json"))
	if err != nil {
		fail("credential store: %v", err)
	}

	// The live transcript, so the tab can show what is happening rather than
	// what has finished. Named from the plan and stage, so a reload finds the
	// same stream.
	rl, rlErr := execute.OpenRunLog(filepath.Join(o.stateDir, "runs"),
		execute.RunID(p.planID, o.stage))
	if rlErr != nil {
		fmt.Fprintf(os.Stderr, "note: no live transcript (%v)\n", rlErr)
	}
	defer rl.Close()

	ex := &execute.Executor{
		PlanID: p.planID, Runbook: p.rb, Params: p.params, Wrapper: o.wrapper,
		State: p.state, Ledger: l, Runner: runnerFor(o),
		ApprovalDir: filepath.Join(o.stateDir, "approvals"),
		DigestDir:   filepath.Join(o.stateDir, "digests"),
		Fingerprint: p.fingerprint, Node: p.node,
		Verifier:  creds,
		Log:       rl,
		ClaimedBy: "aperire-executor",
		// Issue #93. The CLI reads the same approval directory the web path
		// does, so an approval spent here is the same approval burned there —
		// and this is the recovery path, where a refusal that costs nothing is
		// worth more, not less. Fails open like every other reading of it.
		// The --wait read, with no time limit: this is the spend guard, and a
		// bounded read cut into "unknown" would fail open (#1043).
		RotationInFlight: p.state.RotationInFlightWait,
	}
	// The run is over when this returns, and its grant with it (#1063). A
	// stage that ends under a compound grant leaves it claimed, for a
	// restart this run goes on to or for this. os.Exit skips it, so every
	// exit after a stage that can end that way settles it first.
	defer settleOrSay(ex)
	// Ctrl-C, or a stop from the service manager, at a confirm prompt or
	// mid-build (#1074 review, L3). Without this the process died holding
	// its claim, and the next approval of this plan was refused naming a
	// process that no longer existed until the claim lapsed. A run told to
	// stop has stopped: its approval is spent, and this says so.
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupted
		fmt.Fprintf(os.Stderr, "\n%s\n", ex.Interrupt())
		os.Exit(130)
	}()

	when := "before " + o.stage
	if _, ok := ex.CheckPreconditions(o.stage, when); !ok {
		fmt.Fprintln(os.Stderr, "\npreconditions refuse — nothing was done:")
		for _, pc := range p.rb.Preconditions {
			if pc.Gates != "" && pc.Gates != o.stage {
				continue
			}
			if v := pc.Check(p.params, p.state); !v.Passed {
				fmt.Fprintf(os.Stderr, "  [FAIL] %s — %s\n", v.Name, v.Detail)
			}
		}
		os.Exit(1)
	}

	// The pin the PLAN carries, never a second reading. Resolving it again
	// here would let a tag moved between the plan and the run decide what
	// gets installed, which is the substitution the pin exists to prevent.
	steps := execute.LocalImageUpgradeSteps(o.target)
	if d := p.params["digest"]; d != "" {
		fmt.Printf("%s:%s, pinned at %s\n", host.OfficialImageRepo, o.target, d)
		steps = execute.OfficialImageUpgradeSteps(o.target, d)
	}
	if p.state.Kind() == "native" {
		steps = execute.NativeUpgradeSteps(o.target)
	}
	switch p.rb.ID {
	case "restart-node":
		steps = execute.RestartSteps()
	case "rollback-node":
		if p.state.Kind() == "native" {
			// No local image cache to ask about on this kind, RB-004's own
			// "the rollback target is installable" precondition already
			// asked the repositories directly.
			steps = execute.NativeRollbackSteps(o.target)
		} else {
			// Local first, for the reason RB-004's own precondition takes
			// that order: the target is the image this node was running
			// until the upgrade, and the registry is the thing least worth
			// depending on at the moment a rollback is wanted.
			// Which origin holds it decides both the fetch and the verb
			// that writes the deployment file: an image built on this host
			// is named with set-image-local and never pulled, and an
			// official one is rolled back by restoring the whole copy.
			//
			// RollbackTargetOrigin, not ImageLocal, since #680: presence
			// cannot express "built here and since pruned", so the rebuild
			// branch was unreachable and the run fell through to a pull of
			// a localhost/ name no registry answers for.
			im := p.state.RollbackImaging(o.target, p.params["restore_path"])
			fmt.Printf("%s\n", im.Detail)
			// The digest the plan was minted with, against the copy as it
			// reads now (#682, third review).
			sh, cerr := execute.RollbackShapeChecked(o.target, p.params["restore_digest"], im)
			if cerr != nil {
				fail("%v", cerr)
			}
			steps = execute.RollbackSteps(sh)
		}
	case "normalise-deployment":
		// ADR 0023. One change, and the wrapper takes a dated copy of the
		// deployment before it writes: the reversal is restoring that copy.
		steps = execute.NormaliseSteps(p.params["change"], p.params["user"])
	case "config-change":
		// The diff is computed here for the same reason the web path computes
		// it: the wrapper reports how many lines it rewrote, and the only way
		// that number means anything is to have counted them first.
		cfg, cerr := p.state.NodeConfiguration()
		if cerr != nil {
			fail("the node configuration could not be read, so the change could not be checked "+
				"before it was made: %v", cerr)
		}
		// Both shapes, through the same reading the service's gate uses. This
		// used to look for a `key=` line whatever the key was, which meant
		// the command-line path refused node_size on every node that has one.
		ch, cherr := cfg.ChangeFor(o.cfgKey, o.cfgValue)
		if cherr != nil {
			fail("%v", cherr)
		}
		fmt.Printf("%s on %s\n", cfg.File, cfg.Host)
		if ch.Stanza != "" {
			// The header names the setting and does not change. Printed as
			// context, unmarked, the same way the gate renders it.
			fmt.Printf("    [%s]\n", ch.Stanza)
		}
		for _, ln := range ch.Before {
			fmt.Printf("  - %s\n", ln)
		}
		for _, ln := range ch.After {
			fmt.Printf("  + %s\n", ln)
		}
		steps = append(execute.ConfigSteps(o.cfgKey, o.cfgValue, len(ch.Before)), execute.RestartSteps()...)
	}
	fmt.Printf("Plan %s — stage %s\n\n", p.planID, o.stage)

	// The build the node reports right now, read before anything is touched.
	// A restart is confirmed against this and never against a parameter — and
	// if it cannot be read, this stops rather than restarting with the
	// confirmation silently disabled.
	baseline := ""
	if o.stage == approval.StageRestart || o.stage == approval.StageConfig ||
		o.stage == approval.StageRollback {
		v, verr := p.state.RunningVersion()
		if verr != nil || v == "" {
			fail("the node did not say what version it is running, so a restart could not be " +
				"confirmed afterwards; nothing was restarted")
		}
		baseline = v
	}

	// Set when the node restarted onto the right build and was not seen
	// back in full sync inside the window.
	unconfirmed := false

	confirm := func(s execute.Step, out string) bool {
		if o.yes {
			return true
		}
		fmt.Printf("\n  %q could not be confirmed.\n  wrapper said: %q\n", s.Name, out)
		fmt.Print("  That is not proof it is wrong. Continue? [type yes] ")
		var r string
		fmt.Scanln(&r)
		return r == "yes"
	}

	// The approval has to last until the run reaches its last step that
	// needs it, the restart of a config change approved together with it
	// included (#772). Refused before the grant is claimed, so nothing is
	// spent and nothing has moved.
	runStages := []string{o.stage}
	if o.stage == approval.StageConfig {
		if _, cerr := approval.Check(ex.ApprovalDir, p.planID, p.fingerprint, p.node,
			approval.StageRestart, time.Now()); cerr == nil {
			runStages = append(runStages, approval.StageRestart)
		}
	}
	if serr := execute.ApprovalLasts(ex.ApprovalDir, p.planID, p.fingerprint, p.node,
		runStages, steps, time.Now()); serr != nil {
		data := map[string]any{"error": serr.Error()}
		var short *execute.ShortApprovalError
		if errors.As(serr, &short) {
			data = short.Data()
		}
		data["door"] = "cli"
		l.AppendAs(ledger.KindRefusal, p.planID,
			"run refused: the approval would run out before the run reached its last step that needs it",
			data, osActor())
		fail("%v", serr)
	}

	if err := ex.RunStage(ctx, o.stage, steps, confirm); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
		if h := ex.RollbackHint(); h != "" {
			fmt.Fprintf(os.Stderr, "\nRollback:\n%s\n", h)
		}
		fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
		os.Exit(1)
	}

	// The config stage's own hand-off, mirroring the web path: the compound
	// grant covers the edit and then the restart, and the restart is what
	// makes the change real. Re-checked NOW rather than trusted from before
	// the edit ran.
	if o.stage == approval.StageConfig {
		if _, cerr := approval.Check(filepath.Join(o.stateDir, "approvals"),
			p.planID, p.fingerprint, p.node, approval.StageRestart, time.Now()); cerr != nil {
			fmt.Printf("\nThe configuration is written. This setting is read at startup, so it is not\n")
			fmt.Printf("in effect yet: it takes effect at the next restart, which is its own approval.\n")
			settleOrSay(ex)
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			return
		}
		fmt.Printf("\nThe configuration is written — one approval covers the restart too.\n")
		if _, ok := ex.CheckPreconditions(approval.StageRestart, "before restart (auto-chained)"); !ok {
			fmt.Fprintln(os.Stderr, "\nThe automatic restart did not proceed:")
			for _, pc := range p.rb.Preconditions {
				if pc.Gates != "" && pc.Gates != approval.StageRestart {
					continue
				}
				if v := pc.Check(p.params, p.state); !v.Passed {
					fmt.Fprintf(os.Stderr, "  [FAIL] %s — %s\n", v.Name, v.Detail)
				}
			}
			fmt.Fprintln(os.Stderr, "\nThe node is still running on the configuration it started with.")
			settleOrSay(ex)
			os.Exit(1)
		}
		if err := ex.RunStage(ctx, approval.StageRestart, steps, confirm); err != nil {
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			if h := ex.RollbackHint(); h != "" {
				fmt.Fprintf(os.Stderr, "\nRollback:\n%s\n", h)
			}
			os.Exit(1)
		}
	}

	if o.stage == approval.StageRollback {
		fmt.Printf("\nWaiting for the node to come back on %s and return to full sync.\n", o.target)
		// This node's own measured outage, the sentence the Advisor's gate
		// shows (#1014), rather than a figure from another node.
		fmt.Printf("Expected: %s.\n", outage.FromLedgerFile(filepath.Join(o.stateDir, "ledger.jsonl")).Sentence())
		fmt.Printf("A rollback may also have to rebuild from the network, and the node is not\n")
		fmt.Printf("validating while it does.\n")
		// The same confirmation the web run uses, from the same place, with
		// the outgoing version tolerated for a bounded moment — the version
		// the node was running a second ago is the ordinary shape of a
		// rollback in flight, not a finding.
		verdict, found, proof := ex.AwaitRollback(o.target, baseline, o.timeout, func(v, d string) {
			fmt.Printf("\r  version=%-8s %-60s", v, truncate(d, 60))
		})
		fmt.Println()
		switch verdict {
		case execute.RestartBack:
			fmt.Printf("\n%s.\n", execute.SyncedLine(execute.OpRollback, proof, false))
		case execute.RestartVersionChanged:
			fmt.Fprintf(os.Stderr, "\n%s\n", execute.RollbackStalledNote(o.target, found, baseline))
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			os.Exit(1)
		case execute.RestartNotObserved:
			fmt.Fprintf(os.Stderr, "\n%s\n", execute.NotRestartedNote(proof))
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			os.Exit(1)
		case execute.RestartStillCatchingUp:
			fmt.Printf("\n%s\n", execute.RollbackUnconfirmedNote(o.target, baseline, p.state.Wrapper))
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			os.Exit(exitUnconfirmed)
		}
		fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
		return
	}

	if o.stage == approval.StageRestart || o.stage == approval.StageConfig {
		fmt.Printf("\nWaiting for the node to come back on %s and return to full sync.\n", baseline)
		fmt.Printf("Measured on a node of this class: 8 to 10 minutes back to full, most of it\n")
		fmt.Printf("spent in connected while it catches up from its own store.\n")
		// The same confirmation the web run uses, from the same place. Not
		// AwaitHealthy: that one waits out its whole window before saying
		// anything, so a node that came back on a DIFFERENT build would be
		// called "still catching up" for fifteen minutes, told the operator
		// that was normal, and left a run.unconfirmed entry on the ledger for
		// a node that was up and answering.
		verdict, found, proof := ex.AwaitRestart(baseline, o.timeout, func(v, d string) {
			fmt.Printf("\r  version=%-8s %-60s", v, truncate(d, 60))
		})
		fmt.Println()
		switch verdict {
		case execute.RestartBack:
			fmt.Printf("\n%s.\n", execute.SyncedLine(execute.OpRestart, proof, false))
		case execute.RestartVersionChanged:
			fmt.Fprintf(os.Stderr, "\n%s\n", execute.RestartVersionChangedNote(baseline, found))
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			os.Exit(1)
		case execute.RestartNotObserved:
			fmt.Fprintf(os.Stderr, "\n%s\n", execute.NotRestartedNote(proof))
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			os.Exit(1)
		case execute.RestartStillCatchingUp:
			fmt.Printf("\nYour node restarted and has not returned to full sync yet.\n")
			fmt.Printf("That is normal — it catches up from its own store. Nothing was changed by\n")
			fmt.Printf("this run, so there is nothing to roll back. Watch server_state move through\n")
			fmt.Printf("connected to full; if it is still not full in half an hour, the node's own\n")
			fmt.Printf("logs are the way forward, not a second restart.\n")
			unconfirmed = true
		}
	}

	if o.stage == approval.StageCutover {
		fmt.Println("\nWaiting for the node to report the new version and return to full sync.")
		proof, err := ex.AwaitHealthy(o.target, o.timeout, func(v, d string) {
			fmt.Printf("\r  version=%-8s %-60s", v, truncate(d, 60))
		})
		fmt.Println()
		switch {
		case err == nil:
			fmt.Printf("\n%s.\n", execute.SyncedLine(execute.OpUpgrade, proof, false))
		case errors.Is(err, execute.ErrNotYetHealthy):
			// The restart worked. Exiting non-zero here says the upgrade
			// failed, and a node that is merely still catching up gets rolled
			// back on the strength of that.
			fmt.Printf("\nYour node is running %s and has not returned to full sync yet.\n", o.target)
			fmt.Printf("That is normal after a restart — it catches up from its own store.\n")
			fmt.Printf("Watch server_state move through connected to full. If it is still not\n")
			fmt.Printf("full in half an hour, the way back is:\n\n%s\n", ex.RollbackHint())
			unconfirmed = true
		default:
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			fmt.Fprintf(os.Stderr, "\nRollback:\n%s\n", ex.RollbackHint())
			fmt.Fprintf(os.Stderr, "\nledger head %s\n", l.Head()[:16])
			os.Exit(1)
		}
	}

	// "Complete" only for a stage the node proved (#769). A restart the node
	// came back from on the right build but has not finished syncing is
	// neither done nor failed, and says so, with its own exit status so a
	// script cannot read it as either.
	if unconfirmed {
		fmt.Printf("\nStage %s ran; the node has not reached full sync yet.\n", o.stage)
	} else {
		fmt.Printf("\nStage %s complete.\n", o.stage)
	}
	fmt.Printf("ledger  %s\n", filepath.Join(o.stateDir, "ledger.jsonl"))
	fmt.Printf("head    %s\n", l.Head()[:16])
	if unconfirmed {
		os.Exit(exitUnconfirmed)
	}
	if o.stage == approval.StagePrepare {
		// This used to hand the operator an approve command that could never
		// work, at the exact moment they most needed the next step to be
		// right: prepared, validation not yet interrupted, looking for how to
		// finish. The cutover approval has to be made where a passkey can be
		// asked for.
		// Said from the node's own reading (#769): on a native host the
		// package install can restart it.
		if r := ex.Reading(o.target); r.State() == execute.NotRestarted {
			fmt.Printf("\nThe node was not restarted: it reports %s from the process that was\n", r.Version())
			fmt.Printf("running before this run began. To cut over, approve the\n")
		} else if r.Restarted() {
			fmt.Printf("\nThe package install restarted the node itself; it reports %s, %s.\n", r.Version(), r.ServerState())
			fmt.Printf("Check it before cutting over. To cut over, approve the\n")
		} else {
			fmt.Printf("\nThe node gave no reading (%s), so whether it restarted is not known.\n", r.ReadError())
			fmt.Printf("Check it before cutting over. To cut over, approve the\n")
		}
		fmt.Printf("restart in the Advisor tab — it asks for the confirm code and then\n")
		fmt.Printf("your passkey — and then:\n")
		fmt.Printf("  aperire-executor execute --target=%s --stage=cutover\n", o.target)
		if h := ex.RollbackHint(); h != "" {
			fmt.Printf("\nOr stop here and roll back:\n%s\n", h)
		}
	}
}

// stageIn is membership, so the refusals below read as the question they ask.
// geteuid is os.Geteuid, a variable so a test can stand in for root.
var geteuid = os.Geteuid

// refuseRoot is execute's and cancel's first check (#1074 review): the
// approvals they claim, spend and withdraw belong to the Advisor's own
// account, and every documented way to run them is as that account. Root
// writing there is how a link that account planted becomes its copy of a
// root file.
func refuseRoot(verb string) error {
	if geteuid() != 0 {
		return nil
	}
	return fmt.Errorf("run this as the Advisor's own account (sudo -u <advisor account> ./bin/aperire-executor %s ...), "+
		"never as root: the approvals and the ledger it writes belong to that account. Nothing was done", verb)
}

// settleOrSay spends what the run still holds, and says so on the terminal
// when the grant could not be spent and is still live (#1061).
func settleOrSay(ex *execute.Executor) {
	if err := ex.Finish(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
	}
}

func stageIn(stages []string, stage string) bool {
	for _, x := range stages {
		if x == stage {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ── ledger ────────────────────────────────────────────────────────────────

func doLedger(o opts) {
	path := filepath.Join(o.stateDir, "ledger.jsonl")
	if o.repair {
		doLedgerRepair(path)
		return
	}
	entries, err := ledger.Entries(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CHAIN BROKEN: %v\n%s", err, brokenChainHint(path))
		os.Exit(1)
	}
	if o.verify {
		fmt.Printf("%s: %d entries, chain intact\n", path, len(entries))
		if len(entries) > 0 {
			fmt.Printf("head %s\n", entries[len(entries)-1].Hash)
		}
		return
	}
	if o.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(entries)
		return
	}
	for _, e := range entries {
		fmt.Printf("%3d  %s  %-24s %s\n", e.Seq, e.At.Format("2006-01-02 15:04:05"), e.Kind, e.Summary)
	}
	fmt.Printf("\n%d entries, chain intact\n", len(entries))
}

// brokenChainHint says what to do about a chain that does not verify: name
// --repair when the break is a fork it can move out, and say plainly when it is
// not, so nobody reaches for the repair on a file that was altered.
func brokenChainHint(path string) string {
	f, err := ledger.Diagnose(path)
	if err != nil {
		var naf *ledger.NotAForkError
		if errors.As(err, &naf) {
			return "\nThis is not a fork, so `ledger --repair` will not touch it: " + naf.Reason +
				".\nKeep the file as it is; it is the evidence.\n"
		}
		return ""
	}
	return fmt.Sprintf("\nThis is a fork: %d row(s) follow entry %d that another row also follows, and no row "+
		"was altered or removed.\n`aperire-executor ledger --repair` keeps the row written first at the fork, moves the "+
		"rest into a sidecar file and carries them whole in one new row,\nkeeps a copy of the ledger as it is now, "+
		"and prints what it did. Run it as the Advisor's own account, with no run in progress.\n",
		len(f.Moved), f.After)
}

// doLedgerRepair is `ledger --repair` (#1091). It prints what it did, every
// time, and never as root: a rewritten file owned by root is one the
// Advisor's service can no longer append to.
func doLedgerRepair(path string) {
	if err := refuseRoot("ledger --repair"); err != nil {
		fail("%v", err)
	}
	// Not while a run holds an approval: that run is writing to this ledger.
	// The question is asked with the ledger lock held, but a claim takes the
	// approvals lock, not this one, so a run can still claim just after it.
	// That is harmless: its rows wait on the ledger lock until the repair is
	// done and then follow the repaired file, which is what the lock is for.
	// The check keeps a repair from starting under a run that is already
	// going; it is not what keeps the chain whole.
	approvals := filepath.Join(filepath.Dir(path), "approvals")
	rep, err := ledger.Repair(path, osActor(), time.Now(), func() error {
		if c, held := approval.HeldAnywhere(approvals, time.Now()); held {
			return fmt.Errorf("a run holds an approval, so the ledger is in use and is not repaired now: %v", c)
		}
		return nil
	})
	switch {
	case errors.Is(err, ledger.ErrNothingToRepair):
		fmt.Printf("%s: the chain is intact. Nothing was changed.\n", path)
		return
	case err != nil:
		fmt.Fprintf(os.Stderr, "%v\nNothing was changed.\n", err)
		os.Exit(1)
	}
	fmt.Printf("Ledger repaired: %s\n", path)
	fmt.Printf("  fork      more than one row followed entry %d\n", rep.Fork.After)
	fmt.Printf("  kept      %d row(s), unchanged: the row written first at the fork stays, with everything before it\n", rep.Fork.Kept)
	fmt.Printf("  moved     %d row(s), unedited, to %s\n", len(rep.Fork.Moved), rep.ForkFile)
	for _, m := range rep.Fork.Moved {
		fmt.Printf("              entry %d  %s  %s  %s\n", m.Seq, m.At.Format("2006-01-02 15:04:05"), m.Kind, m.Summary)
	}
	fmt.Printf("  carried   those rows, whole, in entry %d (%s), so the ledger still says what they recorded\n",
		rep.Entry.Seq, rep.Entry.Kind)
	fmt.Printf("  copy      the ledger as it was: %s\n", rep.Backup)
	fmt.Printf("  head      %s\n", rep.Entry.Hash[:16])
	if es, verr := ledger.Entries(path); verr != nil {
		fmt.Fprintf(os.Stderr, "the repaired ledger does not verify: %v\n", verr)
		os.Exit(1)
	} else {
		fmt.Printf("\n%d entries, chain intact\n", len(es))
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aperire-executor: %s\n", fmt.Sprintf(format, args...))
	os.Exit(2)
}

// ── memory ────────────────────────────────────────────────────────────
//
// Confirming is the only way a conclusion the Advisor drew becomes something
// it may later cite as Documented. It lives here, on the command line, rather
// than in the drawer: agreeing with a conclusion is the operator vouching for
// it, and a button beside the text that made the claim is too easy to press
// without reading.

func doMemory(o opts) {
	// Opening the store makes its directory. For these verbs that would
	// answer "no memory" from a directory this command just created in the
	// wrong place (#1238).
	if _, serr := os.Stat(o.stateDir); errors.Is(serr, os.ErrNotExist) {
		fail("there is no Advisor state directory at %s. Nothing was changed.\nName the right one with --state, or run from the advisor directory.", o.stateDir)
	}
	store, err := memory.Open(filepath.Join(o.stateDir, "memory.jsonl"))
	if err != nil {
		fail("%v", err)
	}
	if o.confirm != "" && o.retract != "" {
		fail("--confirm and --retract name opposite verdicts; give one")
	}
	if o.retract != "" {
		e, err := retractMemory(store, o.stateDir, o.retract, o.reason)
		if err != nil {
			fail("%s", memoryFailure(err, o.stateDir, os.Args))
		}
		fmt.Printf("retracted %s: %s\n", e.ID, e.Title)
		fmt.Println("The Advisor will not recall it again. The memory file keeps the note with this retraction, and the ledger records it.")
		return
	}
	if o.confirm != "" {
		e, err := store.Confirm(o.confirm, operatorName())
		if err != nil {
			fail("%s", memoryFailure(err, o.stateDir, os.Args))
		}
		fmt.Printf("confirmed %s — %s\n", e.ID, e.Title)
		fmt.Println("The Advisor may now cite this as Documented rather than as its own guess.")
		return
	}

	all, err := store.All()
	if err != nil {
		fail("%s", memoryFailure(err, o.stateDir, os.Args))
	}
	if len(all) == 0 {
		fmt.Println("Nothing remembered yet.")
		fmt.Println("The Advisor writes an entry when a conversation establishes something")
		fmt.Println("worth having next time. It comes back marked unconfirmed until you agree.")
		return
	}
	if o.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(all)
		return
	}
	unconfirmed := 0
	for _, e := range all {
		mark := "unconfirmed"
		switch e.Kind {
		case memory.KindConfirmed:
			mark = "confirmed by " + e.ConfirmedBy
		case memory.KindObserved:
			mark = "observed"
		}
		if e.Kind == memory.KindConcluded {
			unconfirmed++
		}
		fmt.Printf("\n%s  %s  [%s]\n  %s\n", e.ID, e.At.Format("2006-01-02 15:04"), mark, e.Title)
		for _, line := range strings.Split(strings.TrimSpace(e.Body), "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Printf("\n%d entries", len(all))
	if unconfirmed > 0 {
		fmt.Printf(", %d unconfirmed — read one and agree with it:\n", unconfirmed)
		fmt.Printf("  aperire-executor memory --confirm <id>\n")
		fmt.Printf("or withdraw one that is wrong:\n")
		fmt.Printf("  aperire-executor memory --retract <id> --reason \"<why>\"\n")
	} else {
		fmt.Println()
	}
}

// memoryFailure words a failed memory verb. A file this account cannot read
// is not a note that is missing: the note may be live, and the operator has to
// hear that it was not looked for, and which account can look (#1238). The
// account is whoever owns the state directory, the same rule
// aperire-compact-check uses; the command to repeat is the one they typed.
func memoryFailure(err error, stateDir string, argv []string) string {
	var ue *memory.UnreadableError
	if errors.As(err, &ue) && ue.Permission() {
		owner := "<the account the Advisor runs as>"
		if fi, serr := os.Stat(stateDir); serr == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				if u, uerr := user.LookupId(strconv.Itoa(int(st.Uid))); uerr == nil {
					owner = u.Username
				}
			}
		}
		return fmt.Sprintf("this account cannot read the Advisor's notes (%s: permission denied), so nothing was looked up or changed.\n"+
			"Run the same command as the account that owns %s:\n  sudo -u %s %s", ue.Path, stateDir, owner, shellWords(argv))
	}
	if errors.Is(err, memory.ErrNoStore) {
		return fmt.Sprintf("%v. Nothing was changed.\nThis command looks in %s; if the Advisor's notes live elsewhere, name that directory with --state.", err, stateDir)
	}
	return err.Error()
}

// shellWords is argv as one line a shell reads back as the same words. The
// command printed for the operator to repeat carries their --reason, which
// has spaces: unquoted, it would run again with a different, shorter reason
// and write that into the ledger.
func shellWords(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		safe := a != ""
		for _, r := range a {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%_+=:,./-", r)) {
				safe = false
				break
			}
		}
		if safe {
			out[i] = a
		} else {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}

// retractMemory withdraws one note and records who did it, in the memory
// file and in the hash-chained ledger: the memory file is the Advisor's own
// and anyone who can write it can rewrite it, while the ledger shows an edit.
// A ledger that cannot be opened is said, not fatal: the retraction itself is
// what the operator asked for.
func retractMemory(store *memory.Store, stateDir, id, why string) (memory.Entry, error) {
	e, err := store.Retract(id, operatorName(), why)
	if err != nil {
		return e, err
	}
	l, lerr := ledger.Open(filepath.Join(stateDir, "ledger.jsonl"))
	if lerr != nil || l == nil {
		fmt.Fprintf(os.Stderr, "the retraction is in the memory file, but the ledger could not be opened: %v\n", lerr)
		return e, nil
	}
	l.AppendAs(ledger.KindMemoryRetracted, "", "a memory note was retracted: "+e.ID,
		map[string]any{"id": e.ID, "node": e.Node, "reason": e.RetractedWhy,
			"retracted_by": e.RetractedBy}, osActor())
	return e, nil
}

// ── cancel ────────────────────────────────────────────────────────────
//
// Abandon a plan and leave the deployment coherent. Not a rollback: that is
// RB-002, for an upgrade that completed and went wrong. This is for one that
// never finished, and the state it exists for is prepare having pointed the
// compose file at a version the node is not running.

func doCancel(o opts) {
	// Never as root, for the reason execute refuses it: the approvals it
	// spends belong to the Advisor's own account (#1074 review).
	if err := refuseRoot("cancel"); err != nil {
		fail("%v", err)
	}
	if o.stage == "" {
		o.stage = "prepare"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o = withSocket(o)
	p := build(ctx, o)

	l := openLedger(o)
	rl, _ := execute.OpenRunLog(filepath.Join(o.stateDir, "runs"),
		execute.RunID(p.planID, o.stage+"-cancel"))
	defer rl.Close()

	c := &execute.Canceller{
		PlanID: p.planID, Stage: o.stage, Wrapper: o.wrapper,
		Runner: runnerFor(o), Ledger: l, Log: rl, State: p.state,
		ComposeFile: p.profile.ComposeFile, ImageRepo: p.profile.ImageRepo,
		RunDir:      filepath.Join(o.stateDir, "runs"),
		ApprovalDir: filepath.Join(o.stateDir, "approvals"),
		Actor:       osActor(),
	}

	fmt.Printf("Cancelling %s stage %s\n\n", p.planID, o.stage)
	rep, err := c.Cancel(ctx)

	fmt.Printf("  before   compose %s · node %s · %s\n",
		orNone(rep.Before.ComposeTag), orNone(rep.Before.RunningVersion), rep.Before.Consensus)
	if err != nil {
		fmt.Printf("\nREFUSED: %v\n", err)
		if rep.Refused != "" {
			fmt.Printf("  %s\n", rep.Refused)
		}
		os.Exit(1)
	}
	if rep.Restored != "" {
		fmt.Printf("  restored %s\n", rep.Restored)
	}
	for _, k := range rep.Kept {
		fmt.Printf("  kept     %s\n", k)
	}
	fmt.Printf("  after    compose %s · node %s · %s\n",
		orNone(rep.After.ComposeTag), orNone(rep.After.RunningVersion), rep.After.Consensus)

	if code := settleCancelGrants(c, p.rb.GrantScopes, l, os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// settleCancelGrants retires the plan's approvals after a cancel and says how
// that went (#1116). The approvals go too: an approval left behind after a
// cancel is an invitation to re-run the thing that was just abandoned. Every
// scope the runbook can be approved for, including the compound one: a merged
// upgrade grant left on disk covers a cutover nobody would be watching.
//
// Spent before the closing line is printed, and read: "nothing is pending" is
// only true when every grant is gone, and a grant that could be neither
// removed nor voided is still live after the plan was cancelled. Returns the
// exit code, 1 when a grant stays live.
func settleCancelGrants(c *execute.Canceller, scopes []string, l *ledger.Ledger, out, errw io.Writer) int {
	notes, spendErr := c.SpendGrants(scopes)
	for _, n := range notes {
		fmt.Fprintf(out, "  note     %s\n", n)
	}
	if spendErr != nil {
		fmt.Fprintf(out, "\nDeployment and node agree.\n")
		fmt.Fprintf(out, "ledger   %s\n", headPrefix(l))
		fmt.Fprintf(errw, "\nNOT CANCELLED CLEANLY: %v\n"+
			"The deployment is restored, but the approval named here is still on disk and still authorises what it "+
			"was granted for until it expires. Do not run this plan again before then.\n", spendErr)
		return 1
	}
	fmt.Fprintf(out, "\nDeployment and node agree. Nothing is pending on this plan.\n")
	fmt.Fprintf(out, "ledger   %s\n", headPrefix(l))
	return 0
}

// headPrefix is the first sixteen characters of the ledger head, or all of it
// for a ledger that has none yet.
func headPrefix(l *ledger.Ledger) string {
	h := l.Head()
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func orNone(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
