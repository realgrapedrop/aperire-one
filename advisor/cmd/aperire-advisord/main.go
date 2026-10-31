// Command aperire-advisord serves the Advisor's own state over HTTP so the
// dashboard tab can show what the executor actually knows, instead of markup
// somebody wrote once.
//
// Loopback only, and read-only. Every endpoint here answers a question; none
// of them changes anything. The write verbs — approve and execute — arrive in
// a later phase, behind a passkey assertion bound to the plan, and they will
// be additions to this file rather than a relaxation of anything in it.
//
// It serves ADVISOR state: the compact, preconditions, the plan, the ledger.
// It deliberately does not serve node metrics. The dashboard has those, and
// each side answering only for its own store is what keeps the two stores
// separable.
//
// How this service READS dashboard data is settled: a versioned read API on
// the dashboard, never the SQLite file (ADR 0008, accepted 2026-08-05). The
// auth tables are excluded by the route not existing, which is a thing a file
// handle cannot be made to honour.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"aperire-advisor/internal/advise"
	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/breakglass"
	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/dashread"
	"aperire-advisor/internal/execute"
	"aperire-advisor/internal/fleet"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/inbox"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/memory"
	"aperire-advisor/internal/model"
	"aperire-advisor/internal/outage"
	"aperire-advisor/internal/proposalrank"
	"aperire-advisor/internal/rollback"
	"aperire-advisor/internal/runbook"
	"aperire-advisor/internal/webauthn"
	"aperire-advisor/internal/xrpl"
)

// version is stamped at build time via -ldflags -X main.version=<commit>
// (#266); it falls back to "dev" for a `go build`/`go run` with no stamp.
// The dashboard reads it off /v1/status and compares it against the release
// the host says it is on, an unstamped "dev" is not a commit shape and
// reads as "not measured", never as a mismatch.
var version = "dev"

type server struct {
	// How this process reaches the host. ExecRunner normally; ViaWrapper when
	// the service runs as an account with no docker group, so that the one
	// docker read goes through the privilege wrapper like everything else.
	runner     host.Runner
	container  string
	adminRPC   string
	stateDir   string
	fleetTrust string
	// fleetPaired is the node's pairing record (#991); empty is
	// defaultFleetPairedPath. Set only by tests.
	fleetPaired string
	wrapper     string
	// The shared short-TTL rotation read, see rotation_cache.go. Zero value
	// ready to use.
	rotCache rotationCache
	// How often the store rotates, for chat's refusals (#1058).
	rotRhythm rotationRhythmCache
	// The shared short-TTL deployment-profile read, see profile_cache.go.
	// Zero value ready to use.
	profCache profileCache

	// #119. The four concern-card 30d history reads, keyed per metric. Same
	// disease as the two caches above, third instance: a per-request read
	// that is cheap on a quiet box and pegs a busy one.
	histCache historyCache
	// The registry answers, cached and kept warm off the request path, see
	// registry_cache.go. Zero value ready to use.
	regCache registryCache
	// The fleet roster this host's dashboard holds (#59), who may be
	// NAMED, as distinct from fleetNodes, who may be READ. Kept off the
	// request path for the reason regCache is; see roster_cache.go.
	rosterCache rosterCache
	// The ledger route's cached chain point, see ledger_cache.go. Zero value
	// ready to use (nothing trusted yet, so the first read verifies whole).
	ledgerCache ledgerHeadCache
	// The keeper that re-evaluates the last /v1/check plan while this daemon
	// is idle, see check_warm.go. Zero value is a keeper that is switched
	// off; main turns it on from --check-warm.
	warm      checkWarm
	modelPath string
	// The two recurring model-note journal lines' own throttles (P3-086),
	// kept apart so one anomaly's quiet hour never hides the other's first
	// sighting. Zero value ready to use: the first sight of either always
	// logs. Touched only from watchModelConfig's own goroutine (startup,
	// then every tick), so neither needs a lock.
	modelNoteRejected    modelAnomalyThrottle
	modelNoteUnjustified modelAnomalyThrottle
	knowledge            string
	// The two pushed layers — advisor/knowledge-fleet/{base,local} (ADR
	// 0017). A sibling of `knowledge`, never inside it: the shipped root's
	// non-recursive walk is load-bearing, and a directory a bundle can
	// write must not be reachable from it.
	knowledgeFleet string
	persona        string
	client         *http.Client
	// Host reads take a second or two and the tab polls. Cache briefly so a
	// browser left open does not hold rippled's admin port at a steady poll
	// rate for no benefit.
	//
	// Guarded, and not optionally: net/http serves every request on its own
	// goroutine, and one tab refresh fires /check and /plan together — both
	// reach latestRelease, both write this map. Two goroutines writing one Go
	// map is a fatal runtime abort, not a panic anything can recover from, so
	// this lock is what stops a page refresh from killing the process that
	// holds the execute path. Never touch the map outside cacheGet/cachePut.
	cacheMu  sync.Mutex
	cache    map[string]cached
	cacheTTL time.Duration
	// Which /v1/check entries are being re-evaluated behind a stale answer
	// right now, and how many resets the cache has seen. Both under cacheMu.
	// See serving-stale below check().
	refreshing map[string]bool
	// The last refresh of each plan that failed and has not been answered by a
	// good one, by the query string that names the plan. Under cacheMu. See
	// checkRefreshFailure.
	refreshFails map[string]checkRefreshFailure
	cacheGen     uint64
	// The dashboard's read API — ADR 0008. The measurements in the prompt are
	// assembled here from this client's own reads, never sent by the page.
	dashRead *dashread.Client
	// Hysteresis for the read-surface probe reported by /v1/status.
	readSurfaceMu     sync.Mutex
	readSurfaceLastOK time.Time

	// The FLEET — D2 option C (advisor-enhancement/decisions.md, decided
	// 2026-08-08). fleetReg is the loaded registry itself; fleetClients and
	// fleetNodes are derived from it. All three are nil or empty for a
	// deployment with no fleet registered, which is exactly the single-node
	// behaviour.
	//
	// Read them through fleetNow(), never directly (#859). Root's broker
	// takes a revoked node out of the file while this process runs, so the
	// registry is re-read when the file changes (fleet_reload.go). What
	// stays true of the old rule is the part that mattered: a question
	// takes ONE view at its start and keeps it, so a registry cannot change
	// under a question that is already running.
	fleetMu      sync.Mutex
	fleetPath    string
	fleetStamp   fleetStamp
	fleetRefused fleetStamp
	fleetReg     *fleet.Registry
	fleetClients map[string]*dashread.Client
	fleetNodes   map[string]bool

	// One knowledge bundle at a time. Two pushes racing the directory swap
	// would leave the receipt describing one corpus and the disk holding
	// another.
	knowledgeMu sync.Mutex

	// One fleet record at a time. The replay guard is "is this record_id
	// already in the ledger", so the scan and the append have to be one
	// step: two copies of the same record arriving together would otherwise
	// both find the id unseen and both append (#455).
	fleetRecordMu sync.Mutex

	// One run at a time per node. Two executors editing the same compose file
	// is not a race anyone should have to reconstruct afterwards.
	runMu   sync.Mutex
	running bool
	// The open transcript of that run, and what it is called. Kept here so a
	// shutdown that gives up waiting can write the run's terminal line
	// (drain.go, abandonRun) instead of leaving a transcript that just stops
	// — which the dashboard reads as a run still in progress. Both are nil/""
	// whenever running is false.
	runLog   *execute.RunLog
	runLabel string

	// Work in flight, for the shutdown drain and for the number /v1/status
	// publishes so a deploy can wait for quiet — punch #24.
	//
	// asks counts questions (ordinary, gated-on-the-ask-path, and gated
	// sessions running behind a 202); runs counts an executor run. Two
	// groups rather than one because the drain treats them differently: an
	// ask that is cut off simply loses an answer, and a run that is cut off
	// has left the node in a state somebody has to check. asksN is the same
	// count in a form that can be read without blocking — a WaitGroup has no
	// way to be asked how many it is holding, and the drain has to DECIDE on
	// that number rather than on a channel a goroutine may not have reached
	// yet (#118). runsN is the same reading for the run group.
	asks  sync.WaitGroup
	asksN atomic.Int64
	runs  sync.WaitGroup
	runsN atomic.Int64

	// #116. Open SSE streams, which are NOT work and must not be waited for.
	//
	// http.Server.Shutdown cannot tell a subscription from a request that is
	// still doing something: it waits for every active request, and a stream
	// handler sitting in its tail loop is active for as long as the browser
	// holds the socket. One dashboard with the Operations panel open turned
	// every restart into a silent sixty seconds, with "0 ask(s) in flight"
	// printed at the top of it.
	//
	// streamStop is closed once, by the drain, before Shutdown is called; the
	// stream loops select on it and return. streamsN is how many are open, so
	// the journal can say what it released rather than leaving the operator to
	// infer it. Lazily created under streamMu because a zero-value server is a
	// real construction here (the drain tests build one directly), and both
	// close(nil) and a double close panic.
	streamMu   sync.Mutex
	streamStop chan struct{}
	streamsN   atomic.Int64

	// Challenges this service issued for the passkey ceremony, each bound to
	// one plan and one stage. See internal/approval/nonce.go for why the
	// Advisor issues its own rather than checking the dashboard's.
	nonces *approval.NonceStore

	// progress is the interrogative loop's live step trace, keyed by the
	// ask_id the page mints — plan-interrogative-loop §9.5/§10.1. Separate
	// from cache: this is per-question, short-lived, and written from a
	// different goroutine (the ask handler's Loop.OnStep callback) than it
	// is read from (a concurrent GET /v1/ask/progress poll).
	progress *progressStore

	// pendingRestarts is the service's own record that it showed someone a
	// restart they can say yes to — issue #72, restart_confirm.go. At most
	// one entry per (node, operator), normally exactly one turn old, and
	// consulted only to decide WHICH restart a plain "yes" is confirming.
	// It authorises nothing: the gate it leads to is minted by the same
	// considerRestartAction the model path calls, against live state.
	pendingRestarts *pendingRestartStore

	// Break glass — plan-interrogative-loop §11. offers holds an accepted
	// question's transcript between the offer and the ceremony that spends
	// it (§11.9); breakglass holds the open window itself (§11.3a), at
	// most one per node. Both are in-memory and restart-volatile like
	// nonces and progress — "glass re-seals when the service restarts" is
	// this property, named.
	offers     *offerStore
	breakglass *breakglass.Store
	// endedWindow is the last break-glass window that ENDED, and why. The
	// Store cannot answer that: a closed window is gone from it after a
	// restart, and before this the tab had no way to distinguish "no window
	// was ever open" from "yours just ended" — so a restart took an
	// operator's window away mid-investigation and their next question ran
	// ungated with nothing said (validator1, 2026-08-21, issue #40). Written
	// by the close notice and by the boot scan, read by /v1/status.
	endedMu     sync.Mutex
	endedWindow *windowEnded
}

type cached struct {
	at   time.Time
	body []byte
}

// wrapperConfPath is where scripts/aperire-node-wrapper.sh reads its paths
// from. Duplicated here rather than discovered, because the wrapper deliberately
// has no way to be told a different location — a search order would let anything
// that can write the repository plant a configuration the wrapper would honour.
// If one moves, the other must move with it; nothing else should know this path.
const wrapperConfPath = "/etc/aperire/node-wrapper.conf"

func main() {
	var (
		addr      = flag.String("addr", "127.0.0.1:7810", "listen address; loopback only")
		container = flag.String("container", "", "container running the node (default: SERVICE from /etc/aperire/node-wrapper.conf, else rippledvalidator)")
		adminRPC  = flag.String("admin-rpc", "http://127.0.0.1:5005", "node admin JSON-RPC")
		stateDir  = flag.String("state", "", "compact, approvals and ledger")
		wrapper   = flag.String("wrapper", "", "privilege wrapper script")
		modelCfg  = flag.String("model-config", "", "operator's model configuration (JSON)")
		knowDir   = flag.String("knowledge", "", "operator's notes, cited as Documented")
		knowFleet = flag.String("knowledge-fleet", "", "fleet knowledge layers (base/ and local/); default <knowledge>/../knowledge-fleet")
		personaF  = flag.String("persona", "", "who the Advisor is; markdown, loaded into the system prompt")
		ttl       = flag.Duration("cache", 10*time.Second, "how long to reuse a host read")

		// Issue #250. On a node nobody polls, the first /v1/check of the day
		// is the cold one, and the operator opening that node's tab from the
		// aggregator is who pays for it. On by default; off is for a host
		// where the evaluation itself is the thing being investigated.
		checkWarm = flag.Bool("check-warm", true,
			"keep the last /v1/check plan warm on a timer, so a viewer gets a cached answer")

		// Print the discovered deployment and exit. The wrapper installer needs
		// these values to generate a script that names this host's real paths,
		// and it must be able to get them before the service is running — that
		// is the state a fresh install is in. Detection is read-only: one
		// `docker inspect`.
		printProfile = flag.Bool("print-profile", false, "print the discovered deployment as JSON and exit")

		// The root socket the wrapper is reached through (ADR 0025). Set when
		// this service runs as its own account with no docker group, which is
		// the arrangement that makes the wrapper a boundary rather than an
		// audit trail: every call to the wrapper, and the one docker read this
		// process performs, goes through it. There is no sudo path.
		wrapperSocket = flag.String("wrapper-socket", "", "reach the node wrapper through this root socket (ADR 0025)")
		// Retired with sudo (ADR 0025), and still parsed for one release: a
		// unit an update has not rewritten yet names it, and refusing the flag
		// would put that Advisor in a crash loop. It now means "the socket
		// that belongs to --wrapper", never sudo.
		sudoWrapper = flag.Bool("sudo-wrapper", false, "retired: read as --wrapper-socket for the installed --wrapper (ADR 0025)")
		// One call through the same client the service uses, printed, then
		// exit with the wrapper's own code. For the installers' prechecks and
		// verify-baseline.sh, so what they test is the Advisor's real route.
		wrapperCall = flag.Bool("wrapper-call", false, "send one call (the remaining arguments) through --wrapper-socket, print the answer and exit with its code")

		// The dashboard origin serving the ADR 0008 read API. Loopback on
		// both sides: the dashboard's read routes reject any socket that is
		// not local, so pointing this anywhere else buys nothing.
		dashReadURL = flag.String("dash-read-url", "http://127.0.0.1:7800", "dashboard origin serving the read API (ADR 0008)")

		// The FLEET's read-only peer table — D2 option C. A row names a
		// sibling node's own read-API origin and read token, per D1;
		// nothing here can name a verb, a wrapper path, an admin RPC
		// endpoint, or a database connection (internal/fleet). Absent is
		// exactly today's single-node behaviour.
		fleetRegistry = flag.String("fleet-registry", "", "read-only peer table (FLEET), mode 0600; default <state>/fleet.json")
		// ADR 0014 decision 4: the dashboard's fleet-trust.yaml holds the
		// aggregator's PUBLIC key under peers.<label>, placed there by
		// aperire-fleet-add.sh. A pushed trust bundle is verified against it.
		// Default derives it from the state dir's grandparent (state is
		// <repo>/advisor/state; the file is <repo>/dashboard/config/...).
		fleetTrust = flag.String("fleet-trust", "", "path to dashboard/config/fleet-trust.yaml; default derived from <state>")

		// Cheap and side-effect-free, the same reason -print-profile is:
		// prepare-host.sh's freshness check (#266) runs this before deciding
		// whether to rebuild, and a probe that touched the node or the state
		// dir would make "is this binary current" itself a reason it is not.
		showVersion = flag.Bool("version", false, "print the stamped build ref and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}

	if *printProfile {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		p, err := host.DiscoverProfile(ctx, host.ExecRunner{}, *container, *adminRPC)
		if err != nil {
			// To stderr, so a caller can consume stdout as JSON unconditionally
			// and still see why it got nothing.
			fmt.Fprintf(os.Stderr, "cannot read the deployment: %v\n", err)
			os.Exit(1)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(p); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		return
	}

	// Where the wrapper is reached (ADR 0025). --sudo-wrapper, from a unit an
	// update has not rewritten yet, is read as the socket that belongs to the
	// installed wrapper it names; there is no sudo path left to take.
	sockPath := *wrapperSocket
	if sockPath == "" && *sudoWrapper {
		sockPath = host.SocketForWrapper(*wrapper)
		if sockPath == "" {
			log.Printf("[boot] --sudo-wrapper is retired and %q is not an installed wrapper name, so no socket could be derived; the node is not reachable until this unit names --wrapper-socket", *wrapper)
		} else {
			log.Printf("[boot] --sudo-wrapper is retired (ADR 0025); reaching the wrapper through %s instead", sockPath)
		}
	}

	if *wrapperCall {
		os.Exit(runWrapperCall(*wrapper, sockPath, flag.Args()))
	}

	// Refuse to listen anywhere but loopback. This process can read a
	// validator's deployment and, in a later phase, act on it; binding it to
	// an interface by accident should not be a thing a flag can do quietly.
	h, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("bad --addr %q: %v", *addr, err)
	}
	if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to listen on %q: loopback only", *addr)
	}

	wd, _ := os.Getwd()
	if *stateDir == "" {
		*stateDir = filepath.Join(wd, "state")
	}
	if *wrapper == "" {
		*wrapper = filepath.Clean(filepath.Join(wd, "..", "scripts", "aperire-node-wrapper.sh"))
	}
	if *container == "" {
		*container = defaultContainer()
	}
	if *modelCfg == "" {
		*modelCfg = filepath.Join(*stateDir, "model.json")
	}
	if *knowDir == "" {
		*knowDir = filepath.Join(wd, "knowledge")
	}
	if *knowFleet == "" {
		*knowFleet = filepath.Join(filepath.Dir(*knowDir), "knowledge-fleet")
	}
	if *personaF == "" {
		*personaF = filepath.Join(wd, "persona.md")
	}
	if *fleetRegistry == "" {
		*fleetRegistry = filepath.Join(*stateDir, "fleet.json")
	}
	if *fleetTrust == "" {
		// <repo>/advisor/state -> <repo>/dashboard/config/fleet-trust.yaml
		repo := filepath.Dir(filepath.Dir(*stateDir))
		*fleetTrust = filepath.Join(repo, "dashboard", "config", "fleet-trust.yaml")
	}

	// Loaded here, and again whenever the file changes (#859, see
	// fleet_reload.go). A malformed file fails the WHOLE registry closed to
	// empty (internal/fleet's own rule) rather than half-registering the
	// fleet; either way the process still starts, because a broken peer
	// table must never be a reason a single-node operator's Advisor refuses
	// to come up.
	fleetStampAtLoad := statFleetStamp(*fleetRegistry)
	fleetReg := loadFleetRegistry(*fleetRegistry)
	fleetClients, fleetNodes := fleetDerived(fleetReg)
	if len(fleetReg.Peers) > 0 {
		log.Printf("[fleet] %d peer(s) registered: %s", len(fleetReg.Peers), strings.Join(fleetReg.Labels(), ", "))
	}

	// One runner, built once, used by every host read. Before this the runner
	// was constructed inline at four call sites, so a change to how this
	// process reaches docker had to be made in four places or it was not made
	// at all.
	var runner host.Runner = host.ExecRunner{}
	if sockPath != "" {
		runner = host.ViaWrapper{Wrapper: *wrapper, Socket: sockPath}
		log.Printf("[boot] reaching the node through the root socket %s (wrapper %s): no docker access, no sudo", sockPath, *wrapper)
	}

	s := &server{
		runner:    runner,
		container: *container, adminRPC: *adminRPC,
		stateDir: *stateDir, fleetTrust: *fleetTrust, wrapper: *wrapper, modelPath: *modelCfg, knowledge: *knowDir,
		knowledgeFleet: *knowFleet,
		persona:        *personaF,
		cache:          map[string]cached{}, cacheTTL: *ttl,
		nonces:          approval.NewNonceStore(),
		progress:        newProgressStore(),
		pendingRestarts: newPendingRestartStore(),
		offers:          newOfferStore(),
		breakglass:      breakglass.NewStore(),
		fleetReg:        fleetReg, fleetClients: fleetClients, fleetNodes: fleetNodes,
		fleetPath: *fleetRegistry, fleetStamp: fleetStampAtLoad,
		client: &http.Client{
			Timeout: 15 * time.Second,
			// HTTP/1.1 only: Go's HTTP/2 fingerprint trips Cloudflare's bot
			// challenge on Docker's endpoints, which arrives as a 403 and
			// reads exactly like "this release does not exist".
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
			},
		},
	}

	s.dashRead = &dashread.Client{
		BaseURL:    *dashReadURL,
		TokenPath:  filepath.Join(*stateDir, "read.token"),
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}

	if _, err := s.ensureToken(); err != nil {
		log.Fatalf("could not establish the service token: %v", err)
	}
	if err := s.ensureReadToken(); err != nil {
		log.Fatalf("could not establish the read token: %v", err)
	}
	s.tightenState()
	s.tightenFleet(*fleetRegistry)
	// Every window this service opens carries the notice that records its
	// ending, whichever of the five endings it turns out to be. Wired before
	// anything can open one — a window opened without it would close in
	// silence, which is the defect (issue #38).
	s.breakglass.SetOnClose(s.recordWindowClosed)
	// And the endings this service was not running for. A restart re-seals the
	// glass, correctly; it used to do so leaving no entry and telling nobody
	// (issue #40). Before the listener, so the first status poll after a
	// restart already knows what to say.
	s.closeOrphanWindows(time.Now())
	// Who may approve on this node is the one privileged change that used to
	// leave no record anywhere. Started before the listener so the startup
	// comparison lands before anything can be approved against a store that
	// changed while this service was down.
	go s.watchTrustStore()
	// And which model is answering. Same reasoning one line up, one step
	// further out: a change to the trust store decides who may approve, and a
	// change to model.json decides what wrote the advice they are approving.
	// Neither left a record before it was watched.
	go s.watchModelConfig()
	// Keep the registry answers warm off the request path — see
	// registry_cache.go for the validator1 measurement that put them there.
	go s.registryRefreshLoop(context.Background())
	// The fleet roster, same discipline (#59): who this host knows exists,
	// so a question naming another node resolves against the fleet rather
	// than against this process's own credentials. See roster_cache.go.
	go s.rosterRefreshLoop(context.Background())
	// And the check itself, for the same reason one layer up: a fleet viewer
	// opening a node's tab must not be the one who pays for the cold
	// evaluation (#250, check_warm.go).
	s.warm.on, s.warm.debug = *checkWarm, checkWarmDebugFromEnv()
	go s.checkWarmLoop(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.readOnly(s.status))
	mux.HandleFunc("/v1/check", s.readOnly(s.check))
	mux.HandleFunc("/v1/plan", s.readOnly(s.plan))
	mux.HandleFunc("/v1/ledger", s.readOnlyCompact(s.ledger))
	// ADR 0021 build step 5: the aggregator's mirror feed for what this
	// node's Advisor remembers and has proposed. Same gate as the ledger,
	// same reason it is worth naming twice: nothing in this pair is public
	// just because it is a read.
	mux.HandleFunc("/v1/memory", s.readOnly(s.memory))
	mux.HandleFunc("/v1/inbox", s.readOnly(s.inboxAll))
	// A read-only window onto the public ledger, config-gated: the operator's
	// xrpl-lookup.json names the one endpoint the Advisor may ask. A missed
	// validation months old cannot be explained by a validator that keeps no
	// history — this is where "what was ledger X" gets its answer.
	mux.HandleFunc("/v1/ledger-lookup", s.readOnly(s.ledgerLookup))
	// The network's view of a validator, from the configured public registry.
	// Same discipline: read-only, one operator-named endpoint, honest about
	// keys the registry does not track.
	mux.HandleFunc("/v1/validator-lookup", s.readOnly(s.validatorLookup))
	// Registered explicitly, as promised when readOnly was written. /v1/ask is
	// POST because it carries a conversation in its body — but it changes no
	// host state, holds no approval, and cannot reach the wrapper. The agent
	// and the executor are separate identities and this is the agent's only
	// door.
	mux.HandleFunc("/v1/ask", s.ask)
	// The interrogative loop's live step trace for a question still in
	// flight (plan-interrogative-loop §9.5/§10.1). Read-only, and answers
	// about a per-question id rather than about the node, so it carries none
	// of the concerns the other reads do — but it still needs the service
	// token, same as every other read here.
	mux.HandleFunc("/v1/ask/progress", s.readOnly(s.askProgress))
	// The first endpoint that writes. It records an approval the dashboard has
	// already verified by passkey. Gated on a bearer token both services read
	// from a file — see approveToken for exactly what that does and does not
	// prove.
	// The ceremony starts here now. The Advisor issues the challenge the
	// operator's passkey will sign, bound to one plan and one stage, so its
	// own later verification is checking something it chose rather than
	// something it was handed.
	mux.HandleFunc("/v1/approve/begin", s.approveBegin)
	mux.HandleFunc("/v1/approve", s.approve)
	// The other half of granting one. Same authority, same gate — the
	// dashboard's session decides who may call this, exactly as it does for
	// /v1/approve — but no new ceremony: revoking consent does not need the
	// consent it revokes to have been re-proven. Registered next to it so the
	// pair reads together.
	mux.HandleFunc("/v1/approve/cancel", s.approveCancel)
	// Capturing a diagnostic snapshot changes nothing on the node — it is a
	// read that saves its own output — but it is the precondition that most
	// often blocks a plan, and requiring a separate CLI command for it turned
	// every pause into a dance. Token-gated like /v1/approve so it is not an
	// open write, and it can only ever write to the Advisor's own state.
	mux.HandleFunc("/v1/evidence", s.captureEvidence)
	// Read-only and streaming. Registered outside readOnly because that helper
	// writes a complete JSON body, which is the opposite of a stream.
	mux.HandleFunc("/v1/runs/", s.runStream)
	// Exact match too — without it ServeMux answers /v1/runs with a 301 that
	// some callers read as an empty body rather than following.
	mux.HandleFunc("/v1/runs", s.runStream)
	// The write that acts. Registered last, and deliberately after the
	// read-only surface, so the order of this list reads as what it is.
	mux.HandleFunc("/v1/execute", s.execute)

	// Break glass — plan-interrogative-loop §11.8. Four endpoints, all
	// admin-only at the dashboard's proxy (dashboard/server.ts's
	// ADVISOR_ADMIN_PATHS), all POST, all token-gated here exactly like
	// approve/execute above. investigate/begin mirrors approve/begin;
	// investigate mirrors approve then execute (verify, spend, and — new —
	// open the window); continue is the endpoint the window exists to make
	// possible, no ceremony; close is the operator's one-click Close.
	mux.HandleFunc("/v1/investigate/offer", s.investigateOffer)
	mux.HandleFunc("/v1/investigate/begin", s.investigateBegin)
	mux.HandleFunc("/v1/investigate/continue", s.investigateContinue)
	mux.HandleFunc("/v1/investigate", s.investigate)
	mux.HandleFunc("/v1/breakglass/close", s.breakglassClose)
	// ADR 0014 decision 4: accept a signed trust bundle from the aggregator.
	// Gated by the service token (like every write) AND the bundle signature
	// against the aggregator's pinned key; pins rp_id+origins on first accept.
	mux.HandleFunc("/v1/trust/bundle", s.trustBundle)
	// The fleet knowledge bundle — ADR 0017. Same gate, same key, same
	// forward as the trust bundle above; what it carries changes advice and
	// nothing else.
	mux.HandleFunc("/v1/knowledge/bundle", s.knowledgeBundle)
	// The proposal inbox — ADR 0017 decision 4. The read is this node's
	// queue, for the aggregator's review card; the mark is the decision
	// coming back, so the node that proposed holds the record of what
	// happened to it. Neither one moves knowledge: that arrives as a signed
	// bundle at the endpoint above.
	mux.HandleFunc("/v1/proposals", s.readOnly(s.proposals))
	mux.HandleFunc("/v1/proposals/mark", s.proposalMark)
	mux.HandleFunc("/v1/proposals/revise", s.proposalRevise)
	// The append surface for an act done TO this node (#455): the aggregator
	// revoked its link, or accepted a changed node key. The same shape of
	// write as the two bundles above, with the same two gates (the service
	// token, and a signature against the aggregator key in fleet-trust.yaml)
	// and one more rule of its own: the set of kinds it accepts is closed and
	// the summary is composed on this side, so nothing off the wire can write
	// prose into this node's record. See fleet_record.go.
	mux.HandleFunc("/v1/fleet/record", s.fleetRecord)

	srv := &http.Server{
		Addr: *addr, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Three timeouts guard three different scopes, and this is the
		// widest of them (plan-interrogative-loop §14, "the one line that
		// will otherwise be missed"): model.Client.HTTP.Timeout bounds one
		// round, ask's own request context bounds one question at up to
		// interrogate.MaxModelCalls rounds (capped at 300s), and this
		// bounds the whole HTTP response — which must be at least as wide
		// as the widest question the loop can run, plus headroom, or a
		// four-round investigation would be cut off by the transport
		// underneath it with an error that reads like a provider timeout.
		// /v1/runs/*/stream, the other long-lived handler on this server,
		// is unaffected: its client reconnects roughly every 20s (the
		// dashboard's watchdog window), so it has never depended on this
		// value being small.
		WriteTimeout: 310 * time.Second,
	}
	log.Printf("aperire-advisord on http://%s/ (read-only)", *addr)
	log.Printf("  node %s via %s", *container, *adminRPC)
	log.Printf("  state %s", *stateDir)

	// ListenAndServe moves off the main goroutine so a signal can be waited
	// on beside it. It used to be wrapped in log.Fatal, which was fine right
	// up until Shutdown existed: Shutdown makes ListenAndServe return
	// http.ErrServerClosed, log.Fatal would exit(1) on it, and the drain that
	// was the whole point would never run.
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	// SIGTERM is what systemd sends on `systemctl stop` and on the restart a
	// deploy performs; SIGINT is Ctrl-C in a terminal. Both mean the same
	// thing here — stop taking new work — and neither means "drop what you
	// are holding".
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-serveErr:
		log.Fatal(err)
	case sig := <-sigc:
		s.drain(srv, sig, drainWindow)
	}
}

// readOnly rejects anything but GET before the handler runs. The write verbs
// do not exist yet; when they do they will be registered explicitly rather
// than by loosening this.
func (s *server) readOnly(h func(http.ResponseWriter, *http.Request) (any, int)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed,
				map[string]any{"error": "this service is read-only"})
			return
		}
		// Reads are gated too. What they return — the audit ledger, run
		// transcripts, the node's deployment — is not public just because it
		// is not a write.
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
			return
		}
		body, code := h(w, r)
		writeJSON(w, code, body)
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(body)
}

// readOnlyCompact is readOnly with the one difference the ledger route
// needs: the body goes over the wire without indentation. ADR 0021 build
// step 1, a since_seq poll answering a few hundred bytes was still being
// measured at roughly double that once pretty-printed, and the whole point
// of the parameter is a poll small enough not to matter. Every other route
// keeps writeJSON's indentation; widening that is not this change's job.
func (s *server) readOnlyCompact(h func(http.ResponseWriter, *http.Request) (any, int)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed,
				map[string]any{"error": "this service is read-only"})
			return
		}
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
			return
		}
		body, code := h(w, r)
		writeJSONCompact(w, code, body)
	}
}

func writeJSONCompact(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

// defaultRunbook is what a caller that names none is asking about. Every
// route below defaulted to it by hard-coding a Lookup; naming it once is what
// let a second runbook exist at all — ADR 0016.
const defaultRunbook = "upgrade-xrpld"

// lookupRunbook resolves a runbook ID, treating an absent one as the upgrade.
// The default is here rather than in each handler so a caller that says
// nothing gets the same runbook everywhere, and an unknown one is refused by
// the registry rather than silently becoming the upgrade.
func lookupRunbook(id string) (runbook.Runbook, error) {
	if id == "" {
		id = defaultRunbook
	}
	return runbook.V1().Lookup(id)
}

// planParams is everything a caller may supply for any runbook's parameters,
// in one value.
//
// A struct rather than a positional list, and that is the point: the
// parameters are inside the fingerprint, so /v1/check, /v1/approve/begin,
// /v1/approve and /v1/execute must bind them identically or the dashboard and
// this service disagree about what was approved — which surfaces as a 409
// after the passkey touch. Adding a field here does not compile until every
// site has been looked at, which is the property four hand-written argument
// lists did not have.
type planParams struct {
	Target string
	Intent string
	Key    string
	Value  string
	// Source is the operator asking for a build when an official image
	// also exists (#682). Empty is the ruling's own order: official
	// first. It is bound through the runbook's own enum, so anything
	// else is refused rather than quietly ignored.
	Source string
	// Change and User are RB-005's, ADR 0023: which one change to make
	// to the deployment, and the account for the one change that takes
	// a value.
	Change string
	User   string
	// RestorePath is the NAME of the dated deployment copy a rollback
	// puts back, and RestoreDigest is the digest that copy pins its
	// image to. Neither is taken from the caller either: both are
	// resolved from the host when the plan is made, so the approval's
	// fingerprint covers the file the run will restore (#682, second
	// review).
	RestorePath   string
	RestoreDigest string
	// Digest is the pin, and it is NOT taken from the caller. It is
	// resolved once, here, when the plan is made, and carried to the run
	// that acts on it. Resolving it at the pull would be resolving it
	// after the approval, which is the substitution the pin exists to
	// prevent.
	Digest string
}

// bindRequest binds exactly the parameters a runbook declares, from values a
// caller supplied. A runbook that declares none gets an empty set, and a value
// sent for a parameter that is not declared is dropped here rather than
// reaching BindParams as an undeclared-parameter refusal — the caller sending
// a target to a runbook that has no version is the tab keeping one field, not
// an attempt to widen anything.
// pinSource resolves where a container node's next image comes from, and
// the digest it would be pinned to (#682).
//
// One function, called by the plan path and by both halves of the
// approval ceremony (the run reads its own, see pinRunSource), because the fingerprint an approval is bound to is computed from the
// bound parameters: a plan made with a digest and an approval recomputed
// without one are two different plans, and the run would silently fall
// through to a build. The cached answer is what makes them agree: the
// registry is asked once per version per five minutes, and a tag that
// really moved inside a ceremony reads as "the plan changed", which is the
// correct refusal rather than a substitution.
//
// Not asked at all for a build the operator asked for. That answer needs no
// registry, and asking would let a tag appearing between the click and the
// plan override what was asked for.
func (s *server) pinSource(st *host.State, rb runbook.Runbook, in planParams) planParams {
	if !rb.DeclaresParam("digest") || in.Source == "build" || in.Target == "" {
		return in
	}
	var src, digest string
	if st != nil {
		src, digest, _ = s.upgradeSource(st, in.Target)
	} else {
		src, digest = s.pinnedSource(in.Target)
	}
	if src == host.OfficialImageSource && digest != "" {
		in.Source, in.Digest = "official", digest
	}
	return in
}

// pinRunSource binds where a run's image comes from, read off the node for
// this request (#1033). The run door used to take it from pinnedSource's
// five-minute shelf, so a run started more than five minutes after the card
// last rendered bound no digest, computed another plan, and was refused as
// never approved. One read, here, the way #1029 made the rollback's copy one
// read per request.
//
// A read that fails is an error, never a quiet build: the caller decides.
// The run door binds the unpinned plan and runs it only when that exact
// plan is the one approved, which is what a card on a host the registry
// does not answer offers. Not asked at all for a build the operator asked
// for, the same as pinSource.
func (s *server) pinRunSource(st *host.State, rb runbook.Runbook, in planParams) (planParams, error) {
	if !rb.DeclaresParam("digest") || in.Source == "build" || in.Target == "" || st == nil {
		return in, nil
	}
	src, digest, err := st.RunSource(in.Target)
	if err != nil {
		return in, fmt.Errorf("could not read where %s comes from, so this run cannot bind an official "+
			"image: %w. Nothing was changed; run it again once the registry answers", in.Target, err)
	}
	if src == host.OfficialImageSource && digest != "" {
		in.Source, in.Digest = "official", digest
	}
	return in, nil
}

// ceremonySource binds where an upgrade's image comes from for one half of
// the approval ceremony, read off the registry for this request (#1061),
// the way the run door reads it (#1033). The five-minute shelf both halves
// used lapsed between the card and the passkey touch for anyone who read the
// card slowly, and the ceremony then bound another plan and refused it as
// changed.
//
// One registry read, and no wrapper call: begin's single host read (#105)
// stands. A read that fails binds the plan unpinned, which is the plan the
// card shows on a host the registry does not answer. Anything else it binds
// is compared with the card's fingerprint, by the dashboard at begin and by
// /v1/approve itself, so a registry that moved since the card is refused
// there as the plan having changed, never bound into a challenge the
// operator did not see.
//
// A runbook that declares no source reads nothing, so the restart, the
// config change and the rollback cost the ceremony nothing new. begin has no
// State of its own, so stateFor makes one only when the read is needed.
func (s *server) ceremonySource(stateFor func() *host.State, rb runbook.Runbook, in planParams) planParams {
	if !rb.DeclaresParam("digest") || in.Source == "build" || in.Target == "" {
		return in
	}
	st := stateFor()
	if st == nil {
		return in
	}
	digest, err := st.OfficialPin(in.Target)
	if err != nil {
		log.Printf("[approve] could not read where %s comes from (%v); binding the unpinned plan the card "+
			"shows on such a host", in.Target, err)
		return in
	}
	if digest != "" {
		in.Source, in.Digest = "official", digest
	}
	return in
}

// pinRestoreCopy resolves which dated copy a rollback restores, for the plan
// path (#682, second review). The ceremony doors and the run bind the copy
// their own target gate derived instead (withRestoreCopy), so each of them
// reads the host once.
//
// Read off the host every time, with this node's run history (#1029). It used
// to be read once by the plan and handed to the ceremony paths from the
// service's ten-second cache. A person reading a card and touching a passkey
// takes longer than that, so the run found the shelf empty, bound no copy,
// and evaluated a rollback with nothing to roll back to, under a plan id
// nobody approved. The copy is a local read, not a call to somebody else's
// registry, so there is no reason to hold it back the way pinSource does.
//
// A read that fails is an error, never an empty copy: an empty copy is a
// different plan, and a failed read is not the node's answer changing.
func (s *server) pinRestoreCopy(st *host.State, rb runbook.Runbook, in planParams) (planParams, error) {
	if !rb.DeclaresParam("restore_path") || in.Target == "" || in.RestorePath != "" || st == nil {
		return in, nil
	}
	name, digest, err := st.PlannedRestoreCopy()
	if err != nil {
		return in, fmt.Errorf("could not read the node to name the copy this rollback restores: %w", err)
	}
	return withRestoreCopy(rb, in, restoreCopy{name, digest}), nil
}

// withRestoreCopy binds a copy a door has already derived. The copy is the
// one its own target gate named, off the same reading (#1029, review).
func withRestoreCopy(rb runbook.Runbook, in planParams, cp restoreCopy) planParams {
	if !rb.DeclaresParam("restore_path") || in.Target == "" || in.RestorePath != "" {
		return in
	}
	in.RestorePath, in.RestoreDigest = cp.Name, cp.Digest
	return in
}

// pinnedSource hands back the answer the plan path already took, and never
// goes and asks for one.
//
// Both halves of the ceremony read it rather than the registry. The run
// does not: it reads the node for itself (#1033). /v1/approve/begin
// is the request standing between the confirm code and the passkey prompt and
// costs one host read by design (#105); a call to somebody else's registry is
// not a thing to put in front of a passkey, and a registry answering
// differently at begin than it did at the plan would be two plans wearing one
// confirm code. A shelf that has lapsed hands back nothing, the fingerprint
// does not match the plan the card is showing, and the ceremony is refused
// with "the plan changed" rather than falling through to a build.
func (s *server) pinnedSource(version string) (string, string) {
	if version == "" {
		return "", ""
	}
	if b, ok := s.fromCache("upgrade-source:" + version); ok {
		var a sourceAnswer
		if json.Unmarshal(b, &a) == nil {
			return a.Source, a.Digest
		}
	}
	return "", ""
}

func bindRequest(rb runbook.Runbook, in planParams) (runbook.Params, error) {
	raw := map[string]any{}
	if rb.DeclaresParam("target_version") {
		raw["target_version"] = in.Target
	}
	if rb.DeclaresParam("intent") {
		raw["intent"] = in.Intent
	}
	if rb.DeclaresParam("key") {
		raw["key"] = in.Key
	}
	if rb.DeclaresParam("value") {
		raw["value"] = in.Value
	}
	if rb.DeclaresParam("change") {
		raw["change"] = in.Change
	}
	if rb.DeclaresParam("user") {
		raw["user"] = in.User
	}
	if rb.DeclaresParam("source") {
		raw["source"] = in.Source
	}
	if rb.DeclaresParam("digest") && in.Digest != "" {
		raw["digest"] = in.Digest
	}
	if rb.DeclaresParam("restore_path") && in.RestorePath != "" {
		raw["restore_path"] = in.RestorePath
	}
	if rb.DeclaresParam("restore_digest") && in.RestoreDigest != "" {
		raw["restore_digest"] = in.RestoreDigest
	}
	return rb.BindParams(raw)
}

// resolveRunbook reads which runbook a request is about and binds it.
//
// An explicit target still goes through the runbook's own parameter binding
// rather than being trusted. An absent one is the normal case for the tab:
// the Advisor asks the registry what the newest published release is and
// recommends that — which is the difference between the Advisor deciding and
// the page displaying a constant somebody typed. A runbook that declares no
// version derives nothing, because there is nothing to derive.
func (s *server) resolveRunbook(r *http.Request, st *host.State) (string, runbook.Runbook, runbook.Params, bool, error) {
	q := r.URL.Query()
	return s.resolveRunbookByID(st, q.Get("runbook"), planParams{
		Target: q.Get("target"), Intent: q.Get("intent"),
		Key: q.Get("key"), Value: q.Get("value"),
		Source: q.Get("source"),
		Change: q.Get("change"), User: q.Get("user"),
	})
}

// resolveRunbookByID is resolveRunbook's body, taking bare values instead of
// a request — so the ask context can resolve the SAME plan /v1/check would,
// from values that arrived in a JSON body rather than a query string, without
// a second implementation of "no target given, use the latest release"
// deciding it differently on the two paths.
func (s *server) resolveRunbookByID(st *host.State, id string, in planParams) (string, runbook.Runbook, runbook.Params, bool, error) {
	rb, err := lookupRunbook(id)
	if err != nil {
		return "", runbook.Runbook{}, nil, false, err
	}
	derived := false
	if rb.DeclaresParam("target_version") && in.Target == "" {
		// Only the UPGRADE derives a missing target from the release
		// registry. RB-004 also declares target_version, and "no target
		// given, use the newest published release" would turn a rollback
		// into an upgrade to the latest version — the exact opposite act,
		// under a confirm code the operator would read as a rollback. Its
		// target comes from the node's own backups and run history, and a
		// caller that did not carry it has no plan here.
		if rb.ID != defaultRunbook {
			return "", runbook.Runbook{}, nil, false,
				fmt.Errorf("%s needs a target version; it is derived from this node's own "+
					"deployment history, never from the release registry", rb.ID)
		}
		latest, lerr := s.latestRelease(st)
		if lerr != nil {
			// The origin is inside lerr, which is where it belongs: each half
			// refuses in its own words, and this sentence must not name one of
			// them on a host that has the other (#421).
			return "", runbook.Runbook{}, nil, false,
				fmt.Errorf("no target given and the latest release could not be determined: %v", lerr)
		}
		in.Target, derived = latest.Version, true
	}
	in = s.pinSource(st, rb, in)
	in, err = s.pinRestoreCopy(st, rb, in)
	if err != nil {
		return "", runbook.Runbook{}, nil, false, err
	}
	p, err := bindRequest(rb, in)
	if err != nil {
		return "", runbook.Runbook{}, nil, false, err
	}
	return in.Target, rb, p, derived, nil
}

// resolveUpgradeTarget is the ask context's own resolver, pinned to the
// upgrade. The CEREMONY STATE block it feeds renders a two-stage plan and
// names its stages in prose, so pointing it at a one-stage runbook would
// have it describe a PREPARE step that does not exist — ADR 0016 keeps that
// out of v1 deliberately rather than half-wiring it.
func (s *server) resolveUpgradeTarget(st *host.State, v string) (string, runbook.Runbook, runbook.Params, bool, error) {
	return s.resolveRunbookByID(st, defaultRunbook, planParams{Target: v})
}

// latestAnswer is a resolved "newest release" with its provenance: which
// origin answered, and when it was read.
//
// The provenance travels with the version because a target the Advisor chose
// itself is a claim about somewhere else, and #421 is what an unnamed origin
// costs: a native host was refused in the words of an image registry it has
// never had. Source is the origin's own name (host.LatestReleaseSource), not
// a kind, so the field reads the same on the page as in a refusal.
type latestAnswer struct {
	Version string    `json:"version"`
	Source  string    `json:"source"`
	ReadAt  time.Time `json:"read_at"`
}

// latestRelease caches the origin's answer. Five minutes, not the ten-second
// host-read TTL: releases change on the scale of weeks, the tab polls on the
// scale of seconds, and the background refresher re-primes this every four
// minutes so the origin is asked on ITS schedule, never a page load's.
//
// Which origin that is belongs to the State: host.LatestRelease branches on
// the recorded kind, an image registry on a container host and this host's
// own package repositories on a native one. Nothing here knows which
// answered; it records what the State says it read.
func (s *server) latestRelease(st *host.State) (latestAnswer, error) {
	if a, ok := s.latestReleaseNote(); ok {
		return a, nil
	}
	v, err := st.LatestRelease()
	if err != nil {
		return latestAnswer{}, err
	}
	a := latestAnswer{Version: v, Source: st.LatestReleaseSource(), ReadAt: time.Now().UTC()}
	b, err := json.Marshal(a)
	if err != nil {
		return a, nil
	}
	// Dated forward so this entry outlives the short host-read TTL. Five
	// minutes rather than the old fifty seconds: the background refresher
	// (registry_cache.go) re-primes it every four, so a request should
	// never find it lapsed, the dating is the backstop for a refresher
	// that died, not the cadence the origin is asked at.
	s.cachePut("latest-release", cached{time.Now().Add(5 * time.Minute), b})
	return a, nil
}

// sourceAnswer is where one version's image would come from, and the
// digest it would be pinned to.
type sourceAnswer struct {
	Source string `json:"source"`
	Digest string `json:"digest"`
	Detail string `json:"detail"`
}

// upgradeSource caches the registry's answer about one tag, for the same
// reason latestRelease caches the index's.
//
// The card asks this on every render, and the registry is somebody else's
// service with somebody else's rate limit. Without a cache a 429 in the
// middle of an operator reading the page flips the card between "the
// official image is published" and "no official image carries it yet",
// which is the same fact contradicting itself while nothing changed.
//
// Five minutes, keyed by version. A tag appearing is news that can wait
// five minutes; a tag MOVING is not something a shorter cache would catch
// either, and the digest pinned in the plan is what actually guards that.
func (s *server) upgradeSource(st *host.State, version string) (string, string, string) {
	if version == "" {
		return "", "", "no version to look for"
	}
	key := "upgrade-source:" + version
	if b, ok := s.fromCache(key); ok {
		var a sourceAnswer
		// "built here" rests on a local image, which an operator can remove
		// between two polls. It is re-checked on every hit and re-derived
		// when the image has gone, so the card does not offer a source that
		// is no longer on the disk (#1015). The other answers are about the
		// registry and the index, and stay cached.
		if json.Unmarshal(b, &a) == nil && a.Source != "" {
			if a.Source != host.BuiltHereSource {
				return a.Source, a.Digest, a.Detail
			}
			if ok, _ := st.ImageLocal(version); ok {
				return a.Source, a.Digest, a.Detail
			}
		}
	}
	src, digest, detail := st.UpgradeSource(version)
	if b, err := json.Marshal(sourceAnswer{Source: src, Digest: digest, Detail: detail}); err == nil {
		s.cachePut(key, cached{time.Now().Add(5 * time.Minute), b})
	}
	return src, digest, detail
}

// latestReleaseNote hands back the answer already on the shelf, provenance
// and all, and never goes and asks for one.
//
// Two callers with one reason between them. latestRelease reads it as its
// cache hit, and the response path reads it to say where a derived target
// came from: going and asking there could reach an origin in a different
// state than the resolve did, and put two answers in one body.
func (s *server) latestReleaseNote() (latestAnswer, bool) {
	b, ok := s.fromCache("latest-release")
	if !ok {
		return latestAnswer{}, false
	}
	var a latestAnswer
	if json.Unmarshal(b, &a) != nil || a.Version == "" || a.Source == "" {
		return latestAnswer{}, false
	}
	return a, true
}

// How long a store measurement is worth serving. A walk of a forty-gigabyte
// store is not something a poll of /v1/status should pay for, and the size
// does not move on the scale this document is polled at. The dashboard's own
// walk runs once a minute for the same reason, so the two readings are taken
// at the same cadence and neither can look fresher than the other.
const storeSizeTTL = 60 * time.Second

// storeSizeCached is the store reading /v1/status publishes.
//
// It never fails. A wrapper that refused, an answer in a shape this does not
// recognise and a store the wrapper itself could not measure all come back as
// a reading with no size and a reason, which is the one shape the dashboard
// has to handle. Failures are cached like successes, or a wrapper that is
// refusing would be invoked on every poll.
func (s *server) storeSizeCached(ctx context.Context) host.StoreSize {
	if b, ok := s.fromCache("store-size"); ok {
		var r host.StoreSize
		if json.Unmarshal(b, &r) == nil && !r.MeasuredAt.IsZero() {
			return r
		}
	}
	st := host.New(ctx, host.Profile{}, s.runner, s.client)
	// The reading does not depend on the profile: the wrapper resolves the
	// store path from its own configuration, which is the one that was
	// measured on this host rather than the one the dashboard was pointed at.
	st.Wrapper = s.wrapper
	r, err := st.StoreSize()
	if err != nil {
		r = host.StoreSize{Reason: err.Error(), MeasuredAt: time.Now().UTC()}
	}
	if b, merr := json.Marshal(r); merr == nil {
		s.cachePut("store-size", cached{time.Now().Add(storeSizeTTL), b})
	}
	return r
}

func (s *server) state(ctx context.Context) (host.Profile, *host.State, error) {
	p, err := s.discoverProfileCached(ctx)
	if err != nil {
		return host.Profile{}, nil, err
	}
	st := host.New(ctx, p, s.runner, s.client)
	st.LedgerPath = s.ledgerPath()
	// Read the node's files through the wrapper rather than opening them here.
	// This is what lets the Advisor's account be refused the config directory
	// outright — that directory holds rippled.cfg, and rippled.cfg holds the
	// validator token §7 says this service never reads.
	st.Wrapper = s.wrapper
	// One conventional location, shared with the CLI — a snapshot is evidence
	// about the host, not about whoever took it. And the Advisor keeps its own
	// picture fresh: the snapshot is a read, so a stale one is refreshed here
	// rather than surfaced as a button for the operator to press. The
	// precondition still exists — it now only fails when the read itself does.
	st.EvidencePath = s.evidencePath()
	if err := st.EnsureEvidence(); err != nil {
		log.Printf("[evidence] could not refresh the snapshot: %v", err)
	}
	return p, st, nil
}

// profile is state() without the state: the one docker read, and nothing
// after it.
//
// A caller that writes `profile, err := s.profile(ctx)` is saying it wants the
// container's identity and nothing else — and eleven of them do. They were all
// paying for the rest anyway: host.New, and then EnsureEvidence, which on a
// snapshot older than the hour goes and takes a fresh one. Taking one means an
// admin-RPC server_info round trip and a file write, and server_info is exactly
// the call that goes slow on a host busy re-acquiring its ledger store — which
// is the host an operator is most likely to be approving something on.
//
// So /v1/approve/begin, the one request standing between the confirm code and
// the passkey prompt, was waiting on a diagnostic snapshot whose result it then
// discarded (#105). Nothing is lost by not taking it here: /v1/check calls
// state() and USES it, on every poll of the tab, so the snapshot goes on being
// refreshed by the surface that actually reports on it.
func (s *server) profile(ctx context.Context) (host.Profile, error) {
	return s.discoverProfileCached(ctx)
}

// profileKeyed is profile() plus the identity key this node's approvals,
// windows and compact are all keyed by, host.Profile.IdentityKey, #398.
//
// The two are returned together on purpose. A handler that reads the profile
// and then keys an approval off a field of it is the pairing that broke: the
// key was profile.Container at every such site, empty on a native host, so a
// plan would have been signed against "" and a window opened under "" would
// have been found by any other node that did the same. Handing both back from
// one call means the error branch the handler already has (it could not read
// the deployment) is the same branch as "it could not name the node", and no
// site gets to carry on with a key it did not check.
func (s *server) profileKeyed(ctx context.Context) (host.Profile, string, error) {
	p, err := s.profile(ctx)
	if err != nil {
		return host.Profile{}, "", err
	}
	key, err := p.IdentityKey()
	if err != nil {
		return host.Profile{}, "", err
	}
	return p, key, nil
}

// readState is a State for reading, built from a profile already in hand:
// no snapshot is taken, unlike state(). For a door that has only the profile
// and needs one host reading, the rollback's derivation (#998).
func (s *server) readState(ctx context.Context, p host.Profile) *host.State {
	st := host.New(ctx, p, s.runner, s.client)
	st.LedgerPath = s.ledgerPath()
	st.Wrapper = s.wrapper
	return st
}

// stateKeyed is state() plus the identity key, and exists for the reason
// profileKeyed does: the handlers that read the host's state are the ones
// that then sign a plan against it, and a key that was never checked is how a
// plan comes to be signed against "".
func (s *server) stateKeyed(ctx context.Context) (host.Profile, string, *host.State, error) {
	p, st, err := s.state(ctx)
	if err != nil {
		return host.Profile{}, "", nil, err
	}
	key, err := p.IdentityKey()
	if err != nil {
		return host.Profile{}, "", nil, err
	}
	return p, key, st, nil
}

// nodeKey is the identity key alone, for the readers that key on it without
// needing the profile itself: the status poll's break-glass block, the ask
// path's gate, and the four first-turn action gates.
//
// The fallback to s.container is deliberate and is not a fallback to "". That
// flag is the name this process was started with on a container install, and
// it is the name the compact on such a host was accepted under, so it remains
// a real answer when the wrapper read fails, a docker hiccup should not turn
// an admin's open window into "break glass first". A native install has no
// such flag (it is empty by construction), and keying anything on the empty
// string is the collision #398 exists to close, so that path refuses.
func (s *server) nodeKey(ctx context.Context) (string, error) {
	_, key, err := s.profileKeyed(ctx)
	if err == nil {
		return key, nil
	}
	if s.container != "" {
		return s.container, nil
	}
	return "", fmt.Errorf("this host cannot name its node: %w", err)
}

func (s *server) evidencePath() string {
	return host.ConventionalEvidencePath(s.stateDir)
}

// GET /v1/status — is the Advisor set up on this host, and how.
func (s *server) status(_ http.ResponseWriter, r *http.Request) (any, int) {
	out := map[string]any{"read_only": true, "node": s.container}

	// This binary's own build ref (#266), off the same ldflags variable
	// -version prints. "dev" on an unstamped build, the dashboard already
	// reads that as "not measured" rather than as a mismatch, the same
	// reading relay's unstamped `relay_version` gets.
	out["version"] = version

	// Whether this service is holding a question right now — punch #24. A
	// deploy polls this before it stops the service, so the restart lands
	// between questions instead of on top of one. Published unconditionally,
	// including the zero, because a field that is only present when busy
	// cannot be told apart from a field a caller failed to read.
	out["asks_in_flight"] = s.asksInFlight()

	// What this host has been TOLD it is, when it has been told. Strictly
	// additive: "node" above still reports the container this process was
	// pointed at, because the tab renders it (advisor.html reads
	// p.container || d.node) and this change does not touch the tab.
	//
	// So an aggregator's status still carries the container name it was
	// defaulted to — but no longer ONLY that. A reader now has the honest
	// fact beside it, from the one place that cannot be inferred wrong: the
	// operator's own registry. Suppressing the node probe on a declared
	// aggregator is the obvious next step and is deliberately not taken
	// here — its consumer is in the tab, and the tab is being changed
	// elsewhere.
	// #64. The box's own name, from the kernel, beside the container name and
	// the fleet label. The tab's NODE row names the node an operator selected;
	// without this it could not say which MACHINE that is, while the confirm
	// gate a click later could. Two surfaces naming one node differently is
	// what #64 and #65 are about.
	//
	// Top level, NOT inside the self block below: that block only appears when
	// the fleet registry knows this host (Known() is label-or-role), and a
	// dashboard-alone host still has a hostname. A fact about the box, not
	// about fleet membership.
	//
	// Same source as the confirm gate's, deliberately: hostname() in
	// restart_action.go, the kernel's answer asked fresh each time. Empty when
	// it cannot be read, which the tab renders as absent rather than guessing.
	if h := hostname(); h != "" {
		out["hostname"] = h
	}

	if self := s.fleetNow().reg.SelfIdentity(); self.Known() {
		sf := map[string]any{}
		if self.Label != "" {
			sf["label"] = self.Label
		}
		if self.Role != "" {
			sf["role"] = self.Role
		}
		out["self"] = sf
	}

	profile, err := s.profile(r.Context())
	if err != nil {
		// Report the failure and keep going. Model, trust and compact are
		// facts about THIS host, not about the node — returning early here
		// dropped all three whenever the node was unreachable, and the
		// dashboard read the missing trust field as "the Advisor did not
		// report which passkeys it will accept": a spurious stale-trust
		// banner in the middle of a node outage (and permanently on an
		// aggregator host, which has no node to inspect at all).
		out["deployment_error"] = err.Error()
	} else {
		out["profile"] = profile
	}

	// How big the node's ledger store is, measured on the privileged side.
	//
	// #427. The dashboard cannot open the store on a host where the node runs
	// from its vendor's package: the state directory is 0750 and owned by the
	// node's own account, and giving the account that serves a web page read
	// access to the whole ledger store to fix that is the wrong trade. The
	// wrapper already runs as root and already answers `disk`, so this is one
	// more number over a boundary that exists, rather than a new one.
	//
	// Only where there is a node and a wrapper to ask. An aggregator has
	// neither, and a block that always says "could not be measured" on a host
	// with nothing to measure is noise the dashboard would have to learn to
	// ignore.
	if !s.noLocalNode() && s.wrapper != "" {
		out["store"] = s.storeSizeCached(r.Context())
	}

	// Whether a model is configured and which one — see modelStatus in
	// modelconfig.go for the fields and for why this fact is on status at
	// all rather than discovered by asking the model a question.
	out["model"] = s.modelStatus()

	// What this service will actually accept as an approver. Published so the
	// dashboard — which owns the truth about who may approve — can notice its
	// replica has fallen behind, instead of the operator discovering it when
	// an approval fails and blames their passkey.
	if t := s.trustStatus(); t != nil {
		out["trust"] = t
	}

	// Which fleet knowledge bundle this node is running (ADR 0017). Same
	// reasoning as the trust block beside it: the aggregator knows which
	// sequence it last pushed, and this is how it sees a node that never took
	// it — before an answer somewhere in the fleet is based on a corpus two
	// pushes behind.
	if k := s.knowledgeStatus(); k != nil {
		out["knowledge"] = k
	}

	// The identity key, not the container flag. The flag defaults to SERVICE
	// out of the wrapper's configuration file, which is a record of what was
	// detected at install; the key is read from the deployment itself. Those
	// two agree on a host nobody has moved anything on, and where they
	// disagree, a stale record or a partial name on the command line, this
	// block would answer about a different node than the gates, the windows
	// and the executor, all of which key on the identity (#398). An operator
	// reading a compact that says accepted while a restart is refused has no
	// way to see which of the two moved. The flag stays as the fallback,
	// because on the shape that has one it is a real name (#466).
	compactNode := s.container
	if k, kerr := s.nodeKey(r.Context()); kerr == nil {
		compactNode = k
	}
	if a, err := compact.Load(filepath.Join(s.stateDir, "compact.json"), compactNode); err == nil {
		out["compact"] = map[string]any{
			"accepted": true, "accepted_by": a.AcceptedBy, "accepted_at": a.AcceptedAt,
			"privilege": a.Privilege, "classes": a.Classes, "notes": a.Notes,
			"terms_version": a.TermsVersion,
		}
	} else {
		out["compact"] = map[string]any{"accepted": false, "reason": err.Error()}
	}

	// The break-glass window's status — ui-design §4.6's additive block on
	// this same document, so the chip and the cross-tab nav marker share
	// one status poll with the step trace rather than a bespoke route. The
	// chip's countdown is specified to come from the SERVICE's view, never
	// a client timer (§11.12) — this is that view. OpenForNode calls
	// Touch internally, so a window that has quietly expired since the
	// last poll is reported closed here rather than stale-open.
	//
	// Looked up by the identity key, which is what the window was opened
	// under (#398). This read used s.container, and the comment below already
	// recorded that the two are not guaranteed equal, a partial name or an
	// id prefix on the command line and the chip goes dark over an open
	// window. The profile is already in hand here, so this costs no read.
	var win *breakglass.Window
	var open bool
	if bgNode, bgErr := s.nodeKey(r.Context()); bgErr == nil {
		win, open = s.breakglass.OpenForNode(bgNode, time.Now())
	} else {
		log.Printf("[status] no node identity, so no window can be reported: %v", bgErr)
	}
	if open {
		out["breakglass"] = map[string]any{
			"open": true, "window_id": win.ID, "expires_at": win.ExpiresAt,
			// The node this window belongs to, taken from the WINDOW rather
			// than from anything this handler computed. The page sends it back
			// on continue and close, where it is compared against the profile's
			// identity key; win.Node is the value the window was opened with,
			// so it is the value that matches even if the deployment has been
			// re-read since. The trap this closed: s.container is the name this
			// process was started with, and the key is what the host actually
			// calls the node, so a partial name or an id prefix on the command
			// line used to make a purely local close refuse itself.
			"node":      win.Node,
			"opened_by": win.OpenedBy, "in_flight": win.InFlight,
			"questions_used": win.Questions, "questions_max": breakglass.MaxQuestions,
			"privileged_reads_used": win.PrivilegedReads, "privileged_reads_max": breakglass.MaxPrivilegedReads,
			"spend_tokens_used": win.PromptTokens + win.CompletionTokens, "spend_tokens_max": breakglass.MaxSpendTokens,
		}
	} else {
		bg := map[string]any{"open": false}
		// Why there is no window, when there was one recently. Without this
		// the tab could not tell "nobody has broken glass" apart from "yours
		// just ended", so a window taken away by a service restart looked
		// exactly like one that had never existed and the next question ran
		// ungated with nothing said (validator1, 2026-08-21, issue #40).
		if e := s.recentlyEnded(time.Now()); e != nil {
			bg["ended"] = map[string]any{
				"window_id": e.WindowID, "closed_because": e.Reason,
				"opened_by": e.OpenedBy, "node": e.Node,
				"at": e.At.UTC(), "reconstructed": e.Reconstructed,
			}
		}
		out["breakglass"] = bg
	}

	// "Present" has to mean usable, not merely on disk. The wrapper takes its
	// paths from a root-owned config written at install; without it the script
	// exists and refuses every verb. Reporting present:true in that state would
	// tell the tab the execute path is ready and let the operator find out
	// otherwise partway through an upgrade.
	// The read surface — ADR 0008. Probed here so the tab can name the state
	// ("unauthorized" is token drift, "unreachable" is a service problem, a
	// version mismatch names the fix) instead of rendering an empty panel,
	// the same treatment advisor_unreachable already gets on the other side.
	{
		// 4 s, not 1.5: an aggregator's dashboard is a busy Node process (fleet
		// pollers, SQLite) and a status probe that gives it a second and a
		// half painted "read API not answering" on the tab for one poll and
		// cleared it on the next, in a loop (operator, 2026-08-19). And one
		// missed probe does not override one that succeeded seconds ago:
		// within 90 s of a good probe the surface is reported ok, with the
		// miss named, so the tab's banner only appears when the API has
		// actually been away.
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		ok, state := s.dashRead.Probe(ctx)
		cancel()
		s.readSurfaceMu.Lock()
		if ok {
			s.readSurfaceLastOK = time.Now()
		}
		lastOK := s.readSurfaceLastOK
		s.readSurfaceMu.Unlock()
		rsOut := map[string]any{"ok": ok, "state": state}
		if !ok && !lastOK.IsZero() && time.Since(lastOK) < 90*time.Second {
			rsOut = map[string]any{"ok": true, "state": "ok", "last_probe": state,
				"last_ok_s": int(time.Since(lastOK).Seconds())}
		}
		out["read_surface"] = rsOut
	}

	// Where an operator would run the same thing by hand, from THIS host
	// rather than from the layout the release was built on. The tab used to
	// print a path that existed on one machine, under an account that owns
	// none of the state, so the offered command failed for everyone else.
	{
		advisorDir := filepath.Dir(s.stateDir) // <repo>/advisor
		hr := map[string]any{
			"advisor_dir": advisorDir,
			"executor":    filepath.Join(advisorDir, "bin", "aperire-executor"),
		}
		if u, err := user.Current(); err == nil {
			hr["account"] = u.Username
		}
		out["host_run"] = hr
	}

	w := map[string]any{"path": s.wrapper}
	if _, err := os.Stat(s.wrapper); err != nil {
		w["present"] = false
		w["reason"] = "not installed at this path"
	} else if _, err := os.Stat(wrapperConfPath); err != nil {
		w["present"] = false
		w["reason"] = "no wrapper configuration at " + wrapperConfPath
		w["remedy"] = "curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper (a node in docker) or curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native (a node run by systemd)"
	} else {
		w["present"] = true
	}
	out["wrapper"] = w

	// The terms themselves, so the tab can show what would be agreed to
	// rather than paraphrasing it. V2 — plan-interrogative-loop §11.6 —
	// adds the break-glass paragraph; a host holding a V1 acceptance shows
	// compact.accepted:false below until it re-runs the ceremony.
	t := compact.V2()
	out["terms"] = map[string]any{"version": t.Version, "hash": t.Hash(), "body": t.Body}
	return out, http.StatusOK
}

// stageVerdict is one precondition, evaluated. Shared between /v1/check and
// the ask context's CEREMONY STATE block (see ceremonyContext below) so the
// two never disagree about which checks are failing or which stage a
// failure gates — one evaluation, two renderings.
type stageVerdict struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	// Unmeasured: the check could not take its reading at all (#679). It
	// travels beside Passed rather than replacing it, so a reader that
	// does not know the field behaves as it did before and one that does
	// can stop rendering "I never looked" as a green.
	Unmeasured bool `json:"unmeasured,omitempty"`
	// Which stage this check gates. Empty means every stage.
	Gates string `json:"gates,omitempty"`
	// Key and NoOp are for a machine reader (#838). Key names the check
	// when the runbook gave it one, so a reader never has to find a check
	// by its sentence; NoOp says this failure is the plan changing nothing,
	// the finished state rather than a safety refusal.
	Key  string `json:"key,omitempty"`
	NoOp bool   `json:"no_op,omitempty"`
}

// evaluateReadiness runs a runbook's preconditions against the host once and
// derives, per stage, whether that stage is blocked. Per stage, because a
// check that an earlier stage SATISFIES cannot also forbid that stage.
// Requiring a dated backup before prepare — when prepare's first two steps
// are what take it — made a first upgrade on a host with no previous
// backups impossible to start: the tab correctly refused to offer an
// approval nothing could ever unblock.
func evaluateReadiness(rb runbook.Runbook, params runbook.Params, st runbook.HostState) (vs []stageVerdict, blocked bool, blockedFor map[string]bool) {
	// Seeded from the runbook's own stages rather than from the upgrade's
	// pair. A one-stage runbook seeded with prepare/cutover reports two
	// stages nothing runs and says nothing about the one that does —
	// ADR 0016.
	blockedFor = map[string]bool{}
	for _, stage := range rb.Stages {
		blockedFor[stage] = false
	}
	for _, pc := range rb.Preconditions {
		x := pc.Check(params, st)
		vs = append(vs, stageVerdict{Name: x.Name, Passed: x.Passed, Detail: x.Detail,
			Unmeasured: x.Unmeasured, Gates: pc.Gates, Key: pc.Key, NoOp: x.NoOp})
		if !x.Passed {
			blocked = true
			if pc.Gates == "" {
				for _, stage := range rb.Stages {
					blockedFor[stage] = true
				}
			} else {
				blockedFor[pc.Gates] = true
			}
		}
	}
	return vs, blocked, blockedFor
}

// GET /v1/check?target=3.2.1 — the preconditions, evaluated against the node
// right now. This is the endpoint that makes the tab true rather than
// decorative.
func (s *server) check(_ http.ResponseWriter, r *http.Request) (any, int) {
	t0 := time.Now()
	profile, st, err := s.state(r.Context())
	tState := time.Since(t0)
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	v, rb, params, derived, err := s.resolveRunbook(r, st)
	tResolve := time.Since(t0) - tState
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusBadRequest
	}
	// Ahead of the cache, so a check measured for a target this node does
	// not derive is never served, and no confirm code is handed out for one
	// (#998). One wrapper read, and only for a rollback.
	if rb.ID == rollbackRunbookID {
		if _, refusal := s.rollbackTargetGate(st, v); refusal != nil {
			return refusal, http.StatusBadRequest
		}
	}
	// Serve the last answer measured for this plan, and measure again behind
	// it if that answer is past its TTL. The rotation reading names the entry
	// (the key is split on it, issue #93); it is the most recent one taken,
	// used here only to find the entry, and the entry was built from the
	// reading that was current when it was evaluated. A plan with no answer
	// within the bound, or none at all, is evaluated in line below.
	// A request has named a plan, which is what the keeper keeps warm and
	// what stops it going quiet (#250).
	woke, persist := s.warm.asked(r.URL.RawQuery)
	if woke {
		log.Printf("[check-warm] a request arrived; keeping the check warm again")
	}
	if persist {
		// So a restart begins warm on the plans somebody was looking at. One
		// small atomic write, and never a reason this request fails.
		s.saveWarmPlans()
	}
	// A plan whose last refresh failed is served only as far as the guide
	// promises (checkFailedMax), not to the ten-minute bound: the body behind
	// a failure is the one nobody has been able to renew, and past the
	// promise the request measures in line, where a host that still cannot
	// be read answers with its reason instead of a plausible old card.
	//
	// The failure belongs to the plan, not to the query string that happened
	// to ask: the server asks with runbook=upgrade-xrpld and the page with
	// target=3.4.1, and both are served the one entry.
	if rotating, _, ok := s.rotCache.last(checkStaleMax); ok {
		key := checkCacheKey(rb, params, rotating)
		s.warm.note(key, r.URL.RawQuery)
		b, at, stale, hit := s.cachePeekAt(key, checkStaleMax)
		// A failure counts only when it is newer than the entry it is
		// reported beside: a good evaluation under any query clears it, and
		// one that landed first never carries a later plan's failure.
		failure, failed := s.refreshFailure(key)
		failed = failed && failure.At.After(at)
		if hit && failed && time.Since(at) > checkFailedMax {
			hit = false
		}
		if hit {
			if stale {
				s.refreshCheck(key, r.URL.RawQuery)
			}
			var out map[string]any
			if err := json.Unmarshal(b, &out); err == nil {
				// Stamped now, never into the stored bytes: the age is the
				// entry's at the moment of this answer, and a refresh
				// failure belongs to the serve that reports it.
				out["age_seconds"] = int(time.Since(at).Seconds())
				if failed {
					out["refresh_failed"] = map[string]any{"at": failure.At.UTC().Format(time.RFC3339), "reason": failure.Reason}
				}
				return out, http.StatusOK
			}
			var raw any
			json.Unmarshal(b, &raw)
			return raw, http.StatusOK
		}
	}
	res, code := s.checkEvaluate(st, profile, v, rb, params, derived, r.URL.RawQuery, t0, tState, tResolve)
	if m, ok := res.(map[string]any); ok && code == http.StatusOK {
		// Measured in this request, so no age. The stored copy was marshalled
		// before this line and does not carry it.
		m["age_seconds"] = 0
	}
	return res, code
}

// Serving stale, the 2026-09-02 change to /v1/check.
//
// An uncached check pays for a wrapper exec that reads the node's container
// log (the rotation state) and a readiness evaluation: 2.7 to 3.9 seconds
// on the aperire4 VPS, for an entry that lasted ten seconds. The Operations
// card cannot paint its head until this answers, so every return to the tab
// more than ten seconds after the last poll was a blank panel that filled
// in and folded a few seconds later. The operator noticed.
//
// Now the answer the card paints is the last one measured, handed back at
// once, and a fresh evaluation starts behind it when that answer is older
// than the TTL. The next poll gets the fresh one. Nothing is measured more
// often than before: one refresh per plan is in flight at a time, and a
// poll that finds one running does not start another. Nothing is served
// that was not measured: the body carries its own evaluated_at.
//
// Bounded, at checkStaleMax. Past it the last answer is not served and the
// request evaluates in line as it always did: ten minutes is long enough
// for the node to have changed under an operator who has not been looking,
// and a body that old should not be the first thing they see.
//
// What #93 keeps. The rotation state is read fresh (within its own
// ten-second cache) on every refresh and on every in-line evaluation, and
// the key still separates the two states, so a rotation that begins while
// a stale idle body is being served is late by one refresh plus one poll,
// a few seconds, and then the idle entry is never looked at again. The
// safety boundary was never here: the wrapper's exit-64 refusal and the
// RunStage guard's fresh read still stand at the moment of the act.
//
// A capture that resets the cache (cacheReset) also outdates any evaluation
// still in flight: what it measured is from before the act, so its result
// is dropped rather than stored as the first answer after it.
const (
	checkStaleMax       = 10 * time.Minute
	checkRefreshTimeout = 90 * time.Second
	// checkFailedMax is as old as a body is served once the refresh behind it
	// has failed (#1017). The guide says the keeper holds the answer to about
	// three minutes; this is that and the room for one evaluation, so the
	// promise stays true on the one path where nothing renewed the body.
	checkFailedMax = 4 * time.Minute
)

// checkRefreshFailure is why the last refresh of a plan stored nothing and
// when it said so. It is kept until a good evaluation of the plan lands, and
// it is reported in the body served meanwhile (#1017): a failed refresh used
// to leave the old body in place with a journal line as its only trace.
type checkRefreshFailure struct {
	At     time.Time
	Reason string
}

// noteRefreshFailure records that a refresh of the plan stored under key
// failed. Keyed on the plan (the key without its rotation split), not on the
// query string: two queries can name one plan and are served one entry.
func (s *server) noteRefreshFailure(key, reason string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.refreshFails == nil {
		s.refreshFails = map[string]checkRefreshFailure{}
	}
	s.refreshFails[planKeyOf(key)] = checkRefreshFailure{At: time.Now(), Reason: reason}
}

func (s *server) clearRefreshFailure(key string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	delete(s.refreshFails, planKeyOf(key))
}

func (s *server) refreshFailure(key string) (checkRefreshFailure, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	f, ok := s.refreshFails[planKeyOf(key)]
	return f, ok
}

// planKeyOf is a cache key without its rotation split: the plan itself. A
// failed host read happens before any rotation reading exists, and both
// entries of a plan are renewed by the same refresh.
func planKeyOf(key string) string {
	return strings.Replace(key, "|rotating", "", 1)
}

// refreshCheck re-evaluates one plan in the background, once, however many
// polls ask while it runs. The plan is named by its query string, the same
// way the tab named it, so the refresh resolves exactly what was served.
func (s *server) refreshCheck(key, rawQuery string) {
	if !s.claimRefresh(key) {
		return
	}
	go func() {
		defer s.releaseRefresh(key)
		// Its own context: the poll that started this has already been
		// answered, and its request context dies with it.
		ctx, cancel := context.WithTimeout(context.Background(), checkRefreshTimeout)
		defer cancel()
		s.evaluateCheck(ctx, key, rawQuery)
	}()
}

// refreshCheckNow is the same refresh, run in line and reported on: whether it
// ran at all (another one may already hold this plan) and what the evaluation
// made of the host. The keeper calls this one, so that its backoff decides on
// the evaluation's own outcome rather than on a goroutine it cannot see, and
// so that it goes through the same in-flight rule a poll's refresh does.
func (s *server) refreshCheckNow(ctx context.Context, key, rawQuery string) (ran bool, err error) {
	if !s.claimRefresh(key) {
		return false, nil
	}
	defer s.releaseRefresh(key)
	return true, s.evaluateCheck(ctx, key, rawQuery)
}

// claimRefresh takes the one refresh slot for a plan, or reports that
// somebody else holds it. releaseRefresh gives it back.
func (s *server) claimRefresh(key string) bool {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.refreshing == nil {
		s.refreshing = map[string]bool{}
	}
	if s.refreshing[key] {
		return false
	}
	s.refreshing[key] = true
	return true
}

func (s *server) releaseRefresh(key string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	delete(s.refreshing, key)
}

// evaluateCheck reads the host, resolves the plan its query string names and
// measures it, storing the answer under the plan's own key. The body of a
// refresh, with no cache bookkeeping of its own: both callers above have
// already taken the slot.
func (s *server) evaluateCheck(ctx context.Context, key, rawQuery string) error {
	t0 := time.Now()
	profile, st, err := s.state(ctx)
	tState := time.Since(t0)
	if err != nil {
		log.Printf("[check] the background refresh could not read the host: %v", err)
		s.noteRefreshFailure(key, "the host could not be read: "+err.Error())
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/check?"+rawQuery, nil)
	if err != nil {
		s.noteRefreshFailure(key, "the plan could not be rebuilt: "+err.Error())
		return err
	}
	v, rb, params, derived, err := s.resolveRunbook(r, st)
	tResolve := time.Since(t0) - tState
	if err != nil {
		log.Printf("[check] the background refresh could not resolve %q: %v", rawQuery, err)
		s.noteRefreshFailure(key, "the plan could not be resolved: "+err.Error())
		return err
	}
	// Its answer was thrown away here, and an evaluation that returned an
	// error body had stored nothing: the refresh then reported success, so
	// the keeper did not back off and nothing said the entry had not been
	// renewed (#1017).
	res, code := s.checkEvaluate(st, profile, v, rb, params, derived, rawQuery, t0, tState, tResolve)
	if code != http.StatusOK {
		reason := "the check could not be evaluated"
		if m, ok := res.(map[string]any); ok {
			if e, ok := m["error"].(string); ok && e != "" {
				reason = e
			}
		}
		log.Printf("[check] the background refresh of %q stored nothing: %s", rawQuery, reason)
		s.noteRefreshFailure(key, reason)
		return errors.New(reason)
	}
	return nil
}

// checkEvaluate is the measurement itself: the rotation reading, the
// preconditions, the plan identity, the assessment. It stores what it built
// under the plan's key and returns it, and it is the only thing that does.
func (s *server) checkEvaluate(st *host.State, profile host.Profile, v string, rb runbook.Runbook, params runbook.Params, derived bool,
	rawQuery string, t0 time.Time, tState, tResolve time.Duration) (any, int) {
	// The identity this plan is signed against (#398). Read before anything
	// is measured: a check whose node cannot be named would publish a confirm
	// code minted against "", and that code is what the operator approves.
	node, err := profile.IdentityKey()
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	// Phase timings, logged only when the whole check ran slow. Operational
	// telemetry, not scaffolding: a check that took half a minute has ONE
	// dominant term, and validator1 proved that guessing at it burns days
	// while one log line answers it.
	var tRotation, tEval, tTail time.Duration
	defer func() {
		if total := time.Since(t0); total > 3*time.Second {
			log.Printf("[check] slow: total=%s state=%s resolve=%s rotation=%s evaluate=%s tail=%s",
				total.Round(time.Millisecond), tState.Round(time.Millisecond),
				tResolve.Round(time.Millisecond), tRotation.Round(time.Millisecond),
				tEval.Round(time.Millisecond), tTail.Round(time.Millisecond))
		}
	}()
	// An evaluation that straddles a capture is from before it; see
	// toCacheAt.
	gen := s.cacheGeneration()
	// Read BEFORE the entry is named, and folded into its key — issue #93.
	//
	// This response carries the confirm code the Operations card mints its gate
	// from, and the whole point of withholding it during a rotation is that the
	// operator is never invited to a ceremony the wrapper will refuse. A body
	// cached while the store was idle would keep handing that code out for the
	// rest of the TTL after a rotation started, which is the bug wearing a
	// ten-second hat. Keying on the rotation makes the two states two entries,
	// so neither can be served as the other.
	//
	// One wrapper read per evaluation. The same read the chat assessment
	// already takes per assessment (restart_action.go), on the same verb.
	//
	// A failed read is logged and treated as not in flight, never returned as
	// an error: RotationInFlight fails open on purpose, and turning its error
	// into a failed /v1/check would black out the whole tab on a host whose
	// container log could not be read.
	rotating, rotationDetail, roterr := s.rotationInFlightCached(st)
	if roterr != nil {
		log.Printf("[check] the store-rotation state could not be read, treating it as not in flight: %v", roterr)
	}
	tRotation = time.Since(t0) - tState - tResolve
	key := checkCacheKey(rb, params, rotating)
	// The node's server_info reads are counted from here, so node_read below
	// speaks for this evaluation and not for the evidence refresh that built
	// the State (#1106).
	st.ResetNodeRead()
	vs, blocked, blockedFor := evaluateReadiness(rb, params, s.readinessHost(st))
	tEval = time.Since(t0) - tState - tResolve - tRotation
	planID, fp, confirmCode := planIdentity(rb.ID, node, params)
	deploymentTag, dterr := st.DeploymentTag()
	if dterr != nil {
		deploymentTag = ""
	}
	// The whole reference the file names (#664, review of PR #981). The tag
	// alone cannot tell a deployment naming the official digest from one
	// naming a build of the same release, and the card's "the digest the
	// deployment names" line is only true of the first. Empty on a native
	// host and when the file could not be read.
	deploymentImage, dierr := st.DeploymentImage()
	if dierr != nil {
		deploymentImage = ""
	}
	tTail = time.Since(t0) - tState - tResolve - tRotation - tEval
	out := map[string]any{
		"target": v, "runbook": rb.ID, "class": rb.Class,
		"node": node, "profile": profile,
		"verdicts": vs, "blocked": blocked, "blocked_for": blockedFor,
		// What the deployment file names right now. The tab derives "prepare
		// has staged the change" from this — an observation of the host, not
		// an inference from ledger record shapes, which lied once already.
		// Read once, above, and handed to the assessment as well: two reads
		// in one response can disagree.
		"deployment_tag":   deploymentTag,
		"deployment_image": deploymentImage,
		// The identity of this plan, computed here from what was actually
		// evaluated. A caller that supplied its own could bind an approval to
		// a plan nobody read.
		"plan_id": planID, "fingerprint": fp,
		// True when the Advisor chose this target itself from the registry,
		// rather than being asked about one. The page displays a decision;
		// this is where the decision is made.
		"target_derived": derived,
		// Which stages already hold a live approval. Without this the tab has
		// no way to know an approval survives a navigation, so leaving the page
		// and coming back looked like the approval was lost — and the operator
		// was asked to approve something they had already approved.
		"approved": s.liveApprovals(planID, fp, node, rb.Stages),
		// Which stage last produced a transcript. Without this the tab guessed
		// from whether prepare had finished, switched to watching a cutover
		// stream that did not exist yet, and a completed run appeared to
		// vanish the moment the operator navigated away and back.
		"last_run": s.lastRun(planID, rb.GrantScopes),
		// Is the node's ledger store mid-rotation — issue #93. Its OWN signal,
		// kept out of blocked_for, for the reason #80 and #90 kept it separate
		// on the chat path: the remedy differs. A precondition says go and
		// look at something; this says wait a few minutes.
		//
		// One verdict does read it (#833): "the next store rotation is further
		// off than this swap", when the store is at or past its window. That
		// row used to pass there and leave the rest to this signal, so on a
		// node whose rotations run long it passed only while one was running.
		// It now REFUSES while this reads rotating, from this same reading
		// (rotationForVerdict), so the card shows the withheld code below and
		// a refusing row that says a rotation is running.
		//
		// Published in both states, because a field that appears only when true
		// cannot be told apart from a field the caller failed to read. The
		// detail is what distinguishes "measured, not rotating" from "could not
		// be read", which both arrive here as false — RotationInFlight fails
		// open, so absent is not zero.
		"rotating":        rotating,
		"rotation_detail": rotationDetail,
		"evaluated_at":    time.Now().UTC(),
	}
	// The XXXX-XXXX the operator types to approve. Published on purpose: it
	// identifies a plan, it does not authorise one, and its whole value is
	// being checkable against an independent source.
	//
	// WITHHELD during a rotation, and that is the Operations card's half of
	// issue #93. The card builds its gate only when it is holding a code
	// (termGate's `planState.code`), so an absent one is what stops a doomed
	// ceremony being offered — the same outcome the chat path reaches by
	// refusing before it proposes. Not `blocked`, which would claim a
	// precondition refuses when all of them pass, and not an empty verdict
	// list: the plan is fine, the clock is wrong.
	if !rotating {
		out["confirm_code"] = confirmCode
	}
	// The bound parameters, echoed back under their own names. The tab needs
	// the intent it is holding a confirm code for, and "target" cannot carry
	// it: they are different parameters on different runbooks, and one field
	// meaning two things is how a free-text reason ends up bound to an enum.
	for k, val := range params {
		out[k] = val
	}
	// The restart assessment — readings, the measured expectation, and
	// anything amber. Only this runbook produces one: an assessment on the
	// upgrade would be a second, quieter verdict beside preconditions that
	// already refuse (ADR 0016 decision 3).
	if rb.ID == restartRunbookID {
		out["assessment"] = restartAssessment(st, deploymentTag)
	}
	// RB-003 publishes both: the assessment the model reads, and the diff the
	// operator approves. The diff is computed here for the same reason the
	// plan identity is — one evaluation, from the node's own configuration,
	// so the gate and the approval endpoint cannot be looking at two
	// different changes. A diff that cannot be computed is reported as its
	// own error rather than left absent: absent renders as "no change".
	// Where a target the Advisor chose itself came from, and when that
	// origin was read. Published only beside a derived target, because there
	// is no origin behind one the caller named, and target_derived above is
	// the field that tells those apart: a reader never has to guess whether
	// the pair is missing or inapplicable.
	//
	// #421. The origin is not the same on both shapes, an image registry on a
	// container host and this host's own package repositories on a native
	// one, and a recommendation that does not say which it read cannot be
	// checked by the operator against anything. Read off the shelf, never
	// asked again here, so the page cannot show a source from one lookup
	// beside a version from another.
	if derived {
		if note, ok := s.latestReleaseNote(); ok && note.Version == v {
			out["target_source"] = note.Source
			out["target_source_read_at"] = note.ReadAt
		}
	}
	// #682. Where this release's image would come from, and the digest it
	// would be pinned to. Published for every upgrade plan, derived target
	// or named, because the card's whole first sentence turns on it and an
	// operator reading "3.4.2 is out" has to be told whether an official
	// image carries it.
	//
	// image_source is the words the card uses; image_source_kind is the
	// enum a button sends back, so the page never has to map one to the
	// other and the two vocabularies cannot drift into each other.
	if rb.ID == defaultRunbook && v != "" && st.Kind() != "native" {
		switch params["source"] {
		case "official":
			out["image_source"] = host.OfficialImageSource
			out["image_source_kind"] = "official"
			out["image_digest"] = params["digest"]
			out["image_source_detail"] = host.OfficialImageRepo + ":" + v +
				" is published, pinned at " + params["digest"]
		case "build":
			out["image_source"] = host.OriginLocalBuild.Sentence()
			out["image_source_kind"] = "build"
			out["image_source_detail"] = "you asked for a build, so no registry was asked about " + v
		default:
			// Nothing was pinned when the plan was made, which on a
			// container host means no official tag carried the target.
			// The words come from the reader the plan itself used, so the
			// card and the run cannot disagree about where an image would
			// come from.
			src, digest, why := s.upgradeSource(st, v)
			out["image_source"] = src
			out["image_source_detail"] = why
			if digest != "" {
				out["image_digest"] = digest
			}
			// Derived, never left empty: this is what the card's "build it
			// here instead" button binds against, and a blank would have the
			// page guessing which of two sources it is replacing.
			if src == host.OfficialImageSource && digest != "" {
				out["image_source_kind"] = "official"
			} else {
				out["image_source_kind"] = "build"
			}
		}
		// The advice panel and the gating rows, one reading. The gating
		// ones render in the Operations card because they are what an
		// upgrade is waiting on; the rest render in "Your node's setup"
		// and stay advice.
		//
		// The source is the one the card is naming just above, so a gating
		// row is on the card for the image the run would actually use. Only
		// an explicit build relaxes anything; anything else reads as the
		// official image, the strict reading (#1009).
		findings, shape := st.ShapeFindings(out["image_source_kind"] != "build")
		out["setup_findings"] = findings
		out["setup_gating"] = host.GatingFindings(findings)
		out["setup_read"] = shape.Read
		if len(shape.Notes) > 0 {
			out["setup_notes"] = shape.Notes
		}
	}
	// How long the node is out of consensus once this plan's restart begins,
	// measured on this node (#1014). Published for the two acts whose gates
	// state it, so the card renders the service's sentence instead of a
	// figure of its own: the card's "about 30 seconds offline" was a
	// container coming back up, and a validator was out for 7 to 8.5 minutes.
	// The rollback's own caveat is in its assessment's expected line.
	if rb.ID == defaultRunbook || rb.ID == rollbackRunbookID {
		m := outage.FromLedgerFile(s.ledgerPath())
		out["offline_expected"] = upgradeExpectationFor(profile.Kind, m.Sentence())
		if rb.ID == rollbackRunbookID {
			out["offline_expected"] = rollbackExpectation(m.Sentence())
		}
		measured := map[string]any{"runs": m.Runs}
		if m.Runs > 0 {
			measured["shortest_sec"] = int(m.Shortest.Seconds())
			measured["longest_sec"] = int(m.Longest.Seconds())
			measured["last_at"] = m.LastAt.UTC()
		}
		out["offline_measured"] = measured
	}
	if rb.ID == configRunbookID {
		out["assessment"] = configAssessment(st, deploymentTag)
		if d, derr := configDiffFor(st, params["key"], params["value"]); derr == nil {
			out["diff"] = d
			out["scope"] = configScopeFor(d)
		} else {
			out["diff_error"] = derr.Error()
		}
	}
	// Whether the node answered the reads THIS evaluation took of it (#1106).
	// The page used to guess it from the words of a failing check, so a
	// sentence that merely said "refused" or "could not read what the
	// deployment names" made a full, answering node read as unreachable. A
	// check that read a file or a setting says nothing about the node; this
	// says it, on every answer, from the server_info calls themselves. Set
	// before the body is stored, so a cached answer carries the reading it
	// was made with. An evaluation that took no such read does not get to say
	// "ok" for a node nobody asked: it asks once.
	read, seen := st.NodeRead()
	if !seen {
		_, _ = st.RunningVersion()
		read, _ = st.NodeRead()
	}
	out["node_read"] = read
	if s.toCacheAt(key, out, gen) {
		// A good answer is stored for this plan: whatever failed before it
		// is answered (#1017).
		s.clearRefreshFailure(key)
	}
	// What the keeper re-runs while nobody is asking — issue #250. Noted
	// here, where the entry's key and the query that named it are both in
	// hand, so the pair it holds is always a pair that was really served.
	s.warm.note(key, rawQuery)
	return out, http.StatusOK
}

// restartRunbookID is RB-002's identifier. Named once, because three
// behaviours key off it and a typo in any of them fails by doing nothing.
const restartRunbookID = "restart-node"

// normaliseRunbookID is RB-005, ADR 0023: one change to the deployment an
// operator wrote, so a node can take an image with no entrypoint of its own.
const normaliseRunbookID = "normalise-deployment"

// checkCacheKey is the plan a cached verdict belongs to, not the target it
// happens to name. Keying on the target alone meant an empty one — which is
// every restart, since RB-002 has no version — shared a single entry across
// intents for ten seconds. The operator would have been shown one plan's
// confirm code and had the other's fingerprint recomputed at /v1/approve,
// which surfaces as a 409 AFTER the passkey touch.
//
// The rotation is part of the key, not just part of the body — issue #93. The
// two responses differ in whether they carry a confirm code at all, so an entry
// stored under one state and served under the other is the burn this fix
// exists to remove, arriving a few seconds late.
func checkCacheKey(rb runbook.Runbook, params runbook.Params, rotating bool) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	key := "check:" + rb.ID
	if rotating {
		key += "|rotating"
	}
	for _, k := range keys {
		key += "|" + k + "=" + params[k]
	}
	return key
}

// GET /v1/plan?target=3.2.1 — both renderings of the same decision. The
// operator chooses which one they want: run it themselves, or approve the
// executor to run it.
func (s *server) plan(_ http.ResponseWriter, r *http.Request) (any, int) {
	profile, st, err := s.state(r.Context())
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	return s.planFor(r, profile, st)
}

// planFor is plan's body once the host has been read, so the whole answer,
// refusals included, can be exercised against a host a test builds.
func (s *server) planFor(r *http.Request, profile host.Profile, st *host.State) (any, int) {
	v, rb, params, _, err := s.resolveRunbook(r, st)
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusBadRequest
	}

	// A rollback's target is this node's to derive, never the caller's to
	// name (ADR 0019). Derived once, here, before anything is built from the
	// asked-for one: a plan that echoed target 3.4.0 over an assessment
	// derived for 3.3.0 told a reader two things about one plan (#966). An
	// ask the derivation does not agree with is refused, naming the target
	// this node would use, the same refusal the chat action gives.
	// A derivation that fails refuses too (review of PR #1000, M1): a plan
	// echoing the asked target over an assessment that only says "error" is
	// the same disagreement in another shape.
	var rbDerivation rollback.Derivation
	if rb.ID == rollbackRunbookID {
		var refusal map[string]any
		if rbDerivation, refusal = s.rollbackTargetGate(st, v); refusal != nil {
			return refusal, http.StatusBadRequest
		}
	}

	type step struct {
		N          int    `json:"n"`
		Title      string `json:"title"`
		Why        string `json:"why"`
		Command    string `json:"command,omitempty"`
		Expect     string `json:"expect"`
		Undo       string `json:"undo"`
		Stage      string `json:"stage,omitempty"`
		Verb       string `json:"verb,omitempty"`
		Interrupts bool   `json:"interrupts,omitempty"`
	}

	// Both lists come from the runbook this request named, never from the
	// upgrade regardless. Rendering RB-001's five steps under RB-002's
	// identifier would publish a plan the executor will not run, which is
	// the one thing this endpoint exists to be trusted about.
	var manual []step
	if rb.ID == defaultRunbook {
		for i, x := range advise.UpgradeSteps(profile, v) {
			manual = append(manual, step{N: i + 1, Title: x.Title, Why: x.Why,
				Command: x.Command, Expect: x.Expect, Undo: x.Undo})
		}
	}
	var auto []step
	planLines := 0
	if rb.ID == configRunbookID {
		if d, derr := configDiffFor(st, params["key"], params["value"]); derr == nil {
			planLines = len(d.Before)
		}
	}
	for i, x := range executorSteps(rb, params, v, planLines, st) {
		auto = append(auto, step{N: i + 1, Title: x.Name, Why: x.Why,
			Stage: x.Stage, Verb: x.Verb, Undo: x.Undo, Interrupts: x.Interrupts})
	}

	out := map[string]any{
		"target": v, "runbook": rb.ID, "summary": rb.Summary,
		"reversible": rb.Reversible, "reversed_by": rb.ReversedBy,
		"reversal_note": rb.ReversalNote,
		// Where this came from, and how you will know it worked.
		"why": rb.Why, "expected": rb.Expected,
		"manual_steps":   manual,
		"executor_steps": auto,
		"stages":         stageDescriptions(rb, s.offlineExpectation()),
	}
	for k, val := range params {
		out[k] = val
	}
	if rb.ID == restartRunbookID {
		tag, terr := st.DeploymentTag()
		if terr != nil {
			tag = ""
		}
		out["assessment"] = restartAssessment(st, tag)
	}
	if rb.ID == configRunbookID {
		tag, terr := st.DeploymentTag()
		if terr != nil {
			tag = ""
		}
		out["assessment"] = configAssessment(st, tag)
	}
	if rb.ID == rollbackRunbookID {
		tag, terr := st.DeploymentTag()
		if terr != nil {
			tag = ""
		}
		// Derived for this request, above, and deliberately not cached
		// between requests: this endpoint is what the ceremony's own plan is
		// fetched from, and a target read from a stale copy is a target that
		// stopped matching the file it came from.
		out["assessment"] = rollbackAssessment(st, rbDerivation, tag, s.offlineExpectation())
	}
	return out, http.StatusOK
}

// executorSteps is the runbook's own step list. One place, so the plan
// endpoint, the execute handler and the command-line tool cannot disagree
// about what a stage runs.
// expectLines is how many assignments of the config key the service found
// when it computed the diff for THIS run. Zero for every other runbook, and
// for a caller that only wants the step list to display (the plan endpoint):
// it is read by one step's verification, which never runs there.
// st is asked one question, and only for the rollback: is the target image
// already on this host? A rollback that pulls what is already on the disk is
// a rollback that needs the registry during an incident — ADR 0019.
func executorSteps(rb runbook.Runbook, params runbook.Params, target string, expectLines int,
	st runbook.HostState) []execute.Step {
	switch rb.ID {
	case restartRunbookID:
		return execute.RestartSteps()
	case rollbackRunbookID:
		if st.Kind() == "native" {
			// No local image cache to ask about on this kind, RB-004's own
			// "the rollback target is installable" precondition already
			// asked the repositories directly, and the step list asks again
			// immediately before use.
			return execute.NativeRollbackSteps(params["target_version"])
		}
		// Which origin holds it decides both the fetch and the verb that
		// writes the deployment file, and it is read off the host rather
		// than off the configured repository: a node that upgraded through
		// a locally built image is on the other origin from the one its
		// wrapper was configured with.
		//
		// RollbackTargetOrigin, not ImageLocal, since #680. The origin used
		// to be derived from presence ("local, and its reference is
		// localhost/xrpld"), which cannot express "built here and since
		// pruned", the one case a rebuild exists for. It falls back to the
		// dated deployment copy that named the image, which says where it
		// came from whether or not the image survived.
		// The digest the approval covered, held against the copy as it
		// reads NOW (#682, third review): the steps are built at run
		// time, and the file they read is in a directory the node's own
		// account owns.
		rbShape, rbErr := execute.RollbackShapeChecked(
			params["target_version"], params["restore_digest"],
			st.RollbackImaging(params["target_version"], params["restore_path"]))
		if rbErr != nil {
			return nil
		}
		return execute.RollbackSteps(rbShape)
	case normaliseRunbookID:
		// One change, its own approval, its own ledger entry, its own
		// reversal. ADR 0023, and the operator's rule that the Advisor
		// changes only what an operation needs and never bundles two.
		return execute.NormaliseSteps(params["change"], params["user"])
	case configRunbookID:
		// The edit's steps and then RB-002's restart step, unchanged and
		// reused rather than re-declared. A second declaration of "restart
		// the node in place" is a second thing to keep correct, and the one
		// that matters is the one the restart runbook already proved.
		return append(execute.ConfigSteps(params["key"], params["value"], expectLines), execute.RestartSteps()...)
	}
	if st.Kind() == "native" {
		return execute.NativeUpgradeSteps(target)
	}
	// Three ways for a container node to reach a release, and the order is
	// the ruling (#682): the official image first, a build from the signed
	// package when no tag carries it or when the operator asked for one.
	//
	// A build is asked for by naming the source in the plan's parameters,
	// which is what the card's "build it here instead" button sends. It is
	// checked before the registry is asked at all, so asking for a build
	// costs no network call and cannot be overridden by a tag appearing.
	if params["source"] == "build" {
		return execute.LocalImageUpgradeSteps(target)
	}
	// The digest the PLAN pinned, never a fresh reading. executorSteps is
	// called three times for one upgrade (the plan's display, the prepare
	// run and the cutover run), and asking the registry at each of them
	// would let a tag moved in between decide what the cutover installs,
	// which is the substitution the pin exists to prevent.
	if d := params["digest"]; d != "" {
		return execute.OfficialImageUpgradeSteps(target, d)
	}
	return execute.LocalImageUpgradeSteps(target)
}

// stageDescriptions is what each stage does, in the operator's words. Keyed
// by runbook because the sentences are not derivable from the step list: what
// a stage COSTS is the part worth saying, and only a person can write it.
func stageDescriptions(rb runbook.Runbook, measured string) []map[string]any {
	if rb.ID == restartRunbookID {
		return []map[string]any{
			{"name": execute.StageRestart, "interrupts": true,
				"description": "Restart the node in place, on the image it is already running. " +
					"There is no reversible half: this is the whole runbook, and it takes the node " +
					"off the network for as long as it takes to come back — measured at " +
					restartExpectation + "."},
		}
	}
	if rb.ID == rollbackRunbookID {
		return []map[string]any{
			{"name": execute.StageRollback, "interrupts": true,
				"description": "Take a dated copy of the deployment, pull the release the node " +
					"was running before, point the deployment back at it and recreate the " +
					"container. One stage: the rollback IS the restart, and only the last step " +
					"interrupts. Expected: " + rollbackExpectation(measured) + "."},
		}
	}
	if rb.ID == configRunbookID {
		return []map[string]any{
			{"name": execute.StageConfig, "interrupts": false,
				"description": "Take a dated copy of the node configuration, rewrite every assignment " +
					"of the one allow-listed setting, and verify that nothing else in the file moved. " +
					"Reversible, and the node keeps validating throughout."},
			{"name": execute.StageRestart, "interrupts": true,
				"description": "Restart the node so it reads the new value. Every setting the Advisor " +
					"can change is read at startup, so this is the step that makes the change real — " +
					"and it takes the node off the network for " + restartExpectation + "."},
		}
	}
	return []map[string]any{
		{"name": execute.StagePrepare, "interrupts": false,
			"description": "Backups, build the image from the signed package, verify it, point the deployment at it. Reversible, and the node keeps validating throughout."},
		{"name": execute.StageCutover, "interrupts": true,
			"description": "Restart the node onto the new image. This is the only step that takes it off the network."},
	}
}

// GET /v1/ledger — the record, verified. A broken chain is reported as such
// rather than shown as a list that happens to be shorter than it was.
//
// ?since_seq=N answers only the entries after N, plus the current count and
// head, ADR 0021 build step 1. What gets RE-HASHED is controlled by
// s.ledgerCache's own trusted position, never by N: a poll that finds the
// file unchanged since the last read of any kind hashes nothing, whatever N
// the caller sent. Absent, or not a non-negative integer, is answered
// exactly as before this parameter existed, so every caller that never
// heard of it keeps working, and that full read still verifies the whole
// file from scratch every time, which is what catches an entry mutated
// under a trusted point the since_seq path would not re-check (see
// ledger.EntriesSince's doc comment).
func (s *server) ledger(_ http.ResponseWriter, r *http.Request) (any, int) {
	path := s.ledgerPath()
	sinceParam := r.URL.Query().Get("since_seq")
	if sinceParam == "" {
		return s.ledgerFullRead(path), http.StatusOK
	}
	since, err := strconv.Atoi(sinceParam)
	if err != nil || since < 0 {
		// Not a shape this route understands. The safe answer is the one a
		// caller from before this parameter existed already gets.
		return s.ledgerFullRead(path), http.StatusOK
	}
	tail, count, head, err := s.ledgerCache.tail(path, since)
	if err != nil {
		return map[string]any{
			"chain_intact": false, "error": err.Error(), "entries": []ledger.Entry{},
		}, http.StatusOK
	}
	return map[string]any{
		"chain_intact": true, "count": count, "head": head, "entries": tail,
	}, http.StatusOK
}

// ledgerFullRead is the whole-file answer: every entry, verified from
// scratch, exactly what this route always did before since_seq existed. It
// also seeds s.ledgerCache with the position it lands on, so the first
// incremental request afterwards, from this call, or from the hourly
// witness read in server.ts, which never sends since_seq, has something to
// verify forward from instead of paying for a full read of its own.
func (s *server) ledgerFullRead(path string) map[string]any {
	entries, err := ledger.Entries(path)
	if err != nil {
		// What was trusted, if anything, is worth nothing against a file a
		// full read just proved broken.
		s.ledgerCache.reset()
		return map[string]any{
			"chain_intact": false, "error": err.Error(),
			"entries": entries,
		}
	}
	head := ""
	if len(entries) > 0 {
		head = entries[len(entries)-1].Hash
	}
	s.ledgerCache.store(len(entries), head)
	return map[string]any{
		"chain_intact": true, "count": len(entries), "head": head,
		"entries": entries,
	}
}

func (s *server) fromCache(k string) ([]byte, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	c, ok := s.cache[k]
	if !ok || time.Since(c.at) > s.cacheTTL {
		return nil, false
	}
	return c.body, true
}

func (s *server) toCache(k string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.cachePut(k, cached{time.Now(), b})
}

// cachePeek is fromCache with the bound relaxed: an entry younger than
// maxAge is handed back, and `stale` says whether it is past the TTL, so
// the caller can serve it and refresh behind it. See checkStaleMax.
func (s *server) cachePeek(k string, maxAge time.Duration) (body []byte, stale, ok bool) {
	body, _, stale, ok = s.cachePeekAt(k, maxAge)
	return body, stale, ok
}

// cachePeekAt is cachePeek with the time the entry was stored, for the caller
// that states the entry's age.
func (s *server) cachePeekAt(k string, maxAge time.Duration) (body []byte, at time.Time, stale, ok bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	c, found := s.cache[k]
	if !found {
		return nil, time.Time{}, false, false
	}
	age := time.Since(c.at)
	if age > maxAge {
		return nil, time.Time{}, false, false
	}
	return c.body, c.at, age > s.cacheTTL, true
}

// cacheGeneration and toCacheAt pair an evaluation with the cache it began
// against. cacheReset advances the generation; a store that presents an
// older one measured the node before whatever caused the reset, and is
// dropped rather than served as the first answer after it.
func (s *server) cacheGeneration() uint64 {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	return s.cacheGen
}

// toCacheAt reports whether the answer was stored: false for one that
// straddled a reset, or could not be marshalled.
func (s *server) toCacheAt(k string, v any, gen uint64) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cacheGen != gen {
		return false
	}
	s.cache[k] = cached{time.Now(), b}
	return true
}

// cachePut is the only writer. Its callers differ in what they store — a
// marshalled body, or a raw value with a deliberately extended expiry — so the
// entry arrives already built and this holds the lock for all of them.
func (s *server) cachePut(k string, c cached) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache[k] = c
}

// cacheReset drops everything. Used when a capture has just changed an answer
// the cache would otherwise keep serving for another few seconds.
func (s *server) cacheReset() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache = map[string]cached{}
	s.cacheGen++
	// The profile cache goes with it: a capture that changed the answers may
	// have changed what the deployment looks like, and this is the one moment
	// a twenty-second-old identity could be wrong.
	s.profCache.reset()
	// And the concern histories, for the same reason: an act that changed the
	// node should be described by measurements taken after it, not before.
	s.histCache.reset()
	// And the rotation interval chat quotes (#1058): an act that raised
	// online_delete changed it, and the refusal that told the operator to
	// raise it must not quote the old figure afterwards.
	s.rotRhythm.reset()
}

// ── ask ───────────────────────────────────────────────────────────────
//
// The conversational endpoint. It composes context from this service's own
// reads and sends it to the operator's chosen provider. It cannot call the
// wrapper, cannot write an approval, and cannot touch the ledger — the agent
// holds the model credential and the executor holds the authority, and they
// are deliberately not the same process concern.

type askRequest struct {
	Question string       `json:"question"`
	Focus    string       `json:"focus"`
	Target   string       `json:"target"`
	History  []model.Turn `json:"history"`
	// Operator and Role: who is asking, stamped by the dashboard proxy from
	// the session (never typed by the browser). Used only when a break-glass
	// window is open and this question runs at the gated tier — every
	// privileged read it performs is then recorded against this person.
	Operator string `json:"operator"`
	Role     string `json:"role"`
	// There is deliberately no metrics field. The page used to compute four
	// reduced strings and send them with the question; ADR 0008 retired that
	// path — the service now assembles the measurements from the dashboard's
	// read API itself, so the prompt's picture of the node never depends on
	// what a browser chose to send, and exists with every tab closed.
	// A missed-ledger investigation: the page passes the index (and carries
	// the stored miss context inside the question); the service fetches the
	// public ledger facts itself through the config-gated lookup, so the
	// model reasons over both without either side trusting the other's job.
	Ledger *ledgerRef `json:"ledger"`
	// AskID is minted by the page (crypto.randomUUID()) so a concurrent
	// GET /v1/ask/progress can find this question's step trace while the
	// loop is still running (§9.5/§10.1). Optional and never trusted beyond
	// its shape — askIDValidRe is checked before it is used as a map key,
	// so a malformed value just means no progress for this question, never
	// a failed ask.
	AskID string `json:"ask_id"`
}

type ledgerRef struct {
	Index int64 `json:"index"`
}

// ledgerNumRe matches an explicit ledger reference in a question — "ledger
// 106,053,473", "ledger #106053473" — never a bare number, which could be
// anything.
var ledgerNumRe = regexp.MustCompile(`(?i)ledger\s*#?\s*([0-9][0-9,]{5,14})`)

// A number shaped like an index, wherever it sits in the sentence.
var indexShapedRe = regexp.MustCompile(`\b([0-9][0-9,]{5,14})\b`)

// ledgerIndexInQuestion lets the natural phrasing work. The first version of
// the lookup only fired from the investigate button, and "tell me about
// ledger X" — the way an operator actually asks — got a truthful shrug. The
// second required the word and the number to be ADJACENT, and "this ledger
// took a long time 106133679" — copied straight off the Consensus tab — got
// the same shrug, with a reply telling the operator to rephrase a question
// that already contained everything needed. A question that says "ledger"
// anywhere and carries an index-shaped number anywhere has named the tool it
// needs; only a bare number with no ledger in sight stays untouched, because
// that could be a port, a count, or a year. The cost of a false positive is
// one public lookup injected as context the model is free to ignore — far
// smaller than the cost of a true positive refused.
func ledgerIndexInQuestion(q string) int64 {
	// The adjacent form first: when "ledger 106..." appears, that number is
	// the one meant, even if other large numbers are in the sentence.
	if m := ledgerNumRe.FindStringSubmatch(q); m != nil {
		if n := parseLedgerIndex(m[1]); n > 0 {
			return n
		}
	}
	if !strings.Contains(strings.ToLower(q), "ledger") {
		return 0
	}
	for _, m := range indexShapedRe.FindAllStringSubmatch(q, -1) {
		if n := parseLedgerIndex(m[1]); n > 0 {
			return n
		}
	}
	return 0
}

// ledgerNeighbourhood renders the local window around a named ledger and the
// node's own 24h close-interval baseline, from the dashboard's records via
// the read API. Returns an injectable block, or a stated absence — the model
// must know the comparison is missing rather than compose around a hole.
func (s *server) ledgerNeighbourhood(ctx context.Context, idx int64) string {
	var b strings.Builder
	b.WriteString("\n\nLEDGER NEIGHBOURHOOD (this node's own records — treat as Measured)\n")

	win, err := s.dashRead.LedgerWindow(ctx, idx, 21)
	switch {
	case err != nil:
		fmt.Fprintf(&b, "Window unavailable: %v. Say plainly that the local comparison could not be made.\n", err)
	case win.Returned == 0:
		// Not an error — the node was not observing then (down, restarting,
		// or the index predates this dashboard's records).
		fmt.Fprintf(&b, "No local records for ledgers near %d — this dashboard was not observing "+
			"the network at that time (%d requested, 0 on record). The public lookup above is "+
			"the only per-ledger fact available; say so.\n", idx, win.Requested)
	default:
		// Requested vs returned, always. A window with silent holes reads as
		// "the twenty ledgers around it closed in 3.6–4.2s" about a set that
		// is missing six — the characteristic bug, in the one read the
		// comparison turns on.
		fmt.Fprintf(&b, "%d requested, %d on record", win.Requested, win.Returned)
		if gap := win.Requested - win.Returned; gap > 0 {
			fmt.Fprintf(&b, ", %d not recorded — a gap in this dashboard's observation, not an absence of ledgers", gap)
		}
		b.WriteString(":\n  index      close_s  txns\n")
		for _, r := range win.Ledgers {
			mark := "  "
			if r.LedgerIndex == idx {
				mark = "→ " // the ledger under discussion
			}
			fmt.Fprintf(&b, "%s%d  %7.2f  %4d\n", mark, r.LedgerIndex, r.CloseTime, r.TxnCount)
		}
	}

	// The day's baseline from the same store, so "slow" has a denominator.
	// close_time is already a first-class metric; avg and max over 24h give
	// the shape without shipping 22k samples.
	if avg, err := s.dashRead.History(ctx, "close_time", "24h", "avg"); err == nil && len(avg) > 0 {
		var sum float64
		var peak float64
		for _, p := range avg {
			sum += p.Value
			if p.Value > peak {
				peak = p.Value
			}
		}
		fmt.Fprintf(&b, "This node's close-interval baseline over the last 24h: %.2fs average, "+
			"%.2fs worst hourly bucket. Compare the ledger against BOTH its neighbours above and "+
			"this baseline before calling it slow or normal.\n", sum/float64(len(avg)), peak)
	} else if err != nil {
		fmt.Fprintf(&b, "24h baseline unavailable: %v. Say plainly that the baseline comparison could not be made.\n", err)
	}
	return b.String()
}

func parseLedgerIndex(s string) int64 {
	n, err := strconv.ParseInt(strings.ReplaceAll(s, ",", ""), 10, 64)
	// 32570 is the earliest ledger the network retains; anything below it is
	// not an index anyone can look up.
	if err != nil || n < 32570 {
		return 0
	}
	return n
}

// upgradeStagesInOrder is the UPGRADE's two-stage sequence, and only that.
// renderCeremonyState walks it to say WHICH stage's own steps satisfy a
// later stage's gated precondition — in a two-stage plan that can only ever
// be the stage before the one being gated — and it names the stages in
// prose.
//
// Deliberately not generalised to rb.Stages. The block it builds describes a
// prepare-then-cutover ceremony in sentences; handed a one-stage runbook it
// would render a STEP 1 · PREPARE that does not exist, which is worse than
// not rendering it at all. ADR 0016 keeps that ceremony context on the
// upgrade and says so — every OTHER caller (check, plan, liveApprovals,
// lastRun) now takes its stages from the runbook.
var upgradeStagesInOrder = []string{approval.StagePrepare, approval.StageCutover}

// ceremonyContext gathers the pieces renderCeremonyState needs from the live
// host and this service's own approval/run state, then renders them. Split
// from the rendering itself so the wording — the part worth a dedicated
// test — can be exercised without a *host.State, which means a docker
// runner behind it.
//
// Built because of an incident: asked "can you upgrade my node?", the reply
// described the executor in the abstract and told the operator to take two
// backups themselves, never mentioning that STEP 1 · PREPARE — sitting on
// this same tab, above the drawer — takes both of those backups as its own
// first steps. The model had readiness verdicts (pass/fail) but nothing
// telling it a ceremony offering to resolve them was rendered on the page
// underneath the conversation. This is that telling.
func (s *server) ceremonyContext(profile host.Profile, st *host.State, rb runbook.Runbook,
	params runbook.Params, target string, vs []stageVerdict, blockedFor map[string]bool) string {

	// The same identity the gate itself signs against (#398). Without it the
	// block would describe approvals held against a different key from the
	// one the ceremony will check, so it says nothing rather than something
	// that will not match.
	node, err := profile.IdentityKey()
	if err != nil {
		log.Printf("[ceremony] no node identity, so no ceremony block: %v", err)
		return ""
	}
	fp := approval.Fingerprint(rb.ID, node, params)
	planID := "plan-" + fp[:12]
	approved := s.liveApprovals(planID, fp, node, rb.Stages)
	last := s.lastRun(planID, rb.GrantScopes)
	deploymentTag, _ := st.DeploymentTag()
	deploymentImage, _ := st.DeploymentImage()
	var runningVersion string
	if profile.Kind == "native" {
		runningVersion, _ = st.RunningVersion()
	}
	staged := prepareStaged(target, deploymentTag, deploymentImage, runningImageRef(profile), runningVersion)

	return renderCeremonyState(rb.ID, target, deploymentTag, staged, vs, blockedFor, approved, last)
}

// runningImageRef is the reference the node's container was created from,
// rebuilt from the profile's own reading of it. Empty on a native host.
func runningImageRef(p host.Profile) string {
	if p.Kind == "native" || p.ImageRepo == "" {
		return ""
	}
	ref := p.ImageRepo
	if p.ImageTag != "" {
		ref += ":" + p.ImageTag
	}
	if p.ImageDigest != "" {
		ref += "@" + p.ImageDigest
	}
	return ref
}

// prepareStaged says whether an upgrade's prepare has staged the target and
// the cutover has not yet put it in place: the deployment file names the
// target, AND it names something other than what the node is running.
//
// The tag alone said "staged" on a node that was already running the target.
// a lab validator on 17bc (2026-10-11, #1012): a local build of 3.4.1 running,
// the deployment naming that same build, the card offering the switch to the
// official 3.4.1. The tag matched the target, so the ceremony block told the
// model prepare had run and STEP 2 · CUTOVER was waiting, the model told the
// operator so, and nothing was waiting at all (/v1/check: approved {}).
//
// The running version cannot tell these apart either: halfway through a
// same-release switch the deployment names the official digest while the
// container still runs the local build, both at 3.4.1, and the cutover IS
// waiting. So the comparison is the reference the file names against the one
// the container was created from, on a container host. On a native host there
// is no image, and the release itself is the only thing a prepare moves: the
// installed package names the target and the node does not report it yet.
// Anything unread falls back to the tag, the rule this replaces.
func prepareStaged(target, deploymentTag, deploymentImage, runningRef, runningVersion string) bool {
	if deploymentTag == "" || deploymentTag != target {
		return false
	}
	if deploymentImage != "" && runningRef != "" {
		return !sameImageRef(deploymentImage, runningRef)
	}
	if runningVersion != "" {
		return host.NormalizeVersion(runningVersion) != target
	}
	return true
}

// sameImageRef compares two image references the way the container would
// resolve them: the same repository, and the same digest when both name one,
// otherwise the same tag.
func sameImageRef(a, b string) bool {
	split := func(ref string) (repo, tag, digest string) {
		if i := strings.LastIndex(ref, "@"); i >= 0 {
			ref, digest = ref[:i], ref[i+1:]
		}
		if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
			ref, tag = ref[:i], ref[i+1:]
		}
		return ref, tag, digest
	}
	ar, at, ad := split(strings.TrimSpace(a))
	br, bt, bd := split(strings.TrimSpace(b))
	if ar != br {
		return false
	}
	if ad != "" && bd != "" {
		return ad == bd
	}
	if ad != "" || bd != "" {
		// One side is pinned by digest and the other by tag only: the file
		// and the container name the image two different ways, which is
		// itself a change the cutover has not made.
		return false
	}
	return at == bt
}

// renderCeremonyState builds the CEREMONY STATE block: the plan the tab is
// running, its per-stage readiness (from the SAME vs/blockedFor
// evaluateReadiness computed — never a second verdict pass), any live
// approval, and — the piece the rest of the context never carried — which
// stage the tab's own gate is offering approval for RIGHT NOW, one scroll
// above this drawer. Pure: no host, no filesystem, so it is the direct
// target for a test asserting the wording rather than the plumbing around it.
//
// staged is prepareStaged's answer, decided by the caller from the host: the
// deployment file names the target and the node is not yet running it.
func renderCeremonyState(runbookID, target, deploymentTag string, staged bool, vs []stageVerdict,
	blockedFor map[string]bool, approved map[string]any, last map[string]any) string {

	// Group failing checks per stage: the ones the OPERATOR still has to
	// resolve (Gates == "" — they gate every stage and nothing on this
	// ceremony takes them automatically) versus the ones a check names
	// (Gates == this stage) that the PREVIOUS stage's own steps satisfy —
	// the two backup checks, gated "cutover", taken by prepare.
	type failing struct {
		verdict     stageVerdict
		satisfiedBy string // "" when the operator must act themselves
	}
	byStage := map[string][]failing{}
	for _, stage := range upgradeStagesInOrder {
		for _, x := range vs {
			if x.Passed {
				continue
			}
			switch {
			case x.Gates == "":
				byStage[stage] = append(byStage[stage], failing{x, ""})
			case x.Gates == stage:
				// The stage whose own steps satisfy this — in the current
				// two-stage plan, always the stage immediately before the
				// one being gated. A third stage would need this taught a
				// real predecessor lookup instead of assuming prepare.
				byStage[stage] = append(byStage[stage], failing{x, approval.StagePrepare})
			}
		}
	}

	// Which stage the gate offers RIGHT NOW — the same "next" the tab's own
	// termGate() computes: cutover once prepare is staged, prepare
	// otherwise. It never jumps ahead to cutover just because prepare is
	// unblocked and lacks an approval; staged is the only thing that moves
	// it. A stage that already holds a live approval is not waiting for the
	// gate either — the tab shows a Run button there instead.
	next := approval.StagePrepare
	if staged {
		next = approval.StageCutover
	}
	var waiting string
	if !blockedFor[next] {
		if _, ok := approved[next]; !ok {
			waiting = next
		}
	}

	var b strings.Builder
	b.WriteString("\n\nCEREMONY STATE (Measured — this tab's own upgrade ceremony, rendered on this " +
		"same Advisor tab, above this drawer)\n")
	fmt.Fprintf(&b, "Runbook %s, target %s. Deployment currently names: %s.\n",
		runbookID, target, nonEmpty(deploymentTag, "unknown"))
	if !staged && deploymentTag != "" && deploymentTag == target {
		// The tag matches and nothing is staged: the node already runs what
		// the file names. Said outright, because "the deployment names the
		// target" reads as "prepare has run" to a reader who has seen this
		// block mid-upgrade (#1012).
		b.WriteString("Nothing is staged and no cutover is pending: the node already runs the image the " +
			"deployment file names. Any change this plan would make, such as where the image comes " +
			"from, has not started.\n")
	}

	for i, stage := range upgradeStagesInOrder {
		label := "STEP " + strconv.Itoa(i+1) + " · " + strings.ToUpper(stage)
		done := stage == approval.StagePrepare && staged
		blocked := blockedFor[stage]
		fmt.Fprintf(&b, "\n%s", label)
		switch {
		case done:
			b.WriteString(" — already run: the deployment file names the target version.\n")
		case blocked:
			b.WriteString(" — blocked\n")
		default:
			b.WriteString(" — ready\n")
		}
		var own, takenEarlier []failing
		for _, f := range byStage[stage] {
			if f.satisfiedBy == "" {
				own = append(own, f)
			} else {
				takenEarlier = append(takenEarlier, f)
			}
		}
		for _, f := range own {
			fmt.Fprintf(&b, "  FAILING, needs the operator's own action: %s — %s\n", f.verdict.Name, f.verdict.Detail)
		}
		for _, f := range takenEarlier {
			fmt.Fprintf(&b, "  FAILING, but taken by %s's own steps — nothing else needed: %s — %s\n",
				strings.ToUpper(f.satisfiedBy[:1])+f.satisfiedBy[1:], f.verdict.Name, f.verdict.Detail)
		}
		if a, ok := approved[stage]; ok {
			if m, ok := a.(map[string]any); ok {
				fmt.Fprintf(&b, "  A live approval is already held for this stage (expires in %vs) — the "+
					"tab shows a Run button here, not the gate.\n", m["expires_in"])
			}
		}
	}

	b.WriteString("\nWHAT THIS TAB IS OFFERING RIGHT NOW\n")
	sameRelease := !staged && deploymentTag != "" && deploymentTag == target
	if waiting != "" && sameRelease {
		// The node already runs this release and nothing is staged, so what
		// the card holds is an offer to change where the image comes from,
		// not a step anyone is part way through. On a lab validator the model read
		// "waiting for approval" here as a ceremony in flight and sent an
		// operator who had asked for a rollback to this card instead (#1012).
		b.WriteString("The tab offers this plan's approval above this drawer: it would change where the " +
			"node's image comes from, at the release it already runs. It is an offer, not a pending " +
			"step: nothing has started and nothing waits on the operator. Mention it only when they " +
			"ask about this change. A rollback, or any other act, is answered from its own assessment, " +
			"not from this card.\n")
	} else if waiting != "" {
		i := 0
		for idx, s2 := range upgradeStagesInOrder {
			if s2 == waiting {
				i = idx
			}
		}
		fmt.Fprintf(&b, "STEP %d · %s is waiting for approval on this tab, above this drawer: the "+
			"operator types the confirm code shown there, then their passkey. Approving it runs %s "+
			"immediately — that is where any FAILING checks marked above as taken by this stage's own "+
			"steps actually get satisfied. Direct the operator to that gate rather than to manual file "+
			"copies or backups; the ceremony already performs them.\n",
			i+1, strings.ToUpper(waiting), waiting)
	} else {
		b.WriteString("Nothing is currently waiting for approval on this tab — either a stage is blocked " +
			"on the operator's own action above, or every stage already holds a live approval or has run.\n")
	}
	if last != nil {
		fmt.Fprintf(&b, "Last run: %v, %vs ago.\n", last["stage"], last["age_sec"])
	} else {
		b.WriteString("No run has been recorded for this plan yet.\n")
	}
	return b.String()
}

// baseContext assembles the part of model.Context that does not depend on
// the question's own text — measurements, node identity, preconditions,
// the compact, knowledge and the recent action ledger and memory. Extracted
// from ask (which also layers on the ledger/validator lookups and the host
// probe seeds a typed question triggers) so /v1/investigate/continue can
// build the same foundation for a gated follow-up without duplicating it.
// Both callers still assemble their own turns and menu — this is the
// context, not the conversation.
// The second return is what this node is running, for knowledge selection —
// model.Target, filled from the SAME profile read this function already
// performs. Returned rather than re-read at the call site: DiscoverProfile
// costs a docker inspect, and a doc's applies_to must be judged against the
// deployment the rest of the prompt was built from, not one discovered a
// moment later. Zero when the deployment could not be read, which
// model.Target treats as "cannot judge" and includes everything.
func (s *server) baseContext(ctx context.Context, focus, target string) (model.Context, model.Target) {
	mc := model.Context{Focus: focus, Target: target}
	var kt model.Target
	// The measurements, from this service's own reads — ADR 0008. A failure
	// is stated in the prompt rather than silently omitted: a model told
	// nothing would answer as if the node had no history, which is worse
	// than a model told the surface is down.
	{
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		sums, err := s.assembleMetricsCached(rctx)
		cancel()
		if err != nil {
			log.Printf("[ask] read surface: %v", err)
			mc.MetricsNote = "the dashboard's read surface did not answer (" + err.Error() + "); no measurements are available for this reply"
		} else {
			for _, m := range sums {
				mc.Metrics = append(mc.Metrics, model.MetricLine{
					Label: m.Label, Now: m.Now, Baseline: m.Baseline, Changed: m.Changed,
				})
			}
		}
	}
	var liveState *host.State
	if profile, st, err := s.state(ctx); err == nil {
		liveState = st
		var fork, version string
		mc.Node, mc.Deployment, fork, version = profile.Describe()
		kt = model.Target{Fork: fork, Version: version}
		// Resolved the same way /v1/check resolves it — resolveUpgradeTarget's
		// "no target given, use the latest release" fallback — rather than
		// binding straight to whatever the caller passed. An empty target used
		// to make BindParams fail closed, which silently dropped BOTH the
		// READINESS block and (now) the ceremony block below on the exact
		// question this exists to fix: "can you upgrade my node?", asked
		// before the tab's own TARGET variable is set.
		if v, rb, params, _, err := s.resolveUpgradeTarget(st, target); err == nil {
			mc.Target = v
			vs, _, blockedFor := evaluateReadiness(rb, params, s.readinessHost(st))
			for _, x := range vs {
				mc.Checks = append(mc.Checks, model.CheckLine{Name: x.Name, Passed: x.Passed, Detail: x.Detail, Unmeasured: x.Unmeasured})
			}
			// The CEREMONY STATE block — see architecture note in
			// ceremonyContext. Built from the SAME vs/blockedFor this just
			// computed, never a second read of the preconditions.
			mc.Ceremony = s.ceremonyContext(profile, st, rb, params, v, vs, blockedFor)
		}
	} else {
		mc.Node = s.container
		if mc.Node == "" {
			// s.container is only ever set on a container install; a native
			// host has nothing to fall back to here, and the profile read
			// that would have named the unit is the very thing that just
			// failed. Say so plainly rather than rendering an empty line,
			// the "never a blank" rule this function exists for holds in
			// its own failure path too.
			mc.Node = "node identity unreadable"
		}
		mc.Deployment = "deployment unreadable: " + err.Error()
	}
	// Same key correction as /v1/status, one prompt further in. The prompt
	// should be told what the gates will enforce, and the gates are keyed on
	// the identity (#398, #466).
	ctxNode := s.container
	if k, kerr := s.nodeKey(ctx); kerr == nil {
		ctxNode = k
	}
	if a, err := compact.Load(filepath.Join(s.stateDir, "compact.json"), ctxNode); err == nil {
		mc.CompactOK = true
		mc.Privilege = string(a.Privilege)
	}
	// Knowledge is no longer assembled here — baseContext has no question to
	// select against, and knowledge now belongs in the system prompt's
	// stable prefix, not this live-state block (token-efficiency work, part
	// 1). Each caller of baseContext loads and selects it separately, right
	// before building its own system prompt: see ask() and
	// investigateContinue().
	// The audit trail, so "has anything been done to this node?" is answered
	// from the record rather than reconstructed from a readiness snapshot.
	if entries, err := ledger.Entries(filepath.Join(s.stateDir, "ledger.jsonl")); err == nil {
		if len(entries) > 30 {
			entries = entries[len(entries)-30:]
		}
		for _, e := range entries {
			mc.Actions = append(mc.Actions, model.ActionLine{
				At: e.At.Format("2006-01-02 15:04"), Kind: string(e.Kind), Summary: e.Summary,
			})
		}
	}
	if mem, err := memory.Open(filepath.Join(s.stateDir, "memory.jsonl")); err == nil {
		if recent, err := mem.Recent(s.container, 12); err == nil {
			mc.Recalled = memory.RenderChecked(recent, s.recallCheck(liveState))
		}
	}
	return mc, kt
}

// knowledgeRefusalSteps LOGS which knowledge files the ranker dropped for
// this question's budget, and returns no operator-visible steps.
//
// It used to emit each drop as a "budget reached" refusal in the drawer's
// trace (D4 build item D). The operator's ruling (2026-08-21) retired that:
// the ranker choosing which curated knowledge to load is the Advisor's own
// job, not a decision the operator makes or can act on, and a stack of amber
// "budget reached" lines reads as something broken to an end user. The
// honesty the visible refusal was for lives in the log instead — an engineer
// can still see exactly what was ranked out, the operator sees the answer.
//
// This is only knowledge SELECTION. Actionable refusals — a read that needs
// break glass (tier), one that needs an admin (role), a wrong-node action —
// are emitted elsewhere and still reach the operator, because those are
// theirs to act on.
func knowledgeRefusalSteps(refusals []model.KnowledgeRefusal) []interrogate.Step {
	if len(refusals) == 0 {
		return nil
	}
	names := make([]string, 0, len(refusals))
	for _, r := range refusals {
		names = append(names, r.Name)
	}
	log.Printf("[knowledge] %d file(s) ranked out of this question's budget: %s",
		len(refusals), strings.Join(names, ", "))
	return nil
}

func (s *server) ask(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST a question"})
		return
	}
	// Unauthenticated, this endpoint spends the operator's model budget,
	// causes outbound egress, and returns the knowledge corpus, ledger and
	// memory refracted through a reply.
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}
	// From here on this request is work a shutdown must wait for — punch #24.
	// Counted after the token check, because a rejected request is not work,
	// and once for the whole handler, which covers the gated branch below
	// too: that one runs its question synchronously on this goroutine.
	defer s.askStart()()
	cfg, err := model.LoadConfig(s.modelPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":  false,
			"error":       err.Error(),
			"config_path": s.modelPath,
		})
		return
	}
	if err := cfg.Validate(); err != nil {
		// Not an HTTP error: "no model configured" is a supported state, and
		// the tab renders it as guidance rather than as a failure.
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":  false,
			"error":       err.Error(),
			"config_path": s.modelPath,
		})
		return
	}

	var req askRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "could not read the question"})
		return
	}
	if strings.TrimSpace(req.Question) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the question is empty"})
		return
	}

	// The context used to be sized for one model call — right when that was
	// all "ask" ever made. The interrogative loop can make up to
	// interrogate.MaxModelCalls of them, so the budget below is scaled by
	// that many round-timeouts and capped at the loop's own 300s hard
	// ceiling (§6.1) — a 60s context around a four-round loop dies partway
	// through round two with an error that reads exactly like a provider
	// timeout, and the operator is told the wrong thing about the wrong
	// component (plan-interrogative-loop §14, "the one line that will
	// otherwise be missed").
	askBudget := time.Duration(max(cfg.TimeoutSec, 60)) * time.Second * time.Duration(interrogate.MaxModelCalls)
	if askBudget > 300*time.Second {
		askBudget = 300 * time.Second
	}
	ctx, cancel := askContext(r, askBudget)
	defer cancel()

	// A window open on this node makes every question a gated one, for as
	// long as it stays open (operator ruling 2026-08-19: break glass is a
	// decision the admin takes from the panel's header, and the questions
	// that follow simply run deeper). Same runner as
	// /v1/investigate/continue — same checks, same bounds, same one-entry-
	// per-privileged-read ledger — run to completion here so the page's
	// ordinary ask/poll path needs no second protocol; the reply comes back
	// in the same shape with `gated` set so the tab can say which tier
	// answered.
	//
	// A monitor's question is never gated: the window belongs to the admin
	// who opened it, and a monitor asking about metrics while it is open
	// simply gets the ordinary tier (the same answer they would get with no
	// window), not a refusal for the fifteen minutes it lasts.
	// Looked up by the identity key the window was opened under (#398), not
	// by the name this process was started with. Those two can differ on a
	// container host and the second is empty on a native one, and a window
	// this lookup misses is a question that runs at the ordinary tier while
	// the operator is looking at an open-window chip.
	gateNode, gateErr := s.nodeKey(ctx)
	if gateErr != nil {
		log.Printf("[ask] no node identity, so no window can gate this question: %v", gateErr)
	}
	var gateWin *breakglass.Window
	var gateOpen bool
	if gateErr == nil {
		gateWin, gateOpen = s.breakglass.OpenForNode(gateNode, time.Now())
	}
	if win, open := gateWin, gateOpen; open && req.Role != "monitor" {
		// The confirm turn, answered without a model call — issue #72's root
		// cause, restart_confirm.go. A "yes" that follows a restart this
		// service proposed reads nothing and decides nothing the service has
		// not already decided, so it is minted here instead of spending a
		// model round that has to cross a gateway capping requests at about a
		// hundred seconds. Anything else falls straight through to the gated
		// path below, unchanged.
		if body, handled := s.confirmRestartDirectly(ctx, req, win.Node, time.Now()); handled {
			s.recordConfirmProgress(req.AskID, body)
			log.Printf("[ask] restart confirm answered from the stored proposal, no model call, %s",
				time.Since(started))
			writeJSON(w, http.StatusOK, body)
			return
		}
		gctx, gcancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer gcancel()
		// Registered BEFORE the preparation below, which discovers the host,
		// reads the dashboard and selects knowledge before the runner's own
		// beginGated ever runs. A page whose POST dies inside that window
		// polls an id this process has not registered yet, gets a 404, and is
		// told the request never reached the Advisor — about a question that
		// is running perfectly well. beginGated replaces this entry when it
		// arrives, which is what it already did to the ungated begin.
		s.progress.begin(req.AskID)
		run, sessionID, status, msg := s.prepareGatedQuestion(gctx, win, win.Node, gatedAsk{
			Question: req.Question, Focus: req.Focus, Target: req.Target, History: req.History,
			Operator: req.Operator, Role: req.Role,
			// The drawer draws the gate under the turn, and recovers it from
			// the progress store when this POST dies at the gateway's cap.
			RendersActions: true,
		}, req.AskID)
		if status != 0 {
			writeJSON(w, status, gatedRefusalBody(req.Role, msg))
			return
		}
		res, err := run()
		if err != nil {
			log.Printf("[ask] gated question failed: %s", err.Error())
			writeJSON(w, http.StatusOK, map[string]any{"configured": true, "error": err.Error(), "gated": true})
			return
		}
		// The action protocol, on the path it actually lands on. A window is
		// open here, so this is where a permitted restart becomes a gate —
		// stripped AND answered inside the runner, beside the progress store's
		// own write, so the gate survives a POST that dies at the gateway's
		// ~100s cap. Read back from the result here; answering it a second
		// time would evaluate one plan twice.
		outcome, steps := res.Outcome, res.Steps
		gAction, gRefused := res.Action, res.Blocked
		log.Printf("[ask] gated: %d rounds, %d reads, %d+%d tokens, %s",
			outcome.Spend.Rounds, outcome.Spend.Reads, outcome.Spend.PromptTokens,
			outcome.Spend.CompletionTokens, time.Since(started))
		gbody := map[string]any{
			"configured": true, "model": cfg.Model, "reply": outcome.FinalReply,
			"steps": steps, "gated": true, "window_id": win.ID, "session_id": sessionID,
			"spend": map[string]any{
				"rounds": outcome.Spend.Rounds, "reads": outcome.Spend.Reads,
				"prompt_tokens": outcome.Spend.PromptTokens, "completion_tokens": outcome.Spend.CompletionTokens,
				"cached_prompt_tokens": outcome.Spend.CachedPromptTokens, "reported": outcome.Spend.UsageReported,
			},
		}
		if gAction != nil {
			gbody["action"] = gAction
		}
		if gRefused != nil {
			gbody["action_blocked"] = gRefused
		}
		if rt := s.routeSuggestion(res.Signal); rt != nil {
			gbody["route"] = rt
		}
		writeJSON(w, http.StatusOK, gbody)
		return
	}

	// Registered before the context is assembled, not after. Everything
	// between here and the loop is I/O — the dashboard's read API, a public
	// ledger lookup, up to three privileged host reads — and a POST that dies
	// inside it left the page polling an id this process had not registered.
	// That is a 404, which the drawer reads as "the request never reached the
	// Advisor" about a question running perfectly well. The gated branch
	// above registers its own for the same reason.
	s.progress.begin(req.AskID)

	mc, knowTarget := s.baseContext(ctx, req.Focus, req.Target)
	// Who is asking and what they may do here, stated before the
	// measurements — ADR 0016 as amended 2026-08-19. See sessionContext.
	mc.Session = s.sessionContext(req.Role, mc.Node, time.Now())

	// A ledger investigation carries fresh public facts fetched HERE — the
	// model gets the stored miss context (in the question, from the page) and
	// the ledger's own profile (from the lookup) and reasons over both. When
	// the lookup is off or fails, the model is told so rather than left to
	// improvise the missing half.
	// The investigate button attaches the reference explicitly; a typed
	// question that names a ledger gets the same treatment.
	if req.Ledger == nil {
		if idx := ledgerIndexInQuestion(req.Question); idx > 0 {
			req.Ledger = &ledgerRef{Index: idx}
		}
	}
	// Seeds registered with the loop's cache below, so a model that re-asks
	// for exactly what was already fetched here gets skipped_cached instead
	// of spending its own budget on a duplicate read (§12's trade-off:
	// "keep the regex seed reads... a cost the per-question cache absorbs").
	var seeded []interrogate.SeedResult

	lookupNote := ""
	if req.Ledger != nil && req.Ledger.Index > 0 {
		lcfg, lerr := xrpl.LoadLookupConfig(filepath.Join(s.stateDir, "xrpl-lookup.json"))
		if lerr != nil || !lcfg.Enabled {
			lookupNote = "\n\nLEDGER LOOKUP\nNot enabled on this host. Answer from the " +
				"context provided only, and say plainly that the public ledger lookup is not enabled."
		} else if sum, err := xrpl.Lookup(ctx, s.client, lcfg.Endpoint, req.Ledger.Index); err != nil {
			lookupNote = "\n\nLEDGER LOOKUP\nFailed: " + err.Error() + ". Answer from the " +
				"context provided, and say plainly that the lookup failed."
		} else {
			lookupNote = "\n\nLEDGER LOOKUP (public XRPL API — treat as Measured, cite the source)\n" +
				sum.Describe()
			if lcfg.Explorer != "" {
				lookupNote += fmt.Sprintf("\nFull breakdown the operator can open: offer the "+
					"markdown link [ledger %d on the explorer](%s/ledger/%d) in your answer.",
					req.Ledger.Index, strings.TrimRight(lcfg.Explorer, "/"), req.Ledger.Index)
			}
			seeded = append(seeded, interrogate.SeedResult{
				Request: interrogate.Request{Read: interrogate.ReadPublicLedger, Index: int(req.Ledger.Index)},
				Result:  interrogate.Result{Status: interrogate.StatusOK, Body: sum.Describe(), Source: "public XRPL API"},
			})
		}
		// The named ledger arrives with its NEIGHBOURHOOD and this node's own
		// baseline — Phase A of the interrogative-loop plan. "This ledger took
		// 4.9s" is not an answer; "4.9s against your node's 3.8s day and
		// neighbours at 3.7–4.1s" is. Both reads are local (the dashboard's own
		// records through the read API), so a slow public endpoint cannot make
		// them slow, and a failure is stated rather than papered over — a
		// missing baseline must never read as a normal one.
		lookupNote += s.ledgerNeighbourhood(ctx, req.Ledger.Index)
	}

	// Same treatment for a validator key named in the question: fetch the
	// registry's view of it. "Not tracked" is delivered as an answer, not an
	// error — for a validator off the published UNLs it is the normal state.
	if m := validatorKeyRe.FindString(req.Question); m != "" {
		lcfg, lerr := xrpl.LoadLookupConfig(filepath.Join(s.stateDir, "xrpl-lookup.json"))
		if lerr == nil && lcfg.Enabled && lcfg.ValidatorEndpoint != "" {
			if v, err := xrpl.LookupValidator(ctx, s.client, lcfg.ValidatorEndpoint, m); err == nil {
				lookupNote += "\n\nVALIDATOR LOOKUP (public registry — treat as Measured, cite the source)\n" +
					v.Describe()
				if lcfg.Explorer != "" && v.Tracked {
					lookupNote += fmt.Sprintf("\nFull record the operator can open: offer the "+
						"markdown link [this validator on the explorer](%s/validator/%s) in your answer.",
						strings.TrimRight(lcfg.Explorer, "/"), m)
				}
				seeded = append(seeded, interrogate.SeedResult{
					Request: interrogate.Request{Read: interrogate.ReadPublicValidator, Key: m},
					Result:  interrogate.Result{Status: interrogate.StatusOK, Body: v.Describe(), Source: "public validator registry"},
				})
			} else {
				lookupNote += "\n\nVALIDATOR LOOKUP\nFailed: " + err.Error() +
					". Say plainly that the registry could not be reached."
			}
		}
	}

	// What this host actually says, when the question is about this host.
	//
	// Before this the Advisor could describe how a validator is usually
	// configured but had to answer "what does mine say?" with a request to
	// paste something — which is where most investigations stop. Every reading
	// is a read-only wrapper verb, logged there, and the node configuration
	// arrives with its key material already removed on the privileged side.
	// One budget per question, shared with the loop's own host_read menu item
	// below — the three-privileged-reads cap counts seed probes and menu
	// reads on the SAME counter, never three each (§9.4). Created
	// unconditionally, even when no wrapper is configured, so the concrete
	// Menu always has one to hold; host.Inspect and the Menu's host_read
	// handler both refuse cleanly against an unconfigured wrapper without
	// needing a nil check on the budget itself.
	hostBudget := host.NewBudget(host.MaxPrivilegedHostReads)
	if s.wrapper != "" {
		// The role filter applies HERE too, not only to the model's own
		// host_read requests below. These probes are matched from the
		// question's own words and land in the reference material as
		// "treat as Measured" before the model is asked anything, so a
		// monitor asking what their config says would otherwise have had
		// the config read to them by the service itself
		// (advisor/knowledge/role-policy.md).
		if note := host.Inspect(ctx, s.runner, s.wrapper, req.Question, hostBudget,
			interrogate.RoleAllowsVerb(req.Role)); note != "" {
			lookupNote += note
			log.Printf("[ask] host readings attached: %.160s",
				strings.ReplaceAll(note, "\n", " | "))
		}
	}

	if lookupNote != "" {
		log.Printf("[ask] lookup note attached: %.200s", strings.ReplaceAll(lookupNote, "\n", " | "))
	}
	// The question goes FIRST and is repeated at the end. It used to sit alone
	// after forty kilobytes of context, and a three-word follow-up — "please
	// do that" — got answered as if it were about the most action-shaped thing
	// in that block, a failing readiness check, rather than about the previous
	// turn. Bracketing the reference material keeps the subject in view at
	// both ends of a long prompt.
	turns := defangedTurns(req.History)
	turns = append(turns, model.Turn{Role: "user",
		Content: "OPERATOR ASKS\n" + req.Question +
			"\n\n--- reference material below, reassembled every turn; not the subject ---\n\n" +
			mc.String() + interrogate.SanitizeInjected(lookupNote) +
			"\n\n--- end of reference material ---\n\nOPERATOR ASKS\n" + req.Question})

	// Read per call, not cached: editing the persona and restarting is one
	// step fewer than editing, rebuilding and restarting, and this is a file
	// an operator is meant to tune.
	personaBody, perr := os.ReadFile(s.persona)
	if perr != nil && !os.IsNotExist(perr) {
		log.Printf("[persona] %s unreadable: %v", s.persona, perr)
	}

	// The concrete read menu — dashread, the public XRPL client, and the
	// privilege wrapper's read-only verbs, bound to channels this process
	// already holds. Describe() renders the prompt's own menu table
	// (§8 point 1), so BuildSystemPrompt below can never say something the
	// menu itself does not serve.
	// One fleet view for the whole question (#859): the menu it describes
	// and the nodes its loop resolves against come from the same file.
	fv := s.fleetNow()
	menu := &liveMenu{
		restartAssess: s.restartAssessmentResult, upgradeAssess: s.upgradeAssessmentResult,
		configAssess:   s.configAssessmentResult,
		rollbackAssess: s.rollbackAssessmentResult,
		selfContainer:  s.container,
		dash:           s.dashRead, httpClient: s.client, stateDir: s.stateDir,
		runner: s.runner, wrapper: s.wrapper,
		hostBudget: hostBudget, peers: fv.clients, fleetReg: fv.reg,
		roster: s.roster(context.Background()),
		role:   req.Role,
	}
	// Computed once, from the operator's own question text, before the loop's
	// first round — knowledge-audit.md §7 items 3-4, and see SelectKnowledge's
	// doc comment for why this must never move inside the loop. loadKnowledge
	// now reads everything and labels it; SelectKnowledge ranks, applies the
	// injection budget and reports anything that did not fit. node comes from
	// mc.Node — this service's own resolution (baseContext, above), never
	// req.Node or anything the model's own <lookup> tool calls could name
	// (security sign-off P2-003).
	knowledge := model.SelectKnowledgeFor(s.loadKnowledge(), req.Question, mc.Node, knowTarget)
	knowledgeSteps := knowledgeRefusalSteps(knowledge.Refusals)
	system := model.BuildSystemPrompt(string(personaBody), s.loadRolePolicy(), menu.Describe(),
		model.RenderKnowledge(knowledge.Selected))
	seedMessages := []interrogate.Message{{Role: "system", Content: system}}
	for _, t := range turns {
		seedMessages = append(seedMessages, interrogate.Message{Role: t.Role, Content: t.Content})
	}
	// Cache breakpoint 2 (token-efficiency work, part 1): the LAST seed
	// message is the turn built above at "OPERATOR ASKS" — the assembled
	// reference material plus the question, fixed from here on and never
	// mutated as the loop appends rounds after it. Marking it is what lets
	// this same investigation's rounds 2-4 read this whole block back
	// cached instead of paying full price for it three more times. See
	// model.Client.ask's ShapeAnthropic branch for where this is spent.
	if n := len(seedMessages); n > 0 {
		seedMessages[n-1].CacheBoundary = true
	}

	// The loop's own budget mirrors hostBudget's starting count — see
	// menu.go's hostRead for why a fourth privileged read past that point
	// must be caught here, as a clean "refused: ceiling", rather than
	// reaching host.ReadVerb and failing with the wrapper's own message.
	loopBudget := interrogate.NewBudget()
	loopBudget.ChargeSeedHostReads(hostBudget.Used())
	// When the context reads the SERVICE chose (memory, disk, unit state,
	// matched from the question) have already spent the whole host cap, the
	// model can never attempt a further host read, so no tier refusal is
	// ever recorded and no break-glass offer can follow: the operator got
	// "the cap is already spent" with nothing to click (2026-08-19). Record
	// the fact as the refusal it is, before the loop starts, so the tab shows
	// it and the offer machinery sees a tier refusal. The cap itself is
	// untouched: three privileged reads per question, seeds included, is the
	// number the security review turned on.
	if hostBudget.Used() >= loopBudget.MaxHostReadsPerQuestion {
		knowledgeSteps = append(knowledgeSteps, interrogate.Step{
			Read: interrogate.ReadHost, Round: 0,
			Label:          "further host reads this question",
			Status:         interrogate.StatusRefused,
			RefusedBecause: interrogate.RefusedTier,
			Detail: fmt.Sprintf("the %d privileged host reads allowed per question at this tier were spent by the context reads matched from the question; a break-glass window allows more",
				loopBudget.MaxHostReadsPerQuestion),
		})
	}

	// Knowledge cap failures are visible in the same steps[] vocabulary a
	// read refusal already uses (D4 build item D) — recorded before the
	// loop's first round, since selection itself ran before it, and the
	// drawer's poll sees them immediately rather than only once the loop
	// finishes.
	for _, st := range knowledgeSteps {
		s.progress.append(req.AskID, st)
	}
	loop := &interrogate.Loop{
		Caller: &modelCaller{client: model.New(cfg)},
		Menu:   menu,
		Budget: loopBudget,
		Seeded: seeded,
		Nodes:  fv.nodes,
		// The same roster the menu described, so what the prompt NAMES and
		// what a lookup RESOLVES against are one reading (#59).
		Roster: menu.roster,
		OnStep: func(st interrogate.Step) { s.progress.append(req.AskID, st) },
		// Same reason as the gated runner's: a round that answers without
		// reading anything emits no step, and a page watching only steps
		// cannot tell that from a service that stopped (#72).
		OnRound: func(round int) { s.progress.setRound(req.AskID, round) },
	}
	outcome, err := loop.Run(ctx, seedMessages, req.Question)
	if err != nil {
		// 200, deliberately. This answer crosses a CDN edge that replaces
		// origin 502s with its own HTML error page — the operator saw "an
		// HTML page, not the dashboard" while the actual provider error,
		// the one thing that would have explained the failure, was thrown
		// away in transit. The body carries the truth; the status stays out
		// of the edge's reach. "Model unreachable" is a supported state
		// here, exactly like "no model configured" above.
		log.Printf("[ask] model call failed: %s", err.Error())
		// Terminal state into the progress store too: the same CDN edge that
		// eats origin errors also kills any POST past its ~100s cap, and the
		// page recovers from a dead POST by polling progress to its end. An
		// error the POST alone carried would be unrecoverable exactly when
		// the transport already failed once.
		s.progress.finish(req.AskID, "ended", "", err.Error())
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true,
			"error":      err.Error(),
		})
		return
	}
	// Knowledge cap failures precede everything the loop itself did, in the
	// final record the same way they did in the live progress poll above.
	outcome.Steps = append(append([]interrogate.Step{}, knowledgeSteps...), outcome.Steps...)
	// The cap can be spent by the loop's OWN reads too, and the model, which
	// is told the number, then stops asking rather than being refused: three
	// host reads done, "the other two can't happen this question", and no
	// step anywhere says tier, so no offer follows (2026-08-19, a five-part
	// host sweep). Same fact as the seed case above, same record: a spent
	// cap IS the refusal of every further host read, whether or not one was
	// attempted. Recorded once, at the end, only when the loop did not
	// already record it, and only at the ungated tier (inside a window there
	// is no higher tier to offer).
	if !loopBudget.Gated && loopBudget.HostReadsUsed() >= loopBudget.MaxHostReadsPerQuestion &&
		!hasTierRefusal(outcome.Steps) {
		st := interrogate.Step{
			Read: interrogate.ReadHost, Round: outcome.Spend.Rounds,
			Label:          "further host reads this question",
			Status:         interrogate.StatusRefused,
			RefusedBecause: interrogate.RefusedTier,
			Detail: fmt.Sprintf("the %d privileged host reads allowed per question at this tier are spent; a break-glass window allows more",
				loopBudget.MaxHostReadsPerQuestion),
		}
		outcome.Steps = append(outcome.Steps, st)
		s.progress.append(req.AskID, st)
	}
	// Extract anything the agent asked to remember. Stored as KindConcluded
	// whatever it says about itself: this path cannot produce a confirmed
	// memory, which is what stops the Advisor establishing its own facts by
	// writing them down and reading them back. extractMemory only ever sees
	// the FINAL reply — the loop already stripped every intermediate
	// <remember> block from what it fed back to itself (§6.4).
	reply, remembered := s.extractMemory(outcome.FinalReply, mc.Node)
	// The <remember>-adjacent proposal path (D3): a note the Advisor wants
	// to keep but that has NOT earned the Documented tier — written to the
	// inbox, never injected, until a person promotes it (a later step).
	reply = s.extractProposal(reply, mc.Node, req.Question, outcome.Steps)

	// The restart action — ADR 0016, amended 2026-08-19. Stripped from every
	// final reply for the same reason the offer block is: a suppressed
	// proposal is silence, never leaked model markup. On this path the
	// window is closed by definition (an open one routes above), so a
	// well-formed action here answers break_glass_required — which is the
	// amber nudge the page renders, and exactly what the operator should
	// see for asking before breaking glass.
	replyClean, sig := stripReplySignalsGiven(reply, injectedText(outcome.Messages))
	reply = replyClean
	actionBlock, actionRefused := s.answerAction(ctx, sig, req.Role, sessionActor(req.Operator, req.Role))
	if actionBlock != nil {
		// The same check the gated path makes (#1044): a reply drawn above
		// a gate claims nothing the gate has not been given yet.
		if fixed, ok := correctPrematureClaims(reply); ok {
			reply = fixed
		}
	}

	// Break glass — plan-interrogative-loop §11.4. Parsed out of every
	// final reply regardless of outcome, because the <offer> block must
	// never reach the operator verbatim even when none of the six
	// conditions below let it become a real offer — a suppressed offer is
	// silence, not leaked model markup.
	var offerBlock map[string]any
	if o, cleanReply, found := interrogate.ParseOffer(reply); found {
		reply = cleanReply
		offerBlock = s.considerOffer(o, nil, outcome.Steps, mc.Node, req.Question, outcome.Messages)
	} else if o, resolved, ok := interrogate.SynthesizeOffer(outcome.Steps); ok {
		// No <offer> from the model, but a read was refused for tier: the
		// operator still gets the offer, authored by the service from the
		// refusals themselves. The gates below are unchanged; only the
		// author of Why and WouldRead differs.
		offerBlock = s.considerOffer(o, resolved, outcome.Steps, mc.Node, req.Question, outcome.Messages)
	}

	log.Printf("[ask] %d rounds, %d reads, %d+%d tokens (%d cached, reported=%v), %s",
		outcome.Spend.Rounds, outcome.Spend.Reads, outcome.Spend.PromptTokens,
		outcome.Spend.CompletionTokens, outcome.Spend.CachedPromptTokens, outcome.Spend.UsageReported, time.Since(started))

	body := map[string]any{
		"configured": true,
		"model":      cfg.Model,
		"reply":      reply,
		"remembered": remembered,
		// steps[] and spend are §7's honesty mechanism and §6.3's cost
		// ledger: authored from the loop's own record, not from parsing
		// back out what the model claims it did.
		"steps": outcome.Steps,
		"spend": map[string]any{
			"rounds": outcome.Spend.Rounds, "reads": outcome.Spend.Reads,
			"prompt_tokens": outcome.Spend.PromptTokens, "completion_tokens": outcome.Spend.CompletionTokens,
			// cached_prompt_tokens is the subset of prompt_tokens billed at
			// the provider's cache-read discount (token-efficiency work,
			// part 3) — never an addition to prompt_tokens. Reading it back
			// out: fresh_prompt_tokens = prompt_tokens - cached_prompt_tokens.
			"cached_prompt_tokens": outcome.Spend.CachedPromptTokens,
			"reported":             outcome.Spend.UsageReported,
		},
	}
	if offerBlock != nil {
		body["offer"] = offerBlock
	}
	if actionBlock != nil {
		body["action"] = actionBlock
	}
	if actionRefused != nil {
		body["action_blocked"] = actionRefused
	}
	if rt := s.routeSuggestion(sig); rt != nil {
		body["route"] = rt
	}
	// The answer lands in the progress store BEFORE the response is written:
	// a page whose POST died at a CDN edge (observed live as HTTP 524, the
	// loop finishing server-side while the delivery was already dead)
	// recovers by polling progress until it reports terminal state. The
	// break-glass offer is deliberately NOT carried here — an offer is a
	// fresh invitation, not a record, and re-asking mints a fresh one. The
	// action (a confirm gate) IS carried: a confirm turn is the ask most
	// likely to run past the cap, and without the gate the operator recovers
	// an answer they cannot act on (#56). Set before finish so a poll that
	// sees the terminal state also sees the gate.
	if actionBlock != nil {
		s.progress.setAction(req.AskID, actionBlock)
	}
	s.progress.finish(req.AskID, "answered", reply, "")
	writeJSON(w, http.StatusOK, body)
}

// The two container tags the model is asked to write into its FINAL reply,
// <remember> and <propose>, are both bookkeeping. The operator asked a
// question, and neither the block nor its body is part of the answer they
// asked for. Everything down to extractProposal exists so that stays true
// for markup the model wrote badly.
//
// Issue #121: the original patterns admitted `title` and nothing else, so a
// tag carrying a second attribute (`<propose title="t" subject="load">`)
// matched nothing, filed nothing, and left the whole block, opening tag and
// body, in the reply the operator read. The open tag is now recognised the
// way internal/interrogate recognises an <action> tag, generically, and the
// attributes are read out of it afterwards.

// maxTagTitle bounds a title in runes. The old pattern carried the bound
// inside the regex ([^"]{1,200}); it is re-imposed here because a title
// travels into the note, the dedup key, a ledger entry and the service log,
// and a permissive attribute read would otherwise hand all four unbounded
// model-authored text. Runes, not bytes, so a clip cannot leave invalid
// UTF-8 behind. Clipped rather than refused: clipping keeps the note,
// refusing loses it.
const maxTagTitle = 200

// tagAttrRe reads one attribute out of an open tag's text. Straight quotes
// are the form the prompt shows. The curly pair is accepted as well because
// a tag written with U+201C/U+201D parsing as having no attributes at all
// is a failure this codebase has already had in production (see
// interrogate's attrQuoteNormalizer, validator1, 2026-08-21), and a note is
// not worth losing over a quote character.
var tagAttrRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*["\x{201c}\x{201d}]([^"\x{201c}\x{201d}]*)["\x{201c}\x{201d}]`)

// tagPattern recognises one container tag by name: its opening tag with
// whatever attributes it happens to carry, and its closing tag.
//
// The open pattern stops at a newline and at 400 characters on purpose. An
// opening tag is written on one line, and a bounded scan is what keeps a
// bare "<propose" the model is QUOTING in prose from swallowing the
// paragraphs up to the next unrelated ">". A mention with no ">" on its own
// line is prose, and prose renders.
type tagPattern struct {
	name  string
	open  *regexp.Regexp
	close *regexp.Regexp
}

// tagPatternNames records every tag this package builds a pattern for, in
// construction order. It exists for one test: TestEveryExtractedTagIsSanitised
// asserts each name is on interrogate.SentinelTags(), the list
// SanitizeInjected is built from.
//
// A tag recognised here but missing there is #124 exactly: a forged block in
// a log tail reaches the prompt intact, the model echoes it, and this
// package files it under this service's own attribution. The dependency only
// runs one way (this is a main package and cannot be imported), so the
// registry lives on this side and the assertion does too.
//
// newTagPattern is the only constructor production uses, and it registers,
// on purpose: a tag pattern that reaches production without going through
// this slice is precisely the hole #124 was, and the guard's own comment a
// few lines down already names the "green while guarding nothing" failure
// that a lazily-registered constructor would reopen. buildTagPattern below
// is the unregistered escape hatch for a test fixture or other throwaway
// check that needs a tagPattern's matching behaviour but is not a real,
// extracted tag; a second test (TestBuildTagPatternIsNotCalledOutsideNewTagPattern,
// in tag_sanitisation_test.go) scans this package's non-test source and
// fails if buildTagPattern is called from anywhere but newTagPattern, so the
// two constructors cannot drift into production use by mistake.
var tagPatternNames []string

func newTagPattern(name string) tagPattern {
	tagPatternNames = append(tagPatternNames, name)
	return buildTagPattern(name)
}

// buildTagPattern builds a tagPattern's regexps and nothing else. It does
// not touch tagPatternNames: it is for tests and throwaway checks only,
// never for a tag this package actually extracts in production. Production
// code calls newTagPattern, which registers as well as builds; see the
// comment on tagPatternNames for why the two must not be merged.
func buildTagPattern(name string) tagPattern {
	return tagPattern{
		name:  name,
		open:  regexp.MustCompile(`(?i)<` + name + `\b[^>\n]{0,400}>`),
		close: regexp.MustCompile(`(?i)</` + name + `\s*>`),
	}
}

// titleRead is what an opening tag gave up: the one attribute this service
// defines, the names of the ones it does not, and a reason when no usable
// title could be read at all.
type titleRead struct {
	title   string
	extra   []string
	clipped bool
	why     string
}

// readTagTitle pulls title out of an opening tag and IGNORES every other
// attribute.
//
// Ignore, rather than refuse the block: the title is right there, the note
// is what the operator gets to review, and refusing over an attribute
// nobody defined would lose a note to a wording choice the model made. The
// operator loses no information they would otherwise have seen. Ignore,
// rather than keep: an undefined attribute is model-authored metadata, and
// this service grades a note from its own record of the investigation,
// never from what the model says about itself (#41). Only the attribute
// NAMES survive, for the log line. A value is unbounded model text and does
// not travel.
func readTagTitle(tagText string) titleRead {
	var r titleRead
	seen := false
	for _, a := range tagAttrRe.FindAllStringSubmatch(tagText, -1) {
		name := strings.ToLower(a[1])
		if name == "title" {
			if !seen {
				r.title, seen = strings.TrimSpace(a[2]), true
			}
			continue
		}
		r.extra = append(r.extra, name)
	}
	switch {
	case !seen:
		r.why = "no title attribute"
	case r.title == "":
		r.why = "an empty title"
	}
	if run := []rune(r.title); len(run) > maxTagTitle {
		r.title, r.clipped = strings.TrimSpace(string(run[:maxTagTitle])), true
	}
	return r
}

// tagBlock is one block that carried a usable title.
type tagBlock struct {
	title   string
	body    string
	extra   []string
	clipped bool
}

// extract lifts every block of this tag out of a reply. It returns the
// blocks that carried a usable title, the reply with ALL of the markup
// removed (the titleless ones and any stray closing tag included), and one
// line per block that was dropped saying why.
//
// Every block is stripped and only the first is returned to the caller,
// which is the behaviour this replaces. A second block left in the answer
// because the first was the one that got filed would be #121 in a new hat.
//
// An unterminated block takes the rest of the reply with it. There is no
// honest end to a block that never closed, and the alternative, stripping
// the markup and leaving the text, renders the note's own "## Summary /
// ## Evidence / ## Recommendation" to the operator as if it were the answer
// to their question, which is this bug minus the angle brackets. The prompt
// asks for the block at the END of the reply, so in the shape the model
// actually writes there is nothing after it to lose. What it does cost is a
// model that quotes its own protocol mid-answer, so the byte count goes in
// the log rather than passing unremarked. It also takes any later block
// with it, this tag's or the other tag's, since the two extractions run one
// after the other over the same reply: an unclosed <remember> costs a
// well-formed <propose> written below it, and the byte count in the log is
// what says so. If the visible reply comes out empty, it is logged empty:
// nothing is invented to fill it.
func (t tagPattern) extract(reply string) (blocks []tagBlock, clean string, dropped []string) {
	rest, found := reply, false
	var out strings.Builder
	for {
		loc := t.open.FindStringIndex(rest)
		if loc == nil {
			break
		}
		found = true
		out.WriteString(rest[:loc[0]])
		tag, after := rest[loc[0]:loc[1]], rest[loc[1]:]
		end := t.close.FindStringIndex(after)
		if end == nil {
			dropped = append(dropped, fmt.Sprintf("an unterminated <%s> block, %d byte(s) dropped from the reply",
				t.name, len(after)))
			rest = ""
			break
		}
		body := after[:end[0]]
		rest = after[end[1]:]
		r := readTagTitle(tag)
		if r.why != "" {
			dropped = append(dropped, fmt.Sprintf("a <%s> block with %s, %d byte(s) dropped from the reply",
				t.name, r.why, len(body)))
			continue
		}
		blocks = append(blocks, tagBlock{
			title: r.title, body: strings.TrimSpace(body), extra: r.extra, clipped: r.clipped,
		})
	}
	out.WriteString(rest)
	text := out.String()
	if n := len(t.close.FindAllString(text, -1)); n > 0 {
		found = true
		dropped = append(dropped, fmt.Sprintf("%d stray </%s> tag(s) removed from the reply", n, t.name))
		text = t.close.ReplaceAllString(text, "")
	}
	if !found {
		// No trace of this tag anywhere: the reply goes back exactly as it
		// arrived, whitespace included.
		return nil, reply, nil
	}
	return blocks, strings.TrimSpace(text), dropped
}

var rememberTag = newTagPattern("remember")

// extractMemory pulls the block out of the reply, stores it, and returns the
// reply without it — the operator asked a question and should not have to read
// the bookkeeping.
func (s *server) extractMemory(reply, node string) (string, *memory.Entry) {
	blocks, clean, dropped := rememberTag.extract(reply)
	for _, d := range dropped {
		log.Printf("[memory] nothing stored: %s", d)
	}
	if clean == "" && (len(blocks) > 0 || len(dropped) > 0) {
		log.Printf("[memory] the visible reply is empty once the block is stripped")
	}
	if len(blocks) == 0 {
		return clean, nil
	}
	b := blocks[0]
	if len(blocks) > 1 {
		log.Printf("[memory] %d <remember> blocks in one reply: storing the first, the rest are stripped and dropped", len(blocks))
	}
	if len(b.extra) > 0 {
		// Names only, never values, and never read as metadata (#41).
		log.Printf("[memory] attribute(s) ignored on the <remember> tag: %s", strings.Join(b.extra, ", "))
	}
	if b.clipped {
		log.Printf("[memory] title clipped to %d characters", maxTagTitle)
	}

	store, err := memory.Open(filepath.Join(s.stateDir, "memory.jsonl"))
	if err != nil {
		return clean, nil
	}
	e, err := store.Remember(memory.Entry{
		Kind:  memory.KindConcluded, // never anything else from this path
		Title: b.title, Body: b.body,
		Node: node, Source: "advisor",
	})
	if err != nil {
		log.Printf("[memory] not stored: %v", err)
		return clean, nil
	}
	log.Printf("[memory] %s recorded (unconfirmed): %s", e.ID, e.Title)
	return clean, &e
}

var proposeTag = newTagPattern("propose")

// extractProposal pulls a <propose> block out of the reply and writes it to
// internal/inbox — the <remember>-adjacent sibling of extractMemory, and
// the Advisor's write side of the D3 knowledge boundary (decided
// 2026-08-08). Where <remember> stores something that CAN be read back as
// evidence (internal/memory), a <propose> block writes a note that
// categorically cannot, until a person promotes it in the curation window
// (a later step) — nothing here is injected into any future prompt. The
// block is stripped from what the operator reads either way, exactly like
// <remember>: the operator asked a question, not to review the Advisor's
// own bookkeeping.
//
// A failed write logs and returns the reply unchanged rather than failing
// the answer — the operator's question was already answered by the time
// this runs, and a note that could not be filed is a smaller loss than an
// answer withheld over it.
//
// The question travels with the note (ADR 0017 decision 4). The reviewer at
// the aggregator is being asked to accept a claim into every Advisor's
// prompt, and "what was the Advisor answering when it concluded this" is the
// first thing they need — a note that arrives without it reads as an
// assertion from nowhere.
//
// So does the grade. steps is the investigation's own record for this
// question, and internal/proposalrank turns it into the provenance and the
// rank the review card orders by. The model has no say in either: it is
// never asked how confident it is, and if it volunteered a number that number
// would be part of the body, not of the metadata. A model grading its own
// note is exactly how "this aggregator has no swap" was promoted (#41).
func (s *server) extractProposal(reply, node, question string, steps []interrogate.Step) string {
	blocks, clean, dropped := proposeTag.extract(reply)
	for _, d := range dropped {
		log.Printf("[inbox] nothing filed: %s", d)
	}
	if clean == "" && (len(blocks) > 0 || len(dropped) > 0) {
		log.Printf("[inbox] the visible reply is empty once the block is stripped")
	}
	if len(blocks) == 0 {
		return clean
	}
	b := blocks[0]
	if len(blocks) > 1 {
		log.Printf("[inbox] %d <propose> blocks in one reply: filing the first, the rest are stripped and dropped", len(blocks))
	}
	if len(b.extra) > 0 {
		// Names only, never values, and never read as metadata (#41).
		log.Printf("[inbox] attribute(s) ignored on the <propose> tag: %s", strings.Join(b.extra, ", "))
	}
	if b.clipped {
		log.Printf("[inbox] title clipped to %d characters", maxTagTitle)
	}

	title, body := b.title, b.body
	dir := filepath.Join(s.stateDir, "inbox")
	// A read failure here is not a reason to refuse the note: it costs the
	// rejected-before cap on this one note, and the empty list says so.
	prior, lerr := inbox.List(dir)
	if lerr != nil {
		log.Printf("[inbox] prior notes unreadable, grading %q without them: %v", title, lerr)
	}
	v := proposalrank.Score(proposalrank.Input{Steps: steps, Title: title, Prior: prior})
	n, err := inbox.Write(dir, inbox.NewNote{
		Title: title, Body: body, Node: node, Source: "advisor", Question: question,
		Provenance: v.Provenance, Rank: v.Rank,
	})
	var dup *inbox.DuplicatePendingError
	if errors.As(err, &dup) {
		// Issue #115: the same recommendation, already waiting. Named, so the
		// line points at the file the operator should be looking at rather
		// than announcing that something was dropped somewhere. The operator
		// loses nothing: the pending note holds this recommendation, and
		// deciding it is what lets the next one through.
		log.Printf("[inbox] proposal %q not written: %v", title, dup)
		return clean
	}
	if err != nil {
		log.Printf("[inbox] proposal %q not written: %v", title, err)
		return clean
	}
	if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
		// The Advisor acted, not an operator. Named as a service so the three
		// attribution classes (operator, OS account, service) stay
		// distinguishable rather than blurring into "no actor".
		l.AppendAs(ledger.KindInboxNoteWritten, "", fmt.Sprintf("proposal written to the inbox: %s", title),
			map[string]any{
				"note_id": n.ID, "node": node, "title": title, "bytes": len(body),
				// On the record beside the note: what it rests on, and what
				// the service counted to say so.
				"provenance": n.Provenance, "rank": n.Rank, "measured_reads": v.Reads,
				"rejected_before": v.RejectedBefore,
			},
			serviceActor("the Advisor"))
	}
	log.Printf("[inbox] wrote proposal %q (%d bytes, %s, rank %d from %d measured read(s)) to %s",
		title, len(body), n.Provenance, n.Rank, v.Reads, n.Path)
	return clean
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── approve ───────────────────────────────────────────────────────────
//
// The dashboard performs the passkey ceremony, because it owns the credential
// store and the session. This endpoint records the result.
//
// It is gated on a bearer token that both services read from a file at 0600.
// Be precise about what that proves: it proves the caller can read a file only
// these services can read. It stops another user on the host, and it stops an
// unprivileged process. On a host where the dashboard and the Advisor run as
// the SAME user, it is not a boundary against something already running as
// that user — such a process could read the token, or simply write the
// approval file itself. The controls that survive that case are the ones in
// the executor: the fingerprint check, the stage split, the re-measured
// preconditions, and a ledger where the absence of a matching passkey entry is
// visible.

type approveRequest struct {
	PlanID      string `json:"plan_id"`
	Fingerprint string `json:"fingerprint"`
	Stage       string `json:"stage"`
	Target      string `json:"target"`
	// Runbook names which plan is being approved. Absent means the upgrade.
	Runbook string `json:"runbook"`
	// Intent is RB-002's bound parameter, carried from /v1/approve/begin so
	// the fingerprint recomputed here matches the one the challenge was
	// issued against. It is deliberately NOT Reason below: that is free text
	// outside the fingerprint, this is an enum inside it, and one field
	// carrying both is how a plan gets approved that nobody read.
	Intent string `json:"intent"`
	// Key and Value are RB-003's bound parameters, here for exactly the
	// reason Intent is: both are inside the fingerprint, so a ceremony begun
	// without them is a ceremony for a different plan.
	Key   string `json:"key"`
	Value string `json:"value"`
	// Change and User are RB-005's, Source is #682's build override, and
	// all three travel for the reason Key and Value do.
	Change    string `json:"change"`
	User      string `json:"user"`
	Source    string `json:"source"`
	GrantedBy string `json:"granted_by"`
	// GrantedByRole is what the dashboard's session says this operator was
	// allowed to do. A claim like GrantedBy is — both are derived server-side
	// from the session, neither is proved here — and the ledger labels it as
	// one. Recorded because role is enforced everywhere and, until now, kept
	// nowhere: a demotion afterwards left "was this person an admin when they
	// restarted the node" unanswerable.
	GrantedByRole string `json:"granted_by_role"`
	TTLSeconds    int    `json:"ttl_seconds"`
	Reason        string `json:"reason"`
	// Evidence of the ceremony, recorded verbatim in the ledger. The dashboard
	// verified it; this is the record that it did.
	CredentialID string `json:"credential_id"`
	SessionUser  string `json:"session_user"`
	Origin       string `json:"origin"`
	// The assertion itself, so this service can verify it rather than trust
	// that the caller did. An approval only a service vouches for is one a
	// stolen service token can forge.
	Assertion *webauthn.Assertion `json:"assertion"`
	Challenge string              `json:"challenge"`
}

// validApproveStage is what a ceremony — begin, finish, or a cancel naming a
// stage — may name FOR THIS RUNBOOK. The compound "upgrade" scope belongs to
// RB-001's list alongside its two concrete stages: it is a real scope an
// operator can sign over, one ceremony covering prepare and cutover in
// sequence. It is deliberately wider than what the execute handler accepts —
// nothing ever RUNS "upgrade"; UpgradeSteps tags every step prepare or
// cutover, and RunStage only ever executes one of those two.
//
// Read from the runbook rather than from a constant, so a scope belonging to
// one runbook can never be named on another: a ceremony for a "cutover" on
// the restart runbook is refused here, before a challenge is minted.
func validApproveStage(rb runbook.Runbook, stage string) bool {
	return stageIn(rb.GrantScopes, stage)
}

// stageIn is membership, named so the call sites read as the question they
// are asking.
func stageIn(stages []string, stage string) bool {
	for _, x := range stages {
		if x == stage {
			return true
		}
	}
	return false
}

// POST /v1/approve/begin — issue the challenge for one ceremony.
//
// The caller says which plan and which stage; this returns a single-use value
// bound to both. The dashboard puts it in front of the operator's passkey, and
// /v1/approve will only accept an assertion carrying it back. Token-gated like
// every other write verb: a challenge is not a secret, but minting them is a
// service act, and there is no reason to let anything else do it.
func (s *server) approveBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	var req struct {
		Target string `json:"target"`
		Stage  string `json:"stage"`
		// Runbook names which plan this ceremony is for. Absent means the
		// upgrade, which is what every caller written before RB-002 sends.
		Runbook string `json:"runbook"`
		// Intent is RB-002's bound parameter, and it travels as its own
		// field from begin to finish. Never merged into Reason: that one is
		// free text and sits OUTSIDE the fingerprint, this one is an enum
		// and is inside it, so feeding either to the other either fails
		// binding or collapses every confirm code on the node into one.
		Intent string `json:"intent"`
		// Key and Value are RB-003's, and travel from begin to finish for
		// exactly the reason Intent does: both are inside the fingerprint the
		// challenge is bound to.
		Key   string `json:"key"`
		Value string `json:"value"`
		// Change and User are RB-005's (ADR 0023), and Source is the
		// operator asking for a build when an official image also exists
		// (#682). All three are inside the fingerprint, for the same reason
		// the four above are. The digest is NOT here: it is resolved on this
		// side, from the registry answer the plan already took, so a caller
		// cannot name the image an approval will install.
		Change string `json:"change"`
		User   string `json:"user"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	rb, err := lookupRunbook(req.Runbook)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !validApproveStage(rb, req.Stage) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown stage"})
		return
	}
	// The same gate /v1/execute holds (#682's fifth ruling), held HERE as
	// well, and this is the one that matters to an operator: refusing at
	// execute alone means the passkey is touched, the grant is written, and
	// then nothing runs. A refusal before the ceremony costs nothing.
	if rb.ID == normaliseRunbookID && !s.normaliseWindowOpen(r.Context()) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "a change to this node's deployment needs an open break-glass window",
			"detail": "Open one from the header (Break glass), then ask for this change again. " +
				"The window is opened on this node and lasts fifteen minutes; nothing here can " +
				"open one for itself, which is the point.",
		})
		return
	}

	// The fingerprint is computed HERE, from the plan this service would
	// actually run, so the challenge is bound to that and not to a value the
	// caller supplied. /v1/approve recomputes it the same way and the two must
	// agree — which is what makes "the plan changed mid-ceremony" detectable.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	profile, node, err := s.profileKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	// A rollback is challenged only for the target this node derives
	// (#998). Before the challenge, so a refusal costs no passkey prompt.
	// The one rollback-only read this door adds over #105's single read.
	//
	// The same reading names the copy the rollback restores (#1029), so the
	// challenge is bound to the plan the card shows, and a read that fails
	// refuses here, before any challenge, rather than binding an empty copy.
	var cp restoreCopy
	if rb.ID == rollbackRunbookID {
		var refusal map[string]any
		if _, cp, refusal = s.rollbackTargetGateCopy(s.readState(ctx, profile), req.Target); refusal != nil {
			writeJSON(w, http.StatusBadRequest, refusal)
			return
		}
	}
	// The image source, read for this request (#1061), the way the run
	// door reads it (#1033). The five-minute shelf lapsed between the card
	// and the passkey touch for anyone who read the card slowly, and the
	// ceremony then bound another plan and refused it as changed. Bound
	// unpinned when the registry does not answer, which is the plan the
	// card itself shows on such a host; a digest that moved since the card
	// computes another fingerprint, and the card's comparison refuses it.
	params, err := bindRequest(rb, withRestoreCopy(rb, s.ceremonySource(func() *host.State { return s.readState(ctx, profile) }, rb, planParams{
		Target: req.Target, Intent: req.Intent, Key: req.Key, Value: req.Value,
		Change: req.Change, User: req.User, Source: req.Source,
	}), cp))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	fp := approval.Fingerprint(rb.ID, node, params)

	// Two minutes: long enough for a passkey prompt and a fingerprint that
	// needs a second attempt, short enough that a captured value is stale
	// before it is useful.
	n, err := s.nonces.Issue(fp, req.Stage, 2*time.Minute)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":   n.Value,
		"fingerprint": fp,
		"stage":       req.Stage,
		"runbook":     rb.ID,
		"expires_in":  int(time.Until(n.Expires).Seconds()),
	})
}

func (s *server) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	var req approveRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	rb, err := lookupRunbook(req.Runbook)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !validApproveStage(rb, req.Stage) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown stage"})
		return
	}
	if req.CredentialID == "" || req.Assertion == nil || req.Challenge == "" {
		writeJSON(w, http.StatusBadRequest,
			map[string]any{"error": "no passkey assertion; an approval without a ceremony is not one"})
		return
	}
	// No grant for a rollback target this node does not derive (#998).
	// Checked before the assertion is spent, so a refused ask burns nothing.
	// The same reading names the copy the fingerprint below binds (#1029).
	var cp restoreCopy
	if rb.ID == rollbackRunbookID {
		gctx, gcancel := context.WithTimeout(r.Context(), 30*time.Second)
		profile, _, perr := s.profileKeyed(gctx)
		if perr != nil {
			gcancel()
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": perr.Error()})
			return
		}
		var refusal map[string]any
		_, cp, refusal = s.rollbackTargetGateCopy(s.readState(gctx, profile), req.Target)
		gcancel()
		if refusal != nil {
			s.recordRollbackTargetRefusal(ledger.KindApprovalRefused, "approval", refusal,
				refusedActor(req.CredentialID, req.GrantedBy, req.GrantedByRole, req.Origin))
			writeJSON(w, http.StatusBadRequest, refusal)
			return
		}
	}
	// Verified here, against keys this service holds. The dashboard already
	// checked — that is not a reason to skip it, it is the reason there are two
	// independent checks instead of one trusted one.
	store, err := host.LoadCredentials(filepath.Join(s.stateDir, "credentials.json"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	refusedBy := refusedActor(req.CredentialID, req.GrantedBy, req.GrantedByRole, req.Origin)
	if err := store.Verify(*req.Assertion, req.Challenge); err != nil {
		l, _ := ledger.Open(filepath.Join(s.stateDir, "ledger.jsonl"))
		if l != nil {
			l.AppendAs(ledger.KindApprovalRefused, req.PlanID,
				"approval refused: the passkey assertion did not verify",
				map[string]any{"stage": req.Stage, "error": err.Error(),
					"credential_id": req.CredentialID}, refusedBy)
		}
		// The ledger above kept the bare cause; the body carries the remedy
		// when the cause is a credential this node was never told about.
		writeJSON(w, http.StatusForbidden, map[string]any{"error": s.enrollmentRemedy(err)})
		return
	}
	// Past this point a key in this service's own store signed the challenge,
	// so the attribution is no longer a bare claim.
	grantedBy := ceremonyActor(store, req.CredentialID, req.GrantedBy, req.GrantedByRole, req.Origin)

	// Recompute the fingerprint here rather than trusting the one sent. If they
	// disagree, the plan changed between the ceremony and this call, and the
	// operator approved something other than what would run.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, node, st, err := s.stateKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	// The copy a rollback restores is the one the target gate above read off
	// the host (#1029), and the image source is read for this request
	// (#1061), as begin reads it. A digest that moved since the card is
	// another fingerprint, refused just below as the plan having changed.
	params, err := bindRequest(rb, withRestoreCopy(rb, s.ceremonySource(func() *host.State { return st }, rb, planParams{
		Target: req.Target, Intent: req.Intent, Key: req.Key, Value: req.Value,
		Change: req.Change, User: req.User, Source: req.Source,
	}), cp))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	fp := approval.Fingerprint(rb.ID, node, params)
	if fp != req.Fingerprint {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "the plan changed between the ceremony and this call; nothing was approved"})
		return
	}

	// Spend the challenge this service issued, against the fingerprint IT just
	// recomputed and the stage being claimed. This is what makes the second
	// verification independent: until now it re-checked a challenge the
	// dashboard chose, which named neither plan nor stage — so a captured
	// prepare ceremony could be resubmitted as a cutover and it verified. The
	// value is single use and is burned even by a failed attempt.
	if err := s.nonces.Consume(req.Challenge, fp, req.Stage); err != nil {
		l, _ := ledger.Open(filepath.Join(s.stateDir, "ledger.jsonl"))
		if l != nil {
			l.AppendAs(ledger.KindApprovalRefused, req.PlanID,
				"approval refused: the challenge does not belong to this act",
				map[string]any{"stage": req.Stage, "error": err.Error(),
					"credential_id": req.CredentialID}, grantedBy)
		}
		log.Printf("[approve] refused: %v (stage %s, plan %s)", err, req.Stage, req.PlanID)
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":  err.Error(),
			"detail": "start the approval again; each ceremony gets its own challenge",
		})
		return
	}

	// An approval for a stage whose preconditions refuse right now is an
	// approval for something that cannot happen.
	//
	// Per stage, and this is the last of four places that had to learn it:
	// a check an earlier stage SATISFIES cannot forbid approving that stage.
	// The two backup checks are taken by prepare, so counting them here made
	// prepare unapprovable on a host that had never been upgraded — after
	// the operator had already typed the code and touched their passkey,
	// which is the worst possible moment to be told the plan was never
	// going to be allowed.
	// A compound StageUpgrade grant is gated exactly as prepare is: it
	// authorises BEGINNING the sequence, and cutover's own preconditions
	// (the two dated backups prepare itself takes) are re-measured at the
	// handoff between the stages, same as an ordinary prepare-only approval
	// never checks them either. Gating a compound grant on cutover's
	// preconditions here would resurrect the exact bug the comment below
	// describes, in a new shape: unapprovable on a host that had never been
	// upgraded.
	// A scope that is not itself a stage — the compound "upgrade" grant — is
	// gated as the FIRST stage it authorises. It permits beginning the
	// sequence; the later stages' own preconditions are re-measured at the
	// handoff between them, exactly as an ordinary prepare-only approval
	// never checks them either.
	gateStage := req.Stage
	if !stageIn(rb.Stages, gateStage) && len(rb.Stages) > 0 {
		gateStage = rb.Stages[0]
	}
	var failed []string
	for _, pc := range rb.Preconditions {
		if pc.Gates != "" && pc.Gates != gateStage {
			continue
		}
		if v := pc.Check(params, st); !v.Passed {
			failed = append(failed, v.Name+" — "+v.Detail)
		}
	}
	if len(failed) > 0 {
		l, _ := ledger.Open(filepath.Join(s.stateDir, "ledger.jsonl"))
		if l != nil {
			l.AppendAs(ledger.KindApprovalRefused, req.PlanID,
				"approval refused: preconditions do not pass",
				map[string]any{"stage": req.Stage, "failures": failed}, grantedBy)
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "preconditions refuse", "failures": failed})
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > 30*time.Minute {
		ttl = 10 * time.Minute
	}
	now := time.Now().UTC()
	ap := approval.Approval{
		PlanID: "plan-" + fp[:12], Fingerprint: fp, RunbookID: rb.ID,
		Node: node, GrantedBy: req.GrantedBy, GrantedByRole: grantedBy.Role,
		GrantedAt: now, ExpiresAt: now.Add(ttl), Stage: req.Stage, Reason: req.Reason,
		Assertion: req.Assertion, Challenge: req.Challenge, Origin: req.Origin,
	}
	// The ledger is opened BEFORE the approval is written (#1091), as break
	// glass does: an approval that cannot be recorded is not granted, and
	// opening it afterwards left a live approval with no record of it.
	l, err := ledger.Open(filepath.Join(s.stateDir, "ledger.jsonl"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	path, err := approval.Grant(filepath.Join(s.stateDir, "approvals"), withPlanImage(ap, params))
	if errors.Is(err, approval.ErrClaimed) {
		// A run is acting on this plan's approval right now (#1063). A
		// second grant over it would hand that run's consent to the next.
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error() +
			". Nothing was approved this time", "reason": "approval_held"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	if _, err := l.AppendAs(ledger.KindApprovalGranted, ap.PlanID,
		fmt.Sprintf("%s approved stage %s by passkey, expires %s",
			ap.GrantedBy, ap.Stage, ap.ExpiresAt.Format(time.RFC3339)),
		map[string]any{
			"stage": ap.Stage, "target": req.Target, "fingerprint": fp,
			"runbook": rb.ID, "params": map[string]string(params),
			"expires_at": ap.ExpiresAt, "reason": req.Reason,
			"ceremony": map[string]any{
				"credential_id": req.CredentialID,
				"session_user":  req.SessionUser,
				"origin":        req.Origin,
			},
		}, grantedBy); err != nil {
		// A grant the ledger has no row for is withdrawn, not left live
		// (#1091): the audit trail is the only account of who approved what.
		fate := s.withdrawUnrecorded(ap.PlanID, ap.Stage, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "the ledger could not record this approval (" + err.Error() + "), and " + fate})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"granted": true, "plan_id": ap.PlanID, "stage": ap.Stage,
		"expires_at": ap.ExpiresAt, "path": path, "ledger_head": l.Head(),
	})
}

type cancelApprovalRequest struct {
	PlanID    string `json:"plan_id"`
	Stage     string `json:"stage"`
	GrantedBy string `json:"granted_by"`
	// GrantedByRole is the revoking operator's role, as the dashboard's
	// session reports it. Revoking is not a ceremony, so there is nothing to
	// prove here and the entry says so.
	GrantedByRole string `json:"granted_by_role"`
	Reason        string `json:"reason"`
	// Runbook names whose stage this is. Absent means the upgrade, so a
	// caller written before RB-002 keeps cancelling exactly what it did.
	Runbook string `json:"runbook"`
}

// POST /v1/approve/cancel — revoke an approval before it is spent.
//
// Two shapes of caller. Named plan and stage — the tab's own "revoke this
// approval" — asks for exactly one file. No stage — logout — clears every
// unspent approval the named operator holds, wherever it is, because an
// operator signing out may not remember which stage they last approved, and
// a standing approval left behind authorises something after nobody is
// watching for it.
//
// The withdrawal is the approval package's own (Withdraw, CancelAllByUser):
// removed, or voided in place when it cannot be removed, the same as a spend.
// A cancelled approval and a spent one are the same fact from RunStage's
// side: neither authorises anything next time. What differs is why, and that
// is what the ledger records, never the file on disk.
func (s *server) approveCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	var req cancelApprovalRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	if req.GrantedBy == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "granted_by is required"})
		return
	}
	rb, err := lookupRunbook(req.Runbook)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if req.Stage != "" && !validApproveStage(rb, req.Stage) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown stage"})
		return
	}

	dir := filepath.Join(s.stateDir, "approvals")
	var cancelled, stillLive []approval.Approval
	if req.Stage != "" {
		if req.PlanID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "plan_id is required with a stage"})
			return
		}
		// One locked act, look and withdraw (#1061): two cancels of one
		// grant at the same moment used to both find it and both write a
		// row for one withdrawal. Only the call that withdrew it records
		// it. A grant already voided was withdrawn before, and a spend that
		// could not remove the file but voided it in place has withdrawn
		// it, and is said and recorded as a withdrawal (#1047, review).
		a, withdrew, werr := withdrawGrant(dir, req.PlanID, req.Stage, time.Now())
		if !withdrew && werr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": werr.Error()})
			return
		}
		if werr != nil {
			log.Printf("[cancel] %v", werr)
		}
		if withdrew {
			cancelled = append(cancelled, a)
		}
	} else {
		var cerr error
		cancelled, cerr = cancelAllByUser(dir, req.GrantedBy)
		var live *approval.StillLiveError
		switch {
		case errors.As(cerr, &live):
			// Logout's cancel must not answer "done" over a grant that still
			// authorises something (#1061). The ones it did withdraw are
			// recorded below as usual; the ones it could not are a row of
			// their own and a failed answer. The dashboard's logout does not
			// wait for this answer, so the row is what an operator finds.
			stillLive = live.Grants
		case cerr != nil:
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": cerr.Error()})
			return
		}
	}

	l, err := ledger.Open(filepath.Join(s.stateDir, "ledger.jsonl"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	// The actor is the person REVOKING, which is not always the person who
	// granted: an admin can revoke a colleague's standing approval, and
	// granted_by beside it is what makes that readable.
	revokedBy := sessionActor(req.GrantedBy, req.GrantedByRole)
	for _, a := range cancelled {
		l.AppendAs(ledger.KindApprovalCancelled, a.PlanID,
			fmt.Sprintf("%s revoked stage %s before it ran (%s)", req.GrantedBy, a.Stage,
				nonEmpty(req.Reason, "no reason given")),
			map[string]any{
				"stage": a.Stage, "granted_by": a.GrantedBy, "originally_expired_at": a.ExpiresAt,
				"reason": req.Reason,
			}, revokedBy)
	}
	if len(stillLive) > 0 {
		var names []map[string]any
		for _, a := range stillLive {
			names = append(names, map[string]any{"plan_id": a.PlanID, "stage": a.Stage, "expires_at": a.ExpiresAt})
		}
		msg := (&approval.StillLiveError{Grants: stillLive}).Error()
		l.AppendAs(ledger.KindRefusal, "",
			fmt.Sprintf("%s's approvals were not all withdrawn: %d still live", req.GrantedBy, len(stillLive)),
			map[string]any{"reason": "cancel_failed", "granted_by": req.GrantedBy, "still_live": names,
				"cancel_reason": req.Reason, "error": msg}, revokedBy)
		log.Printf("[cancel] %s", msg)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": msg, "cancelled": len(cancelled), "still_live": names, "ledger_head": l.Head(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cancelled": len(cancelled), "ledger_head": l.Head(),
	})
}

// withdrawGrant and cancelAllByUser are the approval package's, variables
// so a test can hold a cancel at the moment a second one arrives, or make a
// grant one that cannot be withdrawn.
var (
	withdrawGrant   = approval.Withdraw
	cancelAllByUser = approval.CancelAllByUser
)

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// approveToken reads the shared secret. Generated by the install script at
// 0640 on the shared group; absent means approvals cannot be granted over HTTP at all, which is
// the correct default for a service that has just been installed.
func (s *server) approveToken() (string, error) {
	b, err := os.ReadFile(filepath.Join(s.stateDir, "approve.token"))
	if err != nil {
		return "", fmt.Errorf("no approval token installed; web approval is disabled on this host")
	}
	t := strings.TrimSpace(string(b))
	if len(t) < 32 {
		return "", fmt.Errorf("approval token is too short to be one")
	}
	return t, nil
}

// tightenState narrows anything in the state directory that is readable by
// accounts other than this service's.
//
// Every writer here already creates files at 0640 and directories at 0750. The
// deployed tree still had a world-readable run directory and lookup config,
// because they were created before those modes were set and nothing since has
// looked. The contents are the audit ledger, the run transcripts and the
// credential store — the exact things "loopback is not a user boundary" was
// about — so a mode that was right once and drifted is worth correcting on
// every start rather than at install only.
//
// It only ever removes permission. Anything already correct is untouched, and
// a file this service does not own is reported rather than fought over.
func (s *server) tightenState() {
	if s.stateDir == "" {
		return
	}
	// evidence/ as well as state/. It sits outside the state directory, holds
	// the privilege wrapper's log of every verb it has been asked to run, and
	// was the one thing still being created world-readable — the wrapper runs
	// as root through sudo, which does not carry this unit's UMask across.
	dirs := []string{s.stateDir, filepath.Join(filepath.Dir(s.stateDir), "evidence")}
	for _, d := range dirs {
		s.tightenTree(d)
	}
}

func (s *server) tightenTree(root string) {
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil {
			return nil
		}
		// The token is 0600 and stays 0600; do not widen it to the file rule.
		want := os.FileMode(0o640)
		if fi.IsDir() {
			want = 0o750
		} else if fi.Mode().Perm() == 0o600 {
			return nil
		}
		have := fi.Mode().Perm()
		if have&^want == 0 {
			return nil // already at least this narrow
		}
		if e := os.Chmod(p, have&want); e != nil {
			log.Printf("[state] %s is %04o and could not be narrowed: %v", p, have, e)
			return nil
		}
		log.Printf("[state] narrowed %s from %04o to %04o", p, have, have&want)
		return nil
	})
}

// fileOwnedByProcess reports whether the file's owner is this process's
// effective uid. A variable so a test can stand in for a file owned by
// someone else without needing root to chown one.
var fileOwnedByProcess = func(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true // no owner to read: keep the old behaviour
	}
	return int(st.Uid) == os.Geteuid()
}

// tightenFleet narrows the registry file and every registered peer's read
// token to 0600, explicitly, rather than relying on tightenTree's walk —
// step 5's Security Auditor sign-off condition, and decision-log.md's
// "tightenState extends to cover the registry file and every peer token".
//
// Not folded into tightenTree for two reasons. A peer's TokenPath is not
// guaranteed to sit inside stateDir — the registry can point wherever that
// peer's own install put its token — so a directory walk rooted at
// stateDir would never reach it. And tightenTree's own floor for an
// ordinary file is 0640, one step wider than a credential should ever sit
// at; approve.token and read.token are both left alone at 0600 in
// tightenTree for the same reason this narrows straight to 0600 rather
// than borrowing tightenTree's 0640 rule.
func (s *server) tightenFleet(registryPath string) {
	narrow600 := func(p string) {
		if p == "" {
			return
		}
		fi, err := os.Stat(p)
		if err != nil {
			return // absent is not this function's problem to report
		}
		// A file this account does not own is not this account's to narrow:
		// chmod on it can only fail, and root's tokens under
		// /etc/aperire/fleet-tokens are root:aperire-svc 0640 on purpose, so
		// the dashboard and the Advisor both read them (#892). Say nothing.
		if !fileOwnedByProcess(fi) {
			return
		}
		have := fi.Mode().Perm()
		if have == 0o600 {
			return
		}
		want := have & 0o600
		if err := os.Chmod(p, want); err != nil {
			log.Printf("[fleet] %s is %04o and could not be narrowed: %v", p, have, err)
			return
		}
		log.Printf("[fleet] narrowed %s from %04o to %04o", p, have, want)
	}
	narrow600(registryPath)
	for _, tp := range s.fleetNow().reg.TokenPaths() {
		narrow600(tp)
	}
}

// ensureToken makes the transport boundary exist before anything is served.
//
// Loopback is a network boundary, not a user boundary: every account on this
// host can reach 127.0.0.1. Without a token, any of them could read the audit
// ledger and every run transcript, and POST questions that spend the
// operator's model budget and reflect the knowledge corpus back. So the token
// now gates the whole surface — and a missing one is generated rather than
// treated as "open", because a security boundary that disappears when a file
// is absent is not one.
//
// This does not switch web approval on. An approval still needs a passkey
// assertion verified against the credential store; the token only proves the
// caller can read a file that this service's user owns.
func (s *server) ensureToken() (string, error) {
	if t, err := s.approveToken(); err == nil {
		return t, nil
	}
	p := filepath.Join(s.stateDir, "approve.token")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return "", err
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := base64.RawStdEncoding.EncodeToString(b)
	// 0640, not 0600. The dashboard has to read this file, and when the Advisor
	// runs as its own account the only way to share it is the group both
	// accounts are in. Written at 0600, a regenerated token silently locked the
	// dashboard out — the tab reporting "no advisor token readable on this host"
	// with nothing to explain why, since the install had set 0640 and something
	// later put it back.
	//
	// Still not world-readable: the group is the point, and the containing
	// directory is 0750.
	if err := os.WriteFile(p, []byte(t+"\n"), 0o640); err != nil {
		return "", err
	}
	shareWithStateDirGroup(p, s.stateDir)
	log.Printf("[token] generated %s (0640) — no token was installed, and an "+
		"unauthenticated surface on a shared host is not a default worth having", p)
	return t, nil
}

// shareWithStateDirGroup puts a token this process just wrote on the group of
// the state directory that holds it. Shared exactly as widely as the
// directory: on a dedicated-account install its group is the service group
// both accounts are in, and without this the file would carry this process's
// primary group, which the dashboard is not in. The surface would be silently
// disabled with a token sitting right there (#799 for approve.token, and the
// reason read.token always had it).
//
// Group only: the owner and the 0640 the caller wrote are left as they are.
// A failure is logged and does not stop the service. The Advisor can still
// use its own token, and the line names what the dashboard will then be
// missing, which is more use than a service that will not start.
func shareWithStateDirGroup(path, stateDir string) {
	st, err := os.Stat(stateDir)
	if err != nil {
		log.Printf("[token] %s stays on this service's own group: cannot read %s: %v", path, stateDir, err)
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if err := os.Chown(path, -1, int(sys.Gid)); err != nil {
		log.Printf("[token] %s stays on this service's own group, so the dashboard cannot read it "+
			"(could not move it to group %d, the state directory's): %v", path, sys.Gid, err)
	}
}

// ensureReadToken establishes the read-surface token — ADR 0008. A second
// secret beside approve.token, deliberately not the same one: the two tokens
// authenticate opposite directions, and one token in both would mean
// compromising either service yields both. The dashboard verifies presented
// tokens against this same file, per request, so rotation is one file write
// and deleting the file turns the surface off on both sides at once.
func (s *server) ensureReadToken() error {
	p := filepath.Join(s.stateDir, "read.token")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return nil
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	t := base64.RawStdEncoding.EncodeToString(b)
	if err := os.WriteFile(p, []byte(t+"\n"), 0o640); err != nil {
		return err
	}
	shareWithStateDirGroup(p, s.stateDir)
	log.Printf("[token] generated %s (0640) — the dashboard's read surface authenticates against it", p)
	return nil
}

// authorized reports whether a request carries the service token. Constant
// time, because the alternative leaks the token a byte at a time.
func (s *server) authorized(r *http.Request) bool {
	want, err := s.approveToken()
	if err != nil {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// loadKnowledge reads the operator's notes.
//
// Read on every question rather than cached at startup, so editing a note and
// asking again is the whole loop — an operator who has to restart a service to
// correct something they just wrote will stop correcting things.
//
// No longer the operative cap (D4 §10 change 1). loadKnowledge now loads and
// labels; the byte budget that used to be enforced here (maxDoc truncating
// each file, maxTotal evicting in os.ReadDir name order once the corpus
// passed 96 KB) moved to injection — model.SelectKnowledge, ranked and
// budget-aware, after this function has handed it every doc — per security
// sign-off P2-005: "no commit relaxes or removes maxTotal unless the same
// commit adds the injection budget as a constant in code." safetyBound below
// is what is left at load: a circuit breaker against a pathological corpus
// exhausting memory, not the token-cost limit.
func (s *server) loadKnowledge() []model.KnowledgeDoc {
	// safetyBound is roughly 65x the shipped corpus (125.5 KB across 20
	// files, re-measured 2026-09-27) and exists only so a
	// runaway promotion (or a misconfigured nodes/ tree) cannot bring the
	// process down between one restart and the next — it is not expected to
	// ever fire under any use this project has seen. model.KnowledgeInjectionBudget
	// is the limit an operator's question actually experiences.
	const safetyBound = 8 << 20

	var out []model.KnowledgeDoc
	total := 0
	stop := false

	// read appends one file's KnowledgeDoc, tagged with node (empty for a
	// root file). Returns false when the safety bound was hit, so both
	// callers below can stop walking rather than silently continuing past
	// it — the corpus stays honestly reported (nothing is loaded twice or
	// half-loaded), it just stops growing.
	read := func(full, name, node string, layer model.Layer) bool {
		b, err := os.ReadFile(full)
		if err != nil {
			return true
		}
		if total+len(b) > safetyBound {
			log.Printf("[knowledge] %s and later files skipped: corpus safety bound %dMB reached",
				name, safetyBound>>20)
			return false
		}
		total += len(b)
		out = append(out, model.KnowledgeDoc{Name: name, Body: string(b), Node: node, Layer: layer})
		return true
	}

	entries, err := os.ReadDir(s.knowledge)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if stop {
			break
		}
		n := e.Name()
		// "nodes" is the ONE named exception to the non-recursive walk
		// below, and it goes exactly one level deep — D4 §12 / the D4
		// build's item C: "the loader walks EXACTLY: root *.md (as today)
		// plus nodes/<name>/*.md one level deep — nothing else; unknown
		// subdirectories stay invisible exactly as they are today, because
		// that exclusion-by-structure is load-bearing (D3's inbox depends
		// on it)." The node label comes from the directory name the
		// filesystem handed back — never from a caller, never used to
		// build a path outward — so there is nothing here for a value to
		// traverse with even in principle.
		if n == "nodes" && e.IsDir() {
			nodeDirs, err := os.ReadDir(filepath.Join(s.knowledge, "nodes"))
			if err != nil {
				continue
			}
			for _, nd := range nodeDirs {
				if stop {
					break
				}
				// nd.IsDir() is false for a symlink (it reflects the
				// directory entry's own type, not the target's), so a
				// symlinked "node" folder is skipped here the same way
				// P3-008 skips a symlinked file below — not read, not
				// followed.
				if !nd.IsDir() {
					continue
				}
				label := nd.Name()
				sub, err := os.ReadDir(filepath.Join(s.knowledge, "nodes", label))
				if err != nil {
					continue
				}
				for _, f := range sub {
					fn := f.Name()
					if !strings.HasSuffix(fn, ".md") || fn == "README.md" {
						continue
					}
					// P3-008: a regular-file check so a symlink named
					// *.md inside a per-node folder is skipped, not read.
					// f.Type() is the direntry's own type bits — cheap,
					// no extra stat, and does not follow the link.
					if !f.Type().IsRegular() {
						continue
					}
					if !read(filepath.Join(s.knowledge, "nodes", label, fn), fn, label, model.LayerShipped) {
						stop = true
						break
					}
				}
			}
			continue
		}
		// e.IsDir() skips every OTHER subdirectory of s.knowledge,
		// non-recursively — an accident this project's own history turned
		// into load-bearing security, not a detail to "fix" toward
		// recursion later. The inbox (internal/inbox, D3) is written by
		// advisord and never read back by any reasoning path; the property
		// that makes that true is that it is a SIBLING of s.knowledge
		// (state/inbox, not knowledge/inbox) and this loader does not
		// recurse into anything except the one named "nodes" case above.
		// The moment loadKnowledge walks an arbitrary subtree, every .md a
		// promotion workflow or an Advisor-writable directory ever
		// produces becomes Documented by the accident of being reachable,
		// not by a person having promoted it — the exact failure D3's
		// curation ceremony exists to gate behind a passkey. Same
		// reasoning as wrapperConfPath's fixed path a few hundred lines
		// up: a boundary held by one line of code is worth a comment
		// explaining why the line must not be "improved".
		if e.IsDir() || !strings.HasSuffix(n, ".md") || n == "README.md" {
			continue
		}
		// The role policy is injected into EVERY system prompt by
		// loadRolePolicy, so ranking it here as well would put two copies of
		// it in front of the model on any question whose words happened to
		// match it — and charge for both. Excluded by name, at the root
		// only: a per-node nodes/<label>/role-policy.md would be an
		// operator's own note about one host and is theirs to rank.
		if n == rolePolicyFile {
			continue
		}
		// P3-008, root files: same regular-file check as the per-node case
		// above — a symlink named *.md at the loader root used to be read
		// (e.IsDir() alone does not catch it) up to maxDoc.
		if !e.Type().IsRegular() {
			continue
		}
		if !read(filepath.Join(s.knowledge, n), n, "", model.LayerShipped) {
			stop = true
		}
	}

	// The two fleet layers — ADR 0017 decision 1. A SEPARATE walk, and
	// deliberately: the loop above must stay non-recursive (see its own
	// comment on why the inbox's exclusion by structure depends on that),
	// while a fleet layer is a taxonomy tree and has to be walked. Keeping
	// them apart means teaching the fleet corpus about directories cannot
	// widen what the shipped root reads by accident.
	if !stop {
		s.readFleetLayers(read)
	}
	return out
}

// fleetLayerMaxDepth bounds the taxonomy walk: knowledge-fleet/<layer>/ plus
// three directory levels below it. Deep enough for xrpl/consensus/…, shallow
// enough that a bundle cannot make the loader walk a tree of its own choosing.
const fleetLayerMaxDepth = 3

// readFleetLayers walks advisor/knowledge-fleet/{base,local}/ and hands each
// file to the shared reader, named by its path RELATIVE TO ITS LAYER so
// "base/xrpl/validations.md" is Name "xrpl/validations.md" in LayerFleetBase.
//
// Everything refused here is refused at the bundle door as well (see
// internal/knowledge). This is the second lock on the same door, for the case
// the directory was written by something other than an accepted bundle — an
// operator's own hand, a restored backup, a future pull path.
func (s *server) readFleetLayers(read func(full, name, node string, layer model.Layer) bool) {
	if s.knowledgeFleet == "" {
		return
	}
	layers := []struct {
		dir   string
		layer model.Layer
	}{
		{"base", model.LayerFleetBase},
		{"local", model.LayerFleetLocal},
	}
	for _, l := range layers {
		root := filepath.Join(s.knowledgeFleet, l.dir)
		if _, err := os.Stat(root); err != nil {
			continue // a fleet layer that has never been pushed is not an error
		}
		stopped := false
		err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || stopped {
				return nil //nolint:nilerr // an unreadable subtree is skipped, never fatal
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return fs.SkipDir
			}
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			depth := strings.Count(rel, "/")
			if e.IsDir() {
				// "nodes" is the per-node namespace's own word. A fleet
				// layer using it would produce docs labelled like per-node
				// files that are scoped to no node at all.
				if e.Name() == "nodes" || depth >= fleetLayerMaxDepth {
					return fs.SkipDir
				}
				return nil
			}
			// Same regular-file rule as the shipped loader (P3-008): a
			// symlink is not followed and not read, at any level.
			if !e.Type().IsRegular() {
				return nil
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".md") || name == "README.md" || name == "_index.md" {
				// _index.md is a map for a human reading the tree (ADR 0017
				// decision 2's "_index.md maps"). Injecting a list of links
				// into a prompt spends budget on navigation the model cannot
				// follow.
				return nil
			}
			if name == model.RolePolicyFile {
				log.Printf("[knowledge] %s/%s ignored: %s is read from the shipped corpus only",
					l.dir, rel, model.RolePolicyFile)
				return nil
			}
			if !read(p, rel, "", l.layer) {
				stopped = true
			}
			return nil
		})
		if err != nil {
			log.Printf("[knowledge] fleet layer %s: %v", root, err)
		}
		if stopped {
			return
		}
	}
}

// rolePolicyFile is the one knowledge file that is never ranked. It is read
// in full into every system prompt instead — see loadRolePolicy.
const rolePolicyFile = "role-policy.md"

// loadRolePolicy reads the role policy that goes into every system prompt,
// on every question, whatever was asked.
//
// Read per call rather than cached, for the same reason the persona is:
// editing the file and restarting is one step fewer than editing, rebuilding
// and restarting, and this is a file an operator is meant to be able to read
// and correct. It is small, it is on local disk, and it is read once per
// question, not once per round.
//
// A missing file is a supported state and is logged rather than fatal. What
// is lost is the model's ability to EXPLAIN the rules; the rules themselves
// are enforced in internal/interrogate and do not consult this file, so a
// host that never deployed it refuses exactly the same reads.
func (s *server) loadRolePolicy() string {
	b, err := os.ReadFile(filepath.Join(s.knowledge, rolePolicyFile))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[policy] %s unreadable: %v", rolePolicyFile, err)
		} else {
			log.Printf("[policy] %s is not deployed on this host; the role rules are still enforced, "+
				"the Advisor just cannot explain them", rolePolicyFile)
		}
		return ""
	}
	return string(b)
}

// captureEvidence writes the pre-change diagnostic snapshot.
//
// Deliberately NOT gated on a passkey. A passkey approval is for changing the
// validator; this reads server_info and writes the result to the Advisor's own
// state directory. Treating the two the same would train an operator that a
// passkey prompt means nothing much, which is the opposite of what it has to
// mean at the cutover.
func (s *server) captureEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	// The operator, as the dashboard's session names them. This route is
	// admin-gated at the proxy and writes into the Advisor's state directory,
	// so "not ceremony-gated" was never a reason for it to be unrecorded —
	// which it was, entirely, until now.
	var who struct {
		Operator string `json:"operator"`
		Role     string `json:"role"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&who)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, st, err := s.state(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	path := s.evidencePath()
	if err := st.CaptureEvidence(path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	ok, detail := st.EvidenceCaptured()
	if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
		l.AppendAs(ledger.KindEvidenceCaptured, "",
			"diagnostic snapshot captured",
			map[string]any{"path": path, "captured": ok, "detail": detail},
			sessionActor(who.Operator, who.Role))
	}
	// Cached checks would otherwise report the plan blocked for another ten
	// seconds after the thing blocking it was fixed.
	s.cacheReset()
	log.Printf("[evidence] captured %s", path)
	writeJSON(w, http.StatusOK, map[string]any{"captured": ok, "detail": detail, "path": path})
}

// GET /v1/validator-lookup?key=nH… — the network's view of one validator.
func (s *server) validatorLookup(_ http.ResponseWriter, r *http.Request) (any, int) {
	cfg, err := xrpl.LoadLookupConfig(filepath.Join(s.stateDir, "xrpl-lookup.json"))
	if err != nil || !cfg.Enabled || cfg.ValidatorEndpoint == "" {
		return map[string]any{"enabled": false,
			"error": "validator lookup is not enabled — set validator_endpoint in state/xrpl-lookup.json"}, http.StatusOK
	}
	key := r.URL.Query().Get("key")
	if !validatorKeyRe.MatchString(key) {
		return map[string]any{"error": "key must be a validator public key (nH…)"}, http.StatusBadRequest
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	v, err := xrpl.LookupValidator(ctx, s.client, cfg.ValidatorEndpoint, key)
	if err != nil {
		return map[string]any{"enabled": true, "error": err.Error()}, http.StatusOK
	}
	return map[string]any{"enabled": true, "status": v, "described": v.Describe()}, http.StatusOK
}

// validatorKeyRe matches a validator public key — nH followed by base58.
var validatorKeyRe = regexp.MustCompile(`\bnH[1-9A-HJ-NP-Za-km-z]{40,60}\b`)

// GET /v1/ledger-lookup?index=N — one ledger's public profile, through the
// operator's configured endpoint. Off by default; enabled is a decision.
func (s *server) ledgerLookup(_ http.ResponseWriter, r *http.Request) (any, int) {
	cfg, err := xrpl.LoadLookupConfig(filepath.Join(s.stateDir, "xrpl-lookup.json"))
	if err != nil || !cfg.Enabled {
		return map[string]any{"enabled": false,
			"error": "ledger lookup is not enabled on this host — create state/xrpl-lookup.json " +
				`with {"enabled":true,"endpoint":"https://xrplcluster.com"}`}, http.StatusOK
	}
	var idx int64
	fmt.Sscanf(r.URL.Query().Get("index"), "%d", &idx)
	if idx <= 0 {
		return map[string]any{"error": "index must be a positive ledger index"}, http.StatusBadRequest
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	sum, err := xrpl.Lookup(ctx, s.client, cfg.Endpoint, idx)
	if err != nil {
		return map[string]any{"enabled": true, "error": err.Error()}, http.StatusOK
	}
	return map[string]any{"enabled": true, "summary": sum, "described": sum.Describe()}, http.StatusOK
}

// runIndex lists every run transcript on disk with a summary parsed from its
// lines: attempts, when it last spoke, how the last attempt ended and how
// long it took. The files ARE the archive — nothing new is stored.
func (s *server) runIndex(w http.ResponseWriter) {
	dir := filepath.Join(s.stateDir, "runs")
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	type row struct {
		ID       string `json:"id"`
		Bytes    int64  `json:"bytes"`
		At       string `json:"at"` // last activity
		Attempts int    `json:"attempts"`
		Lines    int    `json:"lines"`
		Verdict  string `json:"verdict"` // done | halt | unconfirmed | none
		Seconds  int    `json:"seconds"` // duration of the last attempt, -1 unknown
	}
	rows := []row{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		lines, err := readRunLines(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		ro := row{ID: strings.TrimSuffix(e.Name(), ".ndjson"), Lines: len(lines), Verdict: "none", Seconds: -1}
		if fi, err := e.Info(); err == nil {
			ro.Bytes = fi.Size()
			ro.At = fi.ModTime().UTC().Format(time.RFC3339)
		}
		var lastStart, lastEnd time.Time
		for _, l := range lines {
			kind, _ := l["kind"].(string)
			at, _ := l["at"].(string)
			t, _ := time.Parse(time.RFC3339Nano, at)
			switch kind {
			case "start":
				ro.Attempts++
				lastStart, lastEnd = t, time.Time{}
				ro.Verdict = "none"
			case "done":
				ro.Verdict, lastEnd = "done", t
				// A done about a node operation that carries no proof was
				// never observed (#769): the lab's own transcript ends on
				// one, and so does every run finished before the verifier
				// existed. Nothing proves either way whether those came
				// back, so the archive calls them what they are, not
				// confirmed: never complete, and not a failure either.
				if _, proven := l["proof"].(map[string]any); !proven &&
					execute.InterruptingScope(runScope(ro.ID)) {
					ro.Verdict = "unconfirmed"
				}
			case "halt":
				ro.Verdict, lastEnd = "halt", t
			}
		}
		if !lastStart.IsZero() && !lastEnd.IsZero() {
			ro.Seconds = int(lastEnd.Sub(lastStart).Seconds())
		}
		rows = append(rows, ro)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].At > rows[j].At })
	writeJSON(w, http.StatusOK, map[string]any{"runs": rows})
}

// runScope is a run id's last segment: the stage or compound scope its
// transcript is filed under (execute.RunID).
func runScope(id string) string {
	if i := strings.LastIndex(id, "."); i >= 0 {
		return id[i+1:]
	}
	return id
}

// runFile returns one transcript, whole and parsed.
func (s *server) runFile(w http.ResponseWriter, id string) {
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad run id"})
		return
	}
	lines, err := readRunLines(filepath.Join(s.stateDir, "runs", id+".ndjson"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such run"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "lines": lines})
}

func readRunLines(path string) ([]map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 4<<20 {
		raw = raw[len(raw)-(4<<20):]
	}
	out := []map[string]any{}
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// ── run stream ────────────────────────────────────────────────────────
//
// GET /v1/runs/{id}/stream — server-sent events, tailing the run's NDJSON
// transcript by byte offset.
//
// The offset is the whole design. A client that reconnects sends its last
// offset back as Last-Event-ID and resumes exactly where it stopped, so the
// server holds no per-client state and a dropped connection or a page reload
// costs nothing. Borrowed from the operator's own developer console, which
// solved this already.
func (s *server) runStream(w http.ResponseWriter, r *http.Request) {
	// Transcripts name the plan, the node and every command that ran.
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/runs")
	rest = strings.TrimPrefix(rest, "/")
	// GET /v1/runs — the archive index: every transcript on disk, newest
	// first, with enough parsed out of each that a history view can be built
	// without fetching them all.
	if rest == "" {
		s.runIndex(w)
		return
	}
	// GET /v1/runs/{id} — one whole transcript, parsed. The static companion
	// to the stream: history browsing replays what happened, it does not tail.
	if !strings.HasSuffix(rest, "/stream") {
		s.runFile(w, rest)
		return
	}
	id := strings.TrimSuffix(rest, "/stream")
	// A run id reaches a filename. Anything that could climb out of the runs
	// directory is refused rather than cleaned.
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad run id"})
		return
	}
	path := filepath.Join(s.stateDir, "runs", id+".ndjson")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var offset int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	} else if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	// A negative offset is not a resume, it is an allocation request. The read
	// below sizes its buffer as size-offset, so `?offset=-2000000000` asks for
	// two gigabytes on a file of a few kilobytes, and the `size <= offset`
	// guard waves it through because every size is greater than a negative
	// number. Nothing legitimate produces one — every id this endpoint emits
	// is a byte count — so it means start from the beginning.
	if offset < 0 {
		offset = 0
	}
	// Every id this endpoint emits is a line boundary, so a well-behaved
	// resume lands on one. A hand-typed offset need not, and half a JSON line
	// is worse than a missing one — advance to the next newline instead.
	if offset > 0 {
		if f, err := os.Open(path); err == nil {
			b := make([]byte, 1)
			if _, err := f.ReadAt(b, offset-1); err == nil && b[0] != '\n' {
				buf := make([]byte, 64<<10)
				if n, _ := f.ReadAt(buf, offset); n > 0 {
					if i := strings.IndexByte(string(buf[:n]), '\n'); i >= 0 {
						offset += int64(i) + 1
					}
				}
			}
			f.Close()
		}
	}

	ctx := r.Context()
	// #116. This handler is an active request for as long as it loops, and
	// http.Server.Shutdown waits for active requests, so without this the
	// drain waits out its entire window on an idle browser tab. Counted for
	// the shutdown log, and released the moment the drain says so.
	defer s.streamStart()()
	stopping := s.streamStopC()
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	// A run that has produced nothing for this long is over, or was never
	// started. Holding the connection open forever would leak one per tab.
	idleLimit := 30 * time.Minute
	lastData := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopping:
			// The service is going down. Ending the stream is the whole
			// courtesy: the transcript is on disk, and the page reattaches
			// with a Last-Event-ID and picks up exactly where this stopped.
			return
		case <-tick.C:
		}

		fi, err := os.Stat(path)
		if err != nil || fi.Size() <= offset {
			if time.Since(lastData) > idleLimit {
				return
			}
			// A comment keeps the connection alive through proxies that would
			// otherwise time it out mid-run.
			fmt.Fprint(w, ": waiting\n\n")
			flusher.Flush()
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			return
		}
		buf := make([]byte, fi.Size()-offset)
		n, _ := f.ReadAt(buf, offset)
		f.Close()
		if n <= 0 {
			continue
		}
		chunk := string(buf[:n])
		// Only emit whole lines; a partial write is finished on the next tick.
		cut := strings.LastIndexByte(chunk, '\n')
		if cut < 0 {
			continue
		}
		for _, line := range strings.Split(chunk[:cut], "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			offset += int64(len(line)) + 1
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", offset, line)
		}
		flusher.Flush()
		lastData = time.Now()
	}
}

// liveApprovals reports which stages currently hold a valid approval.
//
// The approval already outlives the page — it is a file with an expiry — but
// the tab could not see it, so navigating away and back presented the code
// entry again for something already approved. State that survives on the
// server should be visible to the client that has to reflect it.
// liveApprovals reports which of a runbook's own stages already hold an
// approval. Concrete stages only: approval.Check falls back to a compound
// grant by itself, so one "upgrade" ceremony shows up as both prepare and
// cutover being live — which is what the tab reads.
func (s *server) liveApprovals(planID, fingerprint, node string, stages []string) map[string]any {
	out := map[string]any{}
	now := time.Now()
	for _, stage := range stages {
		a, err := approval.Check(filepath.Join(s.stateDir, "approvals"),
			planID, fingerprint, node, stage, now)
		if err != nil {
			continue
		}
		out[stage] = map[string]any{
			"granted_by": a.GrantedBy,
			"expires_at": a.ExpiresAt,
			"expires_in": int(a.ExpiresAt.Sub(now).Seconds()),
		}
	}
	return out
}

// ── execute ───────────────────────────────────────────────────────────
//
// Runs an approved stage. The operator asked what happens when they are on a
// phone and cannot reach a terminal, and that question settles it: Aperire is
// reached from a phone, so an Advisor that diagnoses from anywhere and then
// demands a laptop has not finished the job.
//
// Nothing in the security model changes. This spends an approval that was
// already verified twice — once by the dashboard performing the ceremony, once
// by the executor checking the assertion against credentials it holds itself —
// and it runs the same execute.Executor the CLI runs, with the same
// preconditions re-measured immediately before the interrupting step. What it
// removes is the requirement that a human relay the instruction by hand.
//
// The CLI stays. It is the independent path, and an operator who wants to read
// the command before it runs should keep being able to.

// normaliseWindowOpen reports whether a break-glass window is open for this
// node right now.
//
// Keyed on the identity key the window was opened under (#398), never on
// the name this process was started with: those two differ on a container
// host and the second is empty on a native one, and a window this lookup
// missed would refuse a change while the operator is looking at an
// open-window chip. An identity that cannot be read is NOT an open window:
// this fails closed, like every other gate in this service.
func (s *server) normaliseWindowOpen(ctx context.Context) bool {
	// No window store at all is no open window. Fails closed, like the
	// identity read below: a service that could not tell is a service that
	// does not edit somebody's deployment.
	if s.breakglass == nil {
		return false
	}
	node, err := s.nodeKey(ctx)
	if err != nil {
		log.Printf("[execute] no node identity, so no window can be found: %v", err)
		return false
	}
	_, open := s.breakglass.OpenForNode(node, time.Now())
	return open
}

type executeRequest struct {
	Stage  string `json:"stage"`
	Target string `json:"target"`
	// Runbook names which plan to run. Absent means the upgrade.
	Runbook string `json:"runbook"`
	// Intent is RB-002's bound parameter. It has to arrive here too: the
	// fingerprint is recomputed from the bound parameters, and an approval
	// granted for one intent must not be spendable on another.
	Intent string `json:"intent"`
	// Key and Value are RB-003's, and travel for the same reason.
	Key   string `json:"key"`
	Value string `json:"value"`
	// Change and User are RB-005's, Source is #682's build override, and
	// they travel for the same reason: the fingerprint is recomputed from
	// the bound parameters, so an approval granted for one change must not
	// be spendable on another.
	Change string `json:"change"`
	User   string `json:"user"`
	Source string `json:"source"`
	// Continue answers a step that could not be confirmed. A browser run has
	// nobody to ask mid-flight, so an inconclusive step halts and the operator
	// answers it as a separate, deliberate act rather than a dialog they
	// dismiss to get on with it.
	Continue bool `json:"continue"`
}

func (s *server) execute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	var req executeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	rb, err := lookupRunbook(req.Runbook)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	// Stages, not grant scopes. Nothing ever RUNS the compound "upgrade"
	// scope — it is a thing to sign over, not a thing to perform — and a
	// stage belonging to another runbook is refused here rather than
	// producing an empty run that reports success.
	if !stageIn(rb.Stages, req.Stage) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown stage"})
		return
	}
	// #682's fifth ruling, 2026-09-27: a change to a deployment somebody
	// else wrote happens inside an open break-glass window. The passkey and
	// the diff say WHAT is being changed and that the operator meant it;
	// the window is the separate thing, opened on the node's own side, that
	// says somebody is at the keyboard right now. RB-005 is the only
	// runbook that edits a file this project did not author, and it is the
	// only one gated here.
	//
	// The upgrade is deliberately not: it is the standing exception
	// (2026-08-19), and its own compose edit is the one line the Advisor
	// wrote in the first place.
	if rb.ID == normaliseRunbookID && !s.normaliseWindowOpen(r.Context()) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "a change to this node's deployment needs an open break-glass window",
			"detail": "Open one from the header (Break glass), then approve the change again. " +
				"The window is opened on this node and lasts fifteen minutes; nothing here can " +
				"open one for itself, which is the point.",
		})
		return
	}

	// One run at a time, per node. Two executors editing the same compose file
	// is not a race anyone should have to reason about afterwards.
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		writeJSON(w, http.StatusConflict,
			map[string]any{"error": "a run is already in progress on this node"})
		return
	}
	s.running = true
	s.runMu.Unlock()
	// runLog/runLabel are cleared with the flag, so a shutdown that arrives
	// after a run has finished never writes an abandonment line into a
	// transcript that already ended properly.
	release := func() {
		s.runMu.Lock()
		s.running, s.runLog, s.runLabel = false, nil, ""
		s.runMu.Unlock()
	}

	// Everything up to here is fast. Set the run up synchronously so a failure
	// to start is an error the caller sees, rather than something they have to
	// discover from an empty transcript.
	ctx := context.Background()
	_, node, st, err := s.stateKeyed(ctx)
	if err != nil {
		release()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	// The last door, and the one that matters most (#998): a rollback runs
	// only to the target this node derives, re-derived here rather than
	// trusted from the approval, before the compact, the grant or any
	// wrapper call that changes something.
	//
	// The same reading names the copy the plan binds (#1029, review): one
	// reading, so a read that fails is refused here as a read that failed,
	// never bound as an empty copy and reported as the node's answer moving.
	var cp restoreCopy
	if rb.ID == rollbackRunbookID {
		var refusal map[string]any
		if _, cp, refusal = s.rollbackTargetGateCopy(st, req.Target); refusal != nil {
			release()
			s.recordRollbackTargetRefusal(ledger.KindRefusal, "run", refusal, serviceActor("executor"))
			writeJSON(w, http.StatusBadRequest, refusal)
			return
		}
	}
	// node, not s.container: stateKeyed resolved the identity key one line
	// above, and every gate on the ask path is keyed on it. Loading against
	// the flag here is the one place where a run could be refused after the
	// ask path had already said the class was permitted, on a host where the
	// two names differ (#398, #466).
	acc, err := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	if err != nil {
		release()
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	// The class this runbook belongs to, not the upgrade's. An operator who
	// accepted the compact with --classes=upgrade has not permitted a
	// restart, and this is where that refusal happens.
	if !acc.Permits(rb.Class) {
		release()
		writeJSON(w, http.StatusForbidden,
			map[string]any{"error": "the compact does not permit the " + string(rb.Class) + " class"})
		return
	}
	// The copy a rollback restores, the one the gate above read off the host
	// (#1029). This door used to take it from the cache the plan left, which
	// had lapsed by the time a person finished the ceremony, so the run bound
	// no copy and evaluated a plan nobody approved.
	//
	// The upgrade's image source and digest are read the same way, off the
	// node for this request, never off the plan's five-minute shelf (#1033).
	in := planParams{
		Target: req.Target, Intent: req.Intent, Key: req.Key, Value: req.Value,
		Change: req.Change, User: req.User, Source: req.Source,
	}
	approvalsDir := filepath.Join(s.stateDir, "approvals")
	pinned, readErr := s.pinRunSource(st, rb, in)
	if readErr == nil {
		in = pinned
	}
	params, err := bindRequest(rb, withRestoreCopy(rb, in, cp))
	if err != nil {
		release()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	fp := approval.Fingerprint(rb.ID, node, params)
	planID := "plan-" + fp[:12]

	// A registry that did not answer. On such a host the card's own reader
	// fell back to a build, and that unpinned plan is what was approved:
	// it is bound above, and it runs when it is approved for this stage,
	// because a failed read shows nothing moved. Any other plan cannot be
	// bound without the read, so the run is refused as a read that failed,
	// never as the node's answer moving.
	if readErr != nil {
		if _, cerr := approval.Check(approvalsDir, planID, fp, node, req.Stage, time.Now()); cerr != nil {
			release()
			if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
				l.AppendAs(ledger.KindRefusal, "",
					"run refused: the image source could not be read, so the approved plan could not be bound",
					map[string]any{"door": "run", "reason": "source_unread", "runbook": rb.ID,
						"target": req.Target, "error": readErr.Error()}, serviceActor("executor"))
			}
			writeJSON(w, http.StatusServiceUnavailable,
				map[string]any{"error": readErr.Error(), "reason": "source_unread"})
			return
		}
		log.Printf("[execute] %v; running the approved build of %s, which needs no registry", readErr, req.Target)
	}

	// The plan this node derives now is not the one that was approved, but
	// another plan for the same act was (#1029). Said here, in those words,
	// before a transcript is opened or a precondition is evaluated: running
	// the checks against a plan nobody approved is how a walk read "nothing
	// to roll back to" over an approval for a rollback that had somewhere to
	// go. The approval is left standing; the operator asks again.
	//
	// The upgrade's twin (#1033): an approval for this same request, bound
	// to another image source or digest, is the registry's answer having
	// moved since the gate, and the refusal names both.
	if refusal := s.planMovedRefusal(approvalsDir, rb, node, planID, fp, req.Stage, params, in); refusal != nil {
		release()
		writeJSON(w, http.StatusConflict, refusal)
		return
	}

	// A grant another run holds (#1063): the command-line executor shares
	// no lock with this service, so its run is found by the claim on the
	// grant. Refused here, before a transcript is opened, because the two
	// runs would share one: a refusal written into it would read as the
	// end of the run that is still going.
	if c, held := approval.HeldBy(approvalsDir, planID, req.Stage, time.Now()); held {
		release()
		if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
			l.AppendAs(ledger.KindRefusal, planID,
				"run refused: the approval for this plan is held by another run",
				map[string]any{"door": "run", "reason": "approval_held", "stage": req.Stage,
					"held_by": c.Holder.Process, "held_since": c.Holder.At, "lapses_at": c.Lapses},
				serviceActor("executor"))
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": c.Error() + ". Nothing was done here", "reason": "approval_held",
			"lapses_at": c.Lapses})
		return
	}

	// An approval a run already used (#1074 review). A run that stopped
	// spent it, and says where; the retry is told that, rather than a bare
	// "not approved" from the executor after a transcript was opened.
	if _, cerr := approval.Check(approvalsDir, planID, fp, node, req.Stage, time.Now()); errors.Is(cerr, approval.ErrSpent) {
		release()
		writeJSON(w, http.StatusConflict, map[string]any{"error": cerr.Error(), "reason": "approval_spent"})
		return
	}

	// Which stage this run will CHAIN into under a compound grant, decided
	// before anything else, because two things below depend on it: which
	// baseline reading is required, and which transcript this run belongs to.
	//
	// It is re-checked after the first stage finishes rather than trusted from
	// here — an approval revoked or expired mid-run must not still chain — but
	// it has to be known now, because the reading a chained restart is
	// confirmed against can only be taken BEFORE the node is touched.
	covers := func(stage string) bool {
		_, cerr := approval.Check(approvalsDir, planID, fp, node, stage, time.Now())
		return cerr == nil
	}
	chaining := req.Stage == approval.StagePrepare && covers(approval.StageCutover)
	chainingRestart := req.Stage == approval.StageConfig && covers(approval.StageRestart)

	// The build the node reports RIGHT NOW, read before anything is touched.
	// A restart is confirmed against this and never against a parameter: if
	// the node comes back on a different version that is a finding, not a
	// slow sync. Read here, and refused here if it cannot be read, because a
	// restart whose confirmation is silently disabled is worse than one that
	// does not start (ADR 0016 §5).
	//
	// A config change that will chain into a restart needs it for the same
	// reason and at the same moment. Reading it after the edit would still be
	// before the restart, but it would also be after the only step that could
	// have changed what the node will come back as.
	// A rollback needs it too, and for a second reason: it is the version the
	// node is moving OFF, which the confirmation tolerates for a bounded
	// moment while the old container comes down. Without it every rollback
	// would halt on its first poll, reporting the version it was already
	// running as a finding.
	baseline := ""
	// RB-005 needs it for the same reason a restart does: the change
	// recreates the container, and the node has to be watched back on the
	// build it went down on (#682, review of 2026-09-27). Nothing about the
	// release moves here, so a different build afterwards is a finding.
	if req.Stage == approval.StageRestart || req.Stage == approval.StageRollback ||
		req.Stage == execute.StageNormalise || chainingRestart {
		baseline, err = st.RunningVersion()
		if err != nil || baseline == "" {
			release()
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "the node did not say what version it is running, so the restart could not be " +
					"confirmed afterwards; nothing was changed"})
			return
		}
	}

	// The change, measured from the node's own configuration, NOW.
	//
	// What the line count then pins is that the WRAPPER rewrote what this
	// reading found — not that either matches the diff the operator read at
	// the gate. Those are minutes apart, and nothing carries the gate's own
	// count forward. The residual is stated rather than hidden: a file that
	// gained a second assignment of the key in that window would be rewritten
	// twice against a one-line diff, and the check would pass. It is left
	// this way because the only writer of that file on this host is the
	// root-owned wrapper, and the record makes it visible afterwards — the
	// before and after lines below go into the run log and the ledger, beside
	// the ones action.proposed recorded at the gate, so the two can be
	// compared. Carrying the gate's count would mean storing it against the
	// plan, which is a second thing to keep in step with the fingerprint.
	// The copy a rollback would restore, as it reads now, against the digest
	// the approval covered (#682, third review). Said here rather than left
	// to an empty step list: a run that does nothing is not a refusal an
	// operator can read, and this one has a reason worth reading.
	if rb.ID == rollbackRunbookID && params["restore_digest"] != "" {
		im := st.RollbackImaging(params["target_version"], params["restore_path"])
		if _, cerr := execute.RollbackShapeChecked(
			params["target_version"], params["restore_digest"], im); cerr != nil {
			release()
			writeJSON(w, http.StatusConflict, map[string]any{"error": cerr.Error()})
			return
		}
	}
	steps := executorSteps(rb, params, req.Target, 0, st)
	var diff configDiff
	if rb.ID == configRunbookID {
		d, derr := configDiffFor(st, params["key"], params["value"])
		if derr != nil {
			release()
			writeJSON(w, http.StatusConflict, map[string]any{"error": derr.Error()})
			return
		}
		diff = d
		steps = executorSteps(rb, params, req.Target, len(diff.Before), st)
	}

	// An approval that will run out before this run reaches a step that
	// needs it (#772). Refused here, before the grant is claimed, so nothing
	// is spent and nothing on the host has moved. A merged run is held to
	// the restart at its end, never quietly turned into a prepare on its
	// own: running half of what the operator approved is the bug, not the
	// fallback.
	runStages := []string{req.Stage}
	if chaining {
		runStages = append(runStages, approval.StageCutover)
	}
	if chainingRestart {
		runStages = append(runStages, approval.StageRestart)
	}
	if serr := execute.ApprovalLasts(approvalsDir, planID, fp, node, runStages, steps, time.Now()); serr != nil {
		release()
		var short *execute.ShortApprovalError
		data := map[string]any{"error": serr.Error()}
		if errors.As(serr, &short) {
			data = short.Data()
		}
		data["door"] = "run"
		if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
			l.AppendAs(ledger.KindRefusal, planID,
				"run refused: the approval would run out before the run reached its last step that needs it",
				data, serviceActor("executor"))
		}
		resp := map[string]any{"error": serr.Error(), "reason": "approval_too_short"}
		if short != nil {
			resp["expires_in"] = int(short.Left.Seconds())
			resp["needs_seconds"] = int(short.Need.Seconds())
		}
		writeJSON(w, http.StatusConflict, resp)
		return
	}

	creds, err := host.LoadCredentials(filepath.Join(s.stateDir, "credentials.json"))
	if err != nil {
		release()
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	l, err := ledger.Open(filepath.Join(s.stateDir, "ledger.jsonl"))
	if err != nil {
		release()
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	// A compound StageUpgrade grant already covering cutover, seen here
	// before prepare has even run, is what tells this request it is about to
	// become a merged run — one ceremony, both stages, back to back. That
	// merged run gets its own transcript, filed under "upgrade" rather than
	// "prepare": a file named ".prepare.ndjson" that quietly grew cutover's
	// lines would misreport what it is to anyone reading the archive later,
	// including lastRun's own stage label.
	runID := execute.RunID(planID, req.Stage)
	if chaining {
		runID = execute.RunID(planID, approval.StageUpgrade)
	}
	// A merged config-and-restart run gets its own transcript under the
	// compound scope's name, for the reason the upgrade's does: a file called
	// ".config.ndjson" that quietly grew a restart's lines would misreport
	// what it is to anyone reading the archive later, lastRun's stage label
	// included.
	if chainingRestart {
		runID = execute.RunID(planID, approval.StageConfigRestart)
	}
	rl, err := execute.OpenRunLog(filepath.Join(s.stateDir, "runs"), runID)
	if err != nil {
		release()
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	ex := &execute.Executor{
		PlanID: planID, Runbook: rb, Params: params, Wrapper: s.wrapper,
		State: st, Ledger: l, Runner: s.runner, ClaimedBy: "aperire-advisord",
		ApprovalDir: filepath.Join(s.stateDir, "approvals"),
		DigestDir:   filepath.Join(s.stateDir, "digests"),
		Fingerprint: fp, Node: node,
		Verifier: creds, Log: rl,
		// The one wiring for every stage this handler can reach — issue #93.
		// The primary stage below, the upgrade's auto-chained cutover, and the
		// config change's auto-chained restart (finishConfigStage takes this
		// same executor) all run through RunStage, and RunStage is where the
		// refusal sits, ahead of the point the approval is spent.
		//
		// The --wait read, with no time limit (#1043, PR #1049 review): a
		// bounded read that ran out would answer "unknown" and fail open, and
		// the approval would be spent on a stop the wrapper then refuses.
		RotationInFlight: st.RotationInFlightWait,
	}

	// Preconditions before anything else, and refuse here rather than in the
	// background — a caller told "started" for a run that immediately refused
	// has been told the wrong thing.
	if verdicts, ok := ex.CheckPreconditions(req.Stage, "before "+req.Stage); !ok {
		// The reasons come from the reading that refused, not from a second
		// one: a live check measured again can pass, and the halt would
		// then carry no reason while the ledger row beside it names one.
		// One reading, so the ledger, the 409 and the transcript agree
		// (#1169).
		var failed []string
		for _, v := range verdicts {
			if !v.Passed {
				failed = append(failed, v.Name+" — "+v.Detail)
			}
		}
		rl.Refuse("preconditions refuse; nothing was done", failed)
		rl.Close()
		release()
		writeJSON(w, http.StatusConflict,
			map[string]any{"error": "preconditions refuse", "failures": failed})
		return
	}

	// Registered only now: every path above this line either refused the run
	// or closed the transcript itself, and a shutdown must not write an
	// abandonment line into a transcript that already said "halt".
	s.runMu.Lock()
	s.runLog, s.runLabel = rl, runID
	s.runMu.Unlock()

	// Counted before the goroutine, same reasoning as the gated asks: the
	// 202 this handler is about to write must never be observable while the
	// counter still reads zero.
	runDone := s.runStart()
	go func() {
		defer runDone()
		defer release()
		defer rl.Close()
		// The run is over whichever way it ended, and its grant with it
		// (#1063). Every stop below settles it before writing its line; this
		// is the one that catches a path that did not.
		defer ex.Finish()
		s.runApproved(approvedRun{ex: ex, rl: rl, req: req, rb: rb, params: params, diff: diff,
			steps: steps, approvalsDir: approvalsDir, planID: planID, fp: fp, node: node,
			baseline: baseline, st: st, chained: chaining || chainingRestart})
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"started": true, "plan_id": planID, "stage": req.Stage, "run_id": runID,
		"stream": "/v1/runs/" + runID + "/stream",
	})
}

// expectedAfter is the build a run means to leave the node on: the bound
// target for a run that moves the version, the build it was running for one
// that does not.
func expectedAfter(params runbook.Params, baseline string) string {
	if t := params["target_version"]; t != "" {
		return t
	}
	return baseline
}

// approvedRun is everything an approved run needs once /v1/execute has set it
// up: the executor, the transcript, and the bound plan it was checked against.
type approvedRun struct {
	ex           *execute.Executor
	rl           *execute.RunLog
	req          executeRequest
	rb           runbook.Runbook
	params       runbook.Params
	diff         configDiff
	steps        []execute.Step
	approvalsDir string
	planID       string
	fp           string
	node         string
	baseline     string
	st           *host.State
	// chained is a merged run: one compound grant covering the reversible
	// stage and the restart after it, filed under the compound scope.
	chained bool
}

// runApproved is the body of an approved run, from its first step to its
// single terminal line. Lifted out of /v1/execute's goroutine so the
// decision about how a run ENDS can be driven by a test (#769).
func (s *server) runApproved(p approvedRun) {
	ex, rl, req, rb, params, diff, steps := p.ex, p.rl, p.req, p.rb, p.params, p.diff, p.steps
	approvalsDir, planID, fp, node, baseline, st := p.approvalsDir, p.planID, p.fp, p.node, p.baseline, p.st
	confirm := func(step execute.Step, out string) bool {
		if req.Continue {
			rl.Printf("note", step.Name,
				"could not be confirmed; continuing because the operator said so")
			return true
		}
		rl.Printf("halt", step.Name,
			"could not be confirmed — the wrapper said %q. This is not proof it is "+
				"wrong. Approve again with 'continue' to proceed, or investigate first.", out)
		return false
	}

	// The change, in the record, before it happens. The run log is what
	// someone watching reads; the ledger entry below is what an auditor
	// reads a year later, and neither should have to be reconstructed
	// from the wrapper's own output.
	if rb.ID == configRunbookID {
		rl.Printf("note", "", "%s on %s", diff.File, diff.Host)
		if diff.Stanza != "" {
			// The section a stanza-shaped setting sits under. Without it
			// the record reads "- medium / + large" and an auditor a year
			// later cannot tell which setting that was — the same reason
			// the wrapper reports "was: [node_size] medium" rather than
			// "was: medium".
			rl.Printf("out", "", "  [%s]", diff.Stanza)
		}
		for _, ln := range diff.Before {
			rl.Printf("out", "", "- %s", ln)
		}
		for _, ln := range diff.After {
			rl.Printf("out", "", "+ %s", ln)
		}
	}

	if err := ex.RunStage(context.Background(), req.Stage, steps, confirm); err != nil {
		// With what the run had staged and the node's reading as it
		// stopped: the page says the node's condition from these, never
		// from which steps happen to be in the transcript (#769).
		endStage(ex, rl, err, expectedAfter(params, baseline))
		return
	}

	// What happens after the steps depends on which stage just ran, and
	// it is a switch rather than one early return plus an assumption:
	// everything below the old `if cutover` return treated the remainder
	// as prepare, so a restart would have fallen through into the
	// compound-approval handoff and been asked to chain into a cutover
	// its runbook does not have.
	switch req.Stage {
	case approval.StageRestart:
		awaitRestartHealthy(ex, rl, baseline)
		return
	case approval.StageCutover:
		// The BOUND target, never the request field beside it: what the
		// fingerprint was computed over is what was approved.
		awaitCutoverHealthy(ex, rl, params["target_version"])
		return
	case execute.StageNormalise:
		// RB-005 recreates the container, so the node goes off the
		// network and has to be watched back on (#682, review of
		// 2026-09-27). Without this case the stage fell through to the
		// compound-approval handoff below and the transcript ended
		// "stage prepare complete" over a deployment change that had
		// just taken a validator down: the lab's own screenshot shows
		// it. The release does not move here, so the reading it is
		// confirmed against is the build it went down on.
		awaitNormaliseHealthy(ex, rl, baseline)
		return
	case approval.StageRollback:
		// The target from the BOUND parameters, never from the request
		// field beside them: what the fingerprint was computed over is
		// what was approved.
		awaitRollbackHealthy(ex, rl, params["target_version"], baseline, s.wrapper,
			rollbackExpectation(s.offlineExpectation()))
		return
	case approval.StageConfig:
		s.finishConfigStage(ex, rl, req, rb, params, diff, steps, confirm,
			approvalsDir, planID, fp, node, baseline, st, p.chained)
		return
	}

	// req.Stage is prepare. Re-checked NOW, not reused from before prepare
	// ran: a compound approval revoked — or one that simply expired while
	// a slow pull was in flight — must not be treated as still covering
	// the restart it was granted alongside. Attempting RunStage(cutover)
	// against a gone approval would also be caught, but as a bare "no
	// approval" halt with no explanation of why prepare's own work still
	// stands — the honesty this handoff owes the operator.
	if _, cerr := approval.Check(approvalsDir, planID, fp, node,
		approval.StageCutover, time.Now()); cerr != nil {
		// A prepare run on its own ends here, and prepare finishing is what
		// it was for. A MERGED run does not: its transcript is filed under
		// "upgrade", the operator approved the whole upgrade, and a done
		// here was read as the whole upgrade having finished, "back in full
		// sync", over a node nobody touched (#769). It stopped before the
		// restart and says so.
		unspent := settled(ex)
		target := params["target_version"]
		reading := ex.Reading(target)
		if p.chained {
			stopBeforeRestart(ex, "the restart", cerr, reading, upgradeLeftAs(ex, reading, target)+
				" Approve the upgrade again to finish it."+unspent)
			return
		}
		rl.StageDone(reading, "stage prepare complete"+unspent)
		return
	}

	// A package install can restart the node itself (#415). When it did,
	// onto the target, the upgrade has already happened: the cutover's own
	// restart would only take a node that is catching up down again, and
	// its consensus re-measure would refuse it and stop the run over an
	// upgrade that had in fact landed. So that restart is adopted: the
	// grant is spent, as the cutover would have spent it, and the node is
	// watched back through the same verifier, judged against the moment
	// the package install began (#769).
	//
	// The grant is spent BEFORE the restart is adopted, and a spend that
	// failed stops the run here (#781). It used to be ignored: the grant
	// stayed live and could have paid for a second restart of a node that
	// had just come back.
	if pr, restarted := ex.PrepareRestarted(params["target_version"]); restarted {
		if err := spendAdopted(approvalsDir, planID); err != nil {
			refuseUnspentAdoption(ex, rl, pr, err)
			return
		}
		ex.AdoptPrepareRestart(pr)
		if pr.State() == execute.WrongVersion {
			rl.Halt(pr, "the package install restarted the node itself, onto "+pr.Version()+
				", not the "+params["target_version"]+" this upgrade approved. The run's own restart "+
				"did not run. Check the node before approving anything else")
			return
		}
		rl.Write("handoff", "", "prepare complete — the package install already restarted the node "+
			"onto "+pr.Version()+", so the restart step is not needed; watching it back")
		awaitCutoverHealthy(ex, rl, params["target_version"])
		return
	}

	rl.Write("handoff", "", "prepare complete — one approval covers the restart too; "+
		"continuing automatically")

	// Preconditions gating the interrupting stage, re-measured exactly
	// where the package doc promises: immediately before it, never
	// inferred from what passed at approval time. RunStage's own
	// Interrupts block re-measures consensus and the deployment tag a
	// second time, closer still to the moment it acts.
	if verdicts, ok := ex.CheckPreconditions(approval.StageCutover, "before cutover (auto-chained)"); !ok {
		// The reading that refused, not a second one: a check measured
		// again can pass or read differently, and the stop would then
		// disagree with the ledger row beside it (#1169).
		var failed []string
		for _, v := range verdicts {
			if !v.Passed {
				failed = append(failed, v.Name+" — "+v.Detail)
			}
		}
		unspent := settled(ex)
		reading := ex.Reading(params["target_version"])
		ex.StopBeforeApply("stopped before the restart: its preconditions refused ("+
			strings.Join(failed, "; ")+"), so the restart did not run. "+
			upgradeLeftAs(ex, reading, params["target_version"])+" A fresh approval will try again."+unspent,
			reading, map[string]any{"stage": approval.StageCutover, "failed": failed})
		return
	}

	if err := ex.RunStage(context.Background(), approval.StageCutover, steps, confirm); err != nil {
		endStage(ex, rl, err, params["target_version"])
		return
	}
	awaitCutoverHealthy(ex, rl, params["target_version"])
}

// settled spends whatever the run still holds, before a stop between the
// stages of a merged run is written (#1063), and gives the sentence that
// stop has to carry when the grant could not be spent and is still live
// (#1061). Empty when it went as designed.
func settled(ex *execute.Executor) string {
	err := ex.Finish()
	if err == nil {
		return ""
	}
	msg := err.Error()
	return " " + strings.ToUpper(msg[:1]) + msg[1:] + "."
}

// withPlanImage records on a grant what the plan's image was bound to, so a
// run that finds the node's answer moved can name what was approved
// (#1033). Empty for every runbook that declares no source.
func withPlanImage(a approval.Approval, params runbook.Params) approval.Approval {
	a.Source, a.Digest = params["source"], params["digest"]
	return a
}

// spendGrant is approval.Spend, a variable so a test can make the spend
// fail the way a directory the service cannot write does.
var spendGrant = approval.Spend

// spendAdopted spends every scope the cutover of an upgrade can be paid
// from, the compound grant and a cutover granted on its own, and answers
// with every spend that did not go as designed.
func spendAdopted(dir, planID string) error {
	var errs []error
	for _, scope := range []string{approval.StageUpgrade, approval.StageCutover} {
		if err := spendGrant(dir, planID, scope); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// refuseUnspentAdoption ends a run whose package install restarted the node
// and whose grant could not then be spent (#781). Refused, recorded and
// said with the node's reading, before the restart is taken as this run's.
// The node was restarted by the package, not by this run, and nothing here
// watches it further: a run that cannot retire its own approval does not go
// on acting as if it had.
func refuseUnspentAdoption(ex *execute.Executor, rl *execute.RunLog, pr *execute.Proof, cause error) {
	// Whether it still authorises a restart is read off the grant, never
	// off the wording of the error.
	live := ""
	switch a, err := approval.Check(ex.ApprovalDir, ex.PlanID, ex.Fingerprint, ex.Node,
		approval.StageCutover, time.Now()); {
	case err == nil:
		live = " It could not be voided either, so it stays live until " +
			a.ExpiresAt.UTC().Format("15:04 MST") + ": do not run another restart of this node before then."
	case errors.Is(err, approval.ErrSpent):
		live = " It was voided in place instead, so it authorises nothing more."
	}
	ex.Ledger.AppendAs(ledger.KindRefusal, ex.PlanID,
		"executor refused: the approval could not be spent, so the package install's restart was not adopted",
		map[string]any{"stage": approval.StageCutover, "reason": "spend_failed", "error": cause.Error(),
			"reading": pr.Wire()}, ex.Actor)
	rl.Halt(pr, "stopped: the package install restarted the node itself, onto "+pr.Version()+
		", and the approval for this upgrade could not be spent."+live+
		" Check the node's version and sync state on Overview")
}

// upgradeLeftAs says what an upgrade that stopped before its restart left
// behind: from the node's own reading taken as it stopped (#769), and from
// what the run's steps staged. Nothing here is assumed. A package install
// restarts the node on some platforms (#415), so "not restarted" is said
// only when the reading shows the process from before the run.
func upgradeLeftAs(ex *execute.Executor, p *execute.Proof, target string) string {
	switch p.State() {
	case execute.NotRestarted:
		switch v, how := ex.Staged(); how {
		case "deployment":
			return "Your node was not restarted: it reports " + p.Version() + " from the process " +
				"that was running before this run began, read just now. This run already pointed its " +
				"deployment at " + v + ", so the next restart of the node, by anyone, starts " + v +
				". To back out instead, restore the dated copy of the deployment named above before " +
				"anything restarts the node."
		case "package":
			return "Your node was not restarted: it reports " + p.Version() + " from the process " +
				"that was running before this run began, read just now. This run already installed " +
				"the " + v + " package, so the next restart of the node, by anyone, starts " + v + "."
		}
		return "Your node is untouched: it reports " + p.Version() + " from the process that was " +
			"running before this run began, read just now. Prepare's work stands (backups taken, " +
			"the new image fetched and checked)."
	case execute.CatchingUp, execute.Verified:
		return "The package install already restarted your node onto " + p.Version() + ", and it " +
			"reports " + p.ServerState() + ". This run did not restart it and is not watching it further; " +
			"its sync state is on Overview."
	case execute.WrongVersion:
		return "Your node restarted during this run and now reports " + p.Version() + ", not the " +
			target + " this upgrade targets. This run did not restart it. Check the node before " +
			"approving anything else."
	}
	return "The node did not give a reading as the run stopped (" + p.ReadError() + "), so its " +
		"state is not known from here. Check its version and sync state on Overview before " +
		"approving anything else."
}

// stopBeforeRestart ends a merged run whose grant stopped covering its
// restart between the two stages (#769). Said from the grant check's own
// error, because "it ran out" and "you withdrew it" are different facts and
// only one of them is the operator's doing. No way back is printed: the
// reversible stage's copies exist, but the node was never changed, and a
// restore-and-recreate offered here would be an instruction to restart a
// node for nothing.
func stopBeforeRestart(ex *execute.Executor, what string, cause error, reading *execute.Proof, leftAs string) {
	ex.StopBeforeApply("stopped: "+approvalLapseWhy(cause, what)+", so "+what+" did not run. "+leftAs,
		reading, map[string]any{"cause": cause.Error()})
}

// approvalLapseWhy says why an approval stopped covering what came next,
// from the grant check's own error.
func approvalLapseWhy(cause error, what string) string {
	switch {
	case errors.Is(cause, approval.ErrExpired):
		return "the approval expired before " + what
	case errors.Is(cause, approval.ErrNone):
		return "the approval was withdrawn before " + what
	}
	return "the approval no longer covers " + what + " (" + cause.Error() + ")"
}

// endStage writes the terminal line of a stage RunStage refused or failed.
//
// A stage whose approval lapsed before a step that changes the host stopped
// BEFORE that step (#1047). That is said as a stop, with the node's reading,
// the way a merged run whose grant lapsed between its stages is, whenever
// there is an honest sentence for what the run left behind. Where there is
// not, because an earlier step changed the deployment in a way the run does
// not track as staged, it is a halt with the way back like any other
// refusal. Everything else is the halt it always was.
func endStage(ex *execute.Executor, rl *execute.RunLog, err error, expected string) {
	var lapse *execute.ConsentLapsedError
	if errors.As(err, &lapse) {
		reading := ex.Reading(expected)
		if left, ok := lapseLeftAs(ex, reading, expected); ok {
			what := "the step \"" + lapse.Step + "\""
			back := ""
			if lapse.Restored != "" {
				back = "This stage had already changed the deployment, so the copy taken before that change (" +
					lapse.Restored + ") was put back over it. Nothing was recreated. "
			} else if lapse.RestoreErr != nil {
				back = "This stage had already changed the deployment, and putting it back failed (" +
					lapse.RestoreErr.Error() + "). "
			}
			ex.StopBeforeApply("stopped: "+approvalLapseWhy(lapse.Cause, what)+
				", so it and every step after it did not run. "+back+left,
				reading, map[string]any{"cause": lapse.Cause.Error(), "stage": lapse.Stage, "step": lapse.Step,
					"restored": lapse.Restored})
			return
		}
	}
	ex.HaltWithReading(err.Error(), expected)
	if h := ex.RollbackHint(); h != "" {
		rl.Write("out", "", "rollback:\n"+h)
	}
}

// lapseLeftAs says what a run stopped by a lapsed approval left behind, and
// whether it can say so honestly. Untouched only when no step that changes
// the deployment began and the node's own reading is the process from
// before the run. A staged release is said the way an upgrade stopped
// before its restart says it.
func lapseLeftAs(ex *execute.Executor, p *execute.Proof, expected string) (string, bool) {
	if p == nil {
		return "", false
	}
	v, how := ex.Staged()
	switch {
	case how == "package" && p.State() == execute.NotRestarted:
		// Said plainly, with the way back (#1047, review): the package is
		// installed under a process still running the old one, and the
		// next restart by anyone starts it.
		back := " To stay on " + p.Version() + " instead, reinstall it before anything restarts the node"
		if k := ex.Kept(); k != "" {
			back += ": the copy this run kept is " + k + ", and as root that is `" + ex.Wrapper +
				" package-install --from " + k + "`."
		} else {
			back += "."
		}
		return "Your node was not restarted: it reports " + p.Version() + " from the process that was " +
			"running before this run began, read just now. This run already installed the " + v +
			" package, so the next restart of the node, by anyone, starts " + v + "." + back +
			" Or approve the run again to finish it.", true
	case how != "":
		return upgradeLeftAs(ex, p, expected), true
	case !ex.Touched() && p.State() == execute.NotRestarted:
		return "Your node is untouched: it reports " + p.Version() + " from the process that was " +
			"running before this run began, read just now, and nothing this run did changes what it " +
			"starts on next.", true
	}
	return "", false
}

// awaitCutoverHealthy waits for the node to prove the upgrade and writes the
// verdict. Shared by an explicit cutover request and the automatic hand-off
// that follows a compound approval's prepare stage — same wait, same verdict
// lines, whichever led here. Every verdict line is written from the
// verifier's proof (#769): "done" only from a Verified reading, "pending"
// only from a process that restarted onto the target.
func awaitCutoverHealthy(ex *execute.Executor, rl *execute.RunLog, target string) {
	rl.Write("step", "", "waiting for the node to report "+target+" and return to full sync")
	// Fifteen minutes, not five. A recreate leaves the node to catch up from
	// its store, and a real one here took about six — so the window that was
	// supposed to confirm the upgrade was instead the thing that reported it
	// failed.
	p, err := ex.AwaitHealthy(target, 15*time.Minute, func(v, detail string) {
		rl.Printf("out", "", "version=%s  %s", v, detail)
	})
	switch {
	case err == nil:
		rl.Complete(p, execute.SyncedLine(execute.OpUpgrade, p, false))
	case errors.Is(err, execute.ErrNotYetHealthy):
		// The restart worked, and was seen: a process newer than the restart
		// step reports the target. Saying "halt" here sends an operator to
		// a rollback of a node that is only still syncing.
		rl.Pending(p, execute.CatchingUpLine(execute.OpUpgrade, p))
		rl.Write("out", "", "Nothing has gone wrong that is known. A node that has been "+
			"restarted catches up from its own store, and how long that takes depends on "+
			"how far behind it is. Watch the state on Overview: it moves through connected "+
			"to full. If it is still not full in half an hour, that is worth looking into — "+
			"and the way back is:\n"+ex.RollbackHint())
		// The window closing is not the node failing, and the record should
		// not end on the clock. Keep watching, quietly, for up to two hours:
		// the transcript's node readings stay current (the card's state word
		// is read from them), and the moment the node proves it is back the
		// ledger gets run.confirmed_late and the transcript its done line. A
		// node that never makes it leaves the unconfirmed entry standing,
		// which is still the truth.
		closedAt := time.Now()
		rl.Write("note", "", "still watching: readings continue below and the run is confirmed the moment the node reports full sync on "+target)
		if lp, ok := ex.AwaitHealthyLate(target, 2*time.Hour, closedAt, func(v, detail string) {
			rl.Printf("out", "", "version=%s  %s", v, detail)
		}); ok {
			rl.Complete(lp, execute.SyncedLine(execute.OpUpgrade, lp, true))
		}
	default:
		rl.Halt(p, err.Error())
		rl.Write("out", "", "the way back is:\n"+ex.RollbackHint())
	}
}

// awaitRestartHealthy waits for the node to come back on the build it was
// already running, and writes the verdict — to the transcript for whoever is
// watching, and to the ledger as the record. Beside awaitCutoverHealthy,
// with the same fifteen-minute window and the same two-hour late watch
// afterwards; the ledger kinds are the same ones a cutover uses, because
// what is being recorded is the same fact.
func awaitRestartHealthy(ex *execute.Executor, rl *execute.RunLog, expected string) {
	rl.Write("step", "", "waiting for the node to come back on "+expected+" and return to full sync")
	// The measured expectation, from the resync lab — and deliberately NOT
	// the upgrade gate's "about 30 seconds offline", which describes the
	// container coming back rather than the node rejoining consensus.
	rl.Write("out", "", "Measured on a node of this class: "+restartExpectation+
		", most of it spent in connected while it catches up from its own store.")

	verdict, found, p := ex.AwaitRestart(expected, 15*time.Minute, func(v, d string) {
		rl.Printf("out", "", "version=%s  %s", v, d)
	})

	switch verdict {
	case execute.RestartBack:
		rl.Complete(p, execute.SyncedLine(execute.OpRestart, p, false))
	case execute.RestartVersionChanged:
		rl.Halt(p, execute.RestartVersionChangedNote(expected, found))
	case execute.RestartNotObserved:
		rl.Halt(p, execute.NotRestartedNote(p))
	case execute.RestartStillCatchingUp:
		rl.Pending(p, execute.CatchingUpLine(execute.OpRestart, p))
		rl.Write("out", "", "Nothing has gone wrong that is known. A restarted node catches up from "+
			"its own store, and "+restartExpectation+" is what that measured. Watch the state on "+
			"Overview: it moves through connected to full. Nothing was changed by this run, so "+
			"there is nothing to roll back — if it is still not full in half an hour, the node's "+
			"own logs are the way forward, not a second restart.")
		closedAt := time.Now()
		rl.Write("note", "", "still watching: readings continue below and the run is confirmed the moment the node reports full sync on "+expected)
		if lp, ok := ex.AwaitHealthyLate(expected, 2*time.Hour, closedAt, func(v, d string) {
			rl.Printf("out", "", "version=%s  %s", v, d)
		}); ok {
			rl.Complete(lp, execute.SyncedLine(execute.OpRestart, lp, true))
		}
	}
}

// awaitNormaliseHealthy is awaitRestartHealthy's twin for a deployment
// change (RB-005, ADR 0023). Same reading, different words: nothing about
// the release moved, so a node that came back on another build did not
// come back from this change, and the copy taken before the edit is what
// puts it right.
func awaitNormaliseHealthy(ex *execute.Executor, rl *execute.RunLog, expected string) {
	rl.Write("step", "", "waiting for the node to come back on "+expected+
		" and return to full sync after the deployment change")
	rl.Write("out", "", "Measured on a node of this class: "+restartExpectation+
		". The release did not change here, so this is the same node coming back on the same build.")

	verdict, found, p := ex.AwaitRestart(expected, 15*time.Minute, func(v, d string) {
		rl.Printf("out", "", "version=%s  %s", v, d)
	})

	switch verdict {
	case execute.RestartBack:
		rl.Complete(p, execute.SyncedLine(execute.OpNormalise, p, false))
	case execute.RestartVersionChanged:
		// A changed build after a change that touches no image means the
		// node came back on something nobody asked for. Halted, with the
		// way back named: the wrapper took a dated copy before it wrote.
		rl.Halt(p, "this change moved no image, and the node came back on "+found+
			" rather than "+expected+". Restore the dated copy this run printed and recreate")
	case execute.RestartNotObserved:
		rl.Halt(p, execute.NotRestartedNote(p))
	case execute.RestartStillCatchingUp:
		rl.Pending(p, execute.CatchingUpLine(execute.OpNormalise, p))
		rl.Write("out", "", "A recreated node catches up from its own store, and "+restartExpectation+
			" is what that measured. If it is still not full in half an hour, restore the dated copy "+
			"this run printed and recreate: nothing else on this node changed.")
		closedAt := time.Now()
		rl.Write("note", "", "still watching: readings continue below and the run is confirmed the moment the node reports full sync on "+expected)
		if lp, ok := ex.AwaitHealthyLate(expected, 2*time.Hour, closedAt, func(v, d string) {
			rl.Printf("out", "", "version=%s  %s", v, d)
		}); ok {
			rl.Complete(lp, execute.SyncedLine(execute.OpNormalise, lp, true))
		}
	}
}

// lastRun reports which stage most recently wrote a transcript, so a page
// loading fresh knows what to show rather than inferring it.
//
// It walks the runbook's GRANT SCOPES, not its stages: the one-approval
// path's merged transcript is filed under the compound "upgrade" name
// specifically so a file named ".prepare.ndjson" never carries lines from a
// restart it did not perform — see the execute handler's runID choice.
// Newest wins either way, exactly as it always has.
func (s *server) lastRun(planID string, scopes []string) map[string]any {
	var best string
	var bestAt time.Time
	for _, stage := range scopes {
		p := filepath.Join(s.stateDir, "runs", execute.RunID(planID, stage)+".ndjson")
		fi, err := os.Stat(p)
		if err != nil || fi.Size() == 0 {
			continue
		}
		if fi.ModTime().After(bestAt) {
			bestAt, best = fi.ModTime(), stage
		}
	}
	if best == "" {
		return nil
	}
	return map[string]any{
		"stage":   best,
		"at":      bestAt.UTC(),
		"age_sec": int(time.Since(bestAt).Seconds()),
		"run_id":  execute.RunID(planID, best),
	}
}

// trustBundle accepts a signed credential bundle from the aggregator —
// ADR 0014 decision 4. Two gates, both required: the service token (as every
// advisord write) and the bundle's Ed25519 signature against the aggregator
// public key this node holds in fleet-trust.yaml under peers.<issuer_label>.
// On first accept it PINS rp_id+origins; every later bundle that changes
// them is refused. The credential set is replaced (that is how revocation
// propagates), and every accept writes a ledger entry so a credential cannot
// appear in the store without a record on the node's own hash chain.
func (s *server) trustBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	var req struct {
		Bundle    host.Bundle `json:"bundle"`
		Signature string      `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	if req.Bundle.IssuerLabel == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bundle carries no issuer_label"})
		return
	}

	// The aggregator's public key, by the label the bundle declares. A bundle
	// claiming an issuer this node does not trust fails closed here.
	aggKey, err := host.AggregatorPubKey(s.fleetTrust, req.Bundle.IssuerLabel)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	if err := req.Bundle.VerifySignature(req.Signature, aggKey); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	// A bundle dated past this node's clock is refused by name (#990): the
	// age check below trusts issued_at, and one such bundle would make every
	// later push look older, a revoke's included.
	if future, ahead := bundleIssuedInFuture(&req.Bundle, time.Now()); future {
		log.Printf("[trust] bundle from %q refused: issued_at %s is %s past this node's clock",
			req.Bundle.IssuerLabel, req.Bundle.IssuedAt, ahead.Round(time.Second))
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("bundle issued_at %s is %s past this node's clock, more than the %s allowed; "+
				"check the clocks on the aggregator and this node, then push again",
				req.Bundle.IssuedAt, ahead.Round(time.Second), maxBundleFutureSkew),
			"refusal":      "issued_in_future",
			"skew_seconds": int(ahead.Seconds()),
		})
		return
	}

	// The pin. nil => first install (records the binding); a change to a
	// pinned binding is refused with the ADR's own wording.
	bindingPath := filepath.Join(s.stateDir, "trust-binding.json")
	pinned, err := host.LoadBinding(bindingPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "cannot read the pinned binding: " + err.Error()})
		return
	}
	// The pairing this bundle is accepted under (#991), read only when it can
	// matter: a record for another trust key, or one this cannot read safely,
	// is none.
	paired, perr := loadFleetPairedRecord(s.fleetPairedPath())
	if perr != nil {
		log.Printf("[trust] the pairing record is not used: %v", perr)
		paired = nil
	}
	paired = pairedUnder(paired, aggKey)
	record, err := req.Bundle.CheckBinding(pinned)
	var resetFrom *host.Binding
	if err != nil {
		// #991: a re-pairing the operator approved resets the pin, once. A
		// bundle on its own never does.
		if !rePairingResets(pinned, paired) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		// #991 review, L1: the record covers a bundle for that pairing only.
		if why := rePairingBundleRefusal(paired, &req.Bundle); why != "" {
			log.Printf("[trust] the re-pairing of %s does not cover this bundle: %s", paired.PairedAt, why)
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   err.Error() + ". This node was paired again, but not for this bundle: " + why,
				"refusal": "not_this_pairing",
			})
			return
		}
		record, err = req.Bundle.CheckBinding(nil)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		resetFrom = pinned
		log.Printf("[trust] the re-pairing of %s resets this node's binding: rp_id %q becomes %q",
			paired.PairedAt, pinned.RPID, record.RPID)
	}
	// What is saved: the pin, and the pairing it is now held under. A copy,
	// so the pinned value read above is never changed in place.
	saved := *record
	if paired != nil {
		saved.PairedUnder = paired.Pairing
	} else if pinned != nil && resetFrom == nil {
		saved.PairedUnder = pinned.PairedUnder
	}
	record = &saved

	// Diff against the current store for the ledger summary (counts only,
	// never keys).
	credPath := filepath.Join(s.stateDir, "credentials.json")
	prev, _ := host.LoadCredentials(credPath)

	// The order (#987 review, L4): a bundle older than the one this node
	// installed is not installed, and the answer says the node already holds
	// a newer list. ok, because nothing failed: the pusher's list was
	// overtaken, not refused. A receipt that cannot be read is no receipt,
	// which is how this node behaved before it kept one.
	held, herr := loadTrustBundleReceipt(s.acceptedBundlePath())
	if herr != nil {
		log.Printf("[trust] the last bundle's receipt could not be read, so its age is not compared: %v", herr)
		held = nil
	}
	// #991: a re-pairing skips the issuer comparison, and only that. The
	// receipt still orders the bundle (#991 review, L1): dropping it let a
	// list signed before a revoke become the pin. The receipt written below
	// replaces it.
	if resetFrom == nil && heldIssuerDiffers(held, &req.Bundle) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("bundle issuer %q is unknown here: this node's last bundle came from %q, and it "+
				"does not order bundles across issuers", req.Bundle.IssuerLabel, held.Issuer),
			"refusal": "unknown_issuer",
		})
		return
	}
	if bundleOlderThanHeld(held, &req.Bundle, time.Now()) {
		trusted, rpID := 0, ""
		if prev != nil {
			trusted, rpID = len(prev.Credentials), prev.RPID
		}
		log.Printf("[trust] bundle from %q issued %s not installed: this node holds one issued %s",
			req.Bundle.IssuerLabel, req.Bundle.IssuedAt, held.IssuedAt)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"superseded":     true,
			"issued_at":      req.Bundle.IssuedAt,
			"held_issued_at": held.IssuedAt,
			// What decides whether the pusher may call this ok: the serial is
			// the digest of the admin credentials, so a held serial equal to
			// the pushed one is the same set, and anything else is not.
			"held_serial":   held.Serial,
			"first_install": false,
			"added":         0,
			"removed":       0,
			"trusted":       trusted,
			"rp_id":         rpID,
		})
		return
	}
	prevIDs := map[string]bool{}
	if prev != nil {
		for _, c := range prev.Credentials {
			prevIDs[c.ID] = true
		}
	}
	newStore := req.Bundle.ToStore()
	newIDs := map[string]bool{}
	added := 0
	for _, c := range newStore.Credentials {
		newIDs[c.ID] = true
		if !prevIDs[c.ID] {
			added++
		}
	}
	removed := 0
	for id := range prevIDs {
		if !newIDs[id] {
			removed++
		}
	}

	if err := host.SaveCredentials(credPath, newStore); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "cannot write the credential store: " + err.Error()})
		return
	}
	if err := host.SaveBinding(bindingPath, record); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "cannot write the pinned binding: " + err.Error()})
		return
	}
	// The receipt: which issuer's bundle, which serial, applied when. Written
	// after the store, so a failure to persist it can never claim a bundle
	// that was not installed. A failure to write it is logged and not fatal —
	// the credentials ARE in place at this point, and refusing the push after
	// applying it would report the opposite of what happened.
	if err := saveTrustBundleReceipt(s.acceptedBundlePath(), &trustBundleReceipt{
		Serial:     req.Bundle.Serial,
		Issuer:     req.Bundle.IssuerLabel,
		AcceptedAt: time.Now().UTC().Format(time.RFC3339),
		IssuedAt:   req.Bundle.IssuedAt,
	}); err != nil {
		log.Printf("[trust] bundle applied but the receipt could not be written: %v", err)
	}

	firstInstall := pinned == nil
	if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
		summary := fmt.Sprintf("trust bundle from %q installed: %d added, %d removed, %d trusted",
			req.Bundle.IssuerLabel, added, removed, len(newStore.Credentials))
		fields := map[string]any{
			"issuer":        req.Bundle.IssuerLabel,
			"serial":        req.Bundle.Serial,
			"first_install": firstInstall,
			"added":         added,
			"removed":       removed,
			"trusted":       len(newStore.Credentials),
			"rp_id":         newStore.RPID,
			// The pair the watcher records too, so a pushed change and an
			// observed one read the same way side by side.
			"fingerprint_before": fingerprintOf(prev),
			"fingerprint_after":  newStore.Fingerprint(),
		}
		if resetFrom != nil {
			// #991: the binding this replaced, and the pairing that allowed it.
			summary = fmt.Sprintf("trust bundle from %q installed after a re-pairing reset this node's binding "+
				"(rp_id %q, was %q): %d added, %d removed, %d trusted",
				req.Bundle.IssuerLabel, newStore.RPID, resetFrom.RPID, added, removed, len(newStore.Credentials))
			fields["binding_reset"] = true
			fields["rp_id_before"] = resetFrom.RPID
			fields["origins_before"] = resetFrom.Origins
			fields["paired_at"] = paired.PairedAt
			fields["paired_aggregator"] = paired.Aggregator
		}
		l.AppendAs(ledger.KindTrustBundleInstalled, "", summary, fields,
			serviceActor(aggregatorActorName(req.Bundle.IssuerLabel)))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"first_install": firstInstall,
		"binding_reset": resetFrom != nil,
		"added":         added,
		"removed":       removed,
		"trusted":       len(newStore.Credentials),
		"rp_id":         newStore.RPID,
	})
}

// defaultContainer names the node the same way the executor and the wrapper
// do: SERVICE from the wrapper's configuration, which the installer wrote from
// the running deployment. On a host with no node the installer writes
// SERVICE=none, and this service then describes itself as running none — the
// truth — instead of the hardcoded "rippledvalidator" it used to assume, which
// is what left the lab aggregator's Advisor calling itself a validator node and
// refusing a compact the executor had accepted for "none" (2026-08-19). The
// old name stays as the last resort so a host with no wrapper config at all
// behaves as before.
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
