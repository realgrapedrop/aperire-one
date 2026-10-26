// Package fleet is the read-only peer table advisord loads at start — D2
// option C (advisor-enhancement/decisions.md, decided 2026-08-08). advisord
// keeps acting only on its own node — the compact, the approvals, the
// break-glass window, the executor, the wrapper and the ledger all stay
// single-node and untouched — and gains eyes on the FLEET: a table of
// sibling read-API origins and tokens, read-only, nothing more.
//
// A row can express exactly six things: a node label, a read-API origin, a
// transport note, a path to that peer's read token, the ROLE that peer plays
// in the fleet, and the node public key that peer is expected to be. It
// cannot express a verb, a wrapper path, an admin RPC endpoint, an action
// class, or a database connection (enhancement-plan.md step 5, risk S1) —
// Load rejects the whole file rather than silently ignoring an extra field,
// because a registry that can name a wrapper is D2 option A wearing option
// C's clothes, and it would arrive one convenient field at a time.
//
// Role and ExpectedPubkeyNode are the 2026-08-16 topology addition
// (the aggregator-diagnosis design, tier 2). Neither
// widens what this process may reach, which is the whole of the S1
// objection: Role is descriptive-only in exactly the way Transport already
// is — authored by the operator, never dialled, never consulted to decide
// how to connect — and ExpectedPubkeyNode is a CONSTRAINT on a channel that
// already exists, able only to make a read fail, never to make one reach
// further.
//
// The file has two accepted shapes, and Load takes either:
//
//	[ {peer}, {peer} ]                       — legacy, peers only, no self
//	{ "self": {…}, "peers": [ {peer}, … ] }  — with this host's own identity
//
// Version tolerance is deliberate and is the whole migration story: this is
// host-local config with a handful of instances in the estate, and a
// half-upgraded host must stay honest rather than fail closed to empty
// because its file predates the self block.
//
// An absent registry file is not an error. It reproduces today's
// single-client behaviour exactly — the migration argument option C is
// built on. Any parse or validation failure — an unknown key, a label
// outside its bounded charset, a duplicate label, a missing origin or
// token path — fails the WHOLE file closed to an empty registry, never a
// partial one, on the same "fail closed and visible" rule this project
// already applies elsewhere (Terms.Hash invalidation): a registry that
// loaded two of three peers and said nothing about the third is a worse
// outcome than no registry at all.
package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// labelRe bounds a peer label — enhancement-plan.md step 5: "Constrain it to
// [a-z0-9-], 1 to 32 characters, unique within the file, and reject the row
// outright on any violation." The reason is that this label is written into
// service-authored steps[] text and into the injected result body, the one
// channel the design treats as trustworthy because the service wrote it;
// bounding the charset at the parser is where this project already closes
// its other injection questions.
var labelRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// nodeKeyRe is the shape of a node public key: base58, starting with "n".
// Re-declared here rather than shared, exactly as dashboard/lib's
// fleet-registry.ts re-declares it rather than importing server.ts's —
// advisord does not import from the dashboard, and one regex is not a
// reason to start.
var nodeKeyRe = regexp.MustCompile(`^n[1-9A-HJ-NP-Za-km-z]{20,}$`)

// The roles a fleet member may declare. A CLOSED set, checked at parse: an
// unrecognised role fails the whole file rather than being carried as
// free-text into a prompt, on the same reasoning labelRe bounds a label.
//
// Absent is a fifth, supported state and means UNSPECIFIED — never
// inferred. The design note is explicit about why (tier 2(c), "ask, do not
// infer"): a dashboard with no node and no container looks like an
// aggregator and looks exactly as much like a broken node, and guessing
// between them reproduces the kept-vs-observed failure this whole change
// exists to close.
const (
	RoleAggregator = "aggregator"
	RoleNode       = "node"
	RoleValidator  = "validator"
	RoleRelay      = "relay"
)

var knownRoles = map[string]bool{
	RoleAggregator: true,
	RoleNode:       true,
	RoleValidator:  true,
	RoleRelay:      true,
}

// Self is this host's own identity: what this advisord is running on, in
// the same vocabulary its peers are described in.
//
// Before this existed, advisord learned what it was only by failing —
// a node profile read that errors and a docker binary that is not there,
// once per status poll, forever, while /v1/status reported the container
// name it was defaulted to as though it supervised one. A host that can
// state what it is stops mislabelling itself to the operator and to the
// model.
//
// The zero value means "this host has not been told what it is", which is
// every install that predates the self block. It renders as silence, never
// as a guess.
type Self struct {
	// Label is how the REST of the fleet refers to this host. Bounded by
	// labelRe, and — checked by Load — never also the label of a peer row:
	// a registry whose peer table names this same host is the wrong-node
	// read the design note found live on aperire1, where a peer row's
	// origin had quietly become this host's own dashboard.
	Label string `json:"label,omitempty"`
	// Role is one of knownRoles, or empty for unspecified.
	Role string `json:"role,omitempty"`
}

// Known reports whether this host has been told anything about itself.
func (s Self) Known() bool { return s.Label != "" || s.Role != "" }

// Peer is one registry row.
type Peer struct {
	// Label names the peer. Bounded per labelRe, unique within the
	// registry — checked by Load, never by a caller.
	Label string `json:"label"`
	// Origin is the peer's dashboard read-API origin, e.g.
	// http://127.0.0.1:7801 — nearly always a local port with a tunnel
	// doing the addressing (d2-registry-placement-options.md §4); this
	// package does not interpret or dial it.
	Origin string `json:"origin"`
	// TokenPath is a path to that peer's own read token — a second
	// credential, never shared with this process's own read.token.
	TokenPath string `json:"token_path"`
	// Transport is an operator-authored note on how Origin is reached
	// (e.g. "ssh -L tunnel, restarts with the host") — descriptive only,
	// never consulted by this package or by advisord to decide how to
	// connect. Its purpose is that a row states plainly whether a tunnel
	// is load-bearing rather than hiding it inside a bare URL.
	Transport string `json:"transport,omitempty"`
	// Role is what this peer IS — one of knownRoles, or empty for
	// unspecified. Descriptive only, in the same sense Transport is: this
	// package never reads it to decide anything, and neither does the code
	// that dials a peer. Its one job is that the model is told an
	// aggregator is an aggregator, so it stops offering a node's remedy on
	// a host that has no node, and names the right host in the sentence
	// carrying a command — which advisor/knowledge/metrics-ports-and-relay-feed.md
	// already asked for in prose and could not deliver, because the model
	// had no way to know which box it was on.
	Role string `json:"role,omitempty"`
	// ExpectedPubkeyNode pins this row to a specific node public key —
	// base58 starting with "n", the same shape and the same field NAME the
	// dashboard's own registry already uses (dashboard/lib/fleet-registry.ts),
	// so one fleet.yaml row generates one fleet.json row without a
	// translation table. Empty is unpinned, and is today's behaviour.
	//
	// Carried and surfaced, deliberately NOT enforced on a read yet:
	// whether a node-to-node peer read should verify this pin before
	// trusting the answer is open question 2 of the design note, and it is
	// the one change in that note able to make a previously-working read
	// start failing. So the field records what the operator declares, the
	// prompt renders it AS a declaration rather than as a verified fact,
	// and enforcement stays one named seam away instead of arriving
	// unannounced with a topology change.
	ExpectedPubkeyNode string `json:"expected_pubkey_node,omitempty"`
}

// Registry is the read-only peer table plus this host's own identity. The
// zero value (and a nil *Registry passed to the functions below) is exactly
// today's single-node behaviour: no peers, no self, nothing offered on the
// read menu, byte-identical to a build that never heard of fleet.
type Registry struct {
	// Self is this host. Zero for a legacy array-shaped file and for any
	// file that does not carry a self block — "not told", never guessed.
	Self  Self
	Peers []Peer
}

// SelfIdentity reports what this host has been told it is. Nil-safe, and
// the zero Self means unspecified.
func (r *Registry) SelfIdentity() Self {
	if r == nil {
		return Self{}
	}
	return r.Self
}

// PeerByLabel finds one row. Nil-safe; the bool is false for an unknown
// label so a caller renders "not registered" rather than an empty row that
// reads like a peer with no role.
func (r *Registry) PeerByLabel(label string) (Peer, bool) {
	if r == nil {
		return Peer{}, false
	}
	for _, p := range r.Peers {
		if p.Label == label {
			return p, true
		}
	}
	return Peer{}, false
}

// Labels reports every registered peer's label, in file order — the roster
// interrogate.Loop checks a model's Node field against.
func (r *Registry) Labels() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Peers))
	for _, p := range r.Peers {
		out = append(out, p.Label)
	}
	return out
}

// TokenPaths reports every peer's TokenPath, for tightenState-style mode
// narrowing on every start.
func (r *Registry) TokenPaths() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Peers))
	for _, p := range r.Peers {
		out = append(out, p.TokenPath)
	}
	return out
}

// rawPeer is the wire shape of one row, decoded with DisallowUnknownFields
// so an extra key fails the parse rather than being silently dropped — the
// mechanism behind S1.
type rawPeer struct {
	Label              string `json:"label"`
	Origin             string `json:"origin"`
	TokenPath          string `json:"token_path"`
	Transport          string `json:"transport"`
	Role               string `json:"role"`
	ExpectedPubkeyNode string `json:"expected_pubkey_node"`
}

// rawSelf is the wire shape of the self block.
type rawSelf struct {
	Label string `json:"label"`
	Role  string `json:"role"`
}

// rawFile is the wire shape of the OBJECT form. json.Decoder's
// DisallowUnknownFields applies to every struct it decodes on the way down,
// so one call guards all three levels — the top-level object, the self
// block and each peer row. That matters more than it looks: if the flag
// only reached rawPeer, a file could carry {"self":…,"peers":…,"wrapper":…}
// and the S1 hole this package exists to close would be open at the top
// level while every row underneath was still strict.
type rawFile struct {
	Self  *rawSelf  `json:"self"`
	Peers []rawPeer `json:"peers"`
}

// Load reads the registry file at path, in either accepted shape.
//
// Version tolerance is a one-way door on purpose: a file written before the
// self block existed is a legacy ARRAY, and it loads as peers with no roles
// and no self rather than failing the host closed to an empty registry. The
// alternative — refusing the old shape — would take a working advisord off
// its fleet the moment a binary landed ahead of a config sweep, which is
// the exact ordering an estate upgrade has.
func Load(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Registry{}, nil
		}
		return &Registry{}, fmt.Errorf("fleet registry %s: %w", path, err)
	}
	return Parse(path, b)
}

// Parse applies Load's rules to bytes a caller already read, so a caller
// that opened the file its own way (advisord's re-read, by descriptor with
// O_NOFOLLOW, #859) parses exactly the bytes it checked. path is used in
// error text only.
func Parse(path string, b []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	var raws []rawPeer
	var self Self
	if isObjectForm(b) {
		var file rawFile
		if err := dec.Decode(&file); err != nil {
			return &Registry{}, fmt.Errorf("fleet registry %s: %w", path, err)
		}
		raws = file.Peers
		if file.Self != nil {
			if file.Self.Label != "" && !labelRe.MatchString(file.Self.Label) {
				return &Registry{}, fmt.Errorf(
					"fleet registry %s: self: label %q is not 1-32 characters of [a-z0-9-]",
					path, file.Self.Label)
			}
			if file.Self.Role != "" && !knownRoles[file.Self.Role] {
				return &Registry{}, fmt.Errorf(
					"fleet registry %s: self: role %q is not one of %s",
					path, file.Self.Role, roleList())
			}
			self = Self{Label: file.Self.Label, Role: file.Self.Role}
		}
	} else {
		// The legacy array — and also every malformed file, which reaches
		// the same Decode and produces the same error text it always did.
		if err := dec.Decode(&raws); err != nil {
			return &Registry{}, fmt.Errorf("fleet registry %s: %w", path, err)
		}
	}

	seen := make(map[string]bool, len(raws))
	peers := make([]Peer, 0, len(raws))
	for i, raw := range raws {
		if !labelRe.MatchString(raw.Label) {
			return &Registry{}, fmt.Errorf(
				"fleet registry %s: row %d: label %q is not 1-32 characters of [a-z0-9-]",
				path, i, raw.Label)
		}
		if seen[raw.Label] {
			return &Registry{}, fmt.Errorf("fleet registry %s: row %d: duplicate label %q", path, i, raw.Label)
		}
		if raw.Origin == "" {
			return &Registry{}, fmt.Errorf("fleet registry %s: row %d: peer %q has no origin", path, i, raw.Label)
		}
		if raw.TokenPath == "" {
			return &Registry{}, fmt.Errorf("fleet registry %s: row %d: peer %q has no token_path", path, i, raw.Label)
		}
		// A peer row carrying THIS host's own label. The design note found
		// this live in its worst form: a row whose origin had silently
		// become this host's own dashboard, so this node's swap and
		// agreement would have been handed to the model labelled as another
		// node's. Refused at parse, by name — a registry cannot state that
		// this host is its own peer.
		if self.Label != "" && raw.Label == self.Label {
			return &Registry{}, fmt.Errorf(
				"fleet registry %s: row %d: peer %q is this host's own label — a host cannot be its own fleet peer",
				path, i, raw.Label)
		}
		// Role and the pin: absent is the supported, unremarkable state.
		// Present but not recognised fails the WHOLE file, because a
		// mistyped role reaching a prompt as free text, or a mistyped pin
		// silently never matching, are both worse than a loud refusal.
		if raw.Role != "" && !knownRoles[raw.Role] {
			return &Registry{}, fmt.Errorf(
				"fleet registry %s: row %d: peer %q has role %q, which is not one of %s",
				path, i, raw.Label, raw.Role, roleList())
		}
		if raw.ExpectedPubkeyNode != "" && !nodeKeyRe.MatchString(raw.ExpectedPubkeyNode) {
			return &Registry{}, fmt.Errorf(
				"fleet registry %s: row %d: peer %q has an expected_pubkey_node that is not shaped like a node public key (base58, starting with \"n\")",
				path, i, raw.Label)
		}
		seen[raw.Label] = true
		peers = append(peers, Peer{
			Label: raw.Label, Origin: raw.Origin, TokenPath: raw.TokenPath, Transport: raw.Transport,
			Role: raw.Role, ExpectedPubkeyNode: raw.ExpectedPubkeyNode,
		})
	}
	return &Registry{Self: self, Peers: peers}, nil
}

// isObjectForm reports whether the file's first meaningful byte opens an
// object — the shape sniff the two accepted forms are told apart by.
// Anything else (an array, or garbage) goes down the legacy path, which
// keeps a malformed file's error text exactly what it has always been
// rather than inventing a second vocabulary for the same broken file.
func isObjectForm(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// roleList renders the accepted roles for an error message, in a fixed
// order — a map's own order would make the same failure read differently
// on each run, which is a bad property for a line an operator diffs.
func roleList() string {
	return strings.Join([]string{RoleAggregator, RoleNode, RoleValidator, RoleRelay}, ", ")
}
