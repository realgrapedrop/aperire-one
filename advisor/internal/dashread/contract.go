// Package dashread is the Advisor's client for the dashboard's read API —
// ADR 0008. The Advisor reads dashboard data through these routes and never
// opens the SQLite file; the exclusions (auth tables, the ledger witness)
// are enforced on the dashboard side by the absence of a route.
//
// This file mirrors dashboard/types/read-contract.ts. The two carry one wire
// shape and one ProtocolVersion and must be edited together; a mismatch is a
// named error, never a silent drop. Exactly like relay/contract.go mirrors
// relay-contract.ts.
package dashread

// ProtocolVersion is the read contract version this client speaks. Every
// response body carries the server's; a mismatch is a named error on both
// sides, never a silent drop (ADR 0008, decision 4).
const ProtocolVersion = 1

// RouteNames mirrors READ_ROUTE_NAMES — the exact set served under /read/v1/.
// A route is served because it is named in the contract, never inherited.
var RouteNames = []string{
	"history", "recent", "ledgers", "agreement", "missed-ledgers",
	"alerts", "firing", "digests", "bandwidth", "identity",
	"node-status", "peers", "validation-summary", "consensus-snapshot",
	"amendment-ballot", "governance", "system", "net-stats", "validations-tick",
	"fleet", "node-config",
}

// StreamPath and StreamChannels mirror READ_STREAM_PATH and
// READ_STREAM_CHANNELS — the read API's one streaming member (ADR 0013).
// They sit BESIDE RouteNames and never inside it: the rule RouteNames
// carries is that every JSON route in the contract is reachable through the
// dashboard's peer-read proxy and nothing else is, and a stream fed through
// a JSON reader is a held socket, not a parse error.
//
// Maintained for parity discipline, not for a consumer: the Advisor's
// questions are historical and its data path is ADR 0008's JSON reads. The
// value of the mirrored pair is that one file tells the whole contract — a
// member documented on only one side is how the two drift.
const StreamPath = "/read/v1/stream"

var StreamChannels = []string{"validations_tick"}

// LedgerRow is one row of the `ledgers` route, both forms. Mirrors
// ReadLedgerRow in read-contract.ts (whose source of truth is db.ts).
type LedgerRow struct {
	LedgerIndex int64   `json:"ledger_index"`
	CloseTS     int64   `json:"close_ts"`   // rippled epoch seconds (since 2000-01-01)
	CloseTime   float64 `json:"close_time"` // seconds between this close and the previous
	TxnCount    int     `json:"txn_count"`
	FamMoney    int     `json:"fam_money"`
	FamMarket   int     `json:"fam_market"`
	FamNFT      int     `json:"fam_nft"`
	FamAccts    int     `json:"fam_accts"`
}

// ledgerWindowResponse mirrors LedgerWindowResponse. Around and Span are
// pointers on purpose: the contract-evolution rule (read-contract.ts) says an
// optional parameter needs no protocol_version bump PROVIDED the response
// echoes it and the client asserts the echo's PRESENCE — a server that never
// echoes is a server that ignored the parameter, and this client must fail
// that read by name rather than reason over a silently narrower window.
// Presence, never equality: a clamped span echoes the applied value, and a
// clamp is correct behaviour.
type ledgerWindowResponse struct {
	ProtocolVersion int         `json:"protocol_version"`
	Around          *int64      `json:"around"`
	Span            *int        `json:"span"`
	Requested       int         `json:"requested"`
	Returned        int         `json:"returned"`
	Ledgers         []LedgerRow `json:"ledgers"`
}

// latestLedgersResponse is the OTHER form of the `ledgers` route — the one
// that pre-dates around/span and needs no echo assertion: there is nothing
// here that could silently narrow, only a count the server itself caps at
// 500, so a smaller-than-asked reply is a legitimate answer, not a defect
// the client must catch by name. Mirrors read-contract.ts's
// ReadLedgersLatestResponse. No served byte changes — the route already
// answers `?limit=` this way; this is writing the shape down (§9.1).
type latestLedgersResponse struct {
	ProtocolVersion int         `json:"protocol_version"`
	Limit           int         `json:"limit"`
	Ledgers         []LedgerRow `json:"ledgers"`
}

// HistoryPoint is one bucketed or raw sample: { ts (ms), value }.
type HistoryPoint struct {
	TS    int64   `json:"ts"`
	Value float64 `json:"value"`
}

type historyResponse struct {
	ProtocolVersion int            `json:"protocol_version"`
	Metric          string         `json:"metric"`
	Range           string         `json:"range"`
	Agg             string         `json:"agg"`
	Points          []HistoryPoint `json:"points"`
}

// AgreementRow is one ledger's local agreement record. Mirrors AgreementRow
// in db.ts. TS is milliseconds (Date.now() at write time), not rippled epoch
// seconds — different unit from LedgerRow.CloseTS, which is the source
// table's own convention and is carried through unchanged rather than
// normalised here.
type AgreementRow struct {
	LedgerIndex int64 `json:"ledger_index"`
	OurVoted    int   `json:"our_voted"` // 0 or 1
	TS          int64 `json:"ts"`        // ms
}

type agreementResponse struct {
	ProtocolVersion int            `json:"protocol_version"`
	RetentionDays   int            `json:"retention_days"`
	SinceMs         int64          `json:"since_ms"`
	Rows            []AgreementRow `json:"rows"`
}

// MissedLedgerRow is one recorded miss, with the node's own context at the
// moment of the miss. Mirrors MissedLedgerRow in db.ts. The nullable columns
// are pointers rather than bare ints: a zero validations_seen is a real,
// meaningful reading (nobody else the node could see had validated either),
// and collapsing it onto the same zero value as "not recorded" would be the
// kept-versus-observed defect applied to this table.
type MissedLedgerRow struct {
	LedgerIndex     int64   `json:"ledger_index"`
	TS              int64   `json:"ts"` // ms
	ValidationsSeen *int    `json:"validations_seen"`
	TrustedUNL      *int    `json:"trusted_unl"`
	PeerCount       *int    `json:"peer_count"`
	ServerState     *string `json:"server_state"`
}

type missedLedgersResponse struct {
	ProtocolVersion int               `json:"protocol_version"`
	Limit           int               `json:"limit"`
	Missed          []MissedLedgerRow `json:"missed"`
}

// AlertEvent is one alert lifecycle transition. Mirrors AlertEvent in db.ts.
// Delivery, Value, ThresholdOp, ThresholdValue, DurationS, AckedAt and
// MutedUntil are all nullable on the wire and are pointers/maps for the same
// reason as MissedLedgerRow's nullable columns.
type AlertEvent struct {
	ID             int64             `json:"id"`
	TS             int64             `json:"ts"` // ms
	Metric         string            `json:"metric"`
	Severity       string            `json:"severity"` // warn | critical | page
	State          string            `json:"state"`    // firing | resolved
	Value          *float64          `json:"value"`
	ThresholdOp    *string           `json:"threshold_op"`
	ThresholdValue *float64          `json:"threshold_value"`
	DurationS      *int              `json:"duration_s"`
	DedupKey       string            `json:"dedup_key"`
	Channels       []string          `json:"channels"`
	Delivery       map[string]string `json:"delivery"`
	AckedAt        *int64            `json:"acked_at"`
	MutedUntil     *int64            `json:"muted_until"`
	Context        *string           `json:"context"`
}

type alertsResponse struct {
	ProtocolVersion int          `json:"protocol_version"`
	SinceMs         int64        `json:"since_ms"`
	Limit           int          `json:"limit"`
	Alerts          []AlertEvent `json:"alerts"`
}

// FiringStateRow is one currently-firing alert. Mirrors FiringStateRow in
// db.ts — the live set, not history, which is why it carries no ts window of
// its own on the route.
type FiringStateRow struct {
	DedupKey       string   `json:"dedup_key"`
	Metric         string   `json:"metric"`
	Severity       string   `json:"severity"`
	TriggeredTS    int64    `json:"triggered_ts"`
	FiredTS        int64    `json:"fired_ts"`
	LastValue      *float64 `json:"last_value"`
	LastSeenTS     *int64   `json:"last_seen_ts"`
	ThresholdOp    *string  `json:"threshold_op"`
	ThresholdValue *float64 `json:"threshold_value"`
	DurationS      *int     `json:"duration_s"`
	Channels       []string `json:"channels"`
	AckedAt        *int64   `json:"acked_at"`
	MutedUntil     *int64   `json:"muted_until"`
	LastPagedTS    *int64   `json:"last_paged_ts"`
}

type firingResponse struct {
	ProtocolVersion int              `json:"protocol_version"`
	Firing          []FiringStateRow `json:"firing"`
}

// identityResponse mirrors IdentityResponse — this node's identity as the
// dashboard's own snapshot knows it, carried through unchanged from
// snapshot.server_info rather than normalised for display (see the doc
// comment on IdentityResponse in read-contract.ts for why BuildVersion keeps
// its "rippled-" prefix and Network is the raw network_id, not a Mainnet/
// Testnet/Devnet label). Adding this route did not bump ProtocolVersion —
// same reasoning as read-contract.ts: an older dashboard answers this route
// with the named unknown_read_path error, never a differently-shaped 200.
type identityResponse struct {
	ProtocolVersion int     `json:"protocol_version"`
	PubkeyNode      *string `json:"pubkey_node"`
	BuildVersion    *string `json:"build_version"`
	Network         *int    `json:"network"`
}

// ── D8 first slice — node-status, peers, validation-summary ────────────
// (advisor-enhancement/d8-aggregator-build-plan.md). All three are
// additive and read-only; none bumped ProtocolVersion — same reasoning as
// identityResponse above. unl_total and is_validator appear on both
// nodeStatusResponse and validationSummaryResponse: same in-process
// expressions on the dashboard server within one request, so they cannot
// disagree there, but a caller polling the two routes separately can see
// skew of up to one poll cadence between them.

// NodeReachState mirrors NodeReachState in read-contract.ts (server.ts's
// nodeReachState(), unchanged shape) — whether the dashboard's own node is
// currently answering, separate from what it last said.
type NodeReachState struct {
	OK              bool  `json:"ok"`
	Misses          int   `json:"misses"`
	LastOkMs        int64 `json:"last_ok_ms"`
	UnreachableForS int   `json:"unreachable_for_s"`
}

// AmendmentCounts mirrors AmendmentCounts in read-contract.ts.
type AmendmentCounts struct {
	Enabled   int `json:"enabled"`
	Supported int `json:"supported"`
	Vetoed    int `json:"vetoed"`
	Pending   int `json:"pending"`
	// Null on a node that reports no vote tally at all — same reason as
	// ReadAmendmentBallotRow's pointers below.
	Approaching *int `json:"approaching"`
}

// nodeStatusResponse mirrors NodeStatusResponse. Field types follow the
// same nullable-pointer convention as MissedLedgerRow above; LoadFactor,
// BaseFeeXRP and TimeDriftMs are pointers to float64 (not int) — rippled
// reports load_factor and base_fee_xrp as fractional, and readClock's
// drift computation (server.ts ~3193) is decimal seconds converted to ms,
// also fractional. Getting these three wrong to int is exactly the kind
// of shape drift the parity test does NOT catch (it checks route names and
// ProtocolVersion, never field types) — this comment is the field-for-field
// review every mirrored contract here asks for: both sides change together.
type nodeStatusResponse struct {
	ProtocolVersion      int      `json:"protocol_version"`
	ServerState          *string  `json:"server_state"`
	ValidatedLedgerIndex *int64   `json:"validated_ledger_index"`
	CompleteLedgers      *string  `json:"complete_ledgers"`
	UptimeS              *int64   `json:"uptime_s"`
	BuildVersion         *string  `json:"build_version"`
	BaseFeeXRP           *float64 `json:"base_fee_xrp"`
	LoadFactor           *float64 `json:"load_factor"`
	PeerCount            *int     `json:"peer_count"`
	Network              *int     `json:"network"`
	PubkeyValidator      *string  `json:"pubkey_validator"`
	PubkeyNode           *string  `json:"pubkey_node"`
	// HostName is the node's machine: APERIRE_HOSTNAME, else the host the
	// node's relay reports (on a split install, the validator's machine), else
	// the dashboard's os.hostname(). Pointer-typed, like every
	// other nullable here: a server older than this field omits the key
	// entirely, and a *string keeps that absence distinguishable from a
	// host that reports an empty name. A bare string would render both as
	// "" and state a measurement neither side made.
	HostName *string `json:"host_name"`
	// Hostid is rippled's OWN self-identifier from server_info — the
	// container id under Docker, the machine hostname on a native install.
	// A different fact from HostName above; never treat one as the other.
	Hostid          *string          `json:"hostid"`
	Domain          *string          `json:"domain"`
	UNLTotal        int              `json:"unl_total"`
	IsValidator     bool             `json:"is_validator"`
	Amendments      *AmendmentCounts `json:"amendments"`
	TimeDriftMs     *float64         `json:"time_drift_ms"`
	NTPSynced       *bool            `json:"ntp_synced"`
	ServerInfoAgeMs *int64           `json:"server_info_age_ms"`
	NodeReach       NodeReachState   `json:"node_reach"`
	// DeployRef is the commit the HOST's dashboard install was last deployed
	// from (.deploy-ref at the install root) — a fact about the install, not
	// about rippled, mirrored here because the contract is one file on each
	// side or it is nothing. Pointer-typed like every other nullable: a
	// server older than this field omits the key, a host with no stamp sends
	// null, and neither may be read as "the same ref as mine". Compared for
	// equality only; never parsed, never ordered.
	DeployRef *string `json:"deploy_ref"`
	// RelayVersion is the relay's own build ref on the HOST (#593), already
	// commit-shaped by the server or null: no relay has pushed, an unstamped
	// relay (`dev`), or a node older than this member. Pointer-typed because
	// a server older than the field omits the key and null is "not reported",
	// which a bare string would render as an empty build. No ProtocolVersion
	// bump: an additive member on an existing route, the rule HostName and
	// DeployRef were added under.
	RelayVersion *string `json:"relay_version"`
	// InstallDir is the directory the HOST's dashboard is installed in
	// (#615), absolute or null. A fact about the install, never joined into a
	// command by this side; the dashboard's own pages validate it again before
	// they print it. Same additive rule as RelayVersion.
	InstallDir *string `json:"install_dir"`
	// RunAs is the account the HOST's dashboard process runs as (#615), or
	// null. A fact about the process, not about who installed Aperire.
	RunAs *string `json:"run_as"`
}

// ReadPeerRow mirrors ReadPeerRow in read-contract.ts — one row of the
// `peers` route, the same fields overview.html's applyPeers/showPeerTooltip
// already derive client-side for the local node's own peer ring.
type ReadPeerRow struct {
	Address      *string  `json:"address"`
	Host         *string  `json:"host"`
	Country      *string  `json:"country"`
	Inbound      bool     `json:"inbound"`
	LatencyMs    *int     `json:"latency_ms"`
	Version      *string  `json:"version"`
	UptimeS      *int64   `json:"uptime_s"`
	Sanity       *string  `json:"sanity"`
	HasIssue     bool     `json:"has_issue"`
	IssueReasons []string `json:"issue_reasons"`
}

// peersResponse mirrors PeersResponse.
type peersResponse struct {
	ProtocolVersion int            `json:"protocol_version"`
	Peers           []ReadPeerRow  `json:"peers"`
	Total           int            `json:"total"`
	Out             int            `json:"out"`
	In              int            `json:"in"`
	Issue           int            `json:"issue"`
	LatencyP90Ms    *int           `json:"latency_p90_ms"`
	NodeReach       NodeReachState `json:"node_reach"`
}

// validationSummaryResponse mirrors ValidationSummaryResponse —
// computeAgreementStats()'s output on the dashboard side, field for field.
type validationSummaryResponse struct {
	ProtocolVersion int  `json:"protocol_version"`
	Agreement1h     int  `json:"agreement_1h"`
	Missed1h        int  `json:"missed_1h"`
	Agreement24h    int  `json:"agreement_24h"`
	Missed24h       int  `json:"missed_24h"`
	UNLActive1h     int  `json:"unl_active_1h"`
	UNLTotal        int  `json:"unl_total"`
	IsValidator     bool `json:"is_validator"`
}

// consensusSnapshotResponse mirrors ConsensusSnapshotResponse — the
// Consensus tab's 14 live-value cards, for a peer. See the doc comment on
// ConsensusSnapshotResponse in read-contract.ts for the three-independent-
// staleness-clocks reasoning (ServerInfoAgeMs / FeeAgeMs / LastCloseAgeMs)
// and for why the per-round quorum bar is deliberately NOT part of this
// route. LedgersPerMin and ValidationRatePerMin are plain ints, never
// pointers — both are counts over a real window and 0 is a fact, not an
// absence.
type consensusSnapshotResponse struct {
	ProtocolVersion      int            `json:"protocol_version"`
	AvgClose1hS          *float64       `json:"avg_close_1h_s"`
	Proposers            *int           `json:"proposers"`
	QuorumReq            *int           `json:"quorum_req"`
	ConvergeTimeS        *float64       `json:"converge_time_s"`
	LedgerAgeS           *int           `json:"ledger_age_s"`
	CloseDeltaS          *float64       `json:"close_delta_s"`
	LedgersPerMin        int            `json:"ledgers_per_min"`
	TxLastLedger         *int           `json:"tx_last_ledger"`
	TPS1m                *int           `json:"tps_1m"`
	ValidationRatePerMin int            `json:"validation_rate_per_min"`
	FeeEscalation        *float64       `json:"fee_escalation"`
	OpenLedgerFeeDrops   *int64         `json:"open_ledger_fee_drops"`
	QueueSize            *int           `json:"queue_size"`
	JobOverflow          *int           `json:"job_overflow"`
	ServerInfoAgeMs      *int64         `json:"server_info_age_ms"`
	FeeAgeMs             *int64         `json:"fee_age_ms"`
	LastCloseAgeMs       *int64         `json:"last_close_age_ms"`
	NodeReach            NodeReachState `json:"node_reach"`
}

// ReadAmendmentBallotRow mirrors ReadAmendmentBallotRow in read-contract.ts
// (whose own source of truth is AmendmentBallotRow in lib/amendments.ts).
// OurVote is a string, not an enum — Go has none, and the four values
// (yes/no/default/obsolete) are documented on the TS side.
type ReadAmendmentBallotRow struct {
	Hash        string  `json:"hash"`
	Name        string  `json:"name"`
	XLS         *string `json:"xls"`
	Description *string `json:"description"`
	XLSUrl      *string `json:"xls_url"`
	// Pointers, not values: rippled reports a per-amendment vote tally only
	// on a node that runs the flag-ledger amendment vote, so every one of
	// these is null on a tracking node. Unmarshalling null into an int does
	// not error — it leaves 0 — which would restate "this node has no tally"
	// as "no validator supports it", the exact confusion the dashboard side
	// of this contract exists to prevent.
	Count       *int `json:"count"`
	Threshold   *int `json:"threshold"`
	Validations *int `json:"validations"`
	// count/validations, the share xrpscan publishes. Not count/threshold:
	// the threshold is the 80% bar, so that ratio reads above 100% for an
	// amendment past it.
	SupportPct    *float64 `json:"support_pct"`
	ProgressState *string  `json:"progress_state"` // "pending" | "needs" | null
	NeededCount   *int     `json:"needed_count"`
	// MajorityAtMs is when the amendment reached the network's majority, ms
	// since the Unix epoch. A tracking node reports this even though it
	// reports no tally, so it is often the only support fact on the row.
	MajorityAtMs *int64 `json:"majority_at_ms"`
	// SupportState names which support fact the row has: "tallied" (the
	// node's own count), "counted" (the dashboard counted the votes itself
	// from the trusted validations stream, see Counted), "majority"
	// (majority only), "unreported" (no reading at all). Absent from a
	// dashboard older than this field, treat the empty string as "fall back
	// to the tally fields", not as a mismatch.
	SupportState string `json:"support_state"`
	// Counted is the dashboard's own count, present exactly when
	// SupportState is "counted" and nil otherwise. It never travels in
	// Count/Validations: those stay the node's own, so the two readings
	// cannot be mistaken for each other. Nil from a dashboard older than
	// the field, which is the same as "not counted".
	Counted   *ReadCountedAmendmentSupport `json:"counted"`
	OurVote   string                       `json:"our_vote"` // yes | no | default | obsolete
	Supported bool                         `json:"supported"`
}

// ReadCountedAmendmentSupport mirrors ReadCountedAmendmentSupport in
// read-contract.ts: one voting ledger's count for one amendment. Count of
// Validations trusted validators listed it; Threshold is rippled's bar for
// that round; LedgerIndex and AtMs say which voting ledger and when, so the
// figure can be checked against a validator or xrpscan for the same moment.
type ReadCountedAmendmentSupport struct {
	LedgerIndex int64 `json:"ledger_index"`
	AtMs        int64 `json:"at_ms"`
	Count       int   `json:"count"`
	Validations int   `json:"validations"`
	Threshold   int   `json:"threshold"`
}

// amendmentBallotResponse mirrors AmendmentBallotResponse — the Governance
// tab's per-amendment ballot table, for a peer. The rest of that tab (vote
// stance, publisher health) is the sibling `governance` route, mirrored
// below.
//
// LibraryAgeMs is additive: how old the amendment knowledge library behind
// every row's Description/XLSUrl is (#542), read from the library file's own
// recorded refresh moment, never filesystem mtime. Unused on this side of
// the contract today; kept mirrored so the two never drift silently.
type amendmentBallotResponse struct {
	ProtocolVersion int                      `json:"protocol_version"`
	Rows            []ReadAmendmentBallotRow `json:"rows"`
	FeatureAgeMs    *int64                   `json:"feature_age_ms"`
	LibraryAgeMs    *int64                   `json:"library_age_ms"`
	NodeReach       NodeReachState           `json:"node_reach"`
}

// ReadPublisherSiteRow and ReadPublisherSummary mirror their TS
// counterparts. Expiry and sequence are pointers because builds differ in
// what `validator_list_sites` reports — the lab fleet's returns neither.
type ReadPublisherSiteRow struct {
	Site           string `json:"site"`
	Status         string `json:"status"`
	RefreshAgeS    *int   `json:"refresh_age_s"`
	ListExpiryDays *int   `json:"list_expiry_days"`
	CertExpiryDays *int   `json:"cert_expiry_days"`
	Sequence       *int   `json:"sequence"`
}

type ReadPublisherSummary struct {
	SiteCount      int                    `json:"site_count"`
	RefreshStatus  string                 `json:"refresh_status"`
	RefreshAgeS    *int                   `json:"refresh_age_s"`
	ListExpiryDays *int                   `json:"list_expiry_days"`
	CertExpiryDays *int                   `json:"cert_expiry_days"`
	Sites          []ReadPublisherSiteRow `json:"sites"`
}

// AmendmentOurVotes mirrors GovernanceResponse.our_votes. Plain ints: a
// vote posture is this node's own configuration and is always countable,
// tally or no tally.
type AmendmentOurVotes struct {
	Yes     int `json:"yes"`
	No      int `json:"no"`
	Default int `json:"default"`
}

// governanceResponse mirrors GovernanceResponse — the Governance tab minus
// its ballot table. Two age fields, not one: the amendment aggregates and
// the publisher block come from two different pollers, and folding them
// into a single number would be wrong for whichever moved last.
type governanceResponse struct {
	ProtocolVersion           int                  `json:"protocol_version"`
	AmendmentBlocked          bool                 `json:"amendment_blocked"`
	ThresholdMetCount         *int                 `json:"threshold_met_count"`
	ApproachingThresholdCount *int                 `json:"approaching_threshold_count"`
	OurVotes                  AmendmentOurVotes    `json:"our_votes"`
	NextActivationStatus      string               `json:"next_activation_status"` // pending | gathering | none
	NextActivationName        *string              `json:"next_activation_name"`
	Publishers                ReadPublisherSummary `json:"publishers"`
	FeatureAgeMs              *int64               `json:"feature_age_ms"`
	SitesAgeMs                *int64               `json:"sites_age_ms"`
	NodeReach                 NodeReachState       `json:"node_reach"`
}

// ── #59, fleet, node-config ───────────────────────────────────────────
// Both additive and read-only; neither bumped ProtocolVersion, same
// reasoning as identityResponse above. An older dashboard answers either
// with the named unknown_read_path error, never a differently-shaped 200,
// and the Advisor turns that into "this dashboard does not serve the fleet
// roster" rather than into an empty fleet.

// FleetNode mirrors ReadFleetNode in read-contract.ts, one member of the
// roster this dashboard holds, with what it last OBSERVED of that member.
//
// LastAnsweredMs is a pointer because null and 0 are different facts: null
// is "has never answered since this dashboard started", 0 is a timestamp.
// The Advisor says "has not answered since this dashboard started" for the
// first and dates the second; collapsing them would let it claim a node was
// last reachable at the Unix epoch.
type FleetNode struct {
	Label          string `json:"label"`
	Role           string `json:"role"`
	Self           bool   `json:"self"`
	Verdict        string `json:"verdict"`
	Detail         string `json:"detail"`
	LastAnsweredMs *int64 `json:"last_answered_ms"`
}

// fleetRosterResponse mirrors FleetRosterResponse.
//
// NowMs is the server's clock at the moment the body was built, and every
// age the Advisor states is computed against it rather than against this
// process's own clock. Two hosts' clocks can disagree; one body's cannot
// disagree with itself.
type fleetRosterResponse struct {
	ProtocolVersion int         `json:"protocol_version"`
	Registered      bool        `json:"registered"`
	SelfLabel       string      `json:"self_label"`
	NowMs           int64       `json:"now_ms"`
	Nodes           []FleetNode `json:"nodes"`
}

// FleetRoster is what the client hands back: the response's own fields,
// exported, with the envelope's version already checked.
type FleetRoster struct {
	Registered bool
	SelfLabel  string
	NowMs      int64
	Nodes      []FleetNode
}

// NodeConfig mirrors NodeConfigResponse, the four allow-listed rippled
// settings this host runs, as its own rippled.cfg has them.
//
// Every value is a pointer for the same reason MissedLedgerRow's are: an
// absent stanza is a fact about the file and must not render as a value the
// file does not contain. CfgRead false is the separate, stronger fact that
// no cfg was read at all.
type NodeConfig struct {
	CfgRead bool `json:"cfg_read"`
	// ParsedAtMs dates the VALUES, not the response. The dashboard reads
	// rippled.cfg once at startup, so this can be days older than the
	// request that carried it, and an answer dated by the request would be
	// dated by the wrong clock, this project's characteristic bug.
	ParsedAtMs     *int64  `json:"parsed_at_ms"`
	NodeSize       *string `json:"node_size"`
	LedgerHistory  *string `json:"ledger_history"`
	OnlineDelete   *int64  `json:"online_delete"`
	AdvisoryDelete *bool   `json:"advisory_delete"`
}

type nodeConfigResponse struct {
	ProtocolVersion int `json:"protocol_version"`
	NodeConfig
}

// apiError mirrors ReadErrorBody.
type apiError struct {
	Error            string `json:"error"`
	ServerVersion    int    `json:"server_version"`
	RequestedVersion int    `json:"requested_version"`
	Detail           string `json:"detail"`
}
