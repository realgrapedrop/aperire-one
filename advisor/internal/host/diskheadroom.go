package host

import (
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// DiskHeadroomPct is free space on the filesystem holding the node's data
// path, as a percentage, and the path that reading was taken on.
//
// Uses the non-root free count: an upgrade does not run as root inside the
// container, and reserved blocks are not headroom anyone can spend.
//
// Two ways to take it, in this order.
//
// The Advisor statfs's the store itself first. That is what every container
// host does today (the data path sits under the operator's own home, which
// this account can traverse), what an operator running the CLI on their own
// account does, and what a host with no wrapper grant has. Nothing about
// those hosts changes, and no privileged call is made where none is needed.
//
// Where that read is refused, the wrapper's store-headroom verb takes it as
// root and says which path it measured (#465). On a native host the vendor's
// unit ships StateDirectory=xrpld at 0750 owned by the node's own account,
// and statfs needs traverse on every component of the path it is given, so
// the Advisor's own read comes back "permission denied" on a box with 82% of
// its disk free. The account is not in the node's group and is not going to
// be: install-advisor-account.sh stays out of the business of editing an
// operator's groups on a validator host, and reaching a privileged fact
// through the wrapper is the whole shape of this account.
//
// The reading is taken on the store's own path on both sides, never on an
// ancestor the Advisor happens to be able to reach. A store on its own volume
// is an ordinary validator layout, and an ancestor's numbers would describe a
// different filesystem while reading like the store's.
//
// A reading neither side could take is an error, and it carries both
// sentences. The precondition turns that into a refusal, which is the #427
// rule: unmeasured is never healthy, and never a zero.
func (s *State) DiskHeadroomPct() (float64, string, error) {
	pct, err := statfsHeadroomPct(s.Profile.DataPath)
	if err == nil {
		return pct, s.Profile.DataPath, nil
	}
	if s.Wrapper == "" {
		return 0, "", fmt.Errorf("%w, and no privilege wrapper is configured to take that reading on this host's behalf", err)
	}
	if pct, path, ok := headroomFromCache(s.Wrapper, s.Profile.DataPath); ok {
		return pct, path, nil
	}
	pct, path, werr := s.wrapperHeadroomPct()
	if werr != nil {
		return 0, "", fmt.Errorf("%v; the privilege wrapper could not take it either: %v", err, werr)
	}
	headroomToCache(s.Wrapper, s.Profile.DataPath, pct, path)
	return pct, path, nil
}

// headroomTTL is how long a wrapper-taken reading is reused, and it is the
// same minute StoreSize's cache uses, for the same reason.
//
// Only the wrapper path is cached. The Advisor's own statfs costs a syscall
// and caching it would buy nothing; the wrapper path costs a sudo and a fork,
// and it is walked twice per evaluation (the assessment's readings and the
// precondition), by every /v1/check, by every ask, and by the keeper that
// holds a plan warm every three minutes whether anyone is looking or not.
// That was measured once already on this project and the operator asked what
// it cost (check_warm.go, 2026-09-09), so it is not a cost to add quietly to
// a validator host.
//
// A minute of staleness on a percentage that moves in gigabytes is not a
// risk the floor can feel. A reading that could NOT be taken is never
// cached: a refusal has to be re-asked, or a host that recovers stays
// refused for a minute it did not need.
const headroomTTL = 60 * time.Second

type headroomReading struct {
	pct   float64
	path  string
	taken time.Time
}

var headroomCache = struct {
	sync.Mutex
	at map[string]headroomReading
}{at: map[string]headroomReading{}}

// Keyed by both, because either one moving makes the old number an answer
// about a different filesystem.
func headroomKey(wrapper, dataPath string) string { return wrapper + "\x00" + dataPath }

func headroomFromCache(wrapper, dataPath string) (float64, string, bool) {
	headroomCache.Lock()
	defer headroomCache.Unlock()
	r, ok := headroomCache.at[headroomKey(wrapper, dataPath)]
	if !ok || time.Since(r.taken) > headroomTTL {
		return 0, "", false
	}
	return r.pct, r.path, true
}

func headroomToCache(wrapper, dataPath string, pct float64, path string) {
	headroomCache.Lock()
	defer headroomCache.Unlock()
	headroomCache.at[headroomKey(wrapper, dataPath)] = headroomReading{pct, path, time.Now()}
}

// statfsHeadroomPct is the reading this process takes for itself.
func statfsHeadroomPct(path string) (float64, error) {
	if path == "" {
		return 0, fmt.Errorf("this host's profile names no data path, so there is no filesystem to measure")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	total := float64(st.Blocks) * float64(st.Bsize)
	avail := float64(st.Bavail) * float64(st.Bsize)
	if total <= 0 {
		return 0, fmt.Errorf("statfs %s reported zero capacity", path)
	}
	return avail / total * 100, nil
}

// wrapperHeadroomPct asks the wrapper's store-headroom verb.
//
// The verb answers in the wrapper's own AperireX=Y lines, read by the same
// AperireFacts that reads `inspect` and `store-size`:
//
//	AperireHeadroomPath=/var/lib/xrpld/db/nudb
//	AperireHeadroomTotalBytes=415852134400
//	AperireHeadroomAvailBytes=342745989120
//
// or, where it could not be taken,
//
//	AperireHeadroomPath=/var/lib/xrpld/db/nudb
//	AperireHeadroomTotalBytes=unknown
//	AperireHeadroomAvailBytes=unknown
//	AperireHeadroomReason=stat: cannot read file system information ...
//
// and it exits 0 either way, because "I could not measure it" is an answer to
// the question asked. Unlike StoreSize, an unmeasured answer comes back here
// as an error rather than as a reading with a reason on it: a store size that
// could not be taken is a card that says so, and a headroom that could not be
// taken is a precondition that must refuse.
func (s *State) wrapperHeadroomPct() (float64, string, error) {
	name := s.Wrapper
	args := []string{"store-headroom"}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		// The wrapper refused, or could not be run. Its own sentence is the
		// part an operator can act on.
		return 0, "", fmt.Errorf("%s", wrapperReason(err))
	}
	facts := AperireFacts(out)
	path := facts["AperireHeadroomPath"]
	rawTotal, haveTotal := facts["AperireHeadroomTotalBytes"]
	rawAvail, haveAvail := facts["AperireHeadroomAvailBytes"]
	if !haveTotal || !haveAvail {
		return 0, "", fmt.Errorf("the wrapper's store-headroom answer carries no measurement: %s", excerpt(string(out)))
	}
	if rawTotal == "unknown" || rawAvail == "unknown" {
		if reason := facts["AperireHeadroomReason"]; reason != "" {
			return 0, "", fmt.Errorf("%s", reason)
		}
		// The verb promises a reason beside an unknown. Missing is a wrapper
		// that needs fixing, not a disk that is fine.
		return 0, "", fmt.Errorf("the wrapper reported the headroom as unknown and gave no reason")
	}
	total, terr := strconv.ParseInt(rawTotal, 10, 64)
	avail, aerr := strconv.ParseInt(rawAvail, 10, 64)
	if terr != nil || aerr != nil || total <= 0 || avail < 0 || avail > total {
		return 0, "", fmt.Errorf("the wrapper's store-headroom answer is not a pair of byte counts: total %q, available %q",
			rawTotal, rawAvail)
	}
	return float64(avail) / float64(total) * 100, path, nil
}
