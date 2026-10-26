// Package knowledge holds the mechanical rules for the knowledge corpus —
// what a file must carry to be part of it, and (in bundle.go) how a corpus
// travels from the aggregator to a node.
//
// The rules live here, in a package, rather than inside the command that runs
// them, for one reason worth stating: they are needed in two places. CI lints
// the SHIPPED corpus, which is in the repository and could be checked by a
// plain `go test`. Promotion lints the FLEET corpus, which is a directory on
// the aggregator that no test knows the path of and that no repository
// contains. A test cannot serve the second caller, so the rules are a library
// and cmd/knowledge-lint is a thin front for them — one implementation, two
// callers, and the library half is covered by the same `go test -race ./...`
// the rest of this module is.
package knowledge

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aperire-advisor/internal/model"
)

// The size budget. Both numbers are about the injection budget, not about
// disk: a knowledge file is read whole into a prompt or not at all, so one
// oversized file is one file that either crowds out everything else or gets
// refused as a unit. 8 KB is roughly the largest file in the shipped corpus
// today and is the point at which a note has probably become two notes; 24 KB
// is a quarter of the whole injection budget in a single file, which is not a
// note any more.
//
// Re-measured 2026-09-27: the shipped corpus is 20 files and 125.5 KB, and
// its largest file is field-guide-maintenance-upgrades.md at 19.2 KB. So 8 KB
// is no longer "roughly the largest file"; it is the point two of the field
// guides have grown past, and the warning on those two is doing its job
// rather than reporting a surprise. The numbers stay as they are: they are
// about what belongs in ONE note, and the corpus growing is not a reason to
// call a 19 KB note a note.
const (
	WarnBytes = 8 << 10
	FailBytes = 24 << 10
)

// Level is how much a finding matters. Fail is the only one that changes an
// exit status; a warning is a thing to fix, not a thing to block on.
type Level string

const (
	LevelWarn Level = "warn"
	LevelFail Level = "fail"
)

// Finding is one rule, one file.
type Finding struct {
	Level Level
	Path  string // as the operator would type it: the path the linter was given
	Rule  string
	Msg   string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s: %s (%s)", strings.ToUpper(string(f.Level)), f.Path, f.Msg, f.Rule)
}

// Options is which corpus is being linted. Fleet turns on the rules that only
// make sense for content that travels: a pushed file has to say where it came
// from, and it may not be named for something that reads as authority.
type Options struct {
	// Fleet marks the directory as one of the knowledge-fleet layers
	// (ADR 0017 decision 1), pushed by signed bundle.
	Fleet bool
}

// LintDir walks a corpus directory and returns every finding, sorted by path
// so two runs over the same tree print in the same order.
//
// A directory that does not exist is not a finding: an install with no fleet
// knowledge yet is the ordinary case, and a linter that fails on it would be
// a gate nobody could pass on day one.
func LintDir(root string, opt Options) ([]Finding, error) {
	var out []Finding
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".md") || name == "README.md" || name == "_index.md" {
			return nil
		}
		if !e.Type().IsRegular() {
			out = append(out, Finding{LevelFail, p, "regular-file",
				"not a regular file; the loader will not read it and a bundle may not carry it"})
			return nil
		}
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out = append(out, LintFile(p, body, opt)...)
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

// LintFile applies every rule to one file's bytes. Exported so a caller with
// the content already in hand (a promotion about to write it) can check
// before writing rather than after.
func LintFile(path string, body []byte, opt Options) []Finding {
	var out []Finding
	add := func(l Level, rule, msg string) {
		out = append(out, Finding{l, path, rule, msg})
	}
	name := filepath.Base(path)

	// Size, whatever else the file carries. This one applies to every file,
	// frontmatter or not: the budget does not care what a file declares.
	switch n := len(body); {
	case n > FailBytes:
		add(LevelFail, "size", fmt.Sprintf("%d bytes; the limit is %d — split it into single-topic files", n, FailBytes))
	case n > WarnBytes:
		add(LevelWarn, "size", fmt.Sprintf("%d bytes; over the %d-byte guide — consider splitting it", n, WarnBytes))
	}

	if opt.Fleet {
		// The two names the loader refuses. Linting them is not redundant:
		// a promotion that writes one gets told at the point of writing,
		// rather than by the file silently never being cited.
		if name == model.RolePolicyFile {
			add(LevelFail, "role-policy", model.RolePolicyFile+
				" states what each role may do and is shipped, never pushed")
		}
		if seg := strings.Split(filepath.ToSlash(path), "/"); contains(seg, "nodes") {
			add(LevelFail, "nodes-namespace",
				"a nodes/ directory belongs to per-node knowledge on the node itself; a fleet layer may not use the name")
		}
	}

	fm, _ := model.SplitFrontmatter(string(body))
	if !fm.Present {
		// The whole shipped corpus is in this state and must keep passing:
		// ADR 0017 adds frontmatter, it does not retrofit it. A fleet file
		// is different in degree, not kind — it travelled to get here, and
		// nothing on it says from where — so it earns a warning.
		if opt.Fleet {
			add(LevelWarn, "frontmatter",
				"no frontmatter: nothing on this file says what it is about or where it came from")
		}
		return out
	}

	if strings.TrimSpace(fm.Title) == "" {
		add(LevelFail, "title", "frontmatter without a title")
	}
	if len(fm.Tags) == 0 {
		add(LevelFail, "tags", "frontmatter without tags: the ranker has nothing to scope this file by")
	}
	if strings.TrimSpace(fm.LastReviewed) == "" {
		add(LevelFail, "last_reviewed", "frontmatter without last_reviewed: knowledge with no review date ages invisibly")
	} else if _, err := time.Parse("2006-01-02", strings.TrimSpace(fm.LastReviewed)); err != nil {
		add(LevelFail, "last_reviewed", fmt.Sprintf("last_reviewed %q is not a YYYY-MM-DD date", fm.LastReviewed))
	}
	if opt.Fleet && strings.TrimSpace(fm.Source) == "" {
		add(LevelFail, "source",
			"a fleet knowledge file must carry source: where this came from (a repository and commit, an incident, a node)")
	}
	if fm.Priority != "" && fm.Priority != "high" && fm.Priority != "normal" && fm.Priority != "low" {
		add(LevelWarn, "priority", fmt.Sprintf("priority %q is not one of high, normal, low — only high is read", fm.Priority))
	}
	for _, a := range fm.AppliesTo {
		if strings.ContainsAny(a, "<>=~^") {
			add(LevelWarn, "applies_to", fmt.Sprintf(
				"applies_to %q looks like a version range; matching is by plain token, so this will match nothing", a))
		}
	}
	return out
}

// Failed reports whether any finding blocks. Callers use it for their exit
// status so "warnings printed, exit 0" is one decision made in one place.
func Failed(fs []Finding) bool {
	for _, f := range fs {
		if f.Level == LevelFail {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
