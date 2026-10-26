package model

import "strings"

// YAML frontmatter on a knowledge file — ADR 0017 decision 2. The corpus
// gains taxonomy directories and a small metadata block per file so the
// keyword ranker can scope by tag and path instead of by filename prefix
// alone.
//
// Parsed by hand, and that is a decision rather than an omission. advisord
// carries zero external dependencies (go.mod has no require block at all),
// a property worth keeping for a binary that verifies signatures against a
// validator's approval trust. The block this reads is the one the lint
// enforces and the promotion path writes: flat `key: value` lines, flow
// lists (`tags: [a, b]`) and block lists (`- a` on following lines). It is
// lenient by design — an unrecognised key is skipped, a malformed block is
// treated as no frontmatter at all — because the failure mode has to be "the
// file ranks the way an unannotated file ranks", never "the file disappears".
//
// Every field is optional at parse time. Which fields a file MUST carry is
// the lint's business (internal/knowledge), not this parser's: the corpus
// that ships today has no frontmatter anywhere, and it has to keep working
// exactly as it does now.

// Frontmatter is the parsed block. Present distinguishes "the file opened
// with a --- block" from "every field happened to be empty", which is the
// difference between a file the lint judges and a file it leaves alone.
type Frontmatter struct {
	Present      bool
	Title        string
	Tags         []string
	AppliesTo    []string
	Priority     string
	LastReviewed string
	Source       string
	ProposedBy   string
	PromotedBy   string
}

// fenceLine is the delimiter, matched exactly: three dashes alone on a line.
const fenceLine = "---"

// SplitFrontmatter separates a knowledge file's frontmatter from its body.
//
// A file that does not open with a fence is returned unchanged with an empty
// Frontmatter — the whole shipped corpus takes this path, and takes it to a
// byte-identical body, which is what keeps today's rendered prompt unmoved.
// An opening fence with no closing one is treated the same way: the file is
// all body. Half-parsing a truncated header would silently swallow real
// content.
func SplitFrontmatter(body string) (Frontmatter, string) {
	// A byte-order mark ahead of the fence is the one leading byte worth
	// tolerating: an editor writes it, no author sees it, and it would
	// otherwise make the whole header invisible.
	rest := strings.TrimPrefix(body, "\ufeff")
	lines := strings.Split(rest, "\n")
	if len(lines) == 0 || strings.TrimRight(lines[0], "\r \t") != fenceLine {
		return Frontmatter{}, body
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if t := strings.TrimRight(lines[i], "\r \t"); t == fenceLine || t == "..." {
			end = i
			break
		}
	}
	if end < 0 {
		return Frontmatter{}, body
	}
	fm := parseFrontmatterLines(lines[1:end])
	fm.Present = true
	return fm, strings.Join(lines[end+1:], "\n")
}

// parseFrontmatterLines reads the block between the fences.
//
// Recognised shapes, and nothing else:
//
//	title: Reading the validations stream
//	tags: [consensus, validations]
//	applies_to:
//	  - xrpld
//	  - rippled
//	priority: high
//
// A line that is not `key: value` and not a `- item` continuation of the
// previous key is skipped. Values keep their case for display (title,
// source, the two attributions); the fields ranking compares are lowercased
// at the point of comparison, not here, so a citation still reads the way
// the author wrote it.
func parseFrontmatterLines(lines []string) Frontmatter {
	var fm Frontmatter
	current := ""
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A block-list item continues whichever key was last seen.
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			item := unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")))
			if item != "" {
				appendListField(&fm, current, item)
			}
			continue
		}
		idx := strings.IndexByte(trimmed, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		val := strings.TrimSpace(trimmed[idx+1:])
		current = key
		if val == "" {
			continue // a block list follows, or the key carries nothing
		}
		switch key {
		case "tags", "applies_to":
			for _, item := range splitList(val) {
				appendListField(&fm, key, item)
			}
		case "title":
			fm.Title = unquote(val)
		case "priority":
			fm.Priority = strings.ToLower(unquote(val))
		case "last_reviewed":
			fm.LastReviewed = unquote(val)
		case "source":
			fm.Source = unquote(val)
		case "proposed_by":
			fm.ProposedBy = unquote(val)
		case "promoted_by":
			fm.PromotedBy = unquote(val)
		}
	}
	return fm
}

func appendListField(fm *Frontmatter, key, item string) {
	switch key {
	case "tags":
		fm.Tags = append(fm.Tags, item)
	case "applies_to":
		fm.AppliesTo = append(fm.AppliesTo, item)
	}
}

// splitList reads a flow list (`[a, b]`) or a bare comma-separated value.
// Both appear in real corpora and both cost one line to accept.
func splitList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, part := range strings.Split(v, ",") {
		if item := unquote(strings.TrimSpace(part)); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
