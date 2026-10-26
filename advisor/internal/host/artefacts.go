package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// artefactRow is one file the rollback check considers: the live config or
// deployment file, or a candidate copy of it sitting beside it.
type artefactRow struct {
	name    string
	plain   string // sha256 of the contents
	norm    string // sha256 with the image tag blanked; "" when not applicable
	mod     time.Time
	size    int64
	readErr bool // empty, oversized, or unreadable — not a rollback either way
}

// artefactHashes digests the named artefact and everything beside it.
//
// Through the privilege wrapper when one is configured, so that this process
// never opens the node's config directory. That directory holds rippled.cfg,
// which holds the validator token, and §7 says the Advisor never reads
// validator key material. Reading it here to compute a digest does not leak
// the token — but it means the boundary rests on this code continuing to only
// digest it, and a boundary that rests on good intentions is the kind that
// erodes. With the wrapper doing the read, the account can be refused the
// directory entirely.
//
// Falls back to reading directly when no wrapper is configured. That is the
// operator running the CLI as themselves, where the wrapper adds nothing they
// could not already do.
func (s *State) artefactHashes(kind string) ([]artefactRow, error) {
	if s.Wrapper == "" {
		return s.artefactHashesDirect(kind)
	}
	args := []string{s.Wrapper, "artefact-hashes", kind}
	name := args[0]
	rest := args[1:]
	out, err := s.Runner.Run(s.ctx, name, rest...)
	if err != nil {
		return nil, fmt.Errorf("reading %s through the wrapper: %w", kind, err)
	}
	return parseArtefactRows(string(out))
}

// parseArtefactRows reads the wrapper's tab-separated output. The first field
// says whether the row is the live file or a sibling; the caller decides which
// siblings count.
func parseArtefactRows(out string) ([]artefactRow, error) {
	var rows []artefactRow
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			return nil, fmt.Errorf("unreadable row from the wrapper: %q", line)
		}
		mod, _ := strconv.ParseInt(f[3], 10, 64)
		size, _ := strconv.ParseInt(f[4], 10, 64)
		a := artefactRow{
			name: f[5], plain: f[1], norm: f[2],
			mod: time.Unix(mod, 0), size: size,
			readErr: f[1] == "-",
		}
		// The live file is always first; mark it by name so the caller can
		// separate it without relying on order.
		if f[0] == "origin" {
			a.name = "\x00origin\x00" + a.name
		}
		rows = append(rows, a)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the wrapper returned no rows")
	}
	return rows, nil
}

// originOf splits the live file out of the rows.
func originOf(rows []artefactRow) (artefactRow, []artefactRow) {
	var origin artefactRow
	var rest []artefactRow
	for _, r := range rows {
		if strings.HasPrefix(r.name, "\x00origin\x00") {
			r.name = strings.TrimPrefix(r.name, "\x00origin\x00")
			origin = r
			continue
		}
		rest = append(rest, r)
	}
	return origin, rest
}

// artefactHashesDirect is the same reading done in this process, for the case
// where no wrapper is configured. It produces the identical shape, so the
// logic above it cannot tell which route supplied the numbers.
func (s *State) artefactHashesDirect(kind string) ([]artefactRow, error) {
	origin, err := s.originPath(kind)
	if err != nil {
		return nil, err
	}
	dir := s.BackupDir
	if dir == "" {
		dir = filepath.Dir(origin)
	}
	digest := func(p string, isOrigin bool) artefactRow {
		a := artefactRow{name: filepath.Base(p)}
		if isOrigin {
			a.name = "\x00origin\x00" + a.name
		}
		fi, err := os.Stat(p)
		if err != nil {
			a.readErr = true
			return a
		}
		a.mod, a.size = fi.ModTime(), fi.Size()
		plain, err := hashFile(p)
		if err != nil {
			a.readErr = true
			return a
		}
		a.plain = plain
		if n, err := hashNormalized(p, s.Profile.ImageRepo, s.Profile.Service); err == nil {
			a.norm = n
		}
		return a
	}
	rows := []artefactRow{digest(origin, true)}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Join(dir, e.Name()) == origin {
			continue
		}
		rows = append(rows, digest(filepath.Join(dir, e.Name()), false))
	}
	return rows, nil
}

// originPath resolves the artefact name to the file it refers to.
func (s *State) originPath(kind string) (string, error) {
	switch kind {
	case "node-config":
		if s.Profile.ConfigPath == "" {
			return "", fmt.Errorf("node-config: the profile records no path for this artefact")
		}
		return s.Profile.ConfigPath, nil
	case "deployment-definition":
		if s.Profile.ComposeFile == "" {
			return "", fmt.Errorf("deployment-definition: the profile records no path for this artefact")
		}
		return s.Profile.ComposeFile, nil
	}
	return "", fmt.Errorf("unknown artefact %q", kind)
}
