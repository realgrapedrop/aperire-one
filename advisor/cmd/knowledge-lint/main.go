// Command knowledge-lint checks a knowledge corpus against the mechanical
// rules in ADR 0017 decision 2: required frontmatter fields, a size budget,
// and — for the fleet layers — a source for anything that travelled.
//
//	knowledge-lint knowledge                 # the shipped corpus (CI)
//	knowledge-lint -fleet knowledge-fleet    # before a bundle is built
//
// It prints one line per finding and exits 1 if any of them blocks. A file
// with no frontmatter is not a failure: the shipped corpus has none, and this
// gate arrived after it did.
package main

import (
	"flag"
	"fmt"
	"os"

	"aperire-advisor/internal/knowledge"
)

// version is stamped at build time via -ldflags -X main.version=<commit>, the
// way aperire-executor's is, so every build site of the Advisor's binaries
// reads alike and the stamp has a symbol to land in. "dev" when unstamped.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the commit this binary was built from and exit")
	fleet := flag.Bool("fleet", false, "lint as a fleet layer: source is required, and the pushed-content rules apply")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	dirs := flag.Args()
	if len(dirs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: knowledge-lint [-fleet] <dir>...")
		os.Exit(2)
	}

	var all []knowledge.Finding
	for _, d := range dirs {
		found, err := knowledge.LintDir(d, knowledge.Options{Fleet: *fleet})
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", d, err)
			os.Exit(2)
		}
		all = append(all, found...)
	}

	warns, fails := 0, 0
	for _, f := range all {
		fmt.Println(f)
		if f.Level == knowledge.LevelFail {
			fails++
		} else {
			warns++
		}
	}
	if knowledge.Failed(all) {
		fmt.Fprintf(os.Stderr, "knowledge-lint: %d blocking, %d to look at\n", fails, warns)
		os.Exit(1)
	}
	fmt.Printf("knowledge-lint: clean (%d to look at)\n", warns)
}
