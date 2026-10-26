#!/usr/bin/env bash
# term-style.sh - the one palette the install path is dressed in.
#
# Sourced, never run:
#
#     # shellcheck source=scripts/term-style.sh
#     . "${SCRIPTS_DIR}/term-style.sh"
#
# It defines nothing but strings. After sourcing, S_BOLD S_GREEN S_AMBER
# S_RED S_DIM S_CYAN S_OFF dress stdout and E_* dress stderr, and every one
# of them is empty unless that stream is a terminal. So the call sites stay
# ordinary:
#
#     echo "  ${S_GREEN}installed: ${TARGET}${S_OFF}"
#     echo "${E_RED}error: ...${E_OFF}" >&2
#
# There is one deliberate copy of the block below, inline at the top of
# scripts/get-aperire.sh. That script runs before any checkout exists and has
# nothing to source, so it carries its own. The two are compared byte for byte
# by scripts/test-get-aperire.sh, which fails on any drift between them.

# >>> aperire palette >>>
# Colour says what happened. It is never decoration, and nothing is said in
# colour alone: bold heads a phase, green marks a thing that was read back as
# done, amber marks degraded-but-continuing, red marks a refusal, dim carries
# the detail under a line, and cyan marks a command or an address meant to be
# typed or opened (the same cyan the operator menu uses for the command it is
# about to run).
#
# Set once per stream, because the two streams need not be the same terminal.
# A run whose stdout is a log file and whose stderr is still the operator's
# window must put no escapes in the file and must not strip them from the
# window, so S_ dresses stdout and E_ dresses stderr. Anything written with
# >&2 uses E_.
#
# Every one of them is the empty string when the stream is not a terminal,
# when NO_COLOR is set to anything (https://no-color.org), or under TERM=dumb.
# So a piped, redirected or logged run is byte-plain and greps exactly the way
# it always did. The values hold real escape bytes rather than backslash text,
# which is what lets a plain `echo "${S_GREEN}...${S_OFF}"` carry them.
_aperire_style() {  # $1 = variable prefix, $2 = the fd it dresses
  local p="$1" fd="$2" on=1 n
  [[ -z "${NO_COLOR:-}" ]] || on=0
  [[ "${TERM:-}" != "dumb" ]] || on=0
  [[ -t "$fd" ]] || on=0
  for n in BOLD GREEN AMBER RED DIM CYAN OFF; do printf -v "${p}${n}" '%s' ''; done
  [[ $on -eq 1 ]] || return 0
  printf -v "${p}BOLD"  '\033[1m'
  printf -v "${p}GREEN" '\033[32m'
  printf -v "${p}AMBER" '\033[33m'
  printf -v "${p}RED"   '\033[31m'
  printf -v "${p}DIM"   '\033[2m'
  printf -v "${p}CYAN"  '\033[36m'
  printf -v "${p}OFF"   '\033[0m'
}
_aperire_style S_ 1
_aperire_style E_ 2
# <<< aperire palette <<<
