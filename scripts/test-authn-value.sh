#!/usr/bin/env bash
# scripts/authn-value.sh, the one reader of authn.yaml's values for the shell
# scripts (#1358), and the two scripts that had a reader of their own.
#
#   bash scripts/test-authn-value.sh
#
# install.sh and scripts/aperire-setup.sh read public_url with a sed that took
# a YAML list for unset, so a host whose public_url was a list got the unset
# path ("still localhost", no enrollment link). The dashboard accepts a list
# (#1231) and the pair command reads one (#1275); all three source this now.
# The pick of a list is the dashboard's firstUsableUrl(), host rules and all;
# scripts/test-fleet-pair.sh runs both on the same lists.
#
# install.sh's own closing text is driven for real in
# scripts/test-install-relay-wiring.sh (the authn_row rows). The guided setup
# refuses to run without a terminal, so its real authn_value and
# authn_is_localhost are lifted out of the file here and run against the
# fixtures, the way scripts/test-aperire-menu.sh lifts its step4_verify.
# shellcheck disable=SC2016  # the lifted scripts below hold the inner shell's own variables
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
is()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got: [$2] | want: [$3]"; fi; }

# shellcheck source=scripts/authn-value.sh
. "$REPO_DIR/scripts/authn-value.sh"

F="$TMP/authn.yaml"
put() { printf '%b' "$1" > "$F"; }

echo "1. authn_file_value: a scalar stays one string, a list is the dashboard's comma-joined line"
put 'public_url: https://dash.example.com\nrp_id: dash.example.com\n'
is "one string" "$(authn_file_value "$F" public_url)" "https://dash.example.com"
is "  and the key after it" "$(authn_file_value "$F" rp_id)" "dash.example.com"
put 'public_url: "https://dash.example.com"\n'
is "a double-quoted string loses its quotes" "$(authn_file_value "$F" public_url)" "https://dash.example.com"
put "public_url: 'https://dash.example.com'\n"
is "a single-quoted string loses its quotes" "$(authn_file_value "$F" public_url)" "https://dash.example.com"
put 'public_url:\n  - https://a.example\n  - "https://b.example"\n  - '"'"'https://c.example'"'"'\nrp_id: a.example\n'
is "a block list is joined, quotes off every entry" "$(authn_file_value "$F" public_url)" "https://a.example,https://b.example,https://c.example"
is "  and the key after the list is still its own" "$(authn_file_value "$F" rp_id)" "a.example"
put 'public_url:\n- https://a.example\n- https://b.example\n'
is "a block list that is not indented" "$(authn_file_value "$F" public_url)" "https://a.example,https://b.example"
put 'public_url: ["https://a.example", '"'"'https://b.example'"'"']\n'
is "a flow list is joined, quotes off every entry" "$(authn_file_value "$F" public_url)" "https://a.example, https://b.example"
put 'public_url:\n  # the first is the one links are built from\n  - https://a.example\n\n  - https://b.example\n'
is "a comment and a blank line inside a block list are skipped" "$(authn_file_value "$F" public_url)" "https://a.example,https://b.example"
put 'magic_link:\n  public_url: https://nested.example\n'
is "a key nested under another is not the key" "$(authn_file_value "$F" public_url)" ""
put 'public_url:\nrp_id: x\n'
is "a key with nothing under it is empty" "$(authn_file_value "$F" public_url)" ""
put 'rp_id: x\n'
is "a key that is absent is empty" "$(authn_file_value "$F" public_url)" ""
is "a file that is absent is empty, and not an error" "$(authn_file_value "$TMP/none.yaml" public_url; echo "rc=$?")" "rc=0"

echo
echo "2. authn_public_url: the one entry a script speaks of is the dashboard's pick (firstUsableUrl; scripts/test-fleet-pair.sh compares the two on a table of lists)"
put 'public_url: https://dash.example.com/\n'
is "one string, its trailing slash off" "$(authn_public_url "$F")" "https://dash.example.com"
put 'public_url:\n  - http://localhost:7800\n  - https://dash.example.com\n'
is "a block list that leads with localhost: the public entry behind it" "$(authn_public_url "$F")" "https://dash.example.com"
put 'public_url: [http://localhost:7800, https://dash.example.com]\n'
is "a flow list that leads with localhost: the same pick" "$(authn_public_url "$F")" "https://dash.example.com"
put 'public_url:\n  - https://a.example\n  - https://b.example\n'
is "two public entries: the first" "$(authn_public_url "$F")" "https://a.example"
put 'public_url:\n  - http://localhost:7800\n  - http://127.0.0.1:7800\n'
is "nothing but localhost: the first, so a default install keeps showing it" "$(authn_public_url "$F")" "http://localhost:7800"
# Every spelling of this machine the dashboard's isLocalOnlyHost() knows, leading
# a public entry. A pick that took only the words localhost and 127.0.0.1 for
# local would return each of these and call the host public.
for lead in 'http://[::1]:7800' 'http://0.0.0.0:7800' 'http://127.0.0.2:7800' 'http://box.localhost:7800' \
            'http://localhost.:7800' 'http://[::ffff:127.0.0.1]:7800' 'http://127.1:7800' 'http://2130706433:7800'; do
  put "public_url:\n  - $lead\n  - https://dash.example.com\n"
  is "  $lead leads: the public entry behind it" "$(authn_public_url "$F")" "https://dash.example.com"
done
put 'public_url:\n  - dash.example.com\n  - https://b.example\n'
is "an entry that is not a URL is passed over, as the dashboard passes over it" "$(authn_public_url "$F")" "https://b.example"
put 'public_url:\n  - https://dash.example.com/app/\n'
is "an entry with a path keeps it, and loses the trailing slash" "$(authn_public_url "$F")" "https://dash.example.com/app"
put 'public_url:\n  - https://user:pw@evil.example\n  - https://b.example\n'
is "an entry with a user name is passed over" "$(authn_public_url "$F")" "https://b.example"

echo
echo "2b. authn_public_url_is_local: still the shipped default?"
is_local() { if authn_public_url_is_local "$F"; then echo local; else echo public; fi; }
put 'rp_id: x\n';                                              is "no public_url: local" "$(is_local)" "local"
put 'public_url: http://localhost:7800\n';                     is "the shipped default: local" "$(is_local)" "local"
put 'public_url: https://dash.example.com\n';                  is "a real address: public" "$(is_local)" "public"
put 'public_url:\n  - http://[::1]:7800\n  - http://0.0.0.0:7800\n'; is "a list of nothing but other spellings of this machine: local" "$(is_local)" "local"
put 'public_url:\n  - http://[::1]:7800\n  - https://dash.example.com\n'; is "one of them leading a real address: public" "$(is_local)" "public"
put 'public_url: dash.example.com\n';                          is "a bare name that is not a URL and not localhost: public, as it always was" "$(is_local)" "public"
put 'public_url: localhost:7800\n';                            is "a bare localhost:port that is not a URL: local, as it always was" "$(is_local)" "local"
put 'rp_id: x\n'
is "no public_url: empty" "$(authn_public_url "$F")" ""

echo
echo "3. the guided setup's own reader and localhost test (lifted out of aperire-setup.sh)"
SETUP="$REPO_DIR/scripts/aperire-setup.sh"
lift_fn() { # <file> <name>: one function, one-liners included
  awk -v n="$2" '
    $0 ~ "^" n "\\(\\)[[:space:]]*\\{" { p = 1; print; if ($0 ~ /\}[[:space:]]*$/) exit; next }
    p { print }
    p && /^}$/ { exit }' "$1"
}
{
  echo '. "$1"'
  echo 'AUTHN="$2"'
  lift_fn "$SETUP" authn_value
  lift_fn "$SETUP" authn_is_localhost
  echo 'printf "%s|" "$(authn_public_url "$AUTHN")"; if authn_is_localhost; then echo local; else echo public; fi'
} > "$TMP/setup-lift.sh"
if grep -q '^authn_value() {' "$TMP/setup-lift.sh" && grep -q '^authn_is_localhost() {' "$TMP/setup-lift.sh"; then
  ok "the lift found authn_value and authn_is_localhost in the real guided setup"
else
  bad "the lift found the setup's two functions" "$(grep -E '^[a-z_]+\(\)' "$TMP/setup-lift.sh")"
fi
setup_says() { bash "$TMP/setup-lift.sh" "$REPO_DIR/scripts/authn-value.sh" "$F" 2>&1; }
put 'public_url: https://dash.example.com\nrp_id: dash.example.com\n'
is "setup, one string: a public address" "$(setup_says)" "https://dash.example.com|public"
put 'public_url:\n  - http://localhost:7800\n  - https://dash.example.com\n'
is "setup, a block list: a public address, not unset" "$(setup_says)" "https://dash.example.com|public"
put 'public_url: ["http://localhost:7800", "https://dash.example.com"]\n'
is "setup, a flow list: a public address, not unset" "$(setup_says)" "https://dash.example.com|public"
put 'public_url:\n  - http://localhost:7800\n  - http://127.0.0.1:7800\n'
is "setup, a list of localhost only: still localhost" "$(setup_says)" "http://localhost:7800|local"
put 'public_url:\n  - http://[::1]:7800\n  - https://dash.example.com\n'
is "setup, a list led by [::1]: a public address" "$(setup_says)" "https://dash.example.com|public"
put 'public_url:\n  - http://[::1]:7800\n  - http://0.0.0.0:7800\n'
is "setup, a list of other spellings of this machine only: still localhost" "$(setup_says)" "http://[::1]:7800|local"
put 'public_url: http://localhost:7800\n'
is "setup, one localhost string: still localhost" "$(setup_says)" "http://localhost:7800|local"
put 'rp_id: x\n'
is "setup, no public_url: localhost, as before" "$(setup_says)" "|local"
put 'public_url:\n  - https://a.example\nrp_id: a.example\n'
{
  echo '. "$1"'; echo 'AUTHN="$2"'
  lift_fn "$SETUP" authn_value
  echo 'authn_value rp_id'
} > "$TMP/setup-rp.sh"
is "setup, rp_id beside a list: still read" "$(bash "$TMP/setup-rp.sh" "$REPO_DIR/scripts/authn-value.sh" "$F" 2>&1)" "a.example"

echo
echo "4. no reader of public_url is written out by hand again"
for f in install.sh scripts/aperire-setup.sh scripts/aperire-fleet-pair.sh; do
  if grep -q 'authn-value.sh' "$REPO_DIR/$f" && ! grep -Eq "sed -n \"s/\^\\\$\{1\}:|awk -v key=" "$REPO_DIR/$f"; then
    ok "$f sources authn-value.sh and holds no reader of its own"
  else
    bad "$f sources authn-value.sh and holds no reader of its own" "$(grep -nE 'authn-value|sed -n "s/\^|awk -v key=' "$REPO_DIR/$f")"
  fi
done

echo
echo "pass=$PASS fail=$FAIL"
if [[ $FAIL -eq 0 ]]; then echo "ALL PASS"; exit 0; fi
echo "FAILED"
exit 1
