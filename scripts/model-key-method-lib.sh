#!/usr/bin/env bash
# model-key-method-lib.sh, the one place that decides how this host keeps the
# Advisor's model API key, and the one place that writes the systemd directive
# that loads it (#708).
#
# Sourced, never executed. By the sealer, the credential check, the advisord
# installer, the terminal model setup, and both preflights.
#
# And MIRRORED, not sourced, by one more program: the fleet broker
# (aperire-fleet-broker.sh), for the aggregator's own fleet model store
# (#711). The broker is installed to /usr/local/sbin as one file with no
# sibling library, so the block between the KEY-METHOD-LIB markers below is
# copied into it byte for byte, and scripts/test-fleet-broker.sh diffs the two
# copies. Change it here, copy it there, or CI goes red. The same decision on
# every program that keeps a model key, never a second opinion.
#
#   . "$REPO/scripts/model-key-method-lib.sh"
#   method="$(aperire_key_method)"
#   blob="$(aperire_key_blob_path /etc/aperire/creds model-api-key-xai "$method")"
#
# ---- why there are two methods --------------------------------------
#
# `systemd-creds` and `LoadCredentialEncrypted=` first shipped in systemd 250.
# Ubuntu 22.04 LTS ships systemd 249 and has neither, and xrpl.org lists 22.04
# as one of the two best-supported platforms for a validator, so real operators
# run it. On such a host every earlier version of this project installed
# cleanly, paired cleanly, and then refused every model key with "systemd-creds
# could not seal the key on this host". The node could never hold a model and
# nobody learned that until the seal failed (#708).
#
# So there are two methods, and a host uses whichever one it can:
#
#   sealed   systemd 250 or newer, with systemd-creds on the PATH. The key is
#            encrypted to this machine with `systemd-creds encrypt` and the
#            unit loads it with LoadCredentialEncrypted=. The blob is useless
#            on any other host.
#
#   plain    anything older. The key is kept as a root:root 0600 file inside
#            /etc/aperire/creds, which is itself root:root 0700, and the unit
#            loads it with LoadCredential=. Same credential name, so the
#            Advisor reads $CREDENTIALS_DIRECTORY/<name> exactly as before and
#            knows nothing about which method put it there.
#
# What the fallback trades away, stated plainly: the blob is no longer bound to
# the machine, so a copy of that file is a working key anywhere. What it does
# NOT trade away is who can read it on this host. Without a TPM, which is the
# ordinary case on a VPS, `systemd-creds` encrypts with
# /var/lib/systemd/credential.secret, a 0400 root:root file sitting beside the
# blob. An attacker who can read one can read the other. On such a host the two
# methods have the same reader set, root, and differ only in portability. The
# operator ruled 22.04 supported on exactly that reading (#708, 2026-09-28).
#
# ---- how the two are told apart, forever -----------------------------
#
# By the PATH the key lives at, never by a flag in a config file that could
# disagree with what is on disk:
#
#   sealed   /etc/aperire/creds/<name>
#   plain    /etc/aperire/creds/<name>.plain
#
# One directory, two names, and the file that is there says what it is. That
# matters for the host whose credential outlives the thing that wrote it: a
# `--keep` uninstall keeps /etc/aperire, and the next install has to wire the
# key back with no drop-in to read. It also matters in the other direction. An
# operator who upgrades 22.04 to 24.04 in place keeps a plain key at a path
# that still says "plain", and the installer keeps loading it with
# LoadCredential= instead of handing a plaintext file to `systemd-creds
# decrypt` and quarantining a perfectly good key.
#
# A seal removes the other form for the same name (aperire-seal-model-key.sh).
# Sealing a new key has never revoked an old sealed blob, which is inert
# anywhere else; a plaintext key left behind is a live key, and that is not the
# same thing.

# --- KEY-METHOD-LIB-BEGIN ---
# The suffix, in one place. Named rather than spelled inline anywhere else so
# a change here cannot leave half the tree looking at the other name.
APERIRE_KEY_PLAIN_SUFFIX='.plain'

# aperire_systemd_major. Prints this host's systemd major version, or fails.
#
# The leading run of digits out of the second field, the same rule
# scripts/preflight.sh reads it with: the first line is "systemd 255
# (255.4-1ubuntu8.17)" on one host and carries a distro suffix on another, and
# taking the field whole compares "255" with "249~rc1".
aperire_systemd_major() {
  local line ver
  line="$(systemctl --version 2>/dev/null | head -1)"
  [[ -n "$line" ]] || return 1
  ver="$(printf '%s' "$line" | awk '{print $2}' | grep -oE '^[0-9]+')"
  [[ -n "$ver" ]] || return 1
  printf '%s\n' "$ver"
}

# aperire_key_method. Prints `sealed` or `plain`. Never fails: every host has
# one of the two, and a host this cannot measure gets the method that works
# everywhere.
#
# Both halves are asked, not just the version. A minimal image can carry
# systemd 255 with the systemd-creds binary split into a package that is not
# installed, and a version test alone would send that host down a path whose
# first command is not there.
aperire_key_method() {
  local ver
  command -v systemd-creds >/dev/null 2>&1 || { printf 'plain\n'; return 0; }
  # Only a version this host will actually say, and says is older than 250,
  # sends it down the fallback from here. A version that cannot be read is not
  # evidence of anything, and the binary being on the PATH is the stronger
  # fact: a host whose systemd-creds runs can seal, whatever `systemctl
  # --version` did or did not print.
  ver="$(aperire_systemd_major)" || { printf 'sealed\n'; return 0; }
  if (( ver >= 250 )); then printf 'sealed\n'; else printf 'plain\n'; fi
}

# aperire_key_method_line. One sentence for an operator, said by both
# preflights and by the model setup, so a host tells you up front how it will
# keep the key rather than at the first failure.
aperire_key_method_line() { # $1 = method (optional; measured when absent)
  local method="${1:-}" ver
  [[ -n "$method" ]] || method="$(aperire_key_method)"
  ver="$(aperire_systemd_major || true)"
  if [[ "$method" == sealed ]]; then
    printf 'sealed to this machine with systemd-creds (systemd %s)\n' "${ver:-unknown}"
  elif command -v systemd-creds >/dev/null 2>&1; then
    printf 'a root-only file loaded with LoadCredential= (systemd %s is older than 250, which is where systemd-creds began)\n' "${ver:-unknown}"
  else
    printf 'a root-only file loaded with LoadCredential= (this host has no systemd-creds)\n'
  fi
}

# aperire_key_blob_path $1=creds dir $2=credential name $3=method.
aperire_key_blob_path() {
  case "$3" in
    plain) printf '%s/%s%s\n' "$1" "$2" "$APERIRE_KEY_PLAIN_SUFFIX" ;;
    *)     printf '%s/%s\n' "$1" "$2" ;;
  esac
}

# --- KEY-METHOD-LIB-END ---

# aperire_key_directive $1=method. The systemd setting that loads it.
aperire_key_directive() {
  case "$1" in
    plain) printf 'LoadCredential\n' ;;
    *)     printf 'LoadCredentialEncrypted\n' ;;
  esac
}

# aperire_key_dropin_text $1=credential name $2=blob path $3=method $4=writer.
#
# The whole drop-in, in one place, because two programs write it (the sealer
# and install-advisord.sh), and a byte of drift between them is a host whose
# re-run of the installer rewrites a file the sealer would have left alone.
aperire_key_dropin_text() {
  local name="$1" path="$2" method="$3" writer="$4" directive
  directive="$(aperire_key_directive "$method")"
  cat <<DROPINEOF
# Written by $writer. The model key this Advisor loads.
#
# Removed by:  sudo aperire-seal-model-key --reset
#
# Do not edit by hand. systemd refuses to start a unit that declares a
# credential file which is not there (243/CREDENTIALS), so this line and
# $path come and go together.
[Service]
$directive=$name:$path
DROPINEOF
}
