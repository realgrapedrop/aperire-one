#!/usr/bin/env bash
# docker-ask-lib.sh, the one place in this tree that knows how to ask docker
# what is running. Sourced, never executed.
#
# The bug it exists to stop: `docker ps 2>/dev/null` reads a refused answer as
# an absence. "Docker answered, nothing is running here" and "docker would not
# tell me" arrive as the same empty string, and every caller that treats the
# second as the first decides something on evidence it never had. Six sites in
# this tree did (#140, #142). On one of them the consequence is not a wrong
# decision but wrong data: the relay picks the node's name from the running
# container, and a name chosen by accident forks one node into two metric
# series that nothing can put back together.
#
#   said=''; ask=0
#   said="$(docker_ask '{{.Names}} {{.Image}}')" || ask=$?
#   case $ask in
#     0) ... ;;              # $said is the answer. It may legitimately be empty
#     1) ... ;;              # nothing can be running here: no docker installed,
#                            # or no daemon. A true absence, safe to act on
#     2) ... ;;              # docker is here and would not answer this account
#                            # or root. NOT an absence: stop, or keep what you
#                            # had. $said is docker's complaint
#   esac
#
# One variable carries both because callers read it through a command
# substitution, and a subshell cannot hand a second one back. A reason
# returned in a global would be empty at every call site in this tree, which
# is a quieter version of the bug this file exists to remove.
#
# Extra `docker ps` arguments go after the format: docker_ask '{{.ID}}' --no-trunc
#
# The shape is detect_node() in scripts/get-aperire.sh, which keeps its own
# copy on purpose: it is the script strangers pipe from a URL into a root
# shell, it arrives alone, and it can source nothing.

docker_ask() { # $1 = --format template, $@ = further `docker ps` arguments
  local fmt="$1"; shift
  if ! command -v docker >/dev/null 2>&1; then
    printf '%s' 'docker is not installed here'
    return 1
  fi

  # stdout and stderr are kept apart on purpose: merged, a docker warning
  # would be read as a line of the container list. The complaint is read back
  # in a second call, on the failure path only, where it is cheap.
  local out rc=0 derr='' serr=''
  out="$(docker ps "$@" --format "$fmt" 2>/dev/null)" || rc=$?
  if [[ $rc -ne 0 ]]; then
    derr="$(docker ps "$@" --format '{{.Names}}' 2>&1 >/dev/null | head -1 || true)"
    if command -v sudo >/dev/null 2>&1; then
      rc=0
      out="$(sudo -n docker ps "$@" --format "$fmt" 2>/dev/null)" || rc=$?
      if [[ $rc -ne 0 ]]; then
        serr="$(sudo -n docker ps "$@" --format '{{.Names}}' 2>&1 >/dev/null | head -1 || true)"
      fi
    else
      serr='sudo is not installed here'
    fi
  fi

  if [[ $rc -ne 0 ]]; then
    # Both complaints, because they answer different halves of the question.
    local why="${derr:-no reason given}"
    [[ -n "$serr" ]] && why="${why}; ${serr}"
    printf '%s' "$why"
    # Either one naming a daemon that is not running settles it: no daemon
    # means no container, for this account and for root alike. That is an
    # answer, and the only failure here that is one.
    if printf '%s' "$why" \
       | grep -qiE 'cannot connect to the docker daemon|is the docker daemon running|docker daemon is not running'; then
      return 1
    fi
    return 2
  fi

  printf '%s' "$out"
  return 0
}

# ── Containers created from a digest (#894, #896) ────────────────────────────
# A container created from a digest reference (rippleci/xrpld@sha256:..., the
# shape the Advisor's own upgrade makes) has no name to show: docker ps prints
# the short image ID in the Image column, so a match on the image name stops
# finding the node. docker inspect still has what the container was created
# from, in .Config.Image.

# The image a container was created from, as it was written (Config.Image),
# with any @sha256:... stripped. Asked the way docker_ask asks: this account,
# then sudo -n. Empty output counts as a failure. On failure prints docker's
# own complaint, this account's and then sudo's when sudo was asked, and
# returns 1. --type container so a container that is gone is not answered by
# an image or a volume that shares its name.
docker_config_image() { # $1 = container name or ID
  local out derr serr='' why
  if out="$(docker inspect --type container "$1" --format '{{.Config.Image}}' 2>/dev/null)" && [[ -n "$out" ]]; then
    printf '%s' "${out%%@*}"; return 0
  fi
  derr="$(docker inspect --type container "$1" --format '{{.Config.Image}}' 2>&1 >/dev/null | head -1 || true)"
  if command -v sudo >/dev/null 2>&1; then
    if out="$(sudo -n docker inspect --type container "$1" --format '{{.Config.Image}}' 2>/dev/null)" && [[ -n "$out" ]]; then
      printf '%s' "${out%%@*}"; return 0
    fi
    serr="$(sudo -n docker inspect --type container "$1" --format '{{.Config.Image}}' 2>&1 >/dev/null | head -1 || true)"
  fi
  why="${derr:-no reason given}"
  [[ -n "$serr" ]] && why="${why}; ${serr}"
  printf '%s' "$why"
  return 1
}

# Rewrites docker ps rows so that an Image column that is a bare image ID
# carries the name the container was created from instead. Rows come in on
# $1, the first field of each is the container (name or ID, what docker
# inspect takes) and the second is the Image column, so a caller that also
# asks for {{.Command}} puts it after Image, where a command's own words
# cannot be taken for an image ID. Only that one field is ever looked at or
# changed; the rest of the row, and every separator, is left as it was.
# Returns 0 and the rewritten text, or 2 and docker's complaint when docker
# would not say: a container whose image cannot be read is not a container
# that failed to match, so the caller stops or keeps what it had, as it does
# for a refused docker ps. The one exception is a container that is gone by
# the time it is asked about (either account saying "no such object"), which
# is skipped.
docker_resolve_image_ids() { # $1 = docker ps rows
  local rows="$1" line ref rest lead img tail res out='' nl=$'\n'
  local idre='^(sha256:)?[0-9a-fA-F]{12,64}$'
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      ref="${line%%[[:space:]]*}"
      rest="${line#"$ref"}"
      lead="${rest%%[![:space:]]*}"
      rest="${rest#"$lead"}"
      img="${rest%%[[:space:]]*}"
      tail="${rest#"$img"}"
      if [[ -n "$img" && "$img" =~ $idre ]]; then
        if res="$(docker_config_image "$ref")"; then
          line="${ref}${lead}${res}${tail}"
        elif ! printf '%s' "$res" | grep -qiE 'no such (object|container)'; then
          printf '%s' "$res"
          return 2
        fi
      fi
    fi
    out+="${line}${nl}"
  done <<<"$rows"
  printf '%s' "${out%"$nl"}"
  return 0
}
