#!/usr/bin/env python3
"""Owns, plants and reads files under advisor/state without ever following a name.

advisor/state belongs to the Advisor's own account on a host that has moved
onto one (install-advisor-account.sh). Every root operation this tree aims at
a file in there BY NAME is therefore a root primitive that account can
redirect, by swapping the name for a link between the moment root resolves it
and the moment root acts on it. #652 closed that for the re-own; #661 closed
it for the create; #703 closes it for the rest of the root programs (the
sealer, the credential check, the fleet join, the orphan adoption) and for
root's reads. This file is the only copy of any of it.

Ten subcommands, one rule:

  own      PATH UID GID MODE        re-own a file or directory already here
  own-many UID GID MODE             the same, for NUL-separated paths on stdin
  plant    PATH UID GID MODE [--stdin]  create (or replace) a file
  copy-tree SRC DST UID GID --root DIR
                                    put a finished tree, built where only root
                                    could touch it, at DST: every directory and
                                    file is created new on the destination's
                                    own descriptor, owned by UID:GID from the
                                    moment it holds its content (files 0600, or
                                    0700 if SRC's carries an execute bit;
                                    directories 0700), and nothing that is
                                    already there is written to, followed or
                                    changed. DST is made, or is an empty
                                    directory; anything else at that name is
                                    refused (#1154). Exits 3 if anything was
                                    refused and what the copy made was taken
                                    back, 4 if anything it made is still at DST
                                    or a name it made no longer holds what it
                                    made (the take-back goes by inode, not by
                                    name: #1163). A SIGINT, SIGTERM or SIGHUP
                                    is a refusal during the copy and is waited
                                    out during the take-back, so a stop does
                                    not leave the set at DST (#1164)
  mkdir    PATH UID GID MODE        create a directory, or confirm one is
                                    already there; refuses a non-directory
                                    (a symlink among them) at that name.
                                    With --mode-if-new, MODE (and the owner)
                                    are set only on a directory this call
                                    made, and one already there is left
                                    exactly as it is (#1048)
  read     PATH                     print a file's bytes, refusing a link
                                    (--meta puts "<uid> <gid> <mode>" first)
  ancestors PATH                    report, and change nothing: every component
                                    above --root the rule below would refuse
  unlink   PATH --root DIR          remove one name from a directory, on the
                                    walked descriptor; a link at the name is
                                    removed and never followed, a name that is
                                    not there is not an error, a directory is
                                    refused
  remove-tree PATH --root DIR       remove a directory and everything under it,
                                    on descriptors: a link inside it is removed
                                    and never followed, a link or anything but
                                    a directory at PATH is refused, nothing on
                                    another filesystem is entered, and a name
                                    that is not there is not an error. Both
                                    removing verbs need --root and refuse a
                                    PATH that is not strictly below it
  narrow   DIR                      take group and other write off one
                                    directory, on a descriptor, and print
                                    "<was> <now>" in octal

  UID, GID  numeric, "" to leave that half alone, or "dir" to take the value
            from the containing directory (what `chown --reference=<dir>` did)
  MODE      octal, or "" to leave the mode alone (own and own-many only)
  --stdin   plant's content is read from standard input; without it the
            file is created empty

Options, accepted anywhere after the subcommand:

  --judge-root  ancestors, copy-tree and own-many: judge --root itself too. See
                THE ANCESTOR RULE.
  --root DIR    the directory the ancestor rule below stops at. Defaults to
                the file's own parent, which is right for every single-file
                call; own-many is given the tree it is walking.
  --owner UID   the account that owns the install, numerically. Without it,
                the walk infers it: see THE ANCESTOR RULE.
  --also-owner UID
                the service account the installer made, numerically (#1174):
                the one second account a walk may step into below the install
                owner. See THE ANCESTOR RULE.
  --max BYTES   read's size cap. Default 1 MiB.
  --meta        read prints one line first, "<uid> <gid> <octal mode>", taken
                from the same descriptor the bytes come from, so a caller
                that must judge the file and use it judges the file it read.
  --meta-ino    --meta with the descriptor's device and inode added:
                "<uid> <gid> <octal mode> <st_dev> <st_ino>". For a caller
                that judges a file by what it reads and then re-owns it: it
                hands the pair to own's --expect, so the entry re-owned is
                the one it judged and not one renamed over the name between
                the two calls.
  --expect D:I  own only. The name is refused, and nothing is changed, unless
                it holds the file with this device and inode now (the same
                check own-many --list makes for a recorded entry, #1152).
  --file-uid L  read refuses a file whose owner is not one of these numeric
                uids (comma-separated), checked on the descriptor.
  --list FILE   own-many only (#1152). FILE is what root recorded of the tree
                BEFORE the hand-over began: NUL-terminated records of
                "<st_dev>:<st_ino>:<path>", which is what
                `find DIR -printf '%D:%i:%p\\0'` writes. The paths on stdin only
                propose; the list authorises. A path that is not on the list,
                or is there with another device and inode than was recorded,
                is not changed: it is named and counted as refused, the same
                as a link is. What it answers is "is this the entry root saw",
                which a fresh find cannot: a root-owned file the account
                moved into the tree after the record is not re-owned to
                whoever is receiving the tree. It does not answer "was it
                already there": the record is only as honest as the moment it
                was taken.

WHY NOT `install`. GNU install (coreutils 9.4) looks correct and is not.
Traced with strace: openat(O_CREAT|O_EXCL), fchmod on the descriptor,
fchownat(path, AT_SYMLINK_NOFOLLOW), then fchmodat on the PATH with no
nofollow flag. An account that owns the directory can unlink the fresh file
and put a symlink at the same name in the gap before that last call, and root
then chmods the link's TARGET. Measured on Ubuntu 24.04, coreutils 9.4,
fs.protected_symlinks=1, with the racer in scripts/test-install-advisor-account.sh:
39 to 150 wins out of 150 attempts, across runs on two machines.
protected_symlinks does not
help, because the directory is the attacker's own. The secret itself is never
leaked that way (the content lands on the O_EXCL inode before the swap), but
an arbitrary file of the racer's choosing comes back mode 0640, which is
root-powered local damage during an install. That is #661's residual, and
routing every site through this file is what closes it.

WHAT THIS DOES INSTEAD. One path walk, and nothing after it:

  * the parent directory is reached component by component from /, each one
    opened O_DIRECTORY|O_NOFOLLOW relative to the one above it, so a
    directory anywhere in the chain that has become a link is refused rather
    than walked;
  * the file is created, opened or re-owned RELATIVE TO THAT DESCRIPTOR,
    under O_NOFOLLOW, never by a path;
  * content, fchown and fchmod all act on the descriptor, never on a name;
  * plant's result is moved onto the caller's name with renameat on that same
    directory descriptor, which follows neither side.

A racer that owns the directory can still unlink or rename entries in it,
because that is what owning a directory means. What it cannot do is make any
of root's calls land on a file root did not create: the worst it can achieve
is to make the rename fail, which is reported and changes nothing.

THE ANCESTOR RULE (#703 item 3). O_NOFOLLOW per component is the real fix;
this is the defence in depth beside it. Every component strictly above
--root has to be a directory that only root and one single non-root account
can rewrite:

  * its owner is root or the install owner;
  * it is not world-writable unless it carries the sticky bit (/tmp is the
    case that needs the exception);
  * it is not group-writable unless it carries the sticky bit, or its group
    is private to its own owner. A default Ubuntu account gets umask 002 and
    a private group of its own name, so a checkout under /home/<op> is 0775
    <op>:<op> on every real box I have. That is allowed. The same directory
    group-owned by the group the Advisor shares with the dashboard is NOT,
    and that is the shape this rule exists to catch.

The install owner comes from --owner when the caller knows it. Without it,
the walk infers: the first component below / whose owner is not root pins it,
and every deeper component must then be owned by root or by that same
account. So a chain that belongs to two different non-root accounts is
refused whether or not anyone named the right one.

One pair can be named by the caller: --also-owner UID, the service account the
installer created (#1174). The dashboard runs as its own account and owns its
data directory inside the login's checkout, so a walk rooted below data/ meets
login, then that account. With --also-owner the chain may step from the install
owner into that account once and stay there (root's components are always fine);
a component of any third account, or a step back to the owner, is refused as
before. It is given by the one caller that walks below such a directory, not
inferred, and not a general loosening.

--root itself is NOT checked, and neither is anything below it. That is
deliberate: --root is advisor/state (or the tree own-many is walking), which
belongs to the Advisor's account by design, and a rule that refused it would
refuse every correct install.

The exception is --judge-root (ancestors, copy-tree and own-many only, #1153),
for a caller whose --root is not the Advisor's: the parent a backup is placed
in, the directory a node's store sits in. There the directory handed as --root
is a place root writes into on the operator's behalf, and it is held to the
same rule as everything above it. The refusal ends with the chmod that fixes
it rather than the update command, because the update narrows the Advisor's
own folders and nothing else. Whatever hands over a tree and asks about it
first has to pass the flag to both, or the up-front answer and the hand-over
disagree.

THE TEMPORARY NAME is random, and that is for collision, not for secrecy. The
account that owns the directory can list it, so the name hides nothing; the
security claim here is that no root syscall resolves a name after the create,
not that the racer cannot see the file.

MODE ON THE WAY THROUGH. The new file is created 0600 and only then widened
to the mode asked for, so content written into it is never readable by the
directory's owner in the instant before the mode is set.

python3 is a hard requirement of install-advisor-account.sh already; the
callers that did not need it before say so where they check for it. The two
programs that run from /usr/local/sbin (the sealer and the credential check)
get a root-owned copy of this file installed beside them by the same install
and refresh paths that place them, and resolve it from there, never from a
checkout the grantee can rewrite.
"""

import grp
import os
import struct
import pwd
import re
import signal
import stat
import sys
import types

READ_MAX_DEFAULT = 1024 * 1024

# The install's own second account, numerically, from --also-owner (#1174).
# Set once by main(); read only by _ancestor_problem. None is the rule as it
# always was.
ALSO_OWNER = None

# --judge-root (#1153). Set once by main(); read by walk_dir, ancestors and the
# refusal text. False is the rule as it always was: --root and everything below
# it are the Advisor's own and not judged. True is for a caller whose --root is
# a directory it is about to write into on somebody else's behalf, the parent a
# backup is placed in or the install directory a node's store lives in: that
# directory is held to the rule too, and a refusal names the chmod that fixes it
# instead of the update command, which only narrows the Advisor's own folders.
JUDGE_ROOT = False


def _fail(msg):
    sys.exit("state-file: " + msg)


def _ids(uid, gid, dirstat):
    """"" means leave that half alone, which is what os.fchown reads as -1.

    "dir" means take it from the directory the file sits in, which is what
    every `chown --reference="$dir"` this replaced was asking for.
    """
    out = []
    for value, from_dir in ((uid, dirstat.st_uid), (gid, dirstat.st_gid)):
        if value in ("", None):
            out.append(-1)
        elif value == "dir":
            out.append(from_dir)
        else:
            try:
                out.append(int(value))
            except ValueError:
                _fail("'%s' is not a numeric id, \"\" or \"dir\"" % value)
    return out[0], out[1]


# POSIX ACL entry tags, from <sys/acl.h>. The xattr is a 4-byte version then
# 8-byte entries of (u16 tag, u16 perm, u32 id), little endian on every
# architecture this ships to. Checked against a directory with a known ACL
# rather than taken from the header.
ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20)
ACL_WRITE = 0x02


def _acl_writers(fd):
    """Named users and groups an ACL on this directory lets WRITE it.

    The mode bits are not the whole story (#703, review). `setfacl -m
    u:someone:rwx` on a directory whose owning group is private leaves
    st_mode looking exactly like a directory nobody else can write, and the
    named account can still replace everything under it. st_mode's group bits
    become the ACL MASK when an ACL is present, which is why the mode check
    cannot see this on its own.

    Returns a list of sentences, empty when there is no ACL or nothing in it
    can write. Effective permission is the entry's own bits ANDed with the
    mask, which is what the kernel enforces, so an entry the mask has already
    taken the write off is not reported.

    The two entries the installers set deliberately are `--x` and `---`
    (install-advisor-account.sh grants the Advisor traverse on the operator's
    home that way, rather than by group). Neither carries write, so neither
    is ever reported: the rule is about write, not about the presence of an
    ACL.
    """
    try:
        raw = os.getxattr(fd, "system.posix_acl_access")
    except (OSError, AttributeError):
        return []                      # no ACL, or a filesystem without them
    if len(raw) < 4 or (len(raw) - 4) % 8:
        return []                      # not a shape this can read; say nothing
    entries = []
    for off in range(4, len(raw), 8):
        tag, perm, eid = struct.unpack("<HHI", raw[off:off + 8])
        entries.append((tag, perm, eid))
    mask = 0o7
    for tag, perm, _ in entries:
        if tag == ACL_MASK:
            mask = perm
    out = []
    for tag, perm, eid in entries:
        if tag not in (ACL_USER, ACL_GROUP):
            continue
        if not (perm & mask & ACL_WRITE):
            continue
        who = "user" if tag == ACL_USER else "group"
        out.append("an access control entry lets %s %d write it" % (who, eid))
    return out


_group_private_cache = {}


def _group_is_private(gid, uid):
    """True when nobody but the directory's own owner is in its group.

    A private user group (Ubuntu's default, one group per account) is the
    only group-writable shape a checkout is allowed to have. Both halves of
    membership are read: the group's own member list, and every account whose
    PRIMARY group this is, because a primary membership never appears in
    gr_mem.
    """
    key = (gid, uid)
    if key in _group_private_cache:
        return _group_private_cache[key]
    answer = False
    try:
        owner = pwd.getpwuid(uid).pw_name
        members = set(grp.getgrgid(gid).gr_mem)
        members.discard(owner)
        if not members:
            others = [p.pw_name for p in pwd.getpwall()
                      if p.pw_gid == gid and p.pw_name != owner]
            answer = not others
    except KeyError:
        # An id with no account or group behind it. Not provably private, so
        # not allowed.
        answer = False
    _group_private_cache[key] = answer
    return answer


# The one sentence every refusal about the layout ends with. The update
# narrows these folders itself (narrow_state_ancestors in get-aperire.sh), from
# a checked copy of the release, so that is the command named. The fix script
# in the tree is not: a refusal is a sign somebody can write that tree, and
# the hint must not send root to run a file from it (#886).
FIX_HINT = ("run: curl -fsSL https://get.aperire.one | bash -s -- --update --force")


def _fix_for(kind, path, owner=None):
    """The sentence that ends a refusal (or a report line) under --judge-root.

    The directory is the caller's own, not one of the Advisor's folders, so the
    update does not narrow it and the fix is a command on that one path. It
    removes the write bits the rule refuses and nothing else: go-w leaves a
    0750 directory 0750 and does not make a private one readable. An access
    control entry and a path owned by two accounts have no one-line fix, so the
    sentence says what to look at.
    """
    if kind in ("group-write", "world-write"):
        return "run: sudo chmod go-w %s" % path
    if kind == "acl-write":
        return ("look at it with: getfacl %s, then remove the entry that lets another "
                "account write with: sudo setfacl -x <u|g>:<id> %s" % (path, path))
    if kind == "owner":
        if owner is None:
            who = "one account"
        elif owner == 0:
            who = "root"
        else:
            who = "root or uid %d" % owner
        return ("move it under a directory only %s owns; no mode change fixes a path "
                "two accounts own parts of" % who)
    if kind == "unwalkable":
        return "name the real directory: a link in the path is never followed"
    return FIX_HINT


def _ancestor_problem(path, st, owner, fd=None):
    """(kind, sentence, owner) for one component. kind is None when it is fine.

    Split out of the refusal so that ONE implementation of this rule serves
    both the refusal and the installer step that repairs it (#703, koi). An
    installer with its own copy of "is this group private" would sooner or
    later fix a shape the helper still refuses, or skip one it does not.

    kind is what a caller can act on:
      group-write  the component is group-writable and the group has members
                   other than its owner. Repairable: chmod g-w.
      world-write  world-writable, no sticky bit. Repairable: chmod o-w.
      owner        two different non-root accounts own parts of the path.
                   Not repairable by a mode change, so it is reported only.
    """
    if st.st_uid != 0:
        if owner is None:
            owner = st.st_uid
        elif ALSO_OWNER is not None and st.st_uid == ALSO_OWNER:
            # The chain steps down from the install owner into the account the
            # installer made to run the service, which owns its own data
            # directory inside the owner's checkout (#1174). That is the one
            # pair named by the caller, and only in that direction: from here
            # on a component must be root's or this account's, so a step back
            # to the owner, or on to a third account, is refused as before.
            owner = ALSO_OWNER
        elif st.st_uid != owner:
            who = "root" if owner == 0 else "root or uid %d" % owner
            return ("owner",
                    "%s is owned by uid %d, and the rest of the path belongs to %s; "
                    "a path that belongs to two different accounts is not an "
                    "install this will write into" % (path, st.st_uid, who),
                    owner)
    sticky = bool(st.st_mode & stat.S_ISVTX)
    if (st.st_mode & stat.S_IWOTH) and not sticky:
        return ("world-write",
                "%s is world-writable and not sticky, so anyone on this host can "
                "replace what is under it" % path,
                owner)
    if (st.st_mode & stat.S_IWGRP) and not sticky:
        if not _group_is_private(st.st_gid, st.st_uid):
            return ("group-write",
                    "%s is writable by group %d, which has members other than its own "
                    "owner, so an account that is not the install owner can replace "
                    "what is under it" % (path, st.st_gid),
                    owner)
    # After the mode bits, because an ACL is the quieter way to the same
    # place: it does not show up in `ls -l` beyond a trailing `+`.
    if fd is not None:
        for why in _acl_writers(fd):
            return ("acl-write",
                    "%s carries an access control list, and %s, so an account that is "
                    "not the install owner can replace what is under it"
                    % (path, why),
                    owner)
    return (None, "", owner)


def _check_ancestor(path, st, owner, fd=None):
    """Returns the install owner, pinned if this component is the one that pins it."""
    kind, why, owner = _ancestor_problem(path, st, owner, fd)
    if kind:
        _fail("%s. %s" % (why, _fix_for(kind, path, owner) if JUDGE_ROOT else FIX_HINT))
    return owner


def _norm(path):
    path = os.path.abspath(path)
    return [c for c in path.split("/") if c]


def walk_dir(directory, root, owner):
    """A descriptor on `directory`, reached one O_NOFOLLOW component at a time.

    Every component strictly above `root` goes through _check_ancestor. With
    --judge-root (#1153) `root` itself does too. Everything below it is opened
    the same way and never judged: it is the Advisor's, or the node's, own.
    """
    want = _norm(directory)
    stop = _norm(root if root else directory)
    if want[:len(stop)] != stop and stop[:len(want)] != want:
        _fail("%s is not inside %s, so the ancestor rule has no root to stop at"
              % (directory, root))

    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        if stop or JUDGE_ROOT:         # "/" itself as a root checks nothing, unless asked
            owner = _check_ancestor("/", os.fstat(fd), owner, fd)
        walked = []
        for component in want:
            try:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            except OSError as e:
                _fail("could not walk into /%s safely: %s"
                      % ("/".join(walked + [component]), e))
            os.close(fd)
            fd = nxt
            walked.append(component)
            if len(walked) < len(stop) or (JUDGE_ROOT and len(walked) == len(stop)):
                owner = _check_ancestor("/" + "/".join(walked), os.fstat(fd), owner, fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


def ancestors(path, root, owner):
    """Report every component above --root the rule would refuse. Writes nothing.
    With --judge-root, --root itself is reported too, and each line ends with the
    command that fixes it (#1153).

    One line per offender, tab separated:

        <kind>\t<absolute path>\t<the sentence the refusal would print>

    This exists so the installer step that repairs a layout and the refusal
    that names it are the same rule (#703, found on koi: the install tree was
    0775 koi:koi and the group koi held the Advisor's own account, so the
    Advisor could replace files in the dashboard's tree through group write).
    An installer carrying its own copy of "is this group private" would drift
    from this one, and the drift is invisible until a seal refuses on a host
    the installer has just called repaired.

    Exit status is 0 whether or not anything was found, because this is a
    report. The caller reads the lines. The walk itself is the same
    component-by-component O_NOFOLLOW walk everything else here uses, so an
    ancestor that has become a symlink is reported rather than followed.
    """
    want = _norm(os.path.dirname(os.path.abspath(path)) if not os.path.isdir(path)
                 else os.path.abspath(path))
    stop = _norm(root if root else "/")
    out = []
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        if stop or JUDGE_ROOT:
            kind, why, owner = _ancestor_problem("/", os.fstat(fd), owner, fd)
            if kind:
                out.append((kind, "/", why))
        walked = []
        for component in want:
            try:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            except OSError as e:
                here = "/" + "/".join(walked + [component])
                out.append(("unwalkable", here,
                            "%s could not be opened as a directory without following a "
                            "link: %s" % (here, e)))
                break
            os.close(fd)
            fd = nxt
            walked.append(component)
            if len(walked) < len(stop) or (JUDGE_ROOT and len(walked) == len(stop)):
                here = "/" + "/".join(walked)
                kind, why, owner = _ancestor_problem(here, os.fstat(fd), owner, fd)
                if kind:
                    out.append((kind, here, why))
    finally:
        os.close(fd)
    for kind, here, why in out:
        if JUDGE_ROOT:
            why = "%s; %s" % (why, _fix_for(kind, here, owner))
        sys.stdout.write("%s\t%s\t%s\n" % (kind, here, why))
    return 0


def _split(path, root, owner):
    """(dirfd, basename, dirstat) for a path, with the walk above."""
    directory = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(os.path.abspath(path))
    if not name:
        _fail("%s does not name a file" % path)
    dirfd = walk_dir(directory, root, owner)
    return dirfd, name, os.fstat(dirfd)


def own_one(path, uid, gid, mode, root, owner, fatal=True, expect=None, seen=None):
    """Re-own one entry, on a descriptor (#652, widened for #703).

    Refuses loudly rather than skipping. A symlink at one of these names is
    never a legitimate state for this directory to be in, and quietly
    carrying on would leave a token the dashboard cannot read with nothing
    said about why. Never reads the file: reading a token through a link an
    attacker aimed would copy the target's content into a place it can read.

    `fatal` is False for own-many, where one bad entry must not abandon the
    rest of the adoption. The refusal is still printed and still counted.

    `expect` is (st_dev, st_ino) as root recorded it (#1152). The name is
    refused unless what it holds now is that inode; the opened descriptor is
    then held to the same lstat below, so the entry that is re-owned is the
    one that was recorded and not one moved in since.

    `seen` is own-many's record of walk refusals, {(directory, sentence): count}.
    A walk refuses the same way for every entry in one directory, so the
    sentence is printed for the first and the rest are only counted (#1174).
    """
    def refuse(msg):
        if fatal:
            _fail(msg)
        sys.stderr.write("state-file: " + msg + "\n")
        return 1

    dirfd = None
    fd = None
    try:
        try:
            dirfd, name, dirstat = _split(path, root, owner)
        except SystemExit as e:
            # The walk refused: an ancestor swapped under us, or the layout is
            # one this will not write into. _split reports that by exiting,
            # which is right for a single call and wrong inside a batch: it
            # would abandon every entry after this one and leave the caller a
            # status (1) that means something else. Turned into this entry's
            # own refusal, so a batch always reports 3 (#703, review).
            said = str(e).replace("state-file: ", "")
            if seen is not None and not fatal:
                key = (os.path.dirname(os.path.abspath(path)), said)
                if key in seen:
                    seen[key] += 1
                    return 1
                seen[key] = 1
            return refuse(said)
        uid_n, gid_n = _ids(uid, gid, dirstat)
        try:
            before = os.lstat(name, dir_fd=dirfd)
        except FileNotFoundError:
            return 0                   # nothing here to re-own; not an error
        except OSError as e:
            # Named and counted, so one unreadable entry does not end a
            # hand-over with a traceback and leave the rest of it unsaid.
            return refuse("could not read %s: %s" % (path, e))
        if expect is not None and (before.st_dev, before.st_ino) != expect:
            return refuse("%s is not the entry root recorded before it began (it was "
                          "replaced, or moved here, since); nothing was changed" % path)
        if stat.S_ISDIR(before.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        elif stat.S_ISREG(before.st_mode):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        else:
            return refuse("%s is not a regular file or a directory (it is a symlink or "
                          "a special file); refusing to change its owner or mode" % path)
        try:
            fd = os.open(name, flags, dir_fd=dirfd)
        except OSError as e:
            return refuse("could not open %s safely: %s" % (path, e))
        now = os.fstat(fd)
        if stat.S_IFMT(now.st_mode) != stat.S_IFMT(before.st_mode):
            return refuse("%s changed type while it was being opened" % path)
        if (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino):
            return refuse("%s was replaced while it was being opened; nothing was changed"
                          % path)
        if stat.S_ISREG(now.st_mode) and now.st_nlink != 1:
            return refuse("%s has %d links, so re-owning it would re-own another name for "
                          "the same file; nothing was changed" % (path, now.st_nlink))
        if uid_n != -1 or gid_n != -1:
            os.fchown(fd, uid_n, gid_n)
        if mode:
            os.fchmod(fd, int(mode, 8))
    finally:
        if fd is not None:
            os.close(fd)
        if dirfd is not None:
            os.close(dirfd)
    return 0


def read_list(path):
    """{normalised path: (st_dev, st_ino)} from a --list file (#1152)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        _fail("could not read the list %s: %s" % (path, e))
    recorded = {}
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        parts = rec.decode("utf-8", "surrogateescape").split(":", 2)
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            _fail("the list %s is not <dev>:<ino>:<path> records (NUL-terminated)" % path)
        recorded[os.path.normpath(os.path.abspath(parts[2]))] = (int(parts[0]), int(parts[1]))
    return recorded


def own_many(uid, gid, mode, root, owner, data, listing=None):
    """own_one over a NUL-separated list, one refusal at a time.

    `find -nouser -print0` hands this directories, regular files and, on a
    tree somebody has been at, symlinks. The old `find -exec chown` re-owned
    every one of them by name. Here each entry is judged on its own: a link
    is refused and named, the rest of the adoption carries on, and the exit
    status says whether anything was refused so the caller can tell a
    privilege gap from a tree with links planted in it.

    With `listing` (a --list file, #1152) the paths on stdin are only
    proposals: an entry that is not on the recorded list, or is there with
    another inode, is named and counted as refused, and is left exactly as
    it is.
    """
    if not root:
        _fail("own-many needs --root, the tree its paths are inside")
    recorded = read_list(listing) if listing else None
    refused = 0
    seen = {}
    for raw in data.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        expect = None
        if recorded is not None:
            expect = recorded.get(os.path.normpath(os.path.abspath(path)))
            if expect is None and not os.path.lexists(path):
                continue               # nothing here, listed or not: not an error
            if expect is None:
                sys.stderr.write("state-file: %s is not on the list root recorded before it "
                                 "began, so it was left alone\n" % path)
                refused += 1
                continue
        refused += own_one(path, uid, gid, mode, root, owner, fatal=False, expect=expect,
                           seen=seen)
    covered = 0
    for (directory, _), count in sorted(seen.items()):
        if count > 1:
            covered += count
            sys.stderr.write("state-file: that refusal covers all %d entries in %s; none of "
                             "them was changed\n" % (count, directory))
    if refused and refused != covered:
        sys.stderr.write("state-file: %d entr%s refused above and left alone\n"
                         % (refused, "y was" if refused == 1 else "ies were"))
    if refused:
        return 3
    return 0


def read_file(path, root, owner, limit, meta=False, file_uids=None, ino=False):
    """Print a file's bytes, having proved it is the file and not a link to one.

    Root reads approve.token by name in three places (#703 item 5), and the
    account that owns the directory can point that name anywhere. O_NOFOLLOW
    refuses a symlink; the regular-file check refuses a FIFO, which would
    otherwise park root on an open() for as long as the racer likes;
    O_NONBLOCK makes sure it cannot even for the instant before that check;
    and the single-link rule matches what `own` already demands, so the same
    sentence covers both.
    """
    dirfd = None
    fd = None
    try:
        dirfd, name, _ = _split(path, root, owner)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
        except OSError as e:
            _fail("could not read %s safely: %s" % (path, e))
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            _fail("%s is not a regular file (it is a symlink or a special file); "
                  "refusing to read it" % path)
        if st.st_nlink != 1:
            _fail("%s has %d links, so it is also reachable under another name; "
                  "refusing to read it" % (path, st.st_nlink))
        if file_uids is not None and st.st_uid not in file_uids:
            _fail("%s is owned by uid %d, which is not one of the accounts this "
                  "expected (%s); refusing to read it"
                  % (path, st.st_uid, ",".join(str(u) for u in sorted(file_uids))))
        if st.st_size > limit:
            _fail("%s is %d bytes, past the %d this will read" % (path, st.st_size, limit))
        out = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            out += chunk
            if len(out) > limit:
                _fail("%s grew past the %d bytes this will read" % (path, limit))
    finally:
        if fd is not None:
            os.close(fd)
        if dirfd is not None:
            os.close(dirfd)
    if meta:
        line = "%d %d %o" % (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
        if ino:
            line += " %d %d" % (st.st_dev, st.st_ino)
        sys.stdout.buffer.write((line + "\n").encode())
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    return 0


def narrow(path):
    """Take group and other write off ONE directory, on a descriptor.

    The repair for the layout the ancestor rule refuses (#703). It was a
    `chmod go-w <path>` as root, which is the shape this whole file exists to
    replace: root resolving a name in a tree it has just called renamable by
    an account that is not its owner. Here the directory is reached the same
    component-by-component O_NOFOLLOW way as everything else, and the mode is
    set with fchmod on the descriptor that walk returned.

    THE ANCESTOR RULE IS OFF for this walk, deliberately, and that is not a
    hole. The rule is the thing being repaired: applying it here would refuse
    to narrow advisor/ because the install root above it is still wide, which
    is the state this is called in. What still holds is O_NOFOLLOW on every
    component, which is what stops the call landing somewhere else. The caller
    re-reads the layout afterwards rather than trusting this to have worked.
    """
    fd = walk_dir(path, "/", None)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            _fail("%s is not a directory" % path)
        want = stat.S_IMODE(st.st_mode) & ~(stat.S_IWGRP | stat.S_IWOTH)
        if want != stat.S_IMODE(st.st_mode):
            os.fchmod(fd, want)
        sys.stdout.write("%04o %04o\n" % (stat.S_IMODE(st.st_mode), want))
    finally:
        os.close(fd)
    return 0


def plant(path, uid, gid, mode, data, root, owner):
    """Create the file, or replace whatever is at that name, atomically."""
    name = os.path.basename(os.path.abspath(path))
    if not name or name in (".", ".."):
        _fail("%s does not name a file" % path)
    directory = os.path.dirname(os.path.abspath(path))
    dirfd = walk_dir(directory, root, owner)
    uid, gid = _ids(uid, gid, os.fstat(dirfd))

    tmp = ".%s.new.%s" % (name, os.urandom(8).hex())
    fd = None
    try:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=dirfd)
        except OSError as e:
            _fail("could not create a new file in %s: %s" % (directory, e))
        try:
            while data:
                data = data[os.write(fd, data):]
            if uid != -1 or gid != -1:
                os.fchown(fd, uid, gid)
            if mode:
                os.fchmod(fd, int(mode, 8))
        except OSError as e:
            # Named, not a traceback. The ordinary way to land here is running
            # this without the privilege to give the file away, and the caller
            # prints what that means for the operator.
            _fail("could not set up %s: %s" % (path, e))
        os.close(fd)
        fd = None
        # Onto the caller's name in one call. renameat resolves neither side
        # through a link, so a symlink sitting at the destination is replaced
        # rather than followed, and the file that lands is the one whose
        # descriptor was just set up above.
        try:
            os.rename(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        except OSError as e:
            _fail("could not move the new file onto %s: %s" % (path, e))
        tmp = None
    finally:
        if fd is not None:
            os.close(fd)
        if tmp is not None:
            # The rename did not happen, so this is litter in somebody's
            # directory. Best effort: a racer may have removed it already.
            try:
                os.unlink(tmp, dir_fd=dirfd)
            except OSError:
                pass
        os.close(dirfd)
    return 0


COPY_TREE_DEPTH = 64


class _Made:
    """One name the copy made: what it is called, which inode it landed on, and,
    for a directory, the same record of what was made inside it.

    The inode is what the take-back goes by. A name is only where something was
    put: the account the set is handed to owns every made directory once the
    copy hands it over, so it can unlink, replace or rename a name while the
    take-back runs. `dev` and `ino` are None when the identity could not be read,
    and an entry like that is never removed, only named (#1163).
    """
    __slots__ = ("name", "dev", "ino", "children")

    def __init__(self, name, children=None):
        self.name, self.dev, self.ino, self.children = name, None, None, children

    def note(self, st):
        self.dev, self.ino = st.st_dev, st.st_ino

    def is_(self, st):
        return self.ino is not None and (st.st_dev, st.st_ino) == (self.dev, self.ino)


def _copy_chunks(sfd, dfd):
    while True:
        chunk = os.read(sfd, 1 << 20)
        if not chunk:
            return
        while chunk:
            chunk = chunk[os.write(dfd, chunk):]


def _made_by_us(fd, shown):
    """Refuse a directory this process did not just create (#1154 review).

    A directory made with mkdir is owned by this process's effective uid. One
    that is not was put at that name by somebody who could write the parent, in
    the gap between the mkdir and the open, and writing the set into it would
    place it where that account chooses. The check is on the descriptor that
    was opened, not on the name.
    """
    st = os.fstat(fd)
    if (st.st_uid != os.geteuid() or not stat.S_ISDIR(st.st_mode)
            or st.st_mode & 0o022):
        sys.stderr.write("state-file: %s is not the directory this copy just made (it is "
                         "owned by uid %d, mode %o); nothing was written into it\n"
                         % (shown, st.st_uid, stat.S_IMODE(st.st_mode)))
        return False
    return True


def _copy_dir(srcfd, dstfd, shown, uid_n, gid_n, depth, made):
    """Copy what is in srcfd into dstfd, every name new, every step on a descriptor.

    Returns the number of entries refused. `made` collects what was created in
    dstfd as _Made records: the name, the inode it landed on and, for a
    directory, the same records of what was made inside it. The caller takes
    back exactly that record, by inode, if anything was refused, and nothing
    else (#1163).
    """
    # A refusal, never an exit: this runs with names already made at the
    # destination, and an exit would leave them there past the take-back in
    # copy_tree. The caller counts it, and the take-back runs.
    if depth > COPY_TREE_DEPTH:
        sys.stderr.write("state-file: %s is nested deeper than %d directories, so nothing "
                         "in it was copied\n" % (shown, COPY_TREE_DEPTH))
        return 1
    try:
        names = sorted(os.listdir(srcfd))
    except OSError as e:
        sys.stderr.write("state-file: could not list %s: %s\n" % (shown, e))
        return 1
    refused = 0
    for name in names:
        where = "%s/%s" % (shown, name)
        try:
            st = os.lstat(name, dir_fd=srcfd)
        except OSError as e:
            sys.stderr.write("state-file: could not read %s: %s\n" % (where, e))
            refused += 1
            continue
        if stat.S_ISDIR(st.st_mode):
            try:
                os.mkdir(name, 0o700, dir_fd=dstfd)
            except OSError as e:
                sys.stderr.write("state-file: could not make %s: %s\n" % (where, e))
                refused += 1
                continue
            rec = _Made(name, [])
            made.append(rec)
            inner = rec.children
            # The identity the name was given, read now, before the open and
            # before anything is made inside it. The append stays ahead of the
            # open so a failure in it still leaves the directory on the record.
            try:
                made_st = os.lstat(name, dir_fd=dstfd)
                if stat.S_ISDIR(made_st.st_mode) and made_st.st_uid == os.geteuid():
                    rec.note(made_st)
            except OSError:
                pass
            sub_src = sub_dst = None
            try:
                sub_src = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=srcfd)
                sub_dst = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dstfd)
                now = os.fstat(sub_src)
                if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                    sys.stderr.write("state-file: %s changed while it was being copied\n" % where)
                    refused += 1
                    continue
                if not _made_by_us(sub_dst, where):
                    refused += 1
                    continue
                opened = os.fstat(sub_dst)
                if rec.ino is not None and not rec.is_(opened):
                    sys.stderr.write("state-file: %s was replaced while it was being made, so "
                                     "nothing was written into it\n" % where)
                    refused += 1
                    continue
                rec.note(opened)
                refused += _copy_dir(sub_src, sub_dst, where, uid_n, gid_n, depth + 1, inner)
                extras = sorted(set(os.listdir(sub_dst)) - set(r.name for r in inner))
                for extra in extras:
                    sys.stderr.write("state-file: %s/%s was not put there by this copy, so it "
                                     "was left alone\n" % (where, extra))
                    refused += 1
                # The directory goes to its owner last, with everything in it.
                if uid_n != -1 or gid_n != -1:
                    os.fchown(sub_dst, uid_n, gid_n)
                os.fchmod(sub_dst, 0o700)
            except OSError as e:
                sys.stderr.write("state-file: could not copy %s: %s\n" % (where, e))
                refused += 1
            finally:
                if sub_src is not None:
                    os.close(sub_src)
                if sub_dst is not None:
                    os.close(sub_dst)
        elif stat.S_ISREG(st.st_mode):
            sfd = dfd = None
            try:
                sfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=srcfd)
                now = os.fstat(sfd)
                if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(now.st_mode):
                    sys.stderr.write("state-file: %s changed while it was being copied\n" % where)
                    refused += 1
                    continue
                # O_EXCL never resolves a name that exists: a file, a link or a
                # directory put here first is refused and left exactly as it is.
                dfd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=dstfd)
                rec = _Made(name)
                made.append(rec)
                rec.note(os.fstat(dfd))
                _copy_chunks(sfd, dfd)
                if uid_n != -1 or gid_n != -1:
                    os.fchown(dfd, uid_n, gid_n)
                os.fchmod(dfd, 0o700 if now.st_mode & 0o111 else 0o600)
                os.utime(dfd, ns=(now.st_atime_ns, now.st_mtime_ns))
            except OSError as e:
                sys.stderr.write("state-file: could not copy %s: %s\n" % (where, e))
                refused += 1
            finally:
                if sfd is not None:
                    os.close(sfd)
                if dfd is not None:
                    os.close(dfd)
        else:
            sys.stderr.write("state-file: %s is not a regular file or a directory, so it was "
                             "not copied\n" % where)
            refused += 1
    return refused


class _Impatient(BaseException):
    """A second signal while the take-back runs: stop, and say what is left."""


def _ids_of(entries, out=None):
    """Every (dev, ino) the copy recorded, at any depth."""
    out = set() if out is None else out
    for rec in entries:
        if rec.ino is not None:
            out.add((rec.dev, rec.ino))
        if rec.children:
            _ids_of(rec.children, out)
    return out


def _lock(fd, shown):
    """Close a directory to everyone but this process, on its descriptor.

    A made directory belongs to the account the set is handed to, so that
    account could unlink, replace or rename a name in it between the take-back
    looking at the name and acting on it. Permission is checked on every such
    call, so once the directory is root's and 0700 none of that can happen, and
    what the take-back reads after this is what it removes. It is done on the
    descriptor the identity was just checked on, before anything inside is
    looked at (#1163).
    """
    try:
        os.fchown(fd, os.geteuid(), -1)
        os.fchmod(fd, 0o700)
    except OSError as e:
        sys.stderr.write("state-file: could not close %s before taking it back: %s\n" % (shown, e))
        return False
    return True


def _take_back(dirfd, entries, shown, dev, failed, ids):
    """Remove what a refused copy made in dirfd, by its record, and nothing else.

    `entries` is the _Made record _copy_dir kept. A name is looked at with
    lstat relative to dirfd and must be the inode the copy recorded for it, or it
    is not the copy's and is left. A made directory is opened O_NOFOLLOW, must
    be that inode again on the descriptor, and is closed to everyone else (see
    _lock) before it is taken back from its own record and removed. A name that
    holds anything but what was made goes on `failed`, named, because what the
    copy made may still be somewhere and the caller must not say otherwise.
    `ids` is every identity on the record that is still on disk (an entry's goes
    when it is removed, since a freed number can be handed to somebody else's
    file), so a leftover that is something the copy made, under another name, is
    not called somebody else's. Anything this
    made that cannot be removed goes on `failed`, named with the reason.
    """
    for rec in entries:
        name = rec.name
        where = "%s/%s" % (shown, name)
        try:
            st = os.lstat(name, dir_fd=dirfd)
        except FileNotFoundError:
            # Not at its name. The residue pass looks for it under another one.
            continue
        except OSError as e:
            failed.append(where)
            sys.stderr.write("state-file: could not take back %s: %s\n" % (where, e))
            continue
        try:
            if rec.children is None:
                if not (rec.is_(st) and stat.S_ISREG(st.st_mode)):
                    failed.append(where)
                    sys.stderr.write("state-file: %s is not the file this copy made, so it was "
                                     "left alone\n" % where)
                    continue
                os.unlink(name, dir_fd=dirfd)
                # Gone, so its number is free to be handed to somebody else's
                # file and no longer says anything about what is left. Unless it
                # has another name: then it is still there, and the residue pass
                # finds it by this number.
                if st.st_nlink == 1:
                    ids.discard((rec.dev, rec.ino))
                continue
            if not (rec.is_(st) and stat.S_ISDIR(st.st_mode)) or st.st_dev != dev:
                failed.append(where)
                sys.stderr.write("state-file: %s is not the directory this copy made, so it was "
                                 "left alone\n" % where)
                continue
            sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
            try:
                if not rec.is_(os.fstat(sub)):
                    failed.append(where)
                    sys.stderr.write("state-file: %s changed while it was being taken back, so "
                                     "it was left alone\n" % where)
                    continue
                if not _lock(sub, where):
                    failed.append(where)
                    continue
                before = len(failed)
                _take_back(sub, rec.children, where, dev, failed, ids)
                inside, foreign = [], []
                if len(failed) == before:
                    inside = sorted(os.listdir(sub))
                    for n in inside:
                        try:
                            lst = os.lstat(n, dir_fd=sub)
                            mine = (lst.st_dev, lst.st_ino) in ids
                        except OSError:
                            mine = False
                        if not mine:
                            foreign.append(n)
            finally:
                os.close(sub)
            try:
                os.rmdir(name, dir_fd=dirfd)
                ids.discard((rec.dev, rec.ino))
            except OSError as e:
                if len(failed) == before:
                    if foreign:
                        # What the copy made, under another name, is said and
                        # failed by the residue pass. This is the rest.
                        sys.stderr.write("state-file: %s still holds %s, which this copy did not "
                                         "make, so it was left\n" % (where, ", ".join(foreign)))
                    elif not inside:
                        failed.append(where)
                        sys.stderr.write("state-file: could not take back %s: %s\n" % (where, e))
        except OSError as e:
            failed.append(where)
            sys.stderr.write("state-file: could not take back %s: %s\n" % (where, e))


def _residue(dirfd, entries, shown, dev, ids, failed, depth=0):
    """After the take-back: what the copy made that is still here under another name.

    The take-back goes by the names it recorded, and the account the set was
    handed to can rename what it was handed. This looks at what is left, by
    inode, and puts anything on the record that is not at the name the copy gave
    it on `failed`, named with where it is. A made directory at its own name is
    looked into by its record, because it is there for a reason and the reason
    may be a made file inside it that moved; anything else that is a directory
    is looked into too, because a made file can have been moved into it. A link
    is never followed, and nothing on another filesystem is entered.
    """
    if depth > COPY_TREE_DEPTH:
        sys.stderr.write("state-file: %s is nested deeper than %d directories, so what is in it "
                         "was not checked\n" % (shown, COPY_TREE_DEPTH))
        failed.append(shown)
        return
    by_name = dict((r.name, r) for r in entries)
    try:
        names = sorted(os.listdir(dirfd))
    except OSError as e:
        failed.append(shown)
        sys.stderr.write("state-file: could not look through %s: %s\n" % (shown, e))
        return
    for name in names:
        where = "%s/%s" % (shown, name)
        try:
            st = os.lstat(name, dir_fd=dirfd)
        except OSError:
            continue
        rec = by_name.get(name)
        at_its_name = rec is not None and rec.is_(st)
        if not at_its_name and (st.st_dev, st.st_ino) in ids:
            failed.append(where)
            sys.stderr.write("state-file: %s is what this copy made, under a name it did not give "
                             "it, and it is still there\n" % where)
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_dev != dev:
            continue
        sub = None
        try:
            sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
            if (os.fstat(sub).st_dev, os.fstat(sub).st_ino) != (st.st_dev, st.st_ino):
                continue
            _residue(sub, rec.children if at_its_name and rec.children is not None else [],
                     where, dev, ids, failed, depth + 1)
        except OSError as e:
            failed.append(where)
            sys.stderr.write("state-file: could not look through %s: %s\n" % (where, e))
        finally:
            if sub is not None:
                os.close(sub)


def copy_tree(src, dst, uid, gid, root, owner):
    """Put the finished tree at `src` at `dst`, without writing through a name (#1154).

    The backup builds its set in a directory only root can enter, because the
    set's own directory belongs to the operator from the first byte and every
    write by name into it was a write the operator could redirect. This is the
    one step that crosses into the operator's tree: `dst` is made on the
    parent's descriptor (or is an empty directory already), and everything
    inside it is created new on the descriptor of the directory it goes in.
    A directory stays root's and closed (0700) until it holds all its content,
    and is given to UID:GID last, so an owner who could rename names inside it
    never could while root was still writing. A name that is already there, of
    any kind, is refused and left as it is; so is anything that is not a
    regular file or a directory. If anything was refused, what this made is
    taken back, by the record of what it made and nothing else, and the exit
    status is 3. The record is of inodes, not names: the account the set is
    handed to owns every directory the copy made, so it can replace, rename or
    link a name before the take-back reaches it. A name that no longer holds
    the inode the copy made is named and left, and so is anything the copy made
    that is now under another name or has another link; each goes on the list
    of what could not be cleared, the closing line says it is still at DST, and
    the exit status is 4: a different case from 3, and one the caller must not
    report as an empty destination. A name someone else put in a directory the
    copy made is named and left, and is exit 3, because everything the copy
    made is gone. Each directory is closed to every account but this one on its
    own descriptor before anything in it is read or removed, so what the
    take-back saw is what it removes; a destination that was the receiver's own
    empty directory is closed the same way and given back as it was when the
    take-back leaves nothing in it.

    Signals (#1164): SIGINT, SIGTERM and SIGHUP during the copy stop it and run
    the take-back. During the take-back the first is noted and waited out, so
    the take-back finishes; a second stops it and the exit is 4 with what is
    left named. A kill that cannot be caught leaves whatever was there, which
    the caller reads from the disk.
    """
    if not root:
        _fail("copy-tree needs --root, the directory DST's parent is judged from")
    name = os.path.basename(os.path.abspath(dst))
    if not name or name in (".", ".."):
        _fail("%s does not name a directory" % dst)
    try:
        srcfd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        _fail("could not open %s: %s" % (src, e))
    dirfd = walk_dir(os.path.dirname(os.path.abspath(dst)), root, owner)
    top = None
    created = False
    try:
        uid_n, gid_n = _ids(uid, gid, os.fstat(dirfd))
        try:
            os.mkdir(name, 0o700, dir_fd=dirfd)
            created = True
        except FileExistsError:
            pass
        except OSError as e:
            _fail("could not create %s: %s" % (dst, e))
        try:
            top = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
        except OSError as e:
            _fail("%s is not a directory this can open safely (a link is never followed): %s"
                  % (dst, e))
        if created:
            if not _made_by_us(top, dst):
                _fail("%s was replaced while it was being made; nothing was written" % dst)
        else:
            # A directory that was already there: it has to be one only root and
            # the receiver can change, judged by the ancestor rule on the
            # descriptor just opened, and empty. Anyone else who can write the
            # parent could have made it first.
            #
            # The sticky bit is not an exemption here. For an ancestor it is
            # right (it stops an account replacing somebody else's entry), but
            # this is the directory root creates new names in, and sticky does
            # not stop anyone creating a name. So the rule is run as if the bit
            # were not set: a 1777 destination is refused the way 0777 is.
            top_st = os.fstat(top)
            judged = types.SimpleNamespace(st_uid=top_st.st_uid, st_gid=top_st.st_gid,
                                           st_mode=top_st.st_mode & ~stat.S_ISVTX)
            kind, why, _ = _ancestor_problem(dst, judged,
                                             uid_n if uid_n != -1 else None, top)
            if kind:
                if top_st.st_mode & stat.S_ISVTX:
                    # The rule ran with the bit cleared, so a sentence that says
                    # "not sticky" is untrue of this directory. It is sticky; what
                    # sticky does not do is stop a new name being made.
                    if kind == "world-write":
                        why = ("%s is world-writable; the sticky bit is set, but it does "
                               "not stop anyone creating a new name in it" % dst)
                    else:
                        why += " (the sticky bit does not stop a new name being created there)"
                _fail("%s was already there and cannot be written into: %s" % (dst, why))
            if os.listdir(top):
                _fail("%s already holds something, and a set is never written into a "
                      "directory that does" % dst)
        # A signal is a refusal like any other while the copy runs: it stops the
        # copy, and the take-back below runs. While the take-back runs the first
        # one is noted and waited out, so a Ctrl-C or a `systemctl stop` does not
        # leave the set at the destination; a second one stops the take-back and
        # says what is left (#1164). Nothing here can answer a kill that cannot
        # be caught; the caller reads the disk for that.
        phase = ["copy"]
        stopped = []
        def on_signal(signum, frame):
            sig_name = signal.Signals(signum).name
            stopped.append(sig_name)
            if phase[0] == "copy":
                raise SystemExit("stopped by %s" % sig_name)
            if phase[0] == "take-back" and len(stopped) > 1:
                raise _Impatient(sig_name)
        saved = {}
        try:
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                saved[sig] = signal.signal(sig, on_signal)
        except ValueError:
            pass
        try:
            return _place(top, dirfd, name, dst, created, srcfd, uid_n, gid_n, phase, stopped)
        finally:
            for sig, old in saved.items():
                signal.signal(sig, old)
    finally:
        if top is not None:
            os.close(top)
        os.close(dirfd)
        os.close(srcfd)


def _place(top, dirfd, name, dst, created, srcfd, uid_n, gid_n, phase, stopped):
    """The copy, and the take-back if anything was refused. Returns the exit status."""
    made = []
    top_before = os.fstat(top)
    refused = 0
    # Whatever stops the copy part-way is a refusal, so the take-back below
    # runs. An exit or an error that got out of here would leave a root-owned
    # 0700 set at the destination and tell the caller nothing was left.
    try:
        refused = _copy_dir(srcfd, top, dst, uid_n, gid_n, 1, made)
        for extra in sorted(set(os.listdir(top)) - set(r.name for r in made)):
            sys.stderr.write("state-file: %s/%s was not put there by this copy, so it was "
                             "left alone\n" % (dst, extra))
            refused += 1
    except (OSError, SystemExit) as e:
        sys.stderr.write("state-file: the copy into %s stopped: %s\n"
                         % (dst, str(e).replace("state-file: ", "")))
        refused += 1
    if not refused:
        # The hand-over is the last step, and a failure in it is a refusal
        # like any other: the finished set must not be left at the
        # destination under a traceback.
        try:
            if uid_n != -1 or gid_n != -1:
                os.fchown(top, uid_n, gid_n)
            os.fchmod(top, 0o700)
        except (OSError, SystemExit) as e:
            sys.stderr.write("state-file: could not hand %s over: %s\n"
                             % (dst, str(e).replace("state-file: ", "")))
            refused += 1
    if not refused:
        return 0
    phase[0] = "take-back"
    # Take back what this made, from the record of it by inode, and nothing
    # else. A name somebody else put in the destination, or in a directory this
    # made, is named and left: it is not this copy's to remove.
    failed = []
    try:
        if not created:
            # The destination was the receiver's own empty directory, so the
            # receiver could act in it while this runs. It is closed the same
            # way every made directory is, and given back as it was if the
            # take-back leaves nothing in it.
            if not _lock(top, dst):
                failed.append(dst)
        if not failed:
            ids = _ids_of(made)
            _take_back(top, made, dst, os.fstat(top).st_dev, failed, ids)
            _residue(top, made, dst, os.fstat(top).st_dev, ids, failed)
    except _Impatient as e:
        failed.append(dst)
        sys.stderr.write("state-file: stopped again by %s before the take-back finished, so "
                         "more of what the copy made may still be at %s\n" % (e, dst))
    phase[0] = "closing"
    # The signal that arrived is said once, and what it did not stop with it.
    if stopped:
        sys.stderr.write("state-file: stopped by %s\n" % ", ".join(sorted(set(stopped))))
    try:
        left_here = sorted(os.listdir(top))
    except OSError as e:
        left_here = []
        failed.append(dst)
        sys.stderr.write("state-file: could not read %s after the take-back: %s\n" % (dst, e))
    if created and not failed:
        try:
            os.rmdir(name, dir_fd=dirfd)
        except OSError as e:
            if not left_here:
                failed.append(dst)
                sys.stderr.write("state-file: could not take back %s: %s\n" % (dst, e))
    elif not created and not failed and not left_here:
        try:
            os.fchown(top, top_before.st_uid, top_before.st_gid)
            os.fchmod(top, stat.S_IMODE(top_before.st_mode))
        except OSError as e:
            failed.append(dst)
            sys.stderr.write("state-file: could not give %s back as it was: %s\n" % (dst, e))
    plural = "y was" if refused == 1 else "ies were"
    failed = list(dict.fromkeys(failed))
    if failed:
        now = os.fstat(top)
        sys.stderr.write("state-file: %d entr%s refused above, and %d name%s in %s could not be "
                         "cleared (named above): %s\n"
                         "state-file: what is named is still there. %s is owned by uid %d with mode "
                         "%o and now holds: %s. Look at it and remove it as root before a set is "
                         "placed at %s again\n"
                         % (refused, plural, len(failed), "" if len(failed) == 1 else "s", dst,
                            ", ".join(failed), dst, now.st_uid, stat.S_IMODE(now.st_mode),
                            ", ".join(left_here) or "nothing", dst))
        return 4
    if left_here:
        now = os.fstat(top)
        sys.stderr.write("state-file: %d entr%s refused above; what this copy made was taken back, "
                         "except where a name it did not make is in the way: %s still holds %s "
                         "(named above). %s is owned by uid %d with mode %o, so those names have to "
                         "be looked at and moved out as root\n"
                         % (refused, plural, dst, ", ".join(left_here), dst,
                            now.st_uid, stat.S_IMODE(now.st_mode)))
    else:
        sys.stderr.write("state-file: %d entr%s refused above, so nothing was left at %s\n"
                         % (refused, plural, dst))
    return 3


def _strictly_below(path, root, verb):
    """Refuse unless PATH sits strictly below --root, by components (#1087 L1).

    The two verbs that remove things are bound by the caller's --root, not by
    whatever the caller happened to pass: a target equal to the root, above
    it, beside it, or reached through "..", is refused before anything is
    opened. Components, never a string prefix, so /a/bc is not below /a/b.
    """
    if not root:
        _fail("%s needs --root: the directory %s must sit strictly below. "
              "Nothing was removed." % (verb, path))
    want = _norm(path)
    stop = _norm(root)
    # "/" bounds nothing: every path on the host is below it (#1087 N2).
    if not stop:
        _fail("--root %s names the whole filesystem, which bounds nothing, so %s "
              "will not run under it. Nothing was removed." % (root, verb))
    if len(want) <= len(stop) or want[:len(stop)] != stop:
        _fail("%s is not strictly below %s, so %s will not touch it. "
              "Nothing was removed." % (path, root, verb))


def _unescape_mount(field):
    """A mount point as /proc/self/mountinfo writes it, octal escapes undone."""
    out, i = "", 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1:i + 4].isdigit():
            out += chr(int(field[i + 1:i + 4], 8))
            i += 4
        else:
            out += field[i]
            i += 1
    return out


MOUNTINFO = "/proc/self/mountinfo"


def _mount_points(table=None):
    """Every mount point this process can see, read from the mount table.

    TABLE defaults to MOUNTINFO, /proc/self/mountinfo; the argument exists so
    the suite can hand the real reader a fixture. A mount table that cannot be
    read is a refusal, not an empty list: the caller is about to empty a
    directory and has to know nothing is mounted in it.
    """
    try:
        with open(table or MOUNTINFO, encoding="utf-8", errors="surrogateescape") as f:
            lines = f.read().splitlines()
    except OSError as e:
        _fail("could not read the mount table (%s), so nothing was removed" % e)
    return [_unescape_mount(line.split()[4]) for line in lines if len(line.split()) > 4]


def _no_mount_on_the_way(path, root):
    """Refuse when a mount sits at PATH, inside it, or between --root and it.

    st_dev alone cannot see a bind mount of the same filesystem, which shares
    the device, so the mount table is asked by path. Only mounts strictly
    below --root count: root's own mount and those above it are the host's.
    """
    want = _norm(path)
    stop = _norm(root)
    for mp in _mount_points():
        m = _norm(mp)
        if len(m) <= len(stop) or m[:len(stop)] != stop:
            continue
        if want[:len(m)] == m or m[:len(want)] == want:
            _fail("%s is a mount point on the way to %s, or inside it; nothing "
                  "on another mount is removed, so nothing was" % (mp, path))


def unlink_one(path, root, owner):
    """Remove one name, on the descriptor the walk returned (#888 N1).

    `rm -f NAME` as root resolves every component of NAME again, so a parent
    the dashboard's account has swapped for a link takes the delete into
    whatever directory the link points at. Here the parent is reached the
    O_NOFOLLOW way, so a linked parent is refused, and the name is removed
    with unlinkat on that descriptor. A link sitting at the leaf is removed
    itself, never followed, which is what rm does too. A name that is not there
    is fine (rm -f's contract); a directory is refused, because nothing here
    ever means to remove one.
    """
    name = os.path.basename(os.path.abspath(path))
    if not name or name in (".", ".."):
        _fail("%s does not name a file" % path)
    _strictly_below(path, root, "unlink")
    dirfd = walk_dir(os.path.dirname(os.path.abspath(path)), root, owner)
    try:
        try:
            os.unlink(name, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        except OSError as e:
            # Linux answers EISDIR for a directory and POSIX allows EPERM;
            # either way the name is left alone and the refusal is named.
            _fail("could not remove %s: %s" % (path, e))
    finally:
        os.close(dirfd)
    return 0


REMOVE_TREE_DEPTH = 64


def _empty_dir(fd, shown, dev, depth):
    """Remove everything inside the directory open on fd, never by a path.

    Each entry is judged with lstat relative to fd. A directory is opened
    O_NOFOLLOW|O_DIRECTORY relative to fd and must be the inode the lstat
    saw: a name swapped for a link or for another directory between the two
    is refused, not followed. Anything else (a link, a file, a socket) is
    unlinked by name relative to fd, which removes a link itself and never
    its target.
    """
    if depth > REMOVE_TREE_DEPTH:
        _fail("%s is nested deeper than %d directories; nothing past that was removed"
              % (shown, REMOVE_TREE_DEPTH))
    for name in os.listdir(fd):
        where = "%s/%s" % (shown, name)
        try:
            st = os.lstat(name, dir_fd=fd)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(st.st_mode):
            if st.st_dev != dev:
                _fail("%s is on another filesystem (a mount); nothing under it was "
                      "touched and the rest was left as it stands" % where)
            try:
                sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as e:
                _fail("could not open %s safely: %s" % (where, e))
            try:
                now = os.fstat(sub)
                if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                    _fail("%s changed while it was being removed; the rest was left" % where)
                _empty_dir(sub, where, dev, depth + 1)
            finally:
                os.close(sub)
            try:
                os.rmdir(name, dir_fd=fd)
            except OSError as e:
                _fail("could not remove %s: %s" % (where, e))
        else:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
            except OSError as e:
                _fail("could not remove %s: %s" % (where, e))


def remove_tree(path, root, owner):
    """Remove a directory and everything in it, on descriptors (#1064).

    `rm -rf NAME` as root resolves NAME again, so a parent swapped for a link
    between root's check and root's delete takes the delete wherever the link
    points. Here the parent is reached the O_NOFOLLOW way and the walk below
    it never resolves a name twice. The name itself has to be a directory: a
    link there is refused rather than removed, because the caller means a
    directory and a link at its name is not one. A name that is not there is
    fine. Never crosses into another filesystem, and stops at the first thing
    it cannot remove, saying which, rather than reporting a partial tree as
    gone.
    """
    # The name as given, before abspath folds "x/." into "x": rm refuses to
    # remove "." or "..", and so does this.
    if os.path.basename(path.rstrip("/")) in ("", ".", ".."):
        _fail("%s does not name a directory" % path)
    name = os.path.basename(os.path.abspath(path))
    if not name or name in (".", ".."):
        _fail("%s does not name a directory" % path)
    _strictly_below(path, root, "remove-tree")
    _no_mount_on_the_way(path, root)
    # The device the whole removal stays on is root's, read on root's own
    # descriptor, never the target's: a target that is itself another
    # filesystem is refused below rather than entered.
    rootfd = walk_dir(root, root, owner)
    try:
        root_dev = os.fstat(rootfd).st_dev
    finally:
        os.close(rootfd)
    dirfd = walk_dir(os.path.dirname(os.path.abspath(path)), root, owner)
    try:
        try:
            st = os.lstat(name, dir_fd=dirfd)
        except FileNotFoundError:
            return 0
        if st.st_dev != root_dev:
            _fail("%s is on another filesystem than %s (a mount); nothing was removed"
                  % (path, root))
        if not stat.S_ISDIR(st.st_mode):
            _fail("%s is not a directory (it may be a symlink); refusing to remove "
                  "anything through it" % path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
        except OSError as e:
            _fail("could not open %s safely: %s" % (path, e))
        try:
            now = os.fstat(fd)
            if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                _fail("%s was replaced while it was being opened; nothing was removed" % path)
            _empty_dir(fd, path, root_dev, 1)
        finally:
            os.close(fd)
        try:
            os.rmdir(name, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        except OSError as e:
            _fail("could not remove %s: %s" % (path, e))
    finally:
        os.close(dirfd)
    return 0


def mkdir_one(path, uid, gid, mode, root, owner, only_if_new=False):
    """Create a directory at PATH, or confirm one is already there (#755).

    `mkdir -p` on a path whose leaf already exists follows it if it is a
    symlink to a directory (GNU coreutils checks with `stat`, which
    dereferences), silently treating a planted redirect as "already there".
    This never does that: the leaf is opened O_NOFOLLOW immediately after
    creation, and a name that already exists as anything other than a real
    directory is refused rather than adopted.

    os.mkdir() itself never resolves an existing name of any kind -- a
    symlink already at the leaf makes it fail with EEXIST, the same as a
    plain file would -- so the only new case here, beyond own_one's own
    checks, is telling "wasn't there, now is a directory" apart from "was
    already a directory" from "was something else already".
    """
    name = os.path.basename(os.path.abspath(path))
    if not name or name in (".", ".."):
        _fail("%s does not name a directory" % path)
    directory = os.path.dirname(os.path.abspath(path))
    dirfd = walk_dir(directory, root, owner)
    fd = None
    try:
        uid_n, gid_n = _ids(uid, gid, os.fstat(dirfd))
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=dirfd)
            created = True
        except FileExistsError:
            pass                        # own_one's own lstat below judges it
        except OSError as e:
            _fail("could not create %s: %s" % (path, e))
        try:
            before = os.lstat(name, dir_fd=dirfd)
        except FileNotFoundError:
            _fail("%s vanished while it was being created" % path)
        if not stat.S_ISDIR(before.st_mode):
            _fail("%s already exists and is not a directory (it may be a "
                  "symlink); refusing to write through it" % path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
        except OSError as e:
            _fail("could not open %s safely: %s" % (path, e))
        now = os.fstat(fd)
        if (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino):
            _fail("%s was replaced while it was being opened; nothing was changed" % path)
        if only_if_new and not created:
            # A directory that was already here keeps its owner and its mode:
            # the shared corpus has a group write and a setgid bit that a
            # mode set here would take back (#248).
            return 0
        if uid_n != -1 or gid_n != -1:
            os.fchown(fd, uid_n, gid_n)
        if mode:
            os.fchmod(fd, int(mode, 8))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dirfd)
    return 0


USAGE = ("usage: state-file.py own      PATH UID GID MODE   [--root DIR] [--owner UID] [--expect DEV:INO]\n"
         "       state-file.py own-many UID GID MODE         --root DIR  [--owner UID] [--also-owner UID] [--judge-root]\n"
         "                                                  [--list FILE]\n"
         "       state-file.py plant    PATH UID GID MODE   [--stdin] [--root DIR] [--owner UID]\n"
         "       state-file.py copy-tree SRC DST UID GID     --root DIR  [--owner UID] [--judge-root]\n"
         "       state-file.py mkdir    PATH UID GID MODE   [--root DIR] [--owner UID] [--mode-if-new]\n"
         "       state-file.py read     PATH                [--root DIR] [--owner UID] [--max N]\n"
         "                                                  [--meta|--meta-ino] [--file-uid UID,UID]\n"
         "       state-file.py ancestors PATH               [--root DIR] [--owner UID] [--judge-root]\n"
         "       state-file.py unlink   PATH                 --root DIR  [--owner UID]\n"
         "       state-file.py remove-tree PATH              --root DIR  [--owner UID]\n"
         "       state-file.py narrow   DIR")


def _options(argv):
    """Pulls --root, --owner, --max, --stdin, --meta, --meta-ino, --expect, --mode-if-new and --file-uid out of argv."""
    root = None
    owner = None
    limit = READ_MAX_DEFAULT
    stdin = False
    meta = False
    if_new = False
    file_uids = None
    listing = None
    ino = False
    expect = None
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--stdin":
            stdin = True
        elif a == "--meta":
            meta = True
        elif a == "--meta-ino":
            meta = True
            ino = True
        elif a == "--mode-if-new":
            if_new = True
        elif a == "--judge-root":
            global JUDGE_ROOT
            JUDGE_ROOT = True
        elif a in ("--root", "--owner", "--also-owner", "--max", "--file-uid", "--list", "--expect"):
            i += 1
            if i >= len(argv):
                _fail("%s needs a value\n\n%s" % (a, USAGE))
            if a == "--root":
                root = argv[i]
            elif a == "--list":
                listing = argv[i]
            elif a == "--expect":
                m = re.fullmatch(r"([0-9]+):([0-9]+)", argv[i])
                if not m:
                    _fail("--expect takes <st_dev>:<st_ino>, numeric, not '%s'" % argv[i])
                expect = (int(m.group(1)), int(m.group(2)))
            elif a == "--file-uid":
                try:
                    file_uids = set(int(x) for x in argv[i].split(",") if x != "")
                except ValueError:
                    _fail("--file-uid takes numeric uids, comma-separated, not '%s'" % argv[i])
            elif a == "--owner":
                try:
                    owner = int(argv[i])
                except ValueError:
                    _fail("--owner takes a numeric uid, not '%s'" % argv[i])
            elif a == "--also-owner":
                global ALSO_OWNER
                try:
                    ALSO_OWNER = int(argv[i])
                except ValueError:
                    _fail("--also-owner takes a numeric uid, not '%s'" % argv[i])
            else:
                try:
                    limit = int(argv[i])
                except ValueError:
                    _fail("--max takes a number of bytes, not '%s'" % argv[i])
        else:
            rest.append(a)
        i += 1
    return rest, root, owner, limit, stdin, meta, file_uids, if_new, listing, ino, expect


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__.strip().splitlines()[0] + "\n\n" + USAGE)
    action = argv[1]
    rest, root, owner, limit, stdin, meta, file_uids, if_new, listing, ino, expect = _options(argv[2:])
    if listing and action != "own-many":
        _fail("--list is for own-many only\n\n%s" % USAGE)
    if expect is not None and action != "own":
        _fail("--expect is for own only\n\n%s" % USAGE)
    if ino and action != "read":
        _fail("--meta-ino is for read only\n\n%s" % USAGE)
    if JUDGE_ROOT and action not in ("ancestors", "copy-tree", "own-many"):
        _fail("--judge-root is for ancestors, copy-tree and own-many only\n\n%s" % USAGE)

    if action == "own":
        if len(rest) != 4:
            _fail("own takes PATH UID GID MODE\n\n%s" % USAGE)
        return own_one(rest[0], rest[1], rest[2], rest[3], root, owner, expect=expect)
    if action == "own-many":
        if len(rest) != 3:
            _fail("own-many takes UID GID MODE, with the paths on stdin\n\n%s" % USAGE)
        return own_many(rest[0], rest[1], rest[2], root, owner,
                        sys.stdin.buffer.read(), listing)
    if action == "plant":
        if len(rest) != 4:
            _fail("plant takes PATH UID GID MODE\n\n%s" % USAGE)
        # The content crosses a pipe, never an argument: /proc/<pid>/cmdline
        # is world readable and one of these files holds a shared secret.
        data = sys.stdin.buffer.read() if stdin else b""
        return plant(rest[0], rest[1], rest[2], rest[3], data, root, owner)
    if action == "copy-tree":
        if len(rest) != 4:
            _fail("copy-tree takes SRC DST UID GID\n\n%s" % USAGE)
        return copy_tree(rest[0], rest[1], rest[2], rest[3], root, owner)
    if action == "mkdir":
        if len(rest) != 4:
            _fail("mkdir takes PATH UID GID MODE\n\n%s" % USAGE)
        return mkdir_one(rest[0], rest[1], rest[2], rest[3], root, owner, if_new)
    if action == "read":
        if len(rest) != 1:
            _fail("read takes one PATH\n\n%s" % USAGE)
        return read_file(rest[0], root, owner, limit, meta, file_uids, ino)
    if action == "ancestors":
        if len(rest) != 1:
            _fail("ancestors takes one PATH\n\n%s" % USAGE)
        return ancestors(rest[0], root, owner)
    if action == "unlink":
        if len(rest) != 1:
            _fail("unlink takes one PATH\n\n%s" % USAGE)
        return unlink_one(rest[0], root, owner)
    if action == "remove-tree":
        if len(rest) != 1:
            _fail("remove-tree takes one PATH\n\n%s" % USAGE)
        return remove_tree(rest[0], root, owner)
    if action == "narrow":
        if len(rest) != 1:
            _fail("narrow takes one DIR\n\n%s" % USAGE)
        return narrow(rest[0])
    _fail("unknown action '%s' (expected own, own-many, plant, copy-tree, mkdir, read, ancestors, "
          "unlink, remove-tree or narrow)"
          % action)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
