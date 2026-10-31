# Release signing

Every Aperire One release is signed. The installer and the updater check that signature before they unpack anything, and they refuse a release that is unsigned or signed by any other key. No flag turns the check off for a published release. A local `file://` archive or a git clone isn't a published release, isn't checked, and the installer says so.

This page has the public key, how to check that your host trusts it, what gets checked and when, and how to check a release yourself before you run anything.

## The release key

This is the key a release is signed with, in OpenSSH `allowed_signers` format. Save it to a file called `allowed_signers` to check a release by hand.

<!-- release-signers:start -->
```text
aperire-release-key namespaces="aperire-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIkP5Gqz/T/4taeWVb5repX47RKnpgYkNJPJ69Di9kp aperire-release-key-1
```
<!-- release-signers:end -->

Its fingerprint, the way `ssh-keygen -l` prints it:

<!-- release-fingerprints:start -->
```text
SHA256:xv6P7tpsQEWopHkLE8uvK63Mi0VKaE9I8z0P4MDNvKQ
```
<!-- release-fingerprints:end -->

The same line is in `scripts/release-signers` in the public repository. The copies have to match. If they don't, stop and don't install.

There is one key. During a key change there are two for a short while, and only in the two signed steps described under [When the key changes](#when-the-key-changes).

The key is a plain `ssh-ed25519` key. I keep the private half encrypted with a long passphrase, in a password manager, plus one offline encrypted copy. It is never on the machine that builds a release or on the server that publishes it. The rule I hold to is no copy in a folder a service syncs (iCloud's Desktop and Documents, Dropbox, Google Drive, OneDrive). The file is encrypted, but a copy there puts it in reach of a cloud account, and anyone who gets it can try the passphrase offline for as long as they like. You never hold the key, and nothing on your host asks for it.

## Check the release key on your host

Your host keeps the key it trusts in `/usr/local/lib/aperire/release-signers`, owned by root. Every update is checked against that file, so it is the one to compare with the fingerprint above.

- **In the dashboard:** Settings & Updates, the Updates card, the **Release key** row. It shows the fingerprint read from that file.
- **At a shell:**

  ```bash
  awk '!/^#/ && NF { print $3, $4 }' /usr/local/lib/aperire/release-signers | ssh-keygen -lf -
  ```

  Expect one line, `256 SHA256:... no comment (ED25519)`. The `SHA256:...` part must be the fingerprint above, character for character. Two lines only during a key change.

If they differ, your host trusts some other key. A host installed from a lab or test build does, and says so on every update check. Reinstall it with the one-liner. If you didn't install a lab build, treat it as a host someone has changed.

## What is signed

One file per release, `release.json`, with a detached signature beside it, `release.json.sig`. It names the sha256 of everything the endpoint serves that anything runs:

| Field in `release.json` | What it names |
|---|---|
| `sha256` | `release.tar.gz`, the release itself |
| `bootstrap_sha256` | `get-aperire.sh`, what `curl -fsSL https://get.aperire.one \| bash` runs |
| `advisor_sha256` | `advisor`, the Advisor bootstrap |
| `uninstall_sha256` | `uninstall`, the uninstall bootstrap |
| `uninstaller_sha256` | `uninstall.sh`, the uninstaller it can fetch |
| `files_sha256` | `release.files`, the sha256 of every file inside the archive |
| `signers_sha256` | the release key set every host that installs this release will trust, reduced to its keys (type and base64, sorted) and hashed |
| `committed_signers_sha256` | the same, for the release key committed in the repository at that release's commit. When the two differ, the release was signed by a lab or test key |

So one signature covers every file, through their hashes, and says which keys hosts trust afterwards.

When a release is installed, root writes the per-file sums it will check every later root copy against (`/usr/local/lib/aperire/release.sha256`). For a signed release that record is the signed `release.files`, and the archive has to agree with it entry for entry or nothing is unpacked.

`signers_sha256` keeps the key set honest. My Mac keeps its own copy of the key set and refuses to sign a release whose `signers_sha256`, or whose bootstrap's built-in key set, isn't that copy. Hosts then refuse to install a `scripts/release-signers` that isn't the set `signers_sha256` names. That stops a release from quietly changing which key hosts trust. Before my Mac signs, it also fetches the release's tag from the source repository itself, rebuilds the release from that commit in a pinned Linux container, and signs only when every hash in `release.json` matches its own build. That stops a release whose files differ from what its tagged commit builds. It does not stop bad code in the commit itself. My source repository runs on the same machine that builds releases, so a compromise of that machine can commit and tag bad code, and my rebuild of that tag matches it.

The same two files are also published under a name that never changes, `release-<archive sha256>.json` and `release-<archive sha256>.json.sig`. The installer and the updater fetch those, so a publish in progress can't pair a new `release.json` with an old signature.

## What checks it, and when

| Where | What it checks against | What it refuses |
|---|---|---|
| `get-aperire.sh`, on a first install | the key built into that copy of the script | a release with no signature, a bad signature, or an archive, file list or tree that isn't the one the signed file names. Refused before anything is unpacked |
| `curl -fsSL https://get.aperire.one \| bash -s -- --update` | the key already on this host | the same, plus a release that would change the key by more than one step. Your running tree is untouched |
| The dashboard's Update button, and `/usr/local/sbin/aperire-update` at a shell | the key already on this host, in `/usr/local/lib/aperire/release-signers` | all of the above, plus a bootstrap whose sha256 isn't the one signed, and a release older than the one installed. Root runs nothing it fetched until all of that passes |
| The Updates card's own check, the fleet table and the `update_available` metric | the key already on this host, in the same file | a release with no signature or a bad one. The card says "Not signed by a key this host trusts" and shows nothing from that release: no verdict, no notes, no metric |
| `curl -fsSL https://get.aperire.one/uninstall \| bash`, when it fetches `uninstall.sh` | the key already on this host, in the same file | an `uninstall.sh` whose sha256 isn't the signed `uninstaller_sha256`, and any release it can't verify. Root runs nothing it fetched. On a current install it runs the fetched copy only when the signed release is newer than the newest this host has installed, so a replayed older release gets the host's own uninstaller. On an install older than the keep/wipe question the fetched copy runs because the host's own can't take the question, unless the host has a verified record of installing a newer release, which is refused; a host with no key is told to update first |

The first row checks against a key carried inside the script you just fetched. That's only as trustworthy as the place you fetched it from. The others check against the key your host already has, so they hold even if the endpoint is taken over. The uninstall row is the one exception: the uninstall bootstrap itself comes from the endpoint, so the check holds against an `uninstall.sh` changed beside a genuine bootstrap, not against a changed bootstrap. The Update button is the safer way to update an installed host.

To use it from a shell rather than the page, ask it what's published, then apply exactly that:

```bash
printf 'check\n' | sudo /usr/local/sbin/aperire-update
printf 'apply tag=%s commit=%s sha256=%s\n' <published_tag> <published_commit> <published_sha256> \
  | sudo /usr/local/sbin/aperire-update
```

The first command prints `published_tag=`, `published_commit=` and `published_sha256=`; put those three values into the second. It restarts nothing. It ends by printing `needs_restart=` with the services still running the old code.

The check is `ssh-keygen -Y verify`, from the `openssh-client` package that every supported Ubuntu already has. If a host doesn't have it, the installer says so and names the package.

A local `--source file://...` archive and a `--source <git remote>` clone aren't published releases, so nothing signed them. The installer says so out loud when you use one. The Update button can't reach either: it takes no source at all.

## Check a release by hand

Do this before you pipe anything into a shell. Run it on any machine with OpenSSH 8.2 or newer (Ubuntu 22.04 and 24.04 both qualify).

1. Save the key line above into a file called `allowed_signers`.

2. Fetch the signed file, its signature and the bootstrap:

   ```bash
   curl -fsSLO https://get.aperire.one/release.json
   curl -fsSLO https://get.aperire.one/release.json.sig
   curl -fsSL https://get.aperire.one -o get-aperire.sh
   ```

3. Check the signature:

   ```bash
   ssh-keygen -Y verify -f allowed_signers -I aperire-release-key \
     -n aperire-release -s release.json.sig < release.json
   ```

   Expect `Good "aperire-release" signature for aperire-release-key with ED25519 key SHA256:...`, ending in the fingerprint above. Anything else, stop. Within a few minutes of a new release, a cache can hand you a new `release.json` with the old signature, so fetch both again once before you conclude anything.

4. Check that the bootstrap is the one that was signed:

   ```bash
   sha256sum get-aperire.sh
   grep bootstrap_sha256 release.json
   ```

   The two sums must be identical.

5. Run the file you just checked, not a fresh download:

   ```bash
   bash get-aperire.sh
   ```

   From here it checks the archive against the same signed file on its own.

## What this does and does not protect

| It protects against | It does not protect against |
|---|---|
| Someone who takes over the release endpoint or the account that publishes to it. They can serve files, but they can't sign them, so the Update button and `aperire-update` refuse their release on every installed host | Any `curl \| bash` on a fresh box. Whoever controls the endpoint controls the script you pipe in. Check it by hand first |
| An archive or a bootstrap swapped on the server or in a cache | A compromised build machine that also hosts the source repository, as mine does. It can commit and tag bad code, and my Mac's rebuild of that tag matches it. The rebuild stops staged files that differ from the tagged commit; it is not a review of the commit. Code that runs as root on your host can do anything, including trusting another key |
| An installed host being moved to an older release by replaying an old, validly signed one | Someone who has a copy of the encrypted key file AND its passphrase. The key is a file, so it can be copied. The passphrase and the password manager are what protect it, and malware on my Mac at the moment I sign could take the unlocked key. If that ever happens I rotate the key, as below |
| A cut or corrupted download | An endpoint that freezes: it keeps serving the last signed release forever, or stops answering. Hosts never go backwards, but nothing on a host can tell that a newer release exists and is being withheld. You'd see no update rather than a bad one, so compare the release on the Settings card with the published changelog now and then |

## When the key changes

A host that already trusts a key believes a release only when that key signed it. So a new key reaches installed hosts in two signed steps:

1. **The old key signs a release that names both keys.** Hosts install it and trust both.
2. **The new key signs the next release, which names only the new key.** Hosts that took step 1 accept it and drop the old key.

A host only ever moves one step at a time: one key gains a second, or a pair drops to one of its own two. A release that would swap the whole set at once is refused, whoever signed it. The key built into a freshly fetched script can't change who a host trusts either.

A host that missed step 1 still trusts only the old key, and refuses step 2 until it takes step 1, or until it's uninstalled and reinstalled with the one-liner.

The fingerprint in this guide and on the Settings card changes with each step, so check it again after a key change.
