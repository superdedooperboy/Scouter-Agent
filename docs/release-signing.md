# Release signing & the verified self-update path

Scouter agents can self-update when the fleet operator pushes an `update` command from the Mesh. That
command does a fast-forward `git pull` in the agent's checkout and then re-execs into the new code — on
most deployments as **root**. From the code-review of the three repos (finding #3), that path must not
trust whatever a remote happens to serve: the agent now **verifies the pulled commit is signed by a
pinned release key before it applies it**, and applies it as a **staged** change that **rolls back
automatically** if the new version can't come up cleanly.

This document is the operator's setup for making that verification pass — i.e. for turning on signed
releases as the production update path.

## What the agent does on an update

1. Record the current commit (`prev_sha`).
2. `git pull --ff-only` (optionally from a mesh-provided HTTPS repo).
3. **Verify** the new `HEAD` with `git verify-commit`, using the SSH allowed-signers file
   **`release-signers`** shipped in the checkout. `git verify-commit` exits `0` only for a good
   signature from a key that file trusts. The crypto is git's own — no third-party Python is imported
   (the agents are standard-library only).
4. If verification **fails**, reset the checkout back to `prev_sha` and refuse — the agent never
   re-execs into unverified code.
5. If it **passes**, write `update-stage.json` (prev/new commit + the new source's SHA-256) and re-exec.
6. On the next boot, the agent confirms the staged update only after it has **served cleanly for
   `UPDATE_HEALTHY_SECS` (90s)**. If the new version crash-loops instead, the boot counter climbs and
   after `UPDATE_MAX_BOOTS` (3) restarts the agent **resets back to `prev_sha`** and re-execs the
   restored, known-good version.

Canary / fleet-gated (ring) rollout is intentionally **not** part of this change; this is the per-host
verification + rollback core.

## Fail-closed by default

If **no `release-signers` file is present**, an update **cannot be verified and is refused**. This is
deliberate: an unsigned remote must not be able to replace a root daemon. Two consequences:

- **Set up signing (below) so fleet auto-update keeps working.** Until a signed release ships the
  `release-signers` file, agents running this code will refuse mesh-pushed updates.
- There is a documented escape hatch for an **air-gapped / manually-mirrored** deployment that cannot
  carry a signer file: start the agent with `--allow-unverified-update` (or set
  `SCOUTER_ALLOW_UNVERIFIED_UPDATE=1`). Only use it for a source you fully trust; it restores the old
  "trust the remote" behavior.

## One-time setup (maintainer)

### 1. Create a release signing key

Use a dedicated SSH key, kept off CI logs and ideally in hardware or a secrets manager:

```bash
ssh-keygen -t ed25519 -C "scouter-release" -f scouter-release-ed25519
```

### 2. Ship the pinned public key as `release-signers`

Add a file named **`release-signers`** at the repo root (next to `agent.py`). It is an SSH
*allowed-signers* file — one principal per line:

```text
lonnie.best@bestcyber.co ssh-ed25519 AAAAC3NzaC1lZDI1... scouter-release
```

**The principal (first field) MUST be the email your release commits are committed with.**
`git verify-commit` looks the signing key up under the *committer email*, so a label there
(`scouter-release`) verifies only if that is literally the committer email — it isn't, and the check
fails closed. Confirm the email with `git log -1 --pretty=%ce` and use exactly that. The trailing word
is a free-form comment and is ignored.

Commit it. Because it lives in the signed tree, a later release can't swap the key without a commit
signed by the **current** key.

> The Mac agent resolves `release-signers` next to the root `agent.py`; the Linux agent resolves it next
> to `linux/agent.py`. Ship the file in **both** places — `release-signers` at the repo root **and**
> `linux/release-signers` — so whichever layout a host is deployed in carries the signer beside its
> agent. Both copies are identical and both sit inside the signed tree.

### 3. Sign release commits

Configure git to sign with the release key and point verification at the allowed-signers file:

```bash
git config gpg.format ssh
git config user.signingkey ~/.ssh/scouter_release.pub   # the PUBLIC key; the private half signs via ssh-agent
git config gpg.ssh.allowedSignersFile "$(pwd)/release-signers"
git config commit.gpgsign true
git config tag.gpgsign true
```

Load the key once per session so signing is non-interactive (macOS caches the passphrase in the
keychain):

```bash
ssh-add --apple-use-keychain ~/.ssh/scouter_release
```

Then sign the release commit (and tag):

```bash
git commit -S ...            # or: git commit --amend -S --no-edit
git tag -s mac-v1.18.0 -m "Scouter 1.18.0"
git verify-commit HEAD       # should print a Good signature line and exit 0
```

In CI, import the key into the agent's SSH agent (or use `git config` with a file path) and sign the
release commit on the release branch. Keep this separate from the cosign / SLSA signing already in CI —
that signs *published artifacts*; this signs the *git commit* the agents fast-forward to.

### 4. Verify the round-trip

On a test checkout at the signed commit:

```bash
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=release-signers verify-commit HEAD && echo VERIFIED
```

Once that prints `VERIFIED`, fleet `update` commands apply only signed releases, and a broken one rolls
itself back.

## Rotating the key

Add the new public key line to `release-signers` **and** keep the old one until every agent has updated
past the rotation; sign the rotating commit with the **old** key so deployed agents accept it, then
drop the old line in a later signed release.
