# ssh-config-compact

A Rust CLI that finds and cleans up currently unreachable hosts in `~/.ssh/config`, and merges or formats the config.
By default it only shows the candidates. **Removal always requires user confirmation and a backup of the original.**

## Installation

Linux, macOS, and Windows are supported. The tool runs the OpenSSH client (`ssh`), so it must be installed;
on Windows, that is the built-in OpenSSH Client (Settings > System > Optional features).
`--format-only` without `--sort` works even without the `ssh` command.

### Prebuilt binaries

Download the archive for your platform from the [latest release](https://github.com/weongyo/ssh-config-compact/releases/latest),
check it against `SHA256SUMS`, and put the executable in a directory on your `PATH`.

| Platform | Archive `ssh-config-compact-<version>-...` |
|---|---|
| Linux x86_64 / ARM64 (glibc 2.17 or later) | `x86_64-unknown-linux-gnu.tar.gz` / `aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 / ARM64, static | `x86_64-unknown-linux-musl.tar.gz` / `aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel / Apple silicon | `x86_64-apple-darwin.tar.gz` / `aarch64-apple-darwin.tar.gz` |
| Windows x64 / ARM64 | `x86_64-pc-windows-msvc.zip` / `aarch64-pc-windows-msvc.zip` |

```sh
version=1.0.0 target=x86_64-unknown-linux-gnu
base=https://github.com/weongyo/ssh-config-compact/releases/download/$version
curl -LO "$base/ssh-config-compact-$version-$target.tar.gz" -LO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
tar xzf "ssh-config-compact-$version-$target.tar.gz"
install -m 755 "ssh-config-compact-$version-$target/ssh-config-compact" ~/.local/bin/
```

Prefer the glibc builds on Linux. The static (musl) builds are for systems without glibc, such as Alpine:
they find your account only in `/etc/passwd` and resolve names only through `/etc/hosts` and DNS, without NSS modules (LDAP or SSSD accounts, mDNS, ...).
On Windows, extract the zip and run `ssh-config-compact.exe` from PowerShell or Command Prompt.

### From source

Requires Rust 1.88 or later.

```sh
cargo install --git https://github.com/weongyo/ssh-config-compact --tag 1.0.0 --locked
# or, in a checkout of this repository
cargo install --path . --locked
```

## Usage

```sh
# Check only: no file is changed or backed up
ssh-config-compact

# Review the candidate list; nothing is removed until you approve with y or yes
ssh-config-compact --apply

# Check a different config file
ssh-config-compact --config ./example-config

# 5-second connection timeout, up to 3 attempts, 8 concurrent checks
ssh-config-compact --timeout 5 --attempts 3 --jobs 8

# Remove using the dry-run results (only candidates are rechecked), without the confirmation prompt
ssh-config-compact --apply --yes

# Ignore the cache and check everything again from scratch
ssh-config-compact --rescan

# Besides cleanup, merge blocks with identical settings and drop duplicate aliases and settings with no effect (verified with ssh -G)
ssh-config-compact --merge --apply

# Merge only, without reachability checks or cleanup (no network access)
ssh-config-compact --merge-only --apply

# Preview formatting only, without reachability checks or merging (file unchanged)
ssh-config-compact --format-only

# Apply formatting only (back up the original and save after confirmation)
ssh-config-compact --format-only --apply

# Apply formatting only, without asking (a backup of the original is still made)
ssh-config-compact --format-only --apply --yes

# Format with 4-space indentation in `Key=value` style
ssh-config-compact --format-only --indent 4 --separator =

# Format, sorting the settings in each block by keyword name (verified with ssh -G)
ssh-config-compact --format-only --sort --apply

# Also format the result of cleanup and merging
ssh-config-compact --merge --format --apply

# Always keep Host blocks that contain the given alias (repeatable)
ssh-config-compact --apply --keep production --keep backup

# Keep hosts that resolve to internal addresses without checking them
ssh-config-compact --apply --skip-private

# Keep ProxyJump hosts without checking them (by default they are checked through the jump host)
ssh-config-compact --no-via-proxyjump
```

You can also run it without installing, using `cargo run -- --apply`.

## Log format

Every line of output has the form `<local time> <level> <message>`. Multi-line messages get this prefix on every line.

```text
2026-11-10T10:57:20.681+09:00 INFO  [KEEP] live -> 1.2.3.4:22: TCP connection succeeded
2026-11-10T10:57:21.056+09:00 WARN  [UNREACHABLE] old -> 5.6.7.8:22: 3 failed attempts; ...
```

| Level | Meaning |
|---|---|
| `DEBUG` | ssh commands run, DNS lookup results, per-attempt results |
| `INFO` | Progress, successful connections, intended skips (`--keep`, wildcards, `--skip-private`, etc.), the candidate list, results |
| `WARN` | Connection failures (`[UNREACHABLE]`), hosts kept as undecidable (`ssh -G` failure, jump host problems, DNS timeouts, etc.) |
| `ERROR` | Errors that abort the run (printed to stderr) |

`--log-level debug|info|warn|error` (default `info`) sets the minimum level to print.
The `--apply` confirmation prompt is always printed, regardless of `--log-level`.

With `--apply`, the blocks to delete and the aliases to remove are listed first, like this:

```text
INFO  Removal candidates (remove 1 Host blocks, and 2 aliases from 1 other Host blocks):
INFO    Host legacy: DNS name not found (legacy.example:22, 3 attempts)
INFO    Host 1.2.3.4 5.6.7.8 9.9.9.9 ... (+5): remove 2 of 8 aliases, keep 6
INFO      - 5.6.7.8: connection timed out (no response) (5.6.7.8:922 via bastion, 3 attempts)
INFO      - 9.9.9.9: connection refused (port closed) (9.9.9.9:922 via bastion, 3 attempts)
INFO  Apply to /home/me/.ssh/config (remove 1 Host blocks, and 2 aliases from 1 other Host blocks)? A backup will be created first. [y/N]
```

Only `y` or `yes` counts as approval. Empty input, `n`, and EOF all cancel.
Before approval, no config or backup file is created or modified.
Passing `--yes` (`-y`, alias `--always-yes`) together with `--apply` applies the changes without the confirmation prompt. The backup is still made first.
`--yes` cannot be used without `--apply`.

## Result cache and reuse

Check results are written to the cache as soon as each host is done, so:

- Running `--apply` after a dry run reuses the dry-run results instead of checking again.
- If a check is interrupted (Ctrl-C or a forced kill), the hosts already finished stay cached, so the next run checks only the remaining hosts.
- Of the reused results, `--apply` rechecks **only the removal candidates**, right before removing them, so that hosts that came back in the meantime are not deleted.
  To skip this recheck, pass `--no-recheck`.

The cache is stored in `$XDG_CACHE_HOME/ssh-config-compact/` (default `~/.cache/ssh-config-compact/`; on Windows `%LOCALAPPDATA%\ssh-config-compact\`)
as one file per combination of config path and check options
(`--attempts`, `--timeout`, `--jump-timeout`, `--skip-private`, `--via-proxyjump`), with permissions `0600` (on Windows, the private access list of `%LOCALAPPDATA%`).
In the following cases, results are not reused and hosts are checked again:

- The config file's contents changed (compared by SHA-256)
- The results are older than `--cache-ttl` (default 24 hours)
- `--rescan` is given

`--keep` and `--jobs` do not affect the results, so the cache is reused even when they change.
Changes to `Include`d files, the system config (`/etc/ssh/ssh_config`), or the DNS/network environment are not detected, so use `--rescan` after such changes.
Applying removals changes the config contents, so that config's cache file is deleted.

## Decision criteria

- Explicit `Host` aliases are extracted, and `ssh -G` determines their effective `HostName`, `Port`, and `AddressFamily`.
- By default, each alias gets up to 3 attempts of 3 seconds each, covering the DNS lookup and TCP connection together. Up to 8 hosts are checked concurrently.
- A host is kept if a TCP connection succeeds even once. The tool never logs in to the target host over SSH, enters passwords, authenticates with keys, or runs remote commands.
- Only aliases that failed every attempt are removal candidates.
  - If **all** of a block's aliases fail, the whole block is removed.
  - If only some fail, the block stays and only the failed aliases are dropped from the `Host` line. The indentation, keyword, end-of-line comment, and the block's other setting lines stay as they are.
  - Undecidable aliases (`[SKIP]`) are treated as alive and kept.
  - Since ssh combines the settings of every block that matches an alias, an alias listed in a protected block or a `--keep` block is not removed from other blocks either.
- `--keep` matches an exact alias and preserves the whole block containing that alias.
- With `--skip-private`, hosts whose `HostName` (or any of its DNS lookup results) is an internal address
  are kept without attempting a TCP connection. Covered ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10` (CGNAT/Tailscale), `::1`, `fc00::/7`, `fe80::/10`.
  Hosts whose DNS lookup itself fails (e.g., VPN-only DNS names) have no known address, so they can still become candidates.
- `Host *`, wildcard/negated patterns, and complex alias syntax are preserved.
- `Match` blocks, global settings, `Include` lines, and external included files are never deleted. `Host` blocks containing an `Include` are preserved too.
- By default (`--via-proxyjump`), a `ProxyJump` host is checked by logging in to the jump host and using `ssh -W target:port`
  to open only a TCP connection to the target. There is no login to the target server, and since `BatchMode=yes` is used, key authentication to the jump host must work.
  - Failure to connect or authenticate to the jump host, refused forwarding (`administratively prohibited`), and failure of an intermediate hop in a multi-hop chain are treated as undecidable, so the host is kept.
  - The host counts as failed only when, after authenticating to the jump host, the connection to the target is refused or does not open within `--jump-timeout` (default 5 seconds, including the login).
  - Combined with `--skip-private`, a ProxyJump host is skipped if its `HostName` (an IP, or the result of a local lookup) is an internal address.
    The local lookup uses the system resolver (`getaddrinfo`), so it follows `/etc/hosts` and the nsswitch configuration
    (on Windows, the `hosts` file and the DNS client settings).
    If the local DNS lookup fails (e.g., a name that exists only in the jump host's DNS), the check goes ahead through the jump host anyway.
    The jump host resolves the name for the actual connection, so the local lookup result is used only to decide whether to skip the host.
  - With `--no-via-proxyjump`, ProxyJump hosts are kept without being checked.
  - `ControlMaster`/`ControlPath`/`ControlPersist` from the user's config are not applied. To avoid reusing an existing master connection
    or leaving a new master behind, a temporary config that disables them at the very top and then `Include`s the original config is passed with `-F`.
    ssh also passes `-F` to the inner ssh that handles the earlier hops of a chain, so this covers multi-hop `ProxyJump` too. The temporary file is deleted on exit.
- Hosts that use `ProxyCommand`, `BindAddress`, or `BindInterface` cannot be judged by a direct TCP connection alone, so they are skipped.
- Config evaluation failures, DNS timeouts, temporary DNS errors, and some local socket errors are treated as undecidable, so the host is kept.

A failed connection alone does not prove that a host is stale or permanently decommissioned.
Review the candidate list with your current network situation in mind (VPN, corporate network, server maintenance, etc.) before approving the removal.
Only an open TCP port is confirmed; the tool does not verify that an SSH service is actually running or that you can log in.

Like OpenSSH, the default path is based on the current user's home directory as registered in the OS
(on Windows, the account's profile directory, as Win32-OpenSSH uses it: usually `C:\Users\<name>\.ssh\config`).
To check a different file, specify its path with `--config` instead of changing the `HOME` (or `USERPROFILE`) environment variable.
With the default config path, the system config (`/etc/ssh/ssh_config`, or `%ProgramData%\ssh\ssh_config` on Windows) is also read, as with plain `ssh`.
With `--config`, as with `ssh -F`, the system config is not read automatically.
`ssh -G` evaluates the OpenSSH configuration, so `Match exec` commands in the config may be executed.
`--timeout` applies to config evaluation as well, and remote connections are attempted only by the TCP check.

OpenSSH configuration is interpreted as described in [ssh_config(5)](https://man.openbsd.org/ssh_config) and
[the description of `ssh -G` and `ssh -F`](https://man.openbsd.org/ssh.1).

## Merging (`--merge`)

By default, only cleanup is performed: unreachable blocks and aliases are removed. With `--merge`, the following is also done on top of the cleanup result.
`--merge-only` skips the reachability checks and cleanup and only merges. It uses no network and creates no result cache.

1. An alias that appears twice on the same `Host` line is reduced to one.
2. An alias that appears in several blocks is removed from one of them only if its settings stay the same without it.
   If removing it would change the settings, it is reported with `WARN` and left as is.
3. Setting lines with no effect are deleted. For example: `ServerAliveInterval 5` shadowed by an earlier global setting,
   `HostKeyAlgorithms +ssh-rsa` repeating the value of the final `Host *`, or `Protocol 2`, which is ignored.
4. Blocks whose remaining settings are identical are combined under a single `Host` line, in place of the first block.

Every step is verified with `ssh -G` (which prints the settings ssh would actually use).

- Finally, the `ssh -G` results before and after merging are compared for every alias in the config,
  and merges that change a result are undone. If a difference still remains, the whole merge is cancelled.
- `ssh -G` reflects only this machine, so lines that restate a default (a `User` matching the local account, `Port 22`,
  `PubkeyAuthentication yes`, etc.) are not deleted, since their meaning can differ with another account or another system config.
  A second comparison is run with a stand-in system config that sets those keys to other values, and only settings shadowed by other lines in the config are deleted.
- Blocks with wildcard or negated patterns, `Match` blocks, and blocks with an `Include` are not touched.
- Comments inside blocks that are merged away are deleted with them. Comments and blank lines between blocks are kept.
- Verification runs `ssh -G` hundreds to thousands of times, so a large config takes tens of seconds.

## Formatting (`--format`, `--format-only`)

`--format-only` only tidies up the layout of the given config file, with no reachability checks, removals, or merging.
Without `--sort`, it does not run `ssh`, perform DNS lookups, or evaluate `Match exec`, and it neither reads nor writes Include files or the result cache.
It cannot be combined with `--merge` or `--merge-only`.

| Option | Default | Description |
|---|---|---|
| `--indent N\|tab` | `2` | Indentation of settings inside `Host`/`Match` blocks: a number of spaces (0–16) or `tab` |
| `--separator SEP` | `space` | Separator between a keyword and its value: `space`, `tab`, `=`, `" = "`. `Host`/`Match` lines always use a single space |
| `--sort` | off | Sort the settings in each block by keyword name (verified with `ssh -G`) |

These options can only be used together with `--format` or `--format-only`.

- `Host` and `Match` lines and global settings start at the beginning of the line; settings inside blocks are indented by `--indent`.
- The tabs, spaces, or optional `=` separating a keyword from its value are normalized to `--separator`.
  If the value itself starts with `=` (`User==x` means the user `=x`), the original separator is kept, because OpenSSH skips only one `=`.
- Trailing whitespace is removed. OpenSSH strips it before parsing a line too, so the meaning is unchanged.
- Comment text is left as is; comments are indented according to where they are.
  Comments between settings of the same block, or directly below a setting (with no blank line in between), follow the block's indentation;
  comments directly above a `Host`/`Match` line, and comments separated by a blank line after a block's last setting, start at the beginning of the line.
- Consecutive blank lines are collapsed into one, blank lines at the start and end of the file are removed, and one blank line is placed between blocks.
  A run of comments directly above a header stays attached to the header.
- Line endings are unified to the LF or CRLF style of the first line break, and a non-empty result always ends with a line break.
- The order of blocks and aliases, duplicate settings, keyword case, and values (including inner spaces, quotes, and commands) are left unchanged.
  Without `--sort`, the order of settings is unchanged too. Formatting is idempotent: applying it again to the same file changes nothing.

### Sorting (`--sort`)

The settings inside each block (including the global settings) are stably sorted by keyword name (case-insensitive).
OpenSSH uses the first value given for each keyword, and list keywords such as `IdentityFile`, `LocalForward`, and `SendEnv` use their values in the order they appear,
so the order between settings with different keywords does not affect the result. Lines whose position matters are not moved.

- Settings with the same keyword keep their original order (e.g., the order in which multiple `IdentityFile`s are tried).
- `Include` (reads other settings at its position) and `IgnoreUnknown` (applies only to the lines after it) stay in place, and the settings before and after them are sorted separately.
- Groups separated by blank lines are sorted only within each group.
- Keywords that set the same option keep their relative order: `ProxyJump` and `ProxyCommand` (only whichever comes first applies),
  and old names such as `PubkeyAcceptedKeyTypes`, `ChallengeResponseAuthentication`, and `IdentityFile2` along with their current names.
- A comment directly above a setting moves with that setting; comments at the end of a group stay at the end.
- The order of blocks and of `Host` aliases is not changed, because ssh uses the first value set, reading from the top.

Before the sorted result is applied, the `ssh -G` output before and after sorting is compared for every alias in the config.
If any of them differ (e.g., an invalid option whose error message now reports a different line number), a `WARN` is logged and the config is formatted without sorting.
Like `--merge`, this verification uses `--timeout` and `--jobs`, and may execute `Match exec` commands in the config.

```sshconfig
# Before
Host web
	User	deploy
    HostName = web.example.com
  IdentityFile ~/.ssh/web

# After --format-only --sort
Host web
  HostName web.example.com
  IdentityFile ~/.ssh/web
  User deploy
```

The default is a dry run that only shows a summary of the changes. Add `--log-level debug` to see the full formatted contents as well.

```text
INFO  Format (indent "  ", separator " "):
INFO    rewrite the keyword separator on 102 lines
INFO    trim trailing whitespace on 3 lines
INFO    remove 5 blank lines
INFO  Dry run: config unchanged. Run with --apply to review and confirm the changes.
```

`--apply` saves after confirmation, and `--apply --yes` skips the prompt. Either way, the original is backed up first and its permissions are preserved.
If the file is already formatted, it is neither saved nor backed up.

`--format` adds formatting on top of the reachability check and cleanup. With `--merge` or `--merge-only`, it formats after merging.
If no formatting option is given, only the existing cleanup and merge behavior runs.

## Backups and saving

Once you approve, a backup named `config.bak.<time(ns)>.<PID>.<seq>` is first created next to the original,
containing the original bytes exactly and synced to disk. The backup gets permissions `0600` (on Windows, the original's access control list),
and existing backups are never overwritten.
If the backup fails, the config is not changed. If there are no blocks to remove or you cancel, no backup is created either.

The result is written to a temporary file in the same directory, which then atomically replaces the original.
The existing file's permissions (on Windows, its access control list) and owner are kept, and the indentation, line breaks, and content of the remaining settings are preserved exactly.
Comments inside a removed block are removed with it; blank lines and comments at the end of the block are kept.
Only when `--format` or `--format-only` is given is whitespace (and, with `--sort`, the order of settings) rewritten by the formatting rules above.

If the config is a symbolic link, the link is kept and the real target file is backed up and replaced.
If the file has multiple hard links or its owner cannot be preserved, the tool refuses to apply the changes.
If the file's contents, identity, permissions, owner, or symlink target are found to have changed since the check, the run aborts.
Other programs are not locked out from editing it, so do not edit the same config while changes are being applied.

To restore, use the backup path that was printed:

```sh
cp "$HOME/.ssh/config.bak.<time>.<PID>.<seq>" "$HOME/.ssh/config"
```

```powershell
# Windows (PowerShell)
Copy-Item "$HOME\.ssh\config.bak.<time>.<PID>.<seq>" "$HOME\.ssh\config"
```

## Development and verification

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The tests use temporary configs and local TCP sockets, and never modify your real `~/.ssh/config`.
CI runs them on Linux, macOS, and Windows.

## Releasing

1. Set the new `version` in `Cargo.toml`, run `cargo check` to update `Cargo.lock`, and add a section for the version to `CHANGELOG.md`.
2. Commit, then push a tag named after the version: `git tag -a 1.0.1 -m 1.0.1 && git push origin 1.0.1`.

The release workflow then runs the tests, builds the archives for every platform listed above,
and publishes them with `SHA256SUMS` as a GitHub release, using the `CHANGELOG.md` section as the release notes.
