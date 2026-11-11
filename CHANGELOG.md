# Changelog

## 1.0.0 - 2026-11-11

First stable release.

- Find the `Host` aliases in `~/.ssh/config` whose TCP port does not answer, directly or through their
  `ProxyJump` hosts, and remove them after confirmation and an exact backup of the original.
- `--merge` and `--merge-only` simplify the config: duplicate aliases, settings with no effect, and blocks
  with identical settings, with every change verified by `ssh -G`.
- `--format` and `--format-only` normalize indentation, separators, and blank lines; `--sort` also sorts the
  settings of each block, verified by `ssh -G`.
- Check results are cached per config, so `--apply` after a dry run and interrupted runs do not start over.
- Linux, macOS, and Windows (with the built-in OpenSSH client) are supported, and prebuilt binaries are
  published for x86_64 and ARM64 on each.
