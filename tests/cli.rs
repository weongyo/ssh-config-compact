#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Fixture {
    dir: tempfile::TempDir,
    path: PathBuf,
    original: String,
    live_port: u16,
    _live: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let live = TcpListener::bind("127.0.0.1:0").unwrap();
        let live_port = live.local_addr().unwrap().port();
        // A freed ephemeral port can be grabbed by a parallel test's listener.
        // Port 1 is privileged, so no unprivileged test can ever open it.
        let closed_port = 1;
        let original = format!(
            "# test config\nHost old old-alias\n  HostName 127.0.0.1\n  Port {closed_port}\n\n# keep live\nHost live\n  HostName 127.0.0.1\n  Port {live_port}\n\nHost live shared-dead\n  HostName 127.0.0.1\n  Port {closed_port}\n\nHost through-jump\n  HostName 127.0.0.1\n  Port {closed_port}\n  ProxyJump gateway.invalid\n\nHost *.internal !excluded\n  User tester\n\nMatch all\n  ServerAliveInterval 30\n"
        );
        fs::write(&path, &original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        Self {
            dir,
            path,
            original,
            live_port,
            _live: live,
        }
    }

    fn run(&self, args: &[&str], answer: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ssh-config-compact"))
            .arg("--config")
            .arg(&self.path)
            .args(["--attempts", "1", "--timeout", "1", "--jobs", "2"])
            // Keep result caches inside the fixture, never in the real ~/.cache.
            .env("XDG_CACHE_HOME", self.dir.path().join("cache"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Ignore broken pipe when the CLI finishes a dry run without reading.
        let _ = child.stdin.take().unwrap().write_all(answer.as_bytes());
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn backups(&self) -> Vec<PathBuf> {
        fs::read_dir(self.dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("config.bak.")
            })
            .collect()
    }
}

#[test]
fn dry_run_reports_candidates_without_touching_files() {
    let fixture = Fixture::new();
    let output = fixture.run(&[], "yes\n");
    assert!(
        output.contains(
            "Removal candidates (remove 1 Host blocks, and 1 aliases from 1 other Host blocks)"
        ),
        "{output}"
    );
    assert!(output.contains("  Host old old-alias\n"), "{output}");
    // A block with a live alias keeps it and only loses the failed one.
    assert!(
        output.contains("  Host live shared-dead: remove 1 of 2 aliases, keep 1\n"),
        "{output}"
    );
    assert!(
        output.contains("    - shared-dead: connection refused"),
        "{output}"
    );
    assert!(
        output.contains("    - old: connection refused (port closed) (127.0.0.1:"),
        "{output}"
    );
    assert!(
        output.contains("    - old-alias: connection refused"),
        "{output}"
    );
    assert!(output.contains("[KEEP] live -> 127.0.0.1:"), "{output}");
    assert!(output.contains("[SKIP] through-jump"), "{output}");
    assert!(
        output.contains("[SKIP] Host *.internal !excluded"),
        "{output}"
    );
    assert!(output.contains("Dry run"), "{output}");
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), fixture.original);
    assert!(fixture.backups().is_empty());
}

#[test]
fn apply_cancels_on_no_or_eof_without_creating_backup() {
    let fixture = Fixture::new();
    for answer in ["no\n", ""] {
        let output = fixture.run(&["--apply"], answer);
        assert!(output.contains("[y/N]"), "{output}");
        assert!(output.contains("Cancelled"), "{output}");
        assert_eq!(fs::read_to_string(&fixture.path).unwrap(), fixture.original);
        assert!(fixture.backups().is_empty());
    }
}

#[test]
fn confirmed_apply_removes_only_failed_blocks_after_exact_backup() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--apply"], "yes\n");
    assert!(output.contains("Updated "), "{output}");
    assert!(
        output.contains("remove 1 Host blocks, and 1 aliases from 1 other Host blocks"),
        "{output}"
    );
    let backups = fixture.backups();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), fixture.original);
    let after = fs::read_to_string(&fixture.path).unwrap();
    // The dead block is gone; the mixed block only loses its dead alias and
    // every other byte (settings, comments, blank lines) is unchanged.
    let expected = format!(
        "# test config\n{}",
        &fixture.original[fixture.original.find("\n# keep live").unwrap()..]
    )
    .replace("Host live shared-dead\n", "Host live\n");
    assert_eq!(after, expected);
    assert!(after.contains("Match all\n  ServerAliveInterval 30\n"));
    assert_eq!(fs::metadata(&fixture.path).unwrap().mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(&backups[0]).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn keep_alias_protects_the_entire_shared_block() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--apply", "--keep", "old-alias"], "yes\n");
    assert!(output.contains("protected by --keep"), "{output}");
    assert!(
        output.contains("Removal candidates (remove 1 aliases from 1 Host blocks)"),
        "{output}"
    );
    // Neither alias of the kept block is removed, not even the other one.
    assert!(!output.contains("  Host old old-alias"), "{output}");
    let after = fs::read_to_string(&fixture.path).unwrap();
    assert!(after.contains("Host old old-alias\n"), "{after}");
    assert!(
        after.contains("Host live\n") && !after.contains("shared-dead"),
        "{after}"
    );
}

#[test]
fn invalid_openssh_config_is_preserved() {
    let fixture = Fixture::new();
    fs::write(&fixture.path, "Host old\n  InvalidSshOption yes\n").unwrap();
    let output = fixture.run(&["--apply"], "yes\n");
    assert!(output.contains("ssh -G failed"), "{output}");
    assert!(output.contains("Nothing to change"), "{output}");
    assert!(fixture.backups().is_empty());
    assert_eq!(
        fs::read_to_string(&fixture.path).unwrap(),
        "Host old\n  InvalidSshOption yes\n"
    );
}

#[test]
fn skip_private_preserves_internal_hosts_without_probing() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--apply", "--skip-private"], "yes\n");
    assert!(
        output.contains("[SKIP] old -> 127.0.0.1:") && output.contains("--skip-private"),
        "{output}"
    );
    assert!(!output.contains("[UNREACHABLE]"), "{output}");
    assert!(output.contains("Nothing to change"), "{output}");
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), fixture.original);
    assert!(fixture.backups().is_empty());
}

#[test]
fn proxyjump_hosts_are_checked_through_the_jump_host_unless_disabled() {
    let fixture = Fixture::new();
    // The jump host cannot be resolved, so the target is undecidable.
    let output = fixture.run(&[], "");
    assert!(
        output.contains("[SKIP] through-jump -> 127.0.0.1:")
            && output.contains("via gateway.invalid: jump host gateway.invalid not usable"),
        "{output}"
    );
    let output = fixture.run(&["--no-via-proxyjump"], "");
    assert!(
        output.contains("[SKIP] through-jump: proxyjump requires a connection path"),
        "{output}"
    );
}

#[test]
fn skip_private_resolves_names_of_proxyjump_hosts_locally() {
    let fixture = Fixture::new();
    let config = "Host named-jump\n  HostName localhost\n  ProxyJump gateway.invalid\n";
    fs::write(&fixture.path, config).unwrap();
    let output = fixture.run(&["--skip-private"], "");
    assert!(
        output.contains("[SKIP] named-jump -> localhost:22 via gateway.invalid: internal address"),
        "{output}"
    );
    // Without the flag the (unusable) jump host is actually tried.
    let output = fixture.run(&[], "");
    assert!(
        output.contains("jump host gateway.invalid not usable"),
        "{output}"
    );
}

#[test]
fn every_line_has_timestamp_and_level() {
    let fixture = Fixture::new();
    let output = fixture.run(&[], "");
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let timestamp = fields.next().unwrap();
        assert_eq!(timestamp.len(), 29, "{line}");
        assert!(timestamp.contains('T'), "{line}");
        let level = fields.next().unwrap();
        assert!(matches!(level, "INFO" | "WARN"), "{line}");
    }
    let warn_line = output
        .lines()
        .find(|l| l.contains("[UNREACHABLE] old"))
        .unwrap();
    assert!(warn_line.contains(" WARN  "), "{warn_line}");
    assert!(!output.contains("DEBUG"), "{output}");

    let debug = fixture.run(&["--rescan", "--log-level", "debug"], "");
    assert!(debug.contains(" DEBUG old: attempt 1/1: failed"), "{debug}");
    let quiet = fixture.run(&["--rescan", "--log-level", "warn"], "");
    assert!(quiet.lines().all(|l| l.contains(" WARN  ")), "{quiet}");
}

#[test]
fn second_run_reuses_cached_results() {
    let fixture = Fixture::new();
    let first = fixture.run(&[], "");
    assert!(first.contains("Checking 5 of 5 aliases"), "{first}");
    let second = fixture.run(&[], "");
    assert!(second.contains("Reusing 5 cached results"), "{second}");
    assert!(second.contains("Checking 0 of 5 aliases"), "{second}");
    assert!(
        second.contains(
            "Removal candidates (remove 1 Host blocks, and 1 aliases from 1 other Host blocks)"
        ),
        "{second}"
    );
    let rescan = fixture.run(&["--rescan"], "");
    assert!(rescan.contains("Checking 5 of 5 aliases"), "{rescan}");
    // Different probe options must not reuse results.
    let other = fixture.run(&["--skip-private"], "");
    assert!(other.contains("Checking 5 of 5 aliases"), "{other}");
}

#[test]
fn apply_rechecks_cached_candidates_and_yes_skips_the_prompt() {
    let fixture = Fixture::new();
    fixture.run(&[], "");
    // EOF on stdin would cancel; --yes must not ask at all.
    let output = fixture.run(&["--apply", "--yes"], "");
    assert!(
        output.contains("Re-checking 3 cached removal candidates"),
        "{output}"
    );
    assert!(!output.contains("[y/N]"), "{output}");
    assert!(output.contains("without asking (--yes)"), "{output}");
    assert!(output.contains("Updated "), "{output}");
    assert_eq!(fixture.backups().len(), 1);
    assert!(
        !fs::read_to_string(&fixture.path)
            .unwrap()
            .contains("Host old old-alias")
    );
}

#[test]
fn apply_without_recheck_uses_cached_candidates() {
    let fixture = Fixture::new();
    fixture.run(&[], "");
    let output = fixture.run(&["--apply", "--no-recheck"], "no\n");
    assert!(output.contains("Checking 0 of 5 aliases"), "{output}");
    assert!(!output.contains("Re-checking"), "{output}");
    assert!(output.contains("Cancelled"), "{output}");
}

#[test]
fn yes_requires_apply() {
    let fixture = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_ssh-config-compact"))
        .arg("--config")
        .arg(&fixture.path)
        .arg("--always-yes")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--apply"));
}

#[test]
fn alias_kept_in_one_block_is_not_removed_from_another() {
    let fixture = Fixture::new();
    // "old" is protected via --keep in its first block and also appears in a
    // second block; removing it there would change its effective settings.
    let mut config = fs::read_to_string(&fixture.path).unwrap();
    config.push_str("Host old other-dead\n  HostName 127.0.0.1\n  Port 1\n  User extra\n");
    fs::write(&fixture.path, &config).unwrap();
    let output = fixture.run(&["--apply", "--keep", "old-alias"], "yes\n");
    let after = fs::read_to_string(&fixture.path).unwrap();
    assert!(after.contains("Host old old-alias\n"), "{output}\n{after}");
    assert!(
        after.contains("Host old\n  HostName 127.0.0.1\n  Port 1\n  User extra\n"),
        "{output}\n{after}"
    );
}

fn ssh_g(config: &std::path::Path, alias: &str) -> String {
    let output = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(config)
        .arg("--")
        .arg(alias)
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

/// A config with redundant settings, duplicates and mergeable blocks, all live.
fn mergeable_config(port: u16) -> String {
    format!(
        "ServerAliveInterval 30\n\nHost one\n  HostName 127.0.0.1\n  Port {port}\n  User alice\n  ServerAliveInterval 5\n\nHost two two\n  HostName 127.0.0.1\n  Port {port}\n  User alice\n\nHost three one\n  HostName 127.0.0.1\n  Port {port}\n  User alice\n\nHost other\n  HostName 127.0.0.1\n  Port {port}\n  User bob\n\nHost clash\n  HostName 127.0.0.1\n  Port {port}\n  User carol\n\nHost clash\n  User dave\n  IdentitiesOnly yes\n"
    )
}

#[test]
fn merge_is_opt_in() {
    let fixture = Fixture::new();
    fs::write(&fixture.path, mergeable_config(fixture.live_port)).unwrap();
    let output = fixture.run(&["--apply", "--yes"], "");
    assert!(output.contains("Nothing to change"), "{output}");
    assert!(!output.contains("Merge"), "{output}");
    assert!(fixture.backups().is_empty());
}

#[test]
fn merge_simplifies_without_changing_any_ssh_settings() {
    let fixture = Fixture::new();
    let original = mergeable_config(fixture.live_port);
    fs::write(&fixture.path, &original).unwrap();
    let before = fixture.dir.path().join("before");
    fs::write(&before, &original).unwrap();

    let dry = fixture.run(&["--merge"], "");
    assert!(dry.contains("Merge (merge 6 -> 4 Host blocks"), "{dry}");
    assert!(
        dry.contains("combine 3 Host blocks with identical settings: Host one two three"),
        "{dry}"
    );
    assert!(
        dry.contains("drop setting with no effect: ServerAliveInterval 5 (in 1 Host blocks)"),
        "{dry}"
    );
    assert!(
        dry.contains("drop duplicate alias one from Host three one"),
        "{dry}"
    );
    assert!(
        dry.contains("WARN    clash is listed in 2 Host blocks that give it different settings"),
        "{dry}"
    );
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), original);

    let output = fixture.run(&["--merge", "--apply", "--yes"], "");
    assert!(output.contains("Updated "), "{output}");
    let after = fs::read_to_string(&fixture.path).unwrap();
    let port = fixture.live_port;
    assert_eq!(
        after,
        format!(
            "ServerAliveInterval 30\n\nHost one two three\n  HostName 127.0.0.1\n  Port {port}\n  User alice\n\nHost other\n  HostName 127.0.0.1\n  Port {port}\n  User bob\n\nHost clash\n  HostName 127.0.0.1\n  Port {port}\n  User carol\n\nHost clash\n  IdentitiesOnly yes\n"
        )
    );
    for alias in ["one", "two", "three", "other", "clash"] {
        assert_eq!(
            ssh_g(&before, alias),
            ssh_g(&fixture.path, alias),
            "{alias}"
        );
    }
    assert_eq!(fs::read_to_string(&fixture.backups()[0]).unwrap(), original);
}

#[test]
fn merge_keeps_settings_that_only_restate_defaults() {
    let fixture = Fixture::new();
    let me = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap();
    let me = me.trim();
    let port = fixture.live_port;
    // On this machine "User <me>" and "PubkeyAuthentication yes" change
    // nothing, but they would for another account or system config.
    let config = format!(
        "Host a\n  HostName 127.0.0.1\n  Port {port}\n  User {me}\n  PubkeyAuthentication yes\n\nHost b\n  HostName 127.0.0.1\n  Port {port}\n  User {me}\n  PubkeyAuthentication yes\n"
    );
    fs::write(&fixture.path, &config).unwrap();
    let output = fixture.run(&["--merge", "--apply", "--yes"], "");
    assert!(!output.contains("drop setting"), "{output}");
    assert_eq!(
        fs::read_to_string(&fixture.path).unwrap(),
        format!(
            "Host a b\n  HostName 127.0.0.1\n  Port {port}\n  User {me}\n  PubkeyAuthentication yes\n"
        )
    );
}

#[test]
fn merge_only_skips_checks_and_removes_nothing() {
    let fixture = Fixture::new();
    // "dead" is unreachable (port 1) but must survive: --merge-only never checks.
    let original = format!(
        "{}\nHost dead\n  HostName 127.0.0.1\n  Port 1\n",
        mergeable_config(fixture.live_port)
    );
    fs::write(&fixture.path, &original).unwrap();
    let output = fixture.run(&["--merge-only", "--apply", "--yes"], "");
    assert!(output.contains("Skipping reachability checks"), "{output}");
    assert!(!output.contains("Checking"), "{output}");
    assert!(!output.contains("[UNREACHABLE]"), "{output}");
    assert!(output.contains("combine 3 Host blocks"), "{output}");
    let after = fs::read_to_string(&fixture.path).unwrap();
    assert!(after.contains("Host one two three\n"), "{after}");
    assert!(
        after.contains("Host dead\n  HostName 127.0.0.1\n  Port 1\n"),
        "{after}"
    );
    // No result cache is created for a merge-only run.
    assert!(!fixture.dir.path().join("cache").exists());
}

#[test]
fn format_only_dry_run_and_cancellation_preserve_original() {
    let fixture = Fixture::new();
    let original = "\tHost=dead dead\nUser\t tester\nHost other\n\tUser=tester";
    fs::write(&fixture.path, original).unwrap();
    let output = fixture.run(&["--format-only", "--log-level", "debug"], "yes\n");
    assert!(output.contains("Dry run"), "{output}");
    assert!(output.contains("Formatted config:"), "{output}");
    assert!(output.contains("Host dead dead\n"), "{output}");
    assert!(!output.contains("Checking "), "{output}");
    assert!(!output.contains("Merging:"), "{output}");
    for answer in ["no\n", ""] {
        let output = fixture.run(&["--format-only", "--apply"], answer);
        assert!(output.contains("[y/N]"), "{output}");
        assert!(output.contains("Cancelled"), "{output}");
    }
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), original);
    assert!(fixture.backups().is_empty());
    assert!(!fixture.dir.path().join("cache").exists());
}

#[test]
fn format_only_needs_no_ssh_and_backs_up_once() {
    let fixture = Fixture::new();
    let included = fixture.dir.path().join("included");
    let include_text = "Host included\nUser\talice\n";
    fs::write(&included, include_text).unwrap();
    let marker = fixture.dir.path().join("exec-marker");
    let original = format!(
        "Include={}\n\tHost=dead dead\nHostName = 127.0.0.1\nPort\t1\nHost other\nUser=tester\nMatch exec \"touch {}\"\nUser root",
        included.display(),
        marker.display()
    );
    fs::write(&fixture.path, &original).unwrap();
    for changed in [true, false] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssh-config-compact"))
            .arg("--config")
            .arg(&fixture.path)
            .args(["--format-only", "--apply", "--yes"])
            // Formatting must work without ssh, DNS, or Match exec evaluation.
            .env("PATH", fixture.dir.path().join("no-executables"))
            .env("XDG_CACHE_HOME", fixture.dir.path().join("cache"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.contains("Updated "), changed, "{stdout}");
        assert_eq!(stdout.contains("Nothing to change"), !changed, "{stdout}");
        assert_eq!(fixture.backups().len(), 1);
    }
    let after = fs::read_to_string(&fixture.path).unwrap();
    assert!(after.contains("Host dead dead\n  HostName 127.0.0.1\n  Port 1\n"));
    assert!(after.contains("\n\nHost other\n  User tester\n"));
    assert_eq!(fs::read_to_string(&fixture.backups()[0]).unwrap(), original);
    assert_eq!(fs::metadata(&fixture.path).unwrap().mode() & 0o777, 0o640);
    assert_eq!(
        fs::metadata(&fixture.backups()[0]).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_to_string(included).unwrap(), include_text);
    assert!(!marker.exists());
    assert!(!fixture.dir.path().join("cache").exists());
}

#[test]
fn formatting_preserves_effective_openssh_settings() {
    let fixture = Fixture::new();
    let included = fixture.dir.path().join("included config");
    fs::write(&included, "Host included\n  User included-user\n").unwrap();
    let original = format!(
        "\tInclude = \"{}\"\n\tServerAliveInterval=30\n\tHost = box alias\nHostName\t127.0.0.1\nUser = first\nUser second\nIdentityFile=\"/tmp/key  with spaces\"\nIdentityFile = /tmp/second\nSetEnv\tONE=a=b TWO=\"c  d\"\nProxyCommand = printf '  %s  ' %h\nHost box\nPort=2222\nMatch host box\nCompression=yes\nHost * !excluded\nUser=fallback\n",
        included.display()
    );
    fs::write(&fixture.path, &original).unwrap();
    let before = fixture.dir.path().join("before");
    fs::write(&before, original).unwrap();
    let output = fixture.run(&["--format-only", "--apply"], "yes\n");
    assert!(output.contains("Updated "), "{output}");
    for alias in ["box", "alias", "included", "other", "excluded"] {
        let evaluate = |path: &std::path::Path| {
            let output = Command::new("ssh")
                .args(["-G", "-F"])
                .arg(path)
                .args(["--", alias])
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            output.stdout
        };
        assert_eq!(evaluate(&before), evaluate(&fixture.path), "{alias}");
    }
}

#[test]
fn format_can_follow_merge_without_reachability_checks() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.path,
        "Host one\nUser=tester\nHost two\nUser=tester",
    )
    .unwrap();
    let output = fixture.run(&["--merge-only", "--format", "--apply", "--yes"], "");
    assert!(output.contains("combine 2 Host blocks"), "{output}");
    assert!(output.contains("format whitespace"), "{output}");
    assert_eq!(
        fs::read_to_string(&fixture.path).unwrap(),
        "Host one two\n  User tester\n"
    );
    assert!(!fixture.dir.path().join("cache").exists());
}

#[test]
fn format_only_rejects_merge_flags() {
    let fixture = Fixture::new();
    for flag in ["--merge", "--merge-only"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssh-config-compact"))
            .arg("--config")
            .arg(&fixture.path)
            .args(["--format-only", flag, "--apply", "--yes"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
    }
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), fixture.original);
    assert!(fixture.backups().is_empty());
}

#[test]
fn formatting_is_opt_in() {
    let fixture = Fixture::new();
    let original = format!(
        "\tHost = live\nHostName=127.0.0.1\n\tPort = {}",
        fixture.live_port
    );
    fs::write(&fixture.path, &original).unwrap();
    let output = fixture.run(&["--apply", "--yes"], "");
    assert!(output.contains("Nothing to change"), "{output}");
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), original);
    assert!(fixture.backups().is_empty());
}

#[test]
fn format_runs_after_cleanup_and_invalidates_cache() {
    let fixture = Fixture::new();
    let original = fixture.original.replace("  HostName ", "\tHostName = ");
    fs::write(&fixture.path, &original).unwrap();
    let output = fixture.run(&["--format", "--apply", "--yes"], "");
    assert!(output.contains("[UNREACHABLE]"), "{output}");
    assert!(output.contains("format whitespace"), "{output}");
    let after = fs::read_to_string(&fixture.path).unwrap();
    assert!(!after.contains("Host old old-alias"));
    assert!(!after.contains("shared-dead"));
    assert!(after.contains("Host live\n  HostName 127.0.0.1\n"));
    assert_eq!(fs::read_to_string(&fixture.backups()[0]).unwrap(), original);
    let cache = fixture.dir.path().join("cache/ssh-config-compact");
    assert_eq!(fs::read_dir(cache).unwrap().count(), 0);
}

#[test]
fn format_options_require_a_format_flag() {
    let fixture = Fixture::new();
    for args in [&["--sort"][..], &["--indent", "4"], &["--separator", "tab"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssh-config-compact"))
            .arg("--config")
            .arg(&fixture.path)
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--format|--format-only"), "{stderr}");
    }
}

#[test]
fn format_only_applies_indent_separator_and_verified_sort() {
    let fixture = Fixture::new();
    let original = "Host web alias\n\tUser\tdeploy\n\t# preferred key\n\tIdentityFile /tmp/b\n\tProxyJump bastion\n\tIdentityFile /tmp/a\n\tProxyCommand nc %h %p\n\tHostName 127.0.0.1\n\tInclude /nonexistent/never-read\n\tPort 22\n\tCompression yes\nHost other\n  User x\n";
    fs::write(&fixture.path, original).unwrap();
    let before = fixture.dir.path().join("before");
    fs::write(&before, original).unwrap();
    let args = [
        "--format-only",
        "--indent",
        "4",
        "--separator",
        "=",
        "--sort",
    ];
    let dry = fixture.run(&args, "");
    assert!(
        dry.contains("Sorted settings verified: ssh -G output unchanged for 3 aliases"),
        "{dry}"
    );
    assert!(dry.contains("  sort settings in 1 block\n"), "{dry}");
    assert_eq!(fs::read_to_string(&fixture.path).unwrap(), original);

    let output = fixture.run(&[&args[..], &["--apply", "--yes"]].concat(), "");
    assert!(
        output.contains("Updated ")
            && output.contains("format whitespace, sort settings in 1 block."),
        "{output}"
    );
    // Include stays in place; the comment moves with its setting; repeated
    // IdentityFile and the ProxyJump/ProxyCommand pair keep their order.
    assert_eq!(
        fs::read_to_string(&fixture.path).unwrap(),
        "Host web alias\n    HostName=127.0.0.1\n    # preferred key\n    IdentityFile=/tmp/b\n    IdentityFile=/tmp/a\n    ProxyJump=bastion\n    ProxyCommand=nc %h %p\n    User=deploy\n    Include=/nonexistent/never-read\n    Compression=yes\n    Port=22\n\nHost other\n    User=x\n"
    );
    for alias in ["web", "alias", "other"] {
        assert_eq!(
            ssh_g(&before, alias),
            ssh_g(&fixture.path, alias),
            "{alias}"
        );
    }
}

#[test]
fn sort_is_skipped_when_ssh_g_output_would_change() {
    let fixture = Fixture::new();
    // The error names the line of the bad option, which sorting would move.
    let original = "Host broken\n\tUser x\n  BogusOption y\n  HostName h\n";
    fs::write(&fixture.path, original).unwrap();
    let output = fixture.run(&["--format-only", "--sort", "--apply", "--yes"], "");
    assert!(
        output.contains("WARN  Sort skipped: ssh -G results changed for broken"),
        "{output}"
    );
    assert!(output.contains("Updated ") && !output.contains("sort settings"));
    assert_eq!(
        fs::read_to_string(&fixture.path).unwrap(),
        "Host broken\n  User x\n  BogusOption y\n  HostName h\n"
    );
}
