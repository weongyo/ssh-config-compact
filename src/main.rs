#[cfg(not(unix))]
compile_error!("ssh-config-compact currently supports Unix (Linux and macOS)");

use anyhow::Result;
use clap::{ArgGroup, Parser};
use ssh_config_compact::cache::{ResultCache, ScanKey};
use ssh_config_compact::config::{Config, Edit};
use ssh_config_compact::format::{self, FormatOptions, Formatted};
use ssh_config_compact::log::{self, Level};
use ssh_config_compact::merge::{self, MergeOptions, MergeResult};
use ssh_config_compact::scan::{self, HostResult, ScanOptions, Status};
use ssh_config_compact::storage::{Snapshot, default_config_path};
use ssh_config_compact::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Clean up, merge, or format SSH config with confirmation and backups",
    group(ArgGroup::new("formatting").args(["format", "format_only"]).multiple(true))
)]
struct Args {
    /// Config file to inspect [default: ~/.ssh/config]. Like ssh -F, an explicit
    /// path ignores /etc/ssh/ssh_config.
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Ask for confirmation and back up the original before applying changes
    #[arg(long)]
    apply: bool,

    /// With --apply, apply changes without asking (a backup is still made)
    #[arg(short = 'y', long, visible_alias = "always-yes", requires = "apply")]
    yes: bool,

    /// Ignore cached results and check every host again
    #[arg(long)]
    rescan: bool,

    /// Reuse cached results younger than this many hours
    #[arg(long, value_name = "HOURS", default_value_t = 24, value_parser = clap::value_parser!(u64).range(0..=8760))]
    cache_ttl: u64,

    /// Also simplify the config: merge Host blocks with identical settings and
    /// drop settings and duplicate aliases that have no effect. Every change is
    /// verified with `ssh -G`; nothing that alters a host's settings is kept.
    #[arg(long)]
    merge: bool,

    /// Only merge (as --merge): skip the reachability checks and remove nothing
    #[arg(long)]
    merge_only: bool,

    /// Also format the result of cleanup or merging (see --format-only)
    #[arg(long)]
    format: bool,

    /// Only format: no reachability checks, removals or merging. Rewrites
    /// indentation, the separator after each keyword, trailing whitespace and
    /// blank lines; arguments and comments are kept, and so is the order of
    /// lines unless --sort is given.
    #[arg(long, conflicts_with_all = ["merge", "merge_only"])]
    format_only: bool,

    /// Indentation inside Host and Match blocks: a number of spaces, or `tab`
    #[arg(long, value_name = "N|tab", default_value = "2", value_parser = format::parse_indent, requires = "formatting")]
    indent: String,

    /// Separator between a keyword and its arguments: `space`, `tab`, `=`, or
    /// `" = "`. Host and Match lines always use a space.
    #[arg(long, value_name = "SEP", default_value = "space", value_parser = format::parse_separator, requires = "formatting")]
    separator: String,

    /// Also sort the settings of each block by keyword. Repeated keywords keep
    /// their order; blank lines, Include and IgnoreUnknown stay in place.
    /// Verified with `ssh -G`: if any host's settings would change, the
    /// settings are not sorted.
    #[arg(long, requires = "formatting")]
    sort: bool,

    /// With --apply, delete cached candidates without checking them again first
    #[arg(long, requires = "apply")]
    no_recheck: bool,

    /// Seconds per config evaluation and per DNS/TCP attempt
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout: u64,

    /// A host must fail every attempt to become a removal candidate
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=10))]
    attempts: u8,

    /// Maximum number of hosts to check concurrently
    #[arg(short, long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=64))]
    jobs: u8,

    /// Always preserve a block containing this exact alias (repeatable)
    #[arg(long, value_name = "HOST")]
    keep: Vec<String>,

    /// Skip hosts that resolve to internal addresses (RFC 1918, loopback,
    /// link-local, CGNAT 100.64/10, IPv6 ULA/link-local) instead of probing them
    #[arg(long)]
    skip_private: bool,

    /// Check ProxyJump hosts through their jump host with `ssh -W` (default).
    /// Only the jump host is logged in to; the target only gets a TCP connection.
    #[arg(long, overrides_with = "no_via_proxyjump")]
    via_proxyjump: bool,

    /// Skip ProxyJump hosts instead of checking them through the jump host
    #[arg(long, overrides_with = "via_proxyjump")]
    no_via_proxyjump: bool,

    /// Seconds per jump-host attempt, including the jump host login
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=300))]
    jump_timeout: u64,

    /// Minimum message level to print
    #[arg(long, value_enum, default_value_t = Level::Info)]
    log_level: Level,
}

fn main() {
    let args = Args::parse();
    log::set_level(args.log_level);
    if let Err(error) = run(args) {
        error!("{error:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    let path = match &args.config {
        Some(path) => path.clone(),
        None => default_config_path()?,
    };
    let snapshot = Snapshot::load(&path)?;
    if args.format_only {
        info!("Skipping reachability checks and merging (--format-only).");
        let Some(formatted) = format_config(&args, snapshot.text()?) else {
            info!("Nothing to change. Config unchanged.");
            return Ok(());
        };
        print_format(&args, &formatted);
        let summary = format_summary(&formatted);
        return apply_changes(&args, &path, &snapshot, &formatted.text, &summary).map(|_| ());
    }
    let config = Config::parse(snapshot.text()?.to_owned())?;
    let keep: HashSet<_> = args.keep.iter().cloned().collect();
    let targets = config.targets(&keep);
    for block in &config.hosts {
        if let Some(reason) = &block.protected {
            info!("[SKIP] Host {}: {reason}", single_line(&block.label));
        } else if block.aliases.iter().any(|a| keep.contains(a)) {
            info!("[KEEP] Host {}: protected by --keep", block.label);
        }
    }
    let options = ScanOptions {
        custom_config: args.config.clone(),
        timeout: Duration::from_secs(args.timeout),
        attempts: args.attempts.into(),
        jobs: args.jobs.into(),
        skip_private: args.skip_private,
        via_proxyjump: !args.no_via_proxyjump,
        jump_timeout: Duration::from_secs(args.jump_timeout),
    };
    let key = ScanKey {
        custom_config: options.custom_config.is_some(),
        attempts: options.attempts,
        timeout_secs: args.timeout,
        jump_timeout_secs: args.jump_timeout,
        skip_private: options.skip_private,
        via_proxyjump: options.via_proxyjump,
    };
    let mut cache = if args.merge_only {
        None
    } else {
        Some(ResultCache::open(
            snapshot.canonical_path(),
            snapshot.bytes(),
            key,
            Duration::from_secs(args.cache_ttl * 3600),
            args.rescan,
        )?)
    };
    let mut results: HashMap<String, HostResult> = HashMap::new();
    let mut plan = Plan::new(&config, &keep, &results);
    match cache.as_mut() {
        Some(cache) => {
            plan = check_and_plan(
                &args,
                &config,
                &keep,
                &targets,
                &options,
                cache,
                &mut results,
            );
        }
        None => info!("Skipping reachability checks (--merge-only): nothing is removed."),
    }

    let pruned = config.edited(&plan.edits);
    let merged = if args.merge || args.merge_only {
        info!("Merging: verifying every change with ssh -G ...");
        match merge::merge(&pruned, &eval_options(&args)) {
            Ok(result) if result.changed() => Some(result),
            Ok(_) => {
                info!("Merge: nothing to simplify.");
                None
            }
            Err(error) => {
                warn!("Merge skipped: {error:#}");
                None
            }
        }
    } else {
        None
    };
    let replacement = merged.as_ref().map_or(pruned.as_str(), |m| &m.text);
    let formatted = if args.format {
        format_config(&args, replacement)
    } else {
        None
    };
    if plan.is_empty() && merged.is_none() && formatted.is_none() {
        info!("Nothing to change. Config unchanged.");
        return Ok(());
    }
    let summary = [
        (!plan.is_empty()).then(|| plan.summary()),
        merged.as_ref().map(merge_summary),
        formatted.as_ref().map(format_summary),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("; ");

    if !plan.is_empty() {
        info!("Removal candidates ({}):", plan.summary());
    }
    for (&index, edit) in &plan.edits {
        let block = &config.hosts[index];
        let removed = &plan.removed[&index];
        let reason = |alias: &String| results.get(alias).map(removal_reason).unwrap_or_default();
        match edit {
            Edit::Remove => match removed.as_slice() {
                [alias] => info!("  Host {}: {}", block.label, reason(alias)),
                _ => {
                    info!("  Host {}", block.label);
                    for alias in removed {
                        info!("    - {alias}: {}", reason(alias));
                    }
                }
            },
            Edit::KeepAliases(kept) => {
                info!(
                    "  Host {}: remove {} of {} aliases, keep {}",
                    short_label(&block.aliases),
                    removed.len(),
                    block.aliases.len(),
                    kept.len()
                );
                for alias in removed {
                    info!("    - {alias}: {}", reason(alias));
                }
            }
        }
    }
    if let Some(merged) = &merged {
        print_merge(merged);
    }
    if let Some(formatted) = &formatted {
        print_format(&args, formatted);
    }
    let replacement = formatted.as_ref().map_or(replacement, |f| &f.text);
    if !apply_changes(&args, &path, &snapshot, replacement, &summary)? {
        return Ok(());
    }
    // The cache is keyed by the old config contents and is now useless.
    if let Some(cache) = cache
        && let Err(error) = cache.remove()
    {
        warn!("{error:#}");
    }
    Ok(())
}

/// How merging and the check of sorted settings run `ssh -G`.
fn eval_options(args: &Args) -> MergeOptions {
    MergeOptions {
        // Plain ssh also reads the system config; ssh -F does not.
        system_config: args.config.is_none(),
        timeout: Duration::from_secs(args.timeout),
        jobs: args.jobs.into(),
    }
}

/// Format `text` as requested; None when it is formatted already. Sorted
/// settings are kept only if `ssh -G` shows the same settings for every alias.
fn format_config(args: &Args, text: &str) -> Option<Formatted> {
    let options = FormatOptions {
        indent: args.indent.clone(),
        separator: args.separator.clone(),
        sort: args.sort,
    };
    let mut formatted = format::format(text, &options);
    if formatted.sorted > 0 {
        info!(
            "Sorting settings in {}: verifying with ssh -G ...",
            blocks(formatted.sorted)
        );
        let failure = match merge::changed_aliases(text, &formatted.text, &eval_options(args)) {
            Ok((verified, changed)) if changed.is_empty() => {
                info!("Sorted settings verified: ssh -G output unchanged for {verified} aliases.");
                None
            }
            Ok((_, mut changed)) => {
                changed.sort();
                changed.truncate(5);
                Some(format!("ssh -G results changed for {}", changed.join(", ")))
            }
            Err(error) => Some(format!("{error:#}")),
        };
        if let Some(failure) = failure {
            warn!("Sort skipped: {failure}");
            let options = FormatOptions {
                sort: false,
                ..options
            };
            formatted = format::format(text, &options);
        }
    }
    (formatted.text != text).then_some(formatted)
}

fn format_summary(formatted: &Formatted) -> String {
    match formatted.sorted {
        0 => "format whitespace".to_owned(),
        sorted => format!("format whitespace, sort settings in {}", blocks(sorted)),
    }
}

fn blocks(count: usize) -> String {
    match count {
        1 => "1 block".to_owned(),
        _ => format!("{count} blocks"),
    }
}

fn print_format(args: &Args, formatted: &Formatted) {
    info!(
        "Format (indent {:?}, separator {:?}):",
        args.indent, args.separator
    );
    let changes = formatted.changes();
    for change in &changes {
        info!("  {change}");
    }
    if changes.is_empty() {
        info!("  normalize whitespace");
    }
    debug!("Formatted config:\n{}", formatted.text.trim_end());
}

/// Return whether the replacement was written, so callers can invalidate caches.
fn apply_changes(
    args: &Args,
    path: &std::path::Path,
    snapshot: &Snapshot,
    replacement: &str,
    summary: &str,
) -> Result<bool> {
    if !args.apply {
        info!("Dry run: config unchanged. Run with --apply to review and confirm the changes.");
        return Ok(false);
    }

    if args.yes {
        info!(
            "Applying to {} without asking (--yes): {summary}.",
            path.display()
        );
    } else {
        print!(
            "{}Apply to {} ({summary})? A backup will be created first. [y/N] ",
            log::prefix(Level::Info),
            path.display()
        );
        io::stdout().flush()?;
        if !confirmed(&mut io::stdin().lock())? {
            info!("Cancelled. Config unchanged.");
            return Ok(false);
        }
    }
    debug!("Writing backup and replacement for {}", path.display());
    let backup = snapshot.apply(replacement)?;
    info!("Backup: {}", backup.display());
    info!("Updated {}: {summary}.", path.display());
    Ok(true)
}

/// Check reachability (reusing cached results) and plan the removals.
fn check_and_plan(
    args: &Args,
    config: &Config,
    keep: &HashSet<String>,
    targets: &[String],
    options: &ScanOptions,
    cache: &mut ResultCache,
    results: &mut HashMap<String, HostResult>,
) -> Plan {
    debug!("Result cache: {}", cache.path().display());
    // Reuse what an earlier (possibly interrupted) run already checked.
    let mut cached_aliases = HashSet::new();
    let mut oldest = None;
    for alias in targets {
        if let Some(cached) = cache.get(alias) {
            debug!(
                "cached ({}): {}",
                log::format_time(cached.checked_at),
                describe(&cached.result)
            );
            oldest = oldest
                .min(Some(cached.checked_at))
                .or(Some(cached.checked_at));
            results.insert(alias.clone(), cached.result.clone());
            cached_aliases.insert(alias.clone());
        }
    }
    let pending: Vec<_> = targets
        .iter()
        .filter(|a| !cached_aliases.contains(*a))
        .cloned()
        .collect();
    if let Some(oldest) = oldest {
        info!(
            "Reusing {} cached results (oldest {}); use --rescan to check everything again",
            cached_aliases.len(),
            log::format_time(oldest)
        );
    }
    info!(
        "Checking {} of {} aliases ...",
        pending.len(),
        targets.len()
    );
    check(&pending, options, cache, results);

    let mut plan = Plan::new(config, keep, results);
    if args.apply && !args.no_recheck {
        // Only these results can delete anything, so never act on a stale one.
        let stale: Vec<_> = plan
            .removed_aliases()
            .filter(|alias| cached_aliases.contains(*alias))
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        if !stale.is_empty() {
            info!(
                "Re-checking {} cached removal candidates before deleting ...",
                stale.len()
            );
            check(&stale, options, cache, results);
            plan = Plan::new(config, keep, results);
        }
    }
    plan
}

/// Probe `aliases`, printing and caching each result as soon as it arrives.
fn check(
    aliases: &[String],
    options: &ScanOptions,
    cache: &mut ResultCache,
    results: &mut HashMap<String, HostResult>,
) {
    let mut cache_ok = true;
    let fresh = scan::scan(aliases, options, |result| {
        print_result(result);
        if cache_ok && let Err(error) = cache.record(result) {
            warn!("cannot update result cache: {error:#}");
            cache_ok = false;
        }
    });
    for result in fresh {
        results.insert(result.alias.clone(), result);
    }
}

/// What to change: whole blocks whose aliases all failed are removed; blocks
/// with some failed aliases keep only the others on their Host line.
struct Plan {
    edits: BTreeMap<usize, Edit>,
    /// Aliases dropped from each edited block, in config order.
    removed: BTreeMap<usize, Vec<String>>,
}

impl Plan {
    fn new(config: &Config, keep: &HashSet<String>, results: &HashMap<String, HostResult>) -> Self {
        let mut edits = BTreeMap::new();
        let mut removed = BTreeMap::new();
        // ssh merges settings from every block matching an alias. An alias
        // that must survive somewhere (protected or --keep block) is therefore
        // never removed from any other block either, or its settings change.
        let untouchable: HashSet<&String> = config
            .hosts
            .iter()
            .filter(|b| b.protected.is_some() || b.aliases.iter().any(|a| keep.contains(a)))
            .flat_map(|b| &b.aliases)
            .chain(keep)
            .collect();
        for (index, block) in config.hosts.iter().enumerate() {
            // Protected and --keep blocks are never touched.
            if block.protected.is_some() || block.aliases.iter().any(|a| keep.contains(a)) {
                continue;
            }
            // Only a definite failure removes an alias; undecided ones stay.
            let (dead, alive): (Vec<_>, Vec<_>) =
                block.aliases.iter().cloned().partition(|alias| {
                    !untouchable.contains(alias)
                        && results.get(alias).is_some_and(HostResult::is_unreachable)
                });
            if dead.is_empty() {
                continue;
            }
            let edit = if alive.is_empty() {
                Edit::Remove
            } else {
                Edit::KeepAliases(alive)
            };
            edits.insert(index, edit);
            removed.insert(index, dead);
        }
        Self { edits, removed }
    }

    fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    fn removed_aliases(&self) -> impl Iterator<Item = &String> {
        self.removed.values().flatten()
    }

    fn summary(&self) -> String {
        let blocks = self.edits.values().filter(|e| **e == Edit::Remove).count();
        let pruned = self.edits.len() - blocks;
        let aliases: usize = self
            .edits
            .iter()
            .filter(|(_, e)| **e != Edit::Remove)
            .map(|(i, _)| self.removed[i].len())
            .sum();
        match (blocks, pruned) {
            (_, 0) => format!("remove {blocks} Host blocks"),
            (0, _) => format!("remove {aliases} aliases from {pruned} Host blocks"),
            _ => format!(
                "remove {blocks} Host blocks, and {aliases} aliases from {pruned} other Host blocks"
            ),
        }
    }
}

fn merge_summary(merged: &MergeResult) -> String {
    format!(
        "merge {} -> {} Host blocks, {} -> {} lines",
        merged.blocks.0, merged.blocks.1, merged.lines.0, merged.lines.1
    )
}

fn print_merge(merged: &MergeResult) {
    info!(
        "Merge ({}; every one of {} aliases verified with ssh -G):",
        merge_summary(merged),
        merged.verified
    );
    for (aliases, blocks) in &merged.merged {
        info!(
            "  combine {blocks} Host blocks with identical settings: Host {}",
            short_label(aliases)
        );
    }
    // Group identical settings, e.g. "ServerAliveInterval 5 (in 25 blocks)".
    let mut dropped: BTreeMap<&str, usize> = BTreeMap::new();
    for (aliases, setting) in &merged.dropped {
        *dropped.entry(setting).or_default() += 1;
        debug!("  no effect in Host {}: {setting}", short_label(aliases));
    }
    for (setting, blocks) in dropped {
        info!("  drop setting with no effect: {setting} (in {blocks} Host blocks)");
    }
    for (alias, aliases) in &merged.deduplicated {
        info!(
            "  drop duplicate alias {alias} from Host {}",
            short_label(aliases)
        );
    }
    for (alias, blocks) in &merged.conflicts {
        warn!(
            "  {alias} is listed in {blocks} Host blocks that give it different settings; left as is"
        );
    }
    if merged.reverted > 0 {
        info!(
            "  kept {} groups apart because merging them changed ssh -G results",
            merged.reverted
        );
    }
}

/// First few aliases of a long Host line, e.g. `a b c ... (+57)`.
fn short_label(aliases: &[String]) -> String {
    const SHOWN: usize = 3;
    if aliases.len() <= SHOWN + 1 {
        return aliases.join(" ");
    }
    format!(
        "{} ... (+{})",
        aliases[..SHOWN].join(" "),
        aliases.len() - SHOWN
    )
}

fn confirmed(reader: &mut impl BufRead) -> io::Result<bool> {
    let mut answer = String::new();
    reader.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn print_result(result: &HostResult) {
    let line = describe(result);
    match &result.status {
        Status::Reachable | Status::Excluded(_) => info!("{line}"),
        Status::Unreachable { .. } | Status::Skipped(_) => warn!("{line}"),
    }
}

fn describe(result: &HostResult) -> String {
    let endpoint = result
        .endpoint
        .as_ref()
        .map(|e| format!(" -> {e}"))
        .unwrap_or_default();
    match &result.status {
        Status::Reachable => format!(
            "[KEEP] {}{endpoint}: TCP connection succeeded",
            result.alias
        ),
        Status::Unreachable { attempts, reason } => format!(
            "[UNREACHABLE] {}{endpoint}: {attempts} failed attempts; {}",
            result.alias,
            single_line(reason)
        ),
        Status::Excluded(reason) | Status::Skipped(reason) => {
            format!("[SKIP] {}{endpoint}: {}", result.alias, single_line(reason))
        }
    }
}

/// One-line explanation of why an unreachable alias is a removal candidate.
fn removal_reason(result: &HostResult) -> String {
    let Status::Unreachable { attempts, reason } = &result.status else {
        return "not checked".to_owned();
    };
    let endpoint = result
        .endpoint
        .as_ref()
        .map(|e| format!("{e}, "))
        .unwrap_or_default();
    let plural = if *attempts == 1 { "" } else { "s" };
    format!(
        "{} ({endpoint}{attempts} attempt{plural})",
        brief_reason(reason)
    )
}

fn brief_reason(reason: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    let brief = if lower.starts_with("dns returned no addresses") {
        "no address for the configured address family"
    } else if lower.starts_with("dns lookup failed") {
        if [
            "name or service not known",
            "nodename nor servname",
            "no address associated",
            "not known",
        ]
        .iter()
        .any(|s| lower.contains(s))
        {
            "DNS name not found"
        } else {
            "DNS lookup failed"
        }
    } else if lower.contains("refused") {
        "connection refused (port closed)"
    } else if lower.contains("timed out") {
        "connection timed out (no response)"
    } else if lower.contains("no route to host") || lower.contains("host is unreachable") {
        "no route to host"
    } else if lower.contains("network is unreachable") {
        "network unreachable"
    } else {
        return single_line(reason);
    };
    brief.to_owned()
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_failure_reasons() {
        for (reason, expected) in [
            (
                "DNS lookup failed: failed to lookup address information: Name or service not known",
                "DNS name not found",
            ),
            (
                "1.2.3.4:22: Connection refused (os error 111)",
                "connection refused (port closed)",
            ),
            ("connection timed out", "connection timed out (no response)"),
            (
                "1.2.3.4:22: No route to host (os error 113)",
                "no route to host",
            ),
            ("something odd", "something odd"),
        ] {
            assert_eq!(brief_reason(reason), expected);
        }
    }

    #[test]
    fn confirmation_requires_an_explicit_yes() {
        for answer in ["", "\n", "no\n", "maybe\n", "yes please\n"] {
            assert!(!confirmed(&mut answer.as_bytes()).unwrap());
        }
        for answer in ["y\n", "yes\n", " Y \n", "YES\n"] {
            assert!(confirmed(&mut answer.as_bytes()).unwrap());
        }
    }
}
