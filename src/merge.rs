//! Simplify a config without changing what ssh does with it.
//!
//! Every step is checked with `ssh -G`, which prints the configuration ssh
//! would actually use for a host:
//!
//! 1. Drop aliases listed twice on the same Host line.
//! 2. Drop an alias from one of several blocks listing it, when that alias'
//!    `ssh -G` output stays the same.
//! 3. Drop settings with no effect: a line whose removal leaves `ssh -G`
//!    unchanged for every alias of its block (for example a value that an
//!    earlier global setting already decided, or a repeat of a later
//!    `Host *` value).
//! 4. Merge blocks whose remaining settings are identical into one Host line.
//!
//! Finally every literal alias in the config is compared before and after.
//! Merges that change any result are undone; if a difference remains, the
//! whole merge is abandoned.

use crate::config::{Config, Directive, literal_alias};
use crate::scan::ssh_g;
use crate::storage::{include_arg, system_config_path};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// How to run `ssh -G`, for merging and for verifying other rewrites.
pub struct MergeOptions {
    /// Evaluate like plain `ssh`: the user config followed by the system
    /// config. False for an explicit `--config`, which ssh reads alone.
    pub system_config: bool,
    pub timeout: Duration,
    pub jobs: usize,
}

pub struct MergeResult {
    pub text: String,
    /// Number of aliases whose `ssh -G` output was compared.
    pub verified: usize,
    pub blocks: (usize, usize),
    pub lines: (usize, usize),
    /// Resulting Host line aliases and how many blocks were combined.
    pub merged: Vec<(Vec<String>, usize)>,
    /// (block aliases, setting as written) for every removed setting.
    pub dropped: Vec<(Vec<String>, String)>,
    /// (alias, aliases of the block it was removed from).
    pub deduplicated: Vec<(String, Vec<String>)>,
    /// Aliases still listed in several blocks that contribute different
    /// settings; these are left for a human to sort out.
    pub conflicts: Vec<(String, usize)>,
    /// Merges undone because the final check found a difference.
    pub reverted: usize,
}

impl MergeResult {
    pub fn changed(&self) -> bool {
        self.blocks.0 != self.blocks.1 || !self.dropped.is_empty() || !self.deduplicated.is_empty()
    }
}

/// Edits relative to the parsed source.
#[derive(Clone)]
struct State {
    aliases: Vec<Vec<String>>,
    dropped: Vec<HashSet<usize>>,
    removed: HashSet<usize>,
}

/// Every literal alias of the config's Host lines, once, in order.
fn literal_aliases(config: &Config) -> Vec<String> {
    let mut seen = HashSet::new();
    config
        .hosts
        .iter()
        .flat_map(|b| &b.aliases)
        .filter(|alias| literal_alias(alias) && seen.insert(*alias))
        .cloned()
        .collect()
}

/// Compare `ssh -G` for every literal alias of `before` with `after` as the
/// config. Returns how many aliases were compared and those that differ.
pub fn changed_aliases(
    before: &str,
    after: &str,
    options: &MergeOptions,
) -> Result<(usize, Vec<String>)> {
    let aliases = literal_aliases(&Config::parse(before.to_owned())?);
    let evaluator = Evaluator::new(options)?;
    let old = evaluator.evaluate(before, &aliases, "")?;
    let new = evaluator.evaluate(after, &aliases, "")?;
    let changed = aliases
        .iter()
        .filter(|alias| old.get(*alias) != new.get(*alias))
        .cloned()
        .collect();
    Ok((aliases.len(), changed))
}

pub fn merge(source: &str, options: &MergeOptions) -> Result<MergeResult> {
    let config = Config::parse(source.to_owned())?;
    let hosts = &config.hosts;
    let editable: Vec<bool> = hosts.iter().map(|b| b.protected.is_none()).collect();
    let all = literal_aliases(&config);
    let evaluator = Evaluator::new(options)?;
    let baseline = evaluator.evaluate(source, &all, "")?;
    // Most rejected changes already differ for the first alias, so check it
    // alone before paying for the whole block. Every alias is still checked.
    let stages = |aliases: &[String]| -> [Vec<String>; 2] {
        [aliases.iter().take(1).cloned().collect(), aliases.to_vec()]
    };
    let same = |text: &str, aliases: &[String]| -> Result<bool> {
        for part in stages(aliases) {
            let result = evaluator.evaluate(text, &part, "")?;
            if !part.iter().all(|a| result.get(a) == baseline.get(a)) {
                return Ok(false);
            }
        }
        Ok(true)
    };
    // ssh -G only shows that nothing changes on this machine. A line that
    // merely restates a default (User = the local account, Port 22, ...)
    // would matter for another account or system config. Re-check with a
    // `Host *` that sets the same keys to other values in place of the
    // system config: a line that is really redundant is shadowed by another
    // line of the config and stays invisible; one that relies on the default
    // lets the sentinel through.
    let portable =
        |current: &str, trial: &str, aliases: &[String], keys: &[&Directive]| -> Result<bool> {
            let Some(sentinel) = sentinel(keys) else {
                return Ok(false);
            };
            for part in stages(aliases) {
                let before = evaluator.evaluate(current, &part, &sentinel)?;
                let after = evaluator.evaluate(trial, &part, &sentinel)?;
                let unchanged = part.iter().all(|a| {
                    let output = &before[a];
                    !output.starts_with("error:") && after.get(a) == Some(output)
                });
                if !unchanged {
                    return Ok(false);
                }
            }
            Ok(true)
        };

    let mut state = State {
        aliases: hosts.iter().map(|b| b.aliases.clone()).collect(),
        dropped: vec![HashSet::new(); hosts.len()],
        removed: HashSet::new(),
    };
    let mut deduplicated = Vec::new();
    let mut conflicts = Vec::new();
    let mut dropped = Vec::new();

    // 1. An alias repeated on one Host line is always redundant.
    for (index, aliases) in state.aliases.iter_mut().enumerate() {
        if editable[index] {
            let mut seen = HashSet::new();
            aliases.retain(|a| seen.insert(a.clone()));
        }
    }

    // 2. Aliases listed in several blocks.
    for alias in &all {
        loop {
            let blocks: Vec<usize> = (0..hosts.len())
                .filter(|&i| state.aliases[i].contains(alias))
                .collect();
            if blocks.len() < 2 {
                break;
            }
            let mut progress = false;
            // Prefer dropping later occurrences; the first block usually
            // carries the settings the alias was added for.
            for &block in blocks.iter().rev() {
                if !editable[block] || state.aliases[block].len() < 2 {
                    continue;
                }
                let mut trial = state.clone();
                trial.aliases[block].retain(|a| a != alias);
                let trial_text = render(&config, &trial);
                let alias_slice = std::slice::from_ref(alias);
                let settings: Vec<&Directive> = hosts[block]
                    .directives
                    .iter()
                    .enumerate()
                    .filter(|(line, _)| !state.dropped[block].contains(line))
                    .map(|(_, d)| d)
                    .collect();
                if same(&trial_text, alias_slice)?
                    && portable(
                        &render(&config, &state),
                        &trial_text,
                        alias_slice,
                        &settings,
                    )?
                {
                    deduplicated.push((alias.clone(), state.aliases[block].clone()));
                    state = trial;
                    progress = true;
                    break;
                }
            }
            if !progress {
                conflicts.push((alias.clone(), blocks.len()));
                break;
            }
        }
    }

    // 3. Settings with no effect.
    for (index, block) in hosts.iter().enumerate() {
        if !editable[index] {
            continue;
        }
        for (line, directive) in block.directives.iter().enumerate() {
            let mut trial = state.clone();
            trial.dropped[index].insert(line);
            let trial_text = render(&config, &trial);
            if same(&trial_text, &state.aliases[index])?
                && portable(
                    &render(&config, &state),
                    &trial_text,
                    &state.aliases[index],
                    &[directive],
                )?
            {
                dropped.push((state.aliases[index].clone(), normalize(&directive.text)));
                state = trial;
            }
        }
    }

    // 4. Blocks with identical remaining settings. Only blocks whose aliases
    // appear nowhere else are moved, so no alias changes which blocks match it.
    let mut count: HashMap<&String, usize> = HashMap::new();
    for aliases in &state.aliases {
        for alias in aliases {
            *count.entry(alias).or_default() += 1;
        }
    }
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut by_settings: HashMap<Vec<(String, String)>, usize> = HashMap::new();
    for (index, block) in hosts.iter().enumerate() {
        if !editable[index] || state.aliases[index].iter().any(|a| count[a] > 1) {
            continue;
        }
        let settings: Vec<_> = block
            .directives
            .iter()
            .enumerate()
            .filter(|(line, _)| !state.dropped[index].contains(line))
            .map(|(_, d)| (d.key.clone(), d.value.clone()))
            .collect();
        match by_settings.get(&settings) {
            Some(&group) => groups[group].push(index),
            None => {
                by_settings.insert(settings, groups.len());
                groups.push(vec![index]);
            }
        }
    }
    groups.retain(|g| g.len() > 1);

    // 5. Verify everything; undo merges that change any result.
    let mut reverted = 0;
    let (text, merged_state) = loop {
        let candidate = combine(&state, &groups);
        let text = render(&config, &candidate);
        let result = evaluator.evaluate(&text, &all, "")?;
        let differs: HashSet<&String> = all
            .iter()
            .filter(|a| result.get(*a) != baseline.get(*a))
            .collect();
        if differs.is_empty() {
            break (text, candidate);
        }
        let before = groups.len();
        groups.retain(|g| {
            !g.iter()
                .any(|&i| state.aliases[i].iter().any(|a| differs.contains(a)))
        });
        if groups.len() == before {
            let mut names: Vec<_> = differs.into_iter().cloned().collect();
            names.sort();
            names.truncate(5);
            bail!("ssh -G results changed for {}", names.join(", "));
        }
        reverted += before - groups.len();
    };

    let merged = groups
        .iter()
        .map(|g| (merged_state.aliases[g[0]].clone(), g.len()))
        .collect();
    Ok(MergeResult {
        verified: all.len(),
        blocks: (hosts.len(), hosts.len() - merged_state.removed.len()),
        lines: (source.lines().count(), text.lines().count()),
        text,
        merged,
        dropped,
        deduplicated,
        conflicts,
        reverted,
    })
}

/// Move every group's aliases into its first block and remove the others.
fn combine(state: &State, groups: &[Vec<usize>]) -> State {
    let mut combined = state.clone();
    for group in groups {
        let (first, rest) = group.split_first().expect("groups have members");
        for &other in rest {
            let aliases = std::mem::take(&mut combined.aliases[other]);
            combined.aliases[*first].extend(aliases);
            combined.removed.insert(other);
        }
    }
    combined
}

fn render(config: &Config, state: &State) -> String {
    let source = config.source();
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    for (index, block) in config.hosts.iter().enumerate() {
        if state.removed.contains(&index) {
            // Also take the blank lines after the block, so merged-away
            // blocks do not leave growing gaps behind.
            let mut range = block.removal();
            while let Some(line) = source[range.end..].split_inclusive('\n').next() {
                if !line.trim().is_empty() {
                    break;
                }
                range.end += line.len();
            }
            // At the end of the file, drop the separating blank lines before
            // the block instead, so the file does not end with them.
            if range.end == source.len() {
                while range.start > 0 {
                    let before = &source[..range.start - 1];
                    let start = before.rfind('\n').map_or(0, |i| i + 1);
                    if !source[start..range.start].trim().is_empty() {
                        break;
                    }
                    range.start = start;
                }
            }
            edits.push((range, String::new()));
            continue;
        }
        if state.aliases[index] != block.aliases {
            edits.push((block.alias_list(), state.aliases[index].join(" ")));
        }
        for &line in &state.dropped[index] {
            edits.push((block.directives[line].line.clone(), String::new()));
        }
    }
    edits.sort_by_key(|(range, _)| range.start);
    let mut result = String::with_capacity(source.len());
    let mut offset = 0;
    for (range, replacement) in edits {
        result.push_str(&source[offset..range.start]);
        result.push_str(&replacement);
        offset = range.end;
    }
    result.push_str(&source[offset..]);
    result
}

/// A final `Host *` block giving every key of `directives` a different
/// value, or None when no safe different value is known for some key.
fn sentinel(directives: &[&Directive]) -> Option<String> {
    let mut block = String::from("Host *\n");
    let mut seen = HashSet::new();
    for directive in directives {
        if seen.insert(&directive.key) {
            let value = other_value(&directive.key, &directive.value)?;
            block.push_str(&format!("  {} {value}\n", directive.key));
        }
    }
    Some(block)
}

/// A valid value for `key` that differs from `value`.
fn other_value(key: &str, value: &str) -> Option<String> {
    let pick = |a: &str, b: &str| if value == a { b } else { a }.to_owned();
    Some(match key {
        "user" => format!("{value}x"),
        "port" => pick("2222", "2223"),
        "hostname" | "proxyjump" => "ssh-config-compact.invalid".to_owned(),
        "hostkeyalgorithms"
        | "pubkeyacceptedalgorithms"
        | "pubkeyacceptedkeytypes"
        | "hostbasedacceptedalgorithms" => pick("ssh-ed25519", "ecdsa-sha2-nistp256"),
        "kexalgorithms" => pick("curve25519-sha256", "ecdh-sha2-nistp256"),
        "ciphers" => pick("aes128-ctr", "aes256-ctr"),
        "macs" => pick("hmac-sha2-256", "hmac-sha2-512"),
        "identityfile" | "certificatefile" | "userknownhostsfile" | "identityagent" => {
            pick("~/.ssh/ssh-config-compact-a", "~/.ssh/ssh-config-compact-b")
        }
        "proxycommand" => pick("nc ssh-config-compact.invalid %p", "nc example.invalid %p"),
        // Ignored by every supported OpenSSH; any value is equivalent.
        "protocol" => "2".to_owned(),
        _ => match value {
            "yes" => "no".to_owned(),
            "no" => "yes".to_owned(),
            _ => (value.parse::<u32>().ok()? + 1).to_string(),
        },
    })
}

fn normalize(line: &str) -> String {
    line.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// Runs `ssh -G` against candidate configs, in parallel.
struct Evaluator<'a> {
    dir: tempfile::TempDir,
    options: &'a MergeOptions,
    /// `Include` line for the system config, when plain ssh would read it.
    system_include: Option<String>,
    next: AtomicUsize,
}

impl<'a> Evaluator<'a> {
    fn new(options: &'a MergeOptions) -> Result<Self> {
        let system_include = if options.system_config {
            Some(format!(
                "Include {}\n",
                include_arg(&system_config_path()?)?
            ))
        } else {
            None
        };
        Ok(Self {
            dir: tempfile::Builder::new()
                .prefix("ssh-config-compact-merge-")
                .tempdir()?,
            options,
            system_include,
            next: AtomicUsize::new(0),
        })
    }

    /// `ssh -G` for `aliases` with `text` as the user config, then
    /// `appended`, then the system config (when plain ssh would read it).
    fn evaluate(
        &self,
        text: &str,
        aliases: &[String],
        appended: &str,
    ) -> Result<HashMap<String, String>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let candidate = self.dir.path().join(format!("config-{id}"));
        fs::write(&candidate, text)?;
        let entry: PathBuf = if self.system_include.is_some() || !appended.is_empty() {
            let wrapper = self.dir.path().join(format!("wrapper-{id}"));
            let mut content = format!("Include {}\n", include_arg(&candidate)?);
            // Stands in for a different system config, so it goes before
            // this machine's one: a line kept only because this system config
            // happens to repeat it must not look redundant.
            content.push_str(appended);
            if let Some(system_include) = &self.system_include {
                // Plain ssh reads the system config after the user config.
                content.push_str(system_include);
            }
            fs::write(&wrapper, content)?;
            wrapper
        } else {
            candidate.clone()
        };
        let results = Mutex::new(HashMap::with_capacity(aliases.len()));
        let next = AtomicUsize::new(0);
        thread::scope(|scope| {
            for _ in 0..self.options.jobs.clamp(1, aliases.len().max(1)) {
                scope.spawn(|| {
                    while let Some(alias) = aliases.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let output = describe(&entry, &candidate, alias, self.options.timeout);
                        results.lock().unwrap().insert(alias.clone(), output);
                    }
                });
            }
        });
        let _ = fs::remove_file(&candidate);
        let _ = fs::remove_file(self.dir.path().join(format!("wrapper-{id}")));
        Ok(results.into_inner().unwrap())
    }
}

/// `ssh -G` output, or the error, with the temporary paths masked so that
/// two candidates can be compared.
fn describe(entry: &Path, candidate: &Path, alias: &str, timeout: Duration) -> String {
    let mut output = match ssh_g(entry, alias, timeout) {
        Ok(output) => output,
        Err(error) => format!("error: {error:#}"),
    };
    for path in [entry, candidate] {
        let path = path.to_string_lossy();
        output = output.replace(&*path, "<config>");
        if cfg!(windows) {
            // As written in the Include lines (see include_arg).
            output = output.replace(&path.replace('\\', "/"), "<config>");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_values_differ_and_unknown_kinds_are_refused() {
        for (key, value) in [
            ("user", "weongyo"),
            ("port", "22"),
            ("port", "2222"),
            ("serveraliveinterval", "5"),
            ("pubkeyauthentication", "yes"),
            ("hostkeyalgorithms", "+ssh-rsa"),
        ] {
            assert_ne!(other_value(key, value).unwrap(), value, "{key}");
        }
        assert_eq!(other_value("stricthostkeychecking", "accept-new"), None);
        assert_eq!(other_value("controlpersist", "10m"), None);
    }

    #[test]
    fn renders_alias_changes_dropped_lines_and_removed_blocks() {
        let source =
            "Global yes\n\nHost a a b\n  User x\n  Port 1\n\n\nHost c\n  User x\n\n# end\n";
        let config = Config::parse(source.to_owned()).unwrap();
        let mut state = State {
            aliases: config.hosts.iter().map(|b| b.aliases.clone()).collect(),
            dropped: vec![HashSet::new(); 2],
            removed: HashSet::new(),
        };
        state.aliases[0] = vec!["a".into(), "b".into(), "c".into()];
        state.dropped[0].insert(1);
        state.removed.insert(1);
        assert_eq!(
            render(&config, &state),
            "Global yes\n\nHost a b c\n  User x\n\n\n# end\n"
        );
    }
}
