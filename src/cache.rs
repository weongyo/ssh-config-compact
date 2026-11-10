//! Per-config cache of scan results, so a later run (for example `--apply`
//! after a dry run, or a rerun after an interrupted scan) does not have to
//! probe every host again.
//!
//! Format: JSON Lines. The first line is a [`Header`]; every following line
//! is one [`Entry`], appended (and flushed) as soon as a host is checked, so
//! an interrupted run keeps everything it finished. A torn last line is
//! ignored on load.

use crate::scan::HostResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION: u32 = 1;

/// Everything that changes what a probe would report. Results are only
/// reused when the config bytes and all of these match exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanKey {
    pub custom_config: bool,
    pub attempts: usize,
    pub timeout_secs: u64,
    pub jump_timeout_secs: u64,
    pub skip_private: bool,
    pub via_proxyjump: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Header {
    version: u32,
    config_path: PathBuf,
    config_sha256: String,
    key: ScanKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    checked_at: u64,
    result: HostResult,
}

pub struct Cached {
    pub result: HostResult,
    pub checked_at: SystemTime,
}

pub struct ResultCache {
    path: PathBuf,
    file: File,
    entries: HashMap<String, Cached>,
}

impl ResultCache {
    /// Open the cache for `config_path`, keeping entries that match the
    /// config contents and `key` and are younger than `ttl`. With `fresh`, or
    /// when anything differs, start from an empty cache.
    pub fn open(
        config_path: &Path,
        config: &[u8],
        key: ScanKey,
        ttl: Duration,
        fresh: bool,
    ) -> Result<Self> {
        // One file per config path and option set, so alternating between
        // option sets does not discard the other set's results.
        let mut id = Sha256::new();
        id.update(config_path.as_os_str().as_encoded_bytes());
        id.update([0]);
        id.update(serde_json::to_vec(&key)?);
        let path = cache_dir()?.join(format!("results-{}.jsonl", &hex(&id.finalize())[..16]));
        let header = Header {
            version: VERSION,
            config_path: config_path.to_owned(),
            config_sha256: hex(&Sha256::digest(config)),
            key,
        };
        let now = SystemTime::now();
        let entries = if fresh {
            HashMap::new()
        } else {
            load(&path, &header, now, ttl).unwrap_or_default()
        };
        // Rewrite atomically with only the surviving entries, then append.
        let dir = path.parent().context("cache path has no parent")?;
        let mut temp = tempfile::Builder::new()
            .prefix(".results-")
            .tempfile_in(dir)?;
        writeln!(temp, "{}", serde_json::to_string(&header)?)?;
        for cached in entries.values() {
            write_entry(&mut temp, &cached.result, cached.checked_at)?;
        }
        temp.as_file().sync_all()?;
        temp.persist(&path)
            .with_context(|| format!("cannot write result cache {}", path.display()))?;
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok(Self {
            path,
            file,
            entries,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, alias: &str) -> Option<&Cached> {
        self.entries.get(alias)
    }

    /// Record a fresh result immediately so an interrupted run keeps it.
    pub fn record(&mut self, result: &HostResult) -> Result<()> {
        let now = SystemTime::now();
        write_entry(&mut self.file, result, now)?;
        self.file.flush()?;
        self.entries.insert(
            result.alias.clone(),
            Cached {
                result: result.clone(),
                checked_at: now,
            },
        );
        Ok(())
    }

    /// The config was rewritten; these results no longer describe it.
    pub fn remove(self) -> Result<()> {
        fs::remove_file(&self.path)
            .with_context(|| format!("cannot remove result cache {}", self.path.display()))
    }
}

fn load(
    path: &Path,
    header: &Header,
    now: SystemTime,
    ttl: Duration,
) -> Option<HashMap<String, Cached>> {
    let file = File::open(path).ok()?;
    let mut lines = BufReader::new(file).lines();
    let found: Header = serde_json::from_str(&lines.next()?.ok()?).ok()?;
    if &found != header {
        return None;
    }
    let mut entries = HashMap::new();
    for line in lines {
        let Ok(line) = line else { break };
        // A torn final line from an interrupted run is simply skipped.
        let Ok(entry) = serde_json::from_str::<Entry>(&line) else {
            continue;
        };
        let checked_at = UNIX_EPOCH + Duration::from_secs(entry.checked_at);
        let age = now.duration_since(checked_at).unwrap_or_default();
        if age <= ttl {
            entries.insert(
                entry.result.alias.clone(),
                Cached {
                    result: entry.result,
                    checked_at,
                },
            );
        }
    }
    Some(entries)
}

fn write_entry(out: &mut impl Write, result: &HostResult, checked_at: SystemTime) -> Result<()> {
    let entry = Entry {
        checked_at: checked_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        result: result.clone(),
    };
    writeln!(out, "{}", serde_json::to_string(&entry)?)?;
    Ok(())
}

fn cache_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".cache"),
    };
    let dir = base.join("ssh-config-compact");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("cannot create cache directory {}", dir.display()))?;
    Ok(dir)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Status;

    fn header() -> Header {
        Header {
            version: VERSION,
            config_path: "/c".into(),
            config_sha256: "abc".into(),
            key: ScanKey {
                custom_config: true,
                attempts: 3,
                timeout_secs: 3,
                jump_timeout_secs: 5,
                skip_private: false,
                via_proxyjump: true,
            },
        }
    }

    fn entry(alias: &str, checked_at: SystemTime) -> String {
        let mut out = Vec::new();
        let result = HostResult {
            alias: alias.into(),
            endpoint: None,
            status: Status::Reachable,
        };
        write_entry(&mut out, &result, checked_at).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn loads_matching_fresh_entries_and_ignores_torn_lines() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(7200);
        let file = tempfile::NamedTempFile::new().unwrap();
        let text = format!(
            "{}\n{}{}{{\"checked_at\":1,\"res",
            serde_json::to_string(&header()).unwrap(),
            entry("fresh", now),
            entry("stale", old),
        );
        fs::write(file.path(), text).unwrap();
        let loaded = load(file.path(), &header(), now, Duration::from_secs(3600)).unwrap();
        assert!(loaded.contains_key("fresh"));
        assert!(!loaded.contains_key("stale"));
        assert_eq!(loaded.len(), 1);

        let mut other = header();
        other.config_sha256 = "changed".into();
        assert!(load(file.path(), &other, now, Duration::from_secs(3600)).is_none());
    }
}
