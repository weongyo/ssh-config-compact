use anyhow::{Result, bail};
use std::collections::{BTreeMap, HashSet};
use std::ops::Range;

#[derive(Debug)]
pub struct HostBlock {
    pub label: String,
    pub aliases: Vec<String>,
    pub protected: Option<String>,
    removal: Range<usize>,
    /// Byte range of the alias list on the Host line. Everything before it
    /// (indent, keyword, separator) and after it (comment, line ending) is
    /// kept verbatim when aliases are pruned.
    alias_list: Range<usize>,
    /// Settings inside the block, in order.
    pub(crate) directives: Vec<Directive>,
}

/// One setting line inside a Host block.
#[derive(Clone, Debug)]
pub(crate) struct Directive {
    /// Lowercased keyword.
    pub key: String,
    /// Arguments with whitespace collapsed.
    pub value: String,
    /// The whole line, including its line ending.
    pub line: Range<usize>,
    /// The line as written, without surrounding whitespace.
    pub text: String,
}

/// A change to one Host block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Remove the whole block.
    Remove,
    /// Keep the block but list only these aliases on its Host line.
    KeepAliases(Vec<String>),
}

#[derive(Debug)]
pub struct Config {
    source: String,
    pub hosts: Vec<HostBlock>,
}

impl HostBlock {
    pub(crate) fn removal(&self) -> Range<usize> {
        self.removal.clone()
    }

    pub(crate) fn alias_list(&self) -> Range<usize> {
        self.alias_list.clone()
    }
}

impl Config {
    pub fn parse(source: String) -> Result<Self> {
        let mut hosts: Vec<HostBlock> = Vec::new();
        let mut current = None;
        let mut offset = 0;
        for (index, line) in source.split_inclusive('\n').enumerate() {
            if let Some((key, value)) = directive(line) {
                if key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case("match") {
                    current = None;
                    if key.eq_ignore_ascii_case("host") {
                        let (aliases, comment) =
                            words(value).map_err(|e| anyhow::anyhow!("line {}: {e}", index + 1))?;
                        // value is a subslice of line; recover absolute offsets.
                        let value_start =
                            offset + (value.as_ptr() as usize - line.as_ptr() as usize);
                        let list = value[..comment.unwrap_or(value.len())].trim_end();
                        let alias_list = value_start..value_start + list.len();
                        if aliases.is_empty() {
                            bail!("line {}: Host requires at least one pattern", index + 1);
                        }
                        let protected = aliases
                            .iter()
                            .any(|a| !literal_alias(a))
                            .then(|| "wildcard, negation, or unsupported alias syntax".to_owned());
                        hosts.push(HostBlock {
                            label: aliases.join(" "),
                            aliases,
                            protected,
                            removal: offset..offset + line.len(),
                            alias_list,
                            directives: Vec::new(),
                        });
                        current = Some(hosts.len() - 1);
                    }
                } else if let Some(i) = current {
                    hosts[i].removal.end = offset + line.len();
                    hosts[i].directives.push(Directive {
                        key: key.to_ascii_lowercase(),
                        value: value.split_ascii_whitespace().collect::<Vec<_>>().join(" "),
                        line: offset..offset + line.len(),
                        text: line.trim().to_owned(),
                    });
                    // An include can introduce Host/Match sections and change the scope
                    // of subsequent lines. Never remove such a block.
                    if key.eq_ignore_ascii_case("include") {
                        hosts[i].protected = Some("block contains Include".to_owned());
                    }
                }
            }
            offset += line.len();
        }
        Ok(Self { source, hosts })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn targets(&self, keep: &HashSet<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        self.hosts
            .iter()
            .filter(|block| {
                block.protected.is_none() && !block.aliases.iter().any(|a| keep.contains(a))
            })
            .flat_map(|block| block.aliases.iter())
            .filter(|alias| seen.insert((*alias).clone()))
            .cloned()
            .collect()
    }

    pub fn without(&self, indices: &HashSet<usize>) -> String {
        self.edited(&indices.iter().map(|&i| (i, Edit::Remove)).collect())
    }

    /// Apply `edits` (keyed by Host block index). All other bytes are kept.
    pub fn edited(&self, edits: &BTreeMap<usize, Edit>) -> String {
        let mut result = String::with_capacity(self.source.len());
        let mut offset = 0;
        for (&index, edit) in edits {
            let block = &self.hosts[index];
            match edit {
                Edit::Remove => {
                    result.push_str(&self.source[offset..block.removal.start]);
                    offset = block.removal.end;
                }
                Edit::KeepAliases(aliases) => {
                    debug_assert!(!aliases.is_empty() && block.protected.is_none());
                    result.push_str(&self.source[offset..block.alias_list.start]);
                    // Only literal aliases reach here, so no quoting is needed.
                    result.push_str(&aliases.join(" "));
                    offset = block.alias_list.end;
                }
            }
        }
        result.push_str(&self.source[offset..]);
        result
    }
}

// Only parse directive names and Host arguments; OpenSSH interprets the actual
// connection settings. Keeping byte offsets preserves surviving text verbatim.
fn directive(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_ascii_whitespace() || c == '=')
        .unwrap_or(line.len());
    let key = &line[..end];
    let mut value = line[end..].trim_start();
    if let Some(rest) = value.strip_prefix('=') {
        value = rest.trim_start();
    }
    Some((key, value))
}

/// Split Host arguments. Also returns the byte offset of a trailing comment.
fn words(value: &str) -> Result<(Vec<String>, Option<usize>)> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = None;
    let mut started = false;
    let mut comment = None;
    let mut chars = value.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' if matches!(chars.peek(), Some((_, '"' | '\'' | '\\'))) => {
                word.push(chars.next().unwrap().1);
                started = true;
            }
            '"' | '\'' if quoted.is_none() => {
                quoted = Some(c);
                started = true;
            }
            c if Some(c) == quoted => quoted = None,
            // Older OpenSSH versions allow # inside an unquoted word. Treat
            // that syntax as a literal (and therefore protected) rather than
            // risk deleting a different alias after truncating it.
            '#' if quoted.is_none() && !started => {
                comment = Some(at);
                break;
            }
            c if c.is_ascii_whitespace() && quoted.is_none() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => {
                word.push(c);
                started = true;
            }
        }
    }
    if quoted.is_some() {
        bail!("unterminated quote in Host directive");
    }
    if started {
        words.push(word);
    }
    Ok((words, comment))
}

pub(crate) fn literal_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.starts_with('-')
        && alias
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_host_content_and_preserves_other_bytes() {
        let source = "# global\r\nUser me\r\n\r\nHoSt = \"old\" old-alias # note\r\n  HostName old.invalid\r\n  # internal\r\n  Port 2222\r\n\r\n# next host\r\nHost live\r\n\tHostName 127.0.0.1\r\nMatch user root\r\n  User admin";
        let config = Config::parse(source.to_owned()).unwrap();
        assert_eq!(config.hosts[0].aliases, ["old", "old-alias"]);
        assert_eq!(
            config.without(&HashSet::from([0])),
            "# global\r\nUser me\r\n\r\n\r\n# next host\r\nHost live\r\n\tHostName 127.0.0.1\r\nMatch user root\r\n  User admin"
        );
        assert_eq!(config.without(&HashSet::new()), source);
    }

    #[test]
    fn prunes_aliases_on_the_host_line_only() {
        let source = "Host\t\ta dead1 b dead2   # keep me\r\n  HostName x\nHost=c dead3\nHost dead4\n  Port 1\nHost e\n";
        let config = Config::parse(source.to_owned()).unwrap();
        let edits = BTreeMap::from([
            (0, Edit::KeepAliases(vec!["a".into(), "b".into()])),
            (1, Edit::KeepAliases(vec!["c".into()])),
            (2, Edit::Remove),
        ]);
        assert_eq!(
            config.edited(&edits),
            "Host\t\ta b   # keep me\r\n  HostName x\nHost=c\nHost e\n"
        );
    }

    #[test]
    fn protects_patterns_includes_and_unsupported_aliases() {
        let config = Config::parse(
            "Include conf.d/*\nHost * !old\n  User me\nHost db\n  Include db.conf\nHost weird/alias\nHost good alias\n  Port 22\nMatch all\n  Include others\nHost final\n".to_owned(),
        ).unwrap();
        assert!(config.hosts[..3].iter().all(|b| b.protected.is_some()));
        assert_eq!(config.targets(&HashSet::new()), ["good", "alias", "final"]);
        assert_eq!(config.targets(&HashSet::from(["alias".into()])), ["final"]);
    }

    #[test]
    fn rejects_malformed_headers_and_deduplicates_targets() {
        assert!(Config::parse("Host # empty\n".to_owned()).is_err());
        assert!(Config::parse("Host \"unclosed\n".to_owned()).is_err());
        let config = Config::parse("Host=db\nHost db db2\n".to_owned()).unwrap();
        assert_eq!(config.targets(&HashSet::new()), ["db", "db2"]);
        assert_eq!(config.without(&HashSet::from([0, 1])), "");
    }

    #[test]
    fn protects_hash_inside_alias_instead_of_treating_it_as_a_comment() {
        let config =
            Config::parse("Host old#alias\n  HostName live.example\nHost plain # comment\n".into())
                .unwrap();
        assert_eq!(config.hosts[0].aliases, ["old#alias"]);
        assert!(config.hosts[0].protected.is_some());
        assert_eq!(config.targets(&HashSet::new()), ["plain"]);
    }
}
