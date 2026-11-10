//! Formatting: indentation, keyword separators, blank lines and, on request,
//! the order of settings inside each block.
//!
//! Only whitespace that OpenSSH ignores is rewritten: indentation, the
//! separator after a keyword, and trailing whitespace (OpenSSH strips it
//! before parsing a line). Keywords, arguments, quotes, commands and comment
//! text are kept byte for byte.
//!
//! Sorting is stable and only moves a setting past settings with another
//! keyword. OpenSSH keeps the first value of each keyword, and list keywords
//! (IdentityFile, LocalForward, SendEnv, ...) keep their values in order, so
//! that order does not matter. Lines whose position does matter stay where
//! they are: Include reads other settings at its place, IgnoreUnknown only
//! covers the lines after it, and keywords that set the same option
//! (ProxyJump/ProxyCommand, obsolete names) keep their relative order. Blank
//! lines stay too; they separate groups made on purpose.

use std::collections::HashMap;
use std::ops::Range;

/// Whitespace that OpenSSH splits a line on.
const SPACE: &[char] = &[' ', '\t', '\r'];
/// Whitespace that OpenSSH strips from the end of a line.
const TRAILING: &[char] = &[' ', '\t', '\r', '\x0c'];

#[derive(Clone, Debug)]
pub struct FormatOptions {
    /// Prefix for settings and their comments inside Host and Match blocks.
    pub indent: String,
    /// Between a keyword and its arguments. Host and Match lines always use a
    /// single space.
    pub separator: String,
    /// Sort the settings of every block by keyword.
    pub sort: bool,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            indent: "  ".to_owned(),
            separator: " ".to_owned(),
            sort: false,
        }
    }
}

/// A formatted config and how many lines each kind of change touched.
#[derive(Debug, Default)]
pub struct Formatted {
    pub text: String,
    pub indented: usize,
    pub separators: usize,
    pub trailing: usize,
    pub endings: usize,
    pub blank_removed: usize,
    /// Blank lines added between blocks.
    pub blank_added: usize,
    /// Blocks (counting the global section) whose settings were reordered.
    pub sorted: usize,
}

impl Formatted {
    /// One description per kind of change, for review before applying.
    pub fn changes(&self) -> Vec<String> {
        let lines = |count: usize, what: &str| match count {
            1 => format!("1 {what}"),
            _ => format!("{count} {what}s"),
        };
        [
            (self.indented, "re-indent", "line"),
            (self.separators, "rewrite the keyword separator on", "line"),
            (self.trailing, "trim trailing whitespace on", "line"),
            (self.endings, "fix the line ending of", "line"),
            (self.blank_removed, "remove", "blank line"),
            (self.blank_added, "add", "blank line"),
            (self.sorted, "sort settings in", "block"),
        ]
        .into_iter()
        .filter(|(count, ..)| *count > 0)
        .map(|(count, action, what)| format!("{action} {}", lines(count, what)))
        .collect()
    }
}

/// `--indent`: a number of spaces, `tab`, or the indentation itself.
pub fn parse_indent(value: &str) -> Result<String, String> {
    if value == "tab" {
        return Ok("\t".to_owned());
    }
    if !value.is_empty() && value.chars().all(|c| c == ' ' || c == '\t') {
        return Ok(value.to_owned());
    }
    match value.parse::<u8>() {
        Ok(spaces) if spaces <= 16 => Ok(" ".repeat(spaces.into())),
        _ => Err("expected a number of spaces (0-16) or `tab`".to_owned()),
    }
}

/// `--separator`: `space`, `tab`, or the separator itself: spaces or tabs,
/// optionally around a single `=` (`Key=value`, `Key = value`).
pub fn parse_separator(value: &str) -> Result<String, String> {
    let separator = match value {
        "space" => " ",
        "tab" => "\t",
        other => other,
    };
    let rest = separator.trim_matches([' ', '\t']);
    if !separator.is_empty() && (rest.is_empty() || rest == "=") {
        Ok(separator.to_owned())
    } else {
        Err("expected `space`, `tab`, `=`, or `\" = \"`".to_owned())
    }
}

#[derive(Clone, Copy)]
enum Kind<'a> {
    Blank,
    /// Without surrounding whitespace.
    Comment(&'a str),
    Setting {
        keyword: &'a str,
        /// As written: whitespace, optionally around one `=`.
        separator: &'a str,
        /// Arguments as written, without trailing whitespace.
        value: &'a str,
    },
}

#[derive(Clone, Copy)]
struct Line<'a> {
    indent: &'a str,
    kind: Kind<'a>,
    trailing: bool,
    ending: &'a str,
}

impl<'a> Line<'a> {
    fn parse(raw: &'a str) -> Self {
        let (body, ending) = match raw.strip_suffix('\n') {
            Some(body) => match body.strip_suffix('\r') {
                Some(body) => (body, "\r\n"),
                None => (body, "\n"),
            },
            None => (raw, ""),
        };
        let content = body.trim_start_matches(SPACE);
        let text = content.trim_end_matches(TRAILING);
        let mut line = Self {
            indent: &body[..body.len() - content.len()],
            kind: Kind::Blank,
            trailing: text.len() < content.len(),
            ending,
        };
        if text.is_empty() {
            line.indent = "";
            line.trailing = !body.is_empty();
        } else if text.starts_with('#') {
            line.kind = Kind::Comment(text);
        } else {
            // The same split as OpenSSH: the keyword ends at whitespace or
            // `=`, and one `=` with whitespace around it may follow.
            let end = text
                .find(|c: char| SPACE.contains(&c) || c == '=')
                .unwrap_or(text.len());
            let rest = &text[end..];
            let after_space = rest.trim_start_matches(SPACE);
            let value = after_space
                .strip_prefix('=')
                .map_or(after_space, |value| value.trim_start_matches(SPACE));
            line.kind = Kind::Setting {
                keyword: &text[..end],
                separator: &rest[..rest.len() - value.len()],
                value,
            };
        }
        line
    }

    fn keyword(&self) -> Option<&'a str> {
        match self.kind {
            Kind::Setting { keyword, .. } => Some(keyword),
            _ => None,
        }
    }

    fn is_header(&self) -> bool {
        self.keyword()
            .is_some_and(|k| k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("match"))
    }

    fn is_blank(&self) -> bool {
        matches!(self.kind, Kind::Blank)
    }
}

/// Format an SSH config. Nothing is evaluated and included files are not read.
pub fn format(source: &str, options: &FormatOptions) -> Formatted {
    let newline = match source.find('\n') {
        Some(at) if source[..at].ends_with('\r') => "\r\n",
        _ => "\n",
    };
    let mut lines: Vec<Line> = source.split_inclusive('\n').map(Line::parse).collect();
    let mut result = Formatted::default();
    if options.sort {
        result.sorted = sort_blocks(&mut lines);
    }
    let comment_in_block = comments_in_block(&lines);
    let last = lines.iter().rposition(|line| !line.is_blank());
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut in_block = false;
    for (index, line) in lines.iter().enumerate() {
        let indent = match line.kind {
            Kind::Blank => {
                // At most one blank line in a row, none at the start or end.
                if out.last().is_some_and(|l| !l.is_empty()) && last.is_some_and(|l| index < l) {
                    out.push(String::new());
                    result.trailing += usize::from(line.trailing);
                    result.endings += usize::from(line.ending != newline);
                } else {
                    result.blank_removed += 1;
                }
                continue;
            }
            _ if line.is_header() => {
                // One blank line before a block and the comments right above it.
                let gap = out
                    .iter()
                    .rposition(|l| !l.trim_start().starts_with('#'))
                    .map_or(0, |i| i + 1);
                if gap > 0 && !out[gap - 1].is_empty() {
                    out.insert(gap, String::new());
                    result.blank_added += 1;
                }
                in_block = true;
                ""
            }
            Kind::Comment(_) if !comment_in_block[index] => "",
            _ if in_block => options.indent.as_str(),
            _ => "",
        };
        result.indented += usize::from(line.indent != indent);
        result.trailing += usize::from(line.trailing);
        result.endings += usize::from(line.ending != newline);
        out.push(match line.kind {
            Kind::Comment(text) => format!("{indent}{text}"),
            // OpenSSH rejects a keyword without arguments; keep it.
            Kind::Setting {
                keyword,
                separator,
                value: "",
            } => {
                result.separators += usize::from(!separator.is_empty());
                format!("{indent}{keyword}")
            }
            Kind::Setting {
                keyword,
                separator,
                value,
            } => {
                let wanted = if line.is_header() {
                    " "
                } else {
                    options.separator.as_str()
                };
                // OpenSSH skips a single `=` after a keyword, so a value that
                // starts with `=` must keep the separator it was written with.
                let wanted = if value.starts_with('=') {
                    separator
                } else {
                    wanted
                };
                result.separators += usize::from(separator != wanted);
                format!("{indent}{keyword}{wanted}{value}")
            }
            Kind::Blank => unreachable!("blank lines are handled above"),
        });
    }
    if !out.is_empty() {
        result.text = out.join(newline);
        result.text.push_str(newline);
    }
    result
}

/// Whether each line is a comment that belongs to the settings around it and
/// is indented with them. Comments right above a Host or Match line belong to
/// that line, and comments set apart by blank lines after the last setting of
/// a block belong to the gap between blocks; both start at column 0.
fn comments_in_block(lines: &[Line]) -> Vec<bool> {
    let mut in_block = vec![false; lines.len()];
    let mut above_header = vec![false; lines.len()];
    let (mut header_next, mut setting_later) = (false, false);
    for (index, line) in lines.iter().enumerate().rev() {
        match line.kind {
            Kind::Comment(_) => {
                above_header[index] = header_next;
                in_block[index] = !header_next && setting_later;
            }
            Kind::Blank => header_next = false,
            Kind::Setting { .. } if line.is_header() => {
                (header_next, setting_later) = (true, false)
            }
            Kind::Setting { .. } => (header_next, setting_later) = (false, true),
        }
    }
    // Comments right below a block's last line (a commented-out setting, a
    // closing note) stay with the block.
    let mut below_setting = false;
    for (index, line) in lines.iter().enumerate() {
        match line.kind {
            Kind::Comment(_) => in_block[index] |= below_setting && !above_header[index],
            Kind::Blank => below_setting = false,
            Kind::Setting { .. } => below_setting = true,
        }
    }
    in_block
}

/// Sort the settings of the global section and of every block. Returns how
/// many of them changed.
fn sort_blocks(lines: &mut [Line]) -> usize {
    let mut sorted = 0;
    let mut start = 0;
    while start < lines.len() {
        let body = start + usize::from(lines[start].is_header());
        let end = lines[body..]
            .iter()
            .position(Line::is_header)
            .map_or(lines.len(), |p| body + p);
        let mut changed = false;
        // Blank lines and settings whose position matters split the block
        // into runs that are sorted separately.
        for run in
            lines[body..end].split_mut(|line| line.is_blank() || line.keyword().is_some_and(fixed))
        {
            changed |= sort_run(run);
        }
        sorted += usize::from(changed);
        start = end;
    }
    sorted
}

/// Include reads other settings at its place, and IgnoreUnknown only covers
/// unknown keywords after it.
fn fixed(keyword: &str) -> bool {
    keyword.eq_ignore_ascii_case("include") || keyword.eq_ignore_ascii_case("ignoreunknown")
}

/// The option a keyword sets, for keywords that set the same option. ProxyJump
/// and ProxyCommand count as one: whichever comes first disables the other.
fn option(keyword: &str) -> &str {
    match keyword {
        "challengeresponseauthentication" | "skeyauthentication" | "tisauthentication" => {
            "kbdinteractiveauthentication"
        }
        "dsaauthentication" => "pubkeyauthentication",
        "hostbasedkeytypes" => "hostbasedacceptedalgorithms",
        "identityfile2" => "identityfile",
        "keepalive" => "tcpkeepalive",
        "proxyjump" => "proxycommand",
        "pubkeyacceptedkeytypes" => "pubkeyacceptedalgorithms",
        "smartcarddevice" => "pkcs11provider",
        other => other,
    }
}

/// Stable sort by keyword; each setting moves with the comments right above
/// it. Comments after the last setting stay at the end.
fn sort_run(run: &mut [Line]) -> bool {
    let mut items: Vec<(String, Range<usize>)> = Vec::new();
    let mut start = 0;
    for (index, line) in run.iter().enumerate() {
        if let Some(keyword) = line.keyword() {
            items.push((keyword.to_ascii_lowercase(), start..index + 1));
            start = index + 1;
        }
    }
    // Keywords that set the same option all sort under the name of the
    // first one, so they keep their relative order.
    let mut first: HashMap<&str, &str> = HashMap::new();
    for (keyword, _) in &items {
        first.entry(option(keyword)).or_insert(keyword);
    }
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by_key(|&item| first[option(&items[item].0)]);
    if order
        .iter()
        .enumerate()
        .all(|(position, &item)| position == item)
    {
        return false;
    }
    let sorted: Vec<Line> = order
        .iter()
        .flat_map(|&item| run[items[item].1.clone()].to_vec())
        .collect();
    run[..sorted.len()].copy_from_slice(&sorted);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formatted(source: &str, options: &FormatOptions) -> String {
        let text = format(source, options).text;
        let again = format(&text, options);
        assert_eq!(again.text, text, "formatting must be idempotent");
        assert_eq!(again.sorted, 0, "sorting must be idempotent");
        text
    }

    fn sorted(source: &str) -> String {
        let options = FormatOptions {
            sort: true,
            ..Default::default()
        };
        formatted(source, &options)
    }

    #[test]
    fn formats_global_host_match_and_comments_without_reordering() {
        let source = "\n\n  Include\t= conf.d/*\n\tUser = global\n# first\n\tHoSt=\"web\" web2 # aliases\nHostName\t= web.example\n\tPort   2222\n\n\n# match comment\n  Match  host web exec \"test  -f /tmp/ready\"\nUser\tdeploy\nHost * !web\n\tUser fallback\n\n\n";
        let expected = "Include conf.d/*\nUser global\n\n# first\nHoSt \"web\" web2 # aliases\n  HostName web.example\n  Port 2222\n\n# match comment\nMatch host web exec \"test  -f /tmp/ready\"\n  User deploy\n\nHost * !web\n  User fallback\n";
        assert_eq!(formatted(source, &FormatOptions::default()), expected);
    }

    #[test]
    fn preserves_arguments_and_comment_text_but_not_trailing_whitespace() {
        let source = "Host box\nIdentityFile = \"/tmp/key  with spaces\" # note  \nIdentityFile\tsecond\nProxyCommand=sh -c 'printf \"  %s  \" \"%h\"'  \nSetEnv  ONE=a=b TWO=\"c  d\"\n\t# commented option = yes  \n";
        assert_eq!(
            formatted(source, &FormatOptions::default()),
            "Host box\n  IdentityFile \"/tmp/key  with spaces\" # note\n  IdentityFile second\n  ProxyCommand sh -c 'printf \"  %s  \" \"%h\"'\n  SetEnv ONE=a=b TWO=\"c  d\"\n  # commented option = yes\n"
        );
    }

    #[test]
    fn keeps_crlf_and_adds_a_final_newline() {
        let options = FormatOptions::default();
        let expected = "# header\r\nHost a\r\n  User alice\r\n\r\nHost b\r\n  User bob\r\n";
        assert_eq!(
            formatted(
                "# header\r\n Host=a\r\nUser\talice\r\nHost b\r\nUser bob",
                &options
            ),
            expected
        );
        assert_eq!(formatted(expected, &options), expected);
        assert_eq!(formatted("Host a", &options), "Host a\n");
        assert_eq!(formatted("", &options), "");
        assert_eq!(formatted(" \n\t\n", &options), "");
        assert_eq!(
            formatted("# only a comment", &options),
            "# only a comment\n"
        );
    }

    #[test]
    fn applies_indent_and_separator_but_not_to_host_and_match_lines() {
        let source = "User=me\nHost a\n  User x\n  Port=22\nMatch=host b\nUser y\n";
        let options = |indent: &str, separator: &str| FormatOptions {
            indent: indent.to_owned(),
            separator: separator.to_owned(),
            sort: false,
        };
        assert_eq!(
            formatted(source, &options("\t", " = ")),
            "User = me\n\nHost a\n\tUser = x\n\tPort = 22\n\nMatch host b\n\tUser = y\n"
        );
        assert_eq!(
            formatted(source, &options("    ", "=")),
            "User=me\n\nHost a\n    User=x\n    Port=22\n\nMatch host b\n    User=y\n"
        );
    }

    #[test]
    fn keeps_the_separator_of_values_starting_with_equals() {
        // OpenSSH reads `User==x` as user "=x"; `User =x` would be user "x".
        let options = FormatOptions {
            separator: "\t".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            formatted("Host a\nUser==x\nUser = =y\nPort =22\n", &options),
            "Host a\n  User==x\n  User = =y\n  Port\t22\n"
        );
    }

    #[test]
    fn indents_comments_that_belong_to_a_block() {
        let source = "# global note\nUser me\n# about a\nHost a\n# first setting\nUser x\n#   Port 2222\n\n# between blocks\n\n# about b\nHost b\n  User y\n\n  # later group\n  Port 1\n";
        assert_eq!(
            formatted(source, &FormatOptions::default()),
            "# global note\nUser me\n\n# about a\nHost a\n  # first setting\n  User x\n  #   Port 2222\n\n# between blocks\n\n# about b\nHost b\n  User y\n\n  # later group\n  Port 1\n"
        );
    }

    #[test]
    fn counts_each_kind_of_change() {
        let result = format(
            "Host a\n\tUser\tx  \n\n\n  Port=1",
            &FormatOptions::default(),
        );
        assert_eq!(result.text, "Host a\n  User x\n\n  Port 1\n");
        assert_eq!(
            result.changes(),
            [
                "re-indent 1 line",
                "rewrite the keyword separator on 2 lines",
                "trim trailing whitespace on 1 line",
                "fix the line ending of 1 line",
                "remove 1 blank line",
            ]
        );
        assert!(
            format("Host a\n  User x\n", &FormatOptions::default())
                .changes()
                .is_empty()
        );
    }

    #[test]
    fn sorts_settings_within_runs_and_moves_comments_along() {
        let source = "IdentityFile ~/.ssh/global\nCompression yes\n\nHost a\n  User x\n  # second key first\n  IdentityFile ~/.ssh/b\n  Port 22\n  IdentityFile ~/.ssh/a\n  HostName a.example\n  # trailing note\n\nHost b\n  User y\n  Include b.conf\n  Port 2\n  HostName b.example\n\n  LocalForward 1 x:1\n  Ciphers aes128-ctr\n";
        assert_eq!(
            sorted(source),
            "Compression yes\nIdentityFile ~/.ssh/global\n\nHost a\n  HostName a.example\n  # second key first\n  IdentityFile ~/.ssh/b\n  IdentityFile ~/.ssh/a\n  Port 22\n  User x\n  # trailing note\n\nHost b\n  User y\n  Include b.conf\n  HostName b.example\n  Port 2\n\n  Ciphers aes128-ctr\n  LocalForward 1 x:1\n"
        );
        let options = FormatOptions {
            sort: true,
            ..Default::default()
        };
        assert_eq!(format(source, &options).sorted, 3);
    }

    #[test]
    fn sorting_keeps_the_order_of_settings_for_the_same_option() {
        let source = "Host a\n  ProxyJump j\n  Port 1\n  ProxyCommand nc %h %p\n  PubkeyAcceptedKeyTypes ssh-ed25519\n  PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256\n  IgnoreUnknown UseKeychain\n  UseKeychain yes\n  AddKeysToAgent yes\n";
        assert_eq!(
            sorted(source),
            "Host a\n  Port 1\n  ProxyJump j\n  ProxyCommand nc %h %p\n  PubkeyAcceptedKeyTypes ssh-ed25519\n  PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256\n  IgnoreUnknown UseKeychain\n  AddKeysToAgent yes\n  UseKeychain yes\n"
        );
        // Case does not matter, and a sorted block is left alone.
        let source = "Host a\n  user x\n  HostName h\n  identityFile k\n";
        assert_eq!(
            sorted(source),
            "Host a\n  HostName h\n  identityFile k\n  user x\n"
        );
    }

    #[test]
    fn parses_indent_and_separator_options() {
        assert_eq!(parse_indent("4").unwrap(), "    ");
        assert_eq!(parse_indent("0").unwrap(), "");
        assert_eq!(parse_indent("tab").unwrap(), "\t");
        assert_eq!(parse_indent("  ").unwrap(), "  ");
        for bad in ["", "17", "x", "-1"] {
            assert!(parse_indent(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_separator("space").unwrap(), " ");
        assert_eq!(parse_separator("tab").unwrap(), "\t");
        for good in ["=", " = ", "\t", "  "] {
            assert_eq!(parse_separator(good).unwrap(), good);
        }
        for bad in ["", "==", ":", " x "] {
            assert!(parse_separator(bad).is_err(), "{bad:?}");
        }
    }
}
