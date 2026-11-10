use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub custom_config: Option<PathBuf>,
    pub timeout: Duration,
    pub attempts: usize,
    pub jobs: usize,
    /// Skip hosts whose address is internal (private, loopback, link-local,
    /// CGNAT, or IPv6 unique-local), since reachability depends on the network.
    pub skip_private: bool,
    /// Check ProxyJump hosts by opening `ssh -W` through the jump host.
    pub via_proxyjump: bool,
    /// Overall time limit for one jump-host attempt (login + forwarding).
    pub jump_timeout: Duration,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub hostname: String,
    pub port: u16,
    family: AddressFamily,
    /// Effective ProxyJump chain, when checking through jump hosts.
    pub jump: Option<String>,
}

impl Endpoint {
    fn target(&self) -> String {
        if self.hostname.contains(':') {
            format!("[{}]:{}", self.hostname, self.port)
        } else {
            format!("{}:{}", self.hostname, self.port)
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.target())?;
        if let Some(jump) = &self.jump {
            write!(f, " via {jump}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
enum AddressFamily {
    Any,
    Inet,
    Inet6,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Status {
    Reachable,
    Unreachable {
        attempts: usize,
        reason: String,
    },
    /// Deliberately not checked (by option or unsupported route). Preserved.
    Excluded(String),
    /// Could not be decided (local/config/jump-host problem). Preserved.
    Skipped(String),
}

/// A route this checker intentionally does not test.
#[derive(Debug)]
struct Unsupported(String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unsupported {}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HostResult {
    pub alias: String,
    pub endpoint: Option<Endpoint>,
    pub status: Status,
}

impl HostResult {
    pub fn is_unreachable(&self) -> bool {
        matches!(self.status, Status::Unreachable { .. })
    }
}

pub fn scan(
    targets: &[String],
    options: &ScanOptions,
    mut report: impl FnMut(&HostResult),
) -> Vec<HostResult> {
    // Lives until every jump probe is done; the file is deleted on drop.
    let jump_config = if options.via_proxyjump {
        let config = jump_config(options).map_err(|e| format!("{e:#}"));
        match &config {
            Ok(file) => debug!(
                "jump-host probes use wrapper config {}",
                file.path().display()
            ),
            Err(error) => warn!("cannot prepare jump-host config: {error}"),
        }
        Some(config)
    } else {
        None
    };
    let jump_config = jump_config
        .as_ref()
        .map(|c| c.as_ref().map(|f| f.path()).map_err(String::as_str));
    let next = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..options.jobs.min(targets.len()) {
            let sender = sender.clone();
            let next = &next;
            scope.spawn(move || {
                while let Some(alias) = targets.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let result = check_host(alias, options, jump_config);
                    if sender.send(result).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        receiver
            .into_iter()
            .inspect(|result| report(result))
            .collect()
    })
}

/// `Some(Ok(path))`: wrapper config for jump probes; `Some(Err)`: it could not
/// be created; `None`: jump probes are disabled.
type JumpConfig<'a> = Option<Result<&'a Path, &'a str>>;

/// Build a config for `ssh -W` probes that disables connection multiplexing
/// and then includes the user's real configuration.
///
/// `-o ControlMaster=no` only reaches the outermost ssh. For a ProxyJump chain
/// ssh spawns `ssh -W ... <earlier hop>` itself and forwards just `-F`/`-v`,
/// so a user's `ControlMaster auto`/`ControlPersist` would otherwise make those
/// inner hops reuse or create persistent master connections. Values read first
/// win in ssh_config, so this `Host *` block overrides the user's settings.
fn jump_config(options: &ScanOptions) -> Result<tempfile::NamedTempFile> {
    let mut includes = Vec::new();
    match &options.custom_config {
        Some(config) => includes.push(std::path::absolute(config)?),
        None => {
            // Mirror plain ssh: user config first, then the system config.
            includes.push(crate::storage::default_config_path()?);
            includes.push(PathBuf::from("/etc/ssh/ssh_config"));
        }
    }
    let mut text = String::from(
        "# Generated by ssh-config-compact for jump-host probes.\n\
         Host *\n  ControlMaster no\n  ControlPath none\n  ControlPersist no\n",
    );
    for path in includes {
        let path = path
            .to_str()
            .filter(|p| !p.contains(['"', '\n']))
            .with_context(|| format!("unsupported config path {}", path.display()))?;
        text.push_str(&format!("Include \"{path}\"\n"));
    }
    let mut file = tempfile::Builder::new()
        .prefix("ssh-config-compact-")
        .tempfile()?;
    std::io::Write::write_all(&mut file, text.as_bytes())?;
    Ok(file)
}

fn check_host(alias: &str, options: &ScanOptions, jump_config: JumpConfig<'_>) -> HostResult {
    let endpoint = match effective_endpoint(alias, options) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let reason = format!("{error:#}");
            return HostResult {
                alias: alias.to_owned(),
                endpoint: None,
                status: if error.downcast_ref::<Unsupported>().is_some() {
                    Status::Excluded(reason)
                } else {
                    Status::Skipped(reason)
                },
            };
        }
    };
    debug!("{alias}: effective endpoint {endpoint}");
    let mut last_failure = String::new();
    let mut uncertain = None;
    for attempt in 0..options.attempts {
        let result = match &endpoint.jump {
            Some(jump) => match jump_config {
                Some(Ok(config)) => probe_via_jump(&endpoint, jump, config, options),
                _ => Probe::Uncertain("jump-host config unavailable".into()),
            },
            None => probe(&endpoint, options.timeout, options.skip_private),
        };
        let attempt_label = format!("{alias}: attempt {}/{}", attempt + 1, options.attempts);
        match &result {
            Probe::Connected => debug!("{attempt_label}: connected"),
            Probe::Failed(reason) => debug!("{attempt_label}: failed: {reason}"),
            Probe::Uncertain(reason) => debug!("{attempt_label}: undecidable: {reason}"),
            Probe::Internal(address) => debug!("{attempt_label}: internal address {address}"),
        }
        match result {
            Probe::Connected => {
                return HostResult {
                    alias: alias.to_owned(),
                    endpoint: Some(endpoint),
                    status: Status::Reachable,
                };
            }
            Probe::Failed(reason) => last_failure = reason,
            Probe::Uncertain(reason) => uncertain = Some(reason),
            Probe::Internal(address) => {
                return HostResult {
                    alias: alias.to_owned(),
                    endpoint: Some(endpoint),
                    status: Status::Excluded(format!(
                        "internal address {address} skipped by --skip-private"
                    )),
                };
            }
        }
        if attempt + 1 < options.attempts {
            thread::sleep(Duration::from_millis(250));
        }
    }
    HostResult {
        alias: alias.to_owned(),
        endpoint: Some(endpoint),
        // Any local/indeterminate failure makes deletion unsafe, even if the
        // other attempts returned ordinary network errors.
        status: match uncertain {
            Some(reason) => Status::Skipped(reason),
            None => Status::Unreachable {
                attempts: options.attempts,
                reason: last_failure,
            },
        },
    }
}

fn effective_endpoint(alias: &str, options: &ScanOptions) -> Result<Endpoint> {
    let mut command = Command::new("ssh");
    command.args([
        "-G",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "PermitLocalCommand=no",
    ]);
    if let Some(config) = &options.custom_config {
        command.arg("-F").arg(config);
    }
    command.arg("--").arg(alias).env("LC_ALL", "C");
    debug!("{alias}: running {command:?}");
    let output =
        run_bounded(command, options.timeout).context("cannot evaluate SSH configuration")?;
    parse_endpoint(&output, options.via_proxyjump)
}

/// `ssh -G` for `alias` with `config` as the only (user) configuration file.
pub(crate) fn ssh_g(config: &Path, alias: &str, timeout: Duration) -> Result<String> {
    let mut command = Command::new("ssh");
    command
        .arg("-G")
        .arg("-F")
        .arg(config)
        .arg("--")
        .arg(alias)
        .env("LC_ALL", "C");
    run_bounded(command, timeout)
}

fn parse_endpoint(output: &str, via_proxyjump: bool) -> Result<Endpoint> {
    let mut hostname = None;
    let mut port = None;
    let mut family = AddressFamily::Any;
    let mut jump = None;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match key {
            "hostname" => hostname = Some(value.to_owned()),
            "port" => port = Some(value.parse::<u16>().context("invalid effective SSH port")?),
            "addressfamily" => {
                family = match value {
                    "any" => AddressFamily::Any,
                    "inet" => AddressFamily::Inet,
                    "inet6" => AddressFamily::Inet6,
                    _ => bail!("unsupported address family: {value}"),
                };
            }
            "proxyjump" if via_proxyjump && value != "none" && !value.is_empty() => {
                jump = Some(value.to_owned());
            }
            "proxycommand" | "proxyjump" | "bindaddress" | "bindinterface"
                if value != "none" && !value.is_empty() =>
            {
                return Err(Unsupported(format!(
                    "{key} requires a connection path this TCP checker cannot verify"
                ))
                .into());
            }
            _ => {}
        }
    }
    let hostname = hostname.context("ssh -G did not return a hostname")?;
    if hostname.is_empty() || hostname.contains(['%', '$', ' ', '\t', '\n']) {
        bail!("unexpanded or unsupported HostName: {hostname}");
    }
    let port = port
        .filter(|p| *p != 0)
        .context("ssh -G did not return a valid port")?;
    Ok(Endpoint {
        hostname,
        port,
        family,
        jump,
    })
}

fn run_bounded(mut command: Command, timeout: Duration) -> Result<String> {
    // Files avoid pipe deadlocks and inherited pipes from Match exec children.
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .process_group(0)
        .spawn()
        .context("could not start ssh; install the OpenSSH client")?;
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => break Err(anyhow::anyhow!("ssh -G timed out")),
            Err(error) => break Err(error.into()),
        }
    };
    if outcome.is_err() {
        // Stop descendants from a stalled Match exec as well as ssh itself.
        // SAFETY: kill accepts this numeric process-group id and no pointers.
        // The still-unreaped child owns this process-group id.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
    }
    let _ = child.wait();
    let status = outcome?;
    if !status.success() {
        let error = read_output(&mut stderr)?;
        bail!("ssh -G failed: {}", error.trim());
    }
    read_output(&mut stdout)
}

fn read_output(file: &mut File) -> Result<String> {
    const LIMIT: u64 = 1024 * 1024;
    if file.metadata()?.len() > LIMIT {
        bail!("ssh output exceeded 1 MiB");
    }
    file.seek(SeekFrom::Start(0))?;
    let mut result = String::new();
    file.take(LIMIT + 1).read_to_string(&mut result)?;
    if result.len() as u64 > LIMIT {
        bail!("ssh output exceeded 1 MiB");
    }
    Ok(result)
}

enum Probe {
    Connected,
    Failed(String),
    Uncertain(String),
    Internal(IpAddr),
}

/// Resolve with the system resolver, giving up at `deadline`. Errors are
/// returned as the probe outcome they imply.
fn resolve(hostname: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, Probe> {
    let hostname = hostname.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    // The system resolver may block beyond a socket timeout. Isolate it so a
    // stalled DNS request cannot hold up this host or prevent the CLI exiting.
    if let Err(error) = thread::Builder::new().name("dns".into()).spawn(move || {
        let result = (hostname.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>());
        let _ = sender.send(result);
    }) {
        return Err(Probe::Uncertain(format!(
            "could not start resolver: {error}"
        )));
    }
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => {
            // EAI_AGAIN is surfaced as an ordinary io::Error on Unix.
            let message = error.to_string();
            if message.to_ascii_lowercase().contains("temporary") {
                return Err(Probe::Uncertain(format!(
                    "temporary DNS failure: {message}"
                )));
            }
            Err(Probe::Failed(format!("DNS lookup failed: {message}")))
        }
        Err(_) => Err(Probe::Uncertain("DNS lookup exceeded the timeout".into())),
    }
}

fn probe(endpoint: &Endpoint, timeout: Duration, skip_private: bool) -> Probe {
    let deadline = Instant::now() + timeout;
    let addresses = match resolve(&endpoint.hostname, endpoint.port, deadline) {
        Ok(addresses) => addresses,
        Err(failure) => return failure,
    };
    debug!("{}: resolved to {addresses:?}", endpoint.hostname);
    let addresses: Vec<_> = addresses
        .into_iter()
        .filter(|address| match endpoint.family {
            AddressFamily::Any => true,
            AddressFamily::Inet => address.is_ipv4(),
            AddressFamily::Inet6 => address.is_ipv6(),
        })
        .collect();
    if skip_private {
        // One internal address is enough: the result would depend on which
        // network (VPN, office LAN, ...) this machine is currently attached to.
        if let Some(address) = addresses.iter().find(|a| is_internal(a.ip())) {
            return Probe::Internal(address.ip());
        }
    }
    connect_addresses(&addresses, deadline)
}

pub fn is_internal(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_internal_v4(v4),
            None => is_internal_v6(v6),
        },
    }
}

fn is_internal_v4(address: Ipv4Addr) -> bool {
    let [a, b, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        // 100.64.0.0/10 shared address space (CGNAT, Tailscale, ...)
        || (a == 100 && (b & 0xc0) == 64)
}

fn is_internal_v6(address: Ipv6Addr) -> bool {
    address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local()
}

/// Open a TCP connection to the target from the last jump host with `ssh -W`.
/// Only the jump hosts are logged in to; the target merely gets a TCP
/// connection, exactly like the direct check.
fn probe_via_jump(endpoint: &Endpoint, jump: &str, config: &Path, options: &ScanOptions) -> Probe {
    if options.skip_private {
        // The jump host resolves the name for the real connection, but a local
        // lookup that yields an internal address is still a strong hint that
        // the host lives on a private network. A failed lookup proves nothing
        // here (the name may only exist in the jump host's DNS), so carry on.
        let deadline = Instant::now() + options.timeout;
        let resolved = resolve(&endpoint.hostname, endpoint.port, deadline);
        match &resolved {
            Ok(addresses) => debug!("{}: resolved locally to {addresses:?}", endpoint.hostname),
            Err(_) => debug!(
                "{}: local lookup failed; leaving resolution to the jump host",
                endpoint.hostname
            ),
        }
        if let Ok(addresses) = resolved
            && let Some(address) = addresses.iter().find(|a| is_internal(a.ip()))
        {
            return Probe::Internal(address.ip());
        }
    }
    let (rest, last) = match jump.rsplit_once(',') {
        Some((rest, last)) => (Some(rest), last),
        None => (None, jump),
    };
    let hops = jump.split(',').count();
    let (destination, port) = split_hop(last);
    let mut command = Command::new("ssh");
    // -vv exposes "Authenticated to" and "open confirm", which tell a failing
    // jump host apart from a failing target.
    command.args([
        "-vv",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
    ]);
    command.arg(format!("ConnectTimeout={}", options.timeout.as_secs()));
    // ssh forwards -F to the ssh it spawns for earlier ProxyJump hops.
    command.arg("-F").arg(config);
    if let Some(rest) = rest {
        command.arg("-J").arg(rest);
    }
    if let Some(port) = port {
        command.arg("-p").arg(port);
    }
    command
        .arg("-W")
        .arg(endpoint.target())
        .arg("--")
        .arg(destination)
        .env("LC_ALL", "C");
    debug!("{}: running {command:?}", endpoint.target());
    match run_jump(command, options.jump_timeout, hops) {
        Ok((log, stdout, exited)) => classify_jump(&log, stdout, exited, hops, last),
        Err(error) => Probe::Uncertain(format!("could not run ssh -W: {error:#}")),
    }
}

/// Split the last ProxyJump hop (`[user@]host[:port]` or an ssh:// URI) into
/// an ssh destination and optional port.
fn split_hop(hop: &str) -> (String, Option<&str>) {
    if hop.starts_with("ssh://") {
        return (hop.to_owned(), None);
    }
    let (user, host) = match hop.rsplit_once('@') {
        Some((user, host)) => (format!("{user}@"), host),
        None => (String::new(), hop),
    };
    if let Some(bracketed) = host.strip_prefix('[') {
        let (address, port) = match bracketed.split_once("]:") {
            Some((address, port)) => (address, Some(port)),
            None => (bracketed.trim_end_matches(']'), None),
        };
        return (format!("{user}{address}"), port);
    }
    match host.split_once(':') {
        // A bare IPv6 address has several colons and no port.
        Some((name, port)) if !port.contains(':') => (format!("{user}{name}"), Some(port)),
        _ => (hop.to_owned(), None),
    }
}

/// Run ssh -W until the forwarded channel opens, ssh exits, or time runs out.
/// Returns (stderr log, stdout received, ssh exited on its own).
fn run_jump(mut command: Command, timeout: Duration, hops: usize) -> Result<(String, bool, bool)> {
    let stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .process_group(0)
        .spawn()
        .context("could not start ssh; install the OpenSSH client")?;
    let deadline = Instant::now() + timeout;
    let exited = loop {
        // Every hop of a chain logs its own "open confirm"; only the last one
        // (the channel to the target) means success.
        let confirmed = read_output(&mut stderr)?
            .lines()
            .filter(|l| l.contains("open confirm"))
            .count();
        if stdout.metadata()?.len() > 0 || confirmed >= hops {
            break false;
        }
        match child.try_wait()? {
            Some(_) => break true,
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            None => break false,
        }
    };
    // SAFETY: see run_bounded; the unreaped child owns this process group.
    unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
    let _ = child.wait();
    let received = stdout.metadata()?.len() > 0;
    Ok((read_output(&mut stderr)?, received, exited))
}

fn classify_jump(log: &str, received: bool, exited: bool, hops: usize, last: &str) -> Probe {
    let count = |needle: &str| log.lines().filter(|l| l.contains(needle)).count();
    let authenticated = count("Authenticated to") >= hops;
    if received || count("open confirm") >= hops {
        return Probe::Connected;
    }
    if !authenticated {
        let detail = log
            .lines()
            .rev()
            .find(|l| !l.starts_with("debug") && !l.starts_with("OpenSSH_") && !l.is_empty())
            .unwrap_or("no response");
        return Probe::Uncertain(format!("jump host {last} not usable: {}", detail.trim()));
    }
    // Only the final hop's channel matters; earlier hops already succeeded.
    if let Some(line) = log.lines().rev().find(|l| l.contains("open failed")) {
        if line.contains("administratively prohibited") {
            return Probe::Uncertain(format!("jump host {last} refuses forwarding: {line}"));
        }
        let reason = line.split_once("open failed: ").map_or(line, |(_, r)| r);
        return Probe::Failed(format!("via {last}: {}", reason.trim()));
    }
    if exited {
        return Probe::Uncertain(format!("ssh -W through {last} exited unexpectedly"));
    }
    Probe::Failed(format!("via {last}: connection timed out"))
}

fn connect_addresses(addresses: &[SocketAddr], deadline: Instant) -> Probe {
    if addresses.is_empty() {
        return Probe::Failed("DNS returned no addresses for the configured address family".into());
    }
    let mut last_error = "connection timed out".to_owned();
    let mut uncertain = None;
    for (index, address) in addresses.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Give every resolved address a chance within the per-attempt budget.
        let timeout = remaining / (addresses.len() - index) as u32;
        match TcpStream::connect_timeout(address, timeout.max(Duration::from_nanos(1))) {
            Ok(_) => return Probe::Connected,
            Err(error) => {
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::AddrNotAvailable
                        | io::ErrorKind::OutOfMemory
                        | io::ErrorKind::Unsupported
                ) {
                    uncertain = Some(format!("local connection error: {error}"));
                }
                last_error = format!("{address}: {error}");
            }
        }
    }
    match uncertain {
        Some(reason) => Probe::Uncertain(reason),
        None => Probe::Failed(last_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn interprets_effective_config_and_preserves_unsupported_routes() {
        let endpoint =
            parse_endpoint("hostname ::1\nport 2222\naddressfamily inet6\n", true).unwrap();
        assert_eq!(endpoint.to_string(), "[::1]:2222");
        for line in [
            "proxyjump bastion",
            "proxycommand nc %h %p",
            "bindinterface vpn0",
        ] {
            assert!(parse_endpoint(&format!("hostname db\nport 22\n{line}\n"), false).is_err());
        }
        assert!(parse_endpoint("hostname %h.invalid\nport 22\n", false).is_err());
        assert!(parse_endpoint("hostname example\nport 0\n", false).is_err());
        let jumped = parse_endpoint(
            "hostname db\nport 22\nproxyjump a,b\nproxycommand none\n",
            true,
        )
        .unwrap();
        assert_eq!(jumped.jump.as_deref(), Some("a,b"));
        assert_eq!(jumped.to_string(), "db:22 via a,b");
        assert!(parse_endpoint("hostname db\nport 22\nproxycommand nc %h %p\n", true).is_err());
    }

    #[test]
    fn tests_tcp_without_attempting_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = Endpoint {
            hostname: "127.0.0.1".into(),
            port: address.port(),
            family: AddressFamily::Inet,
            jump: None,
        };
        assert!(matches!(
            probe(&endpoint, Duration::from_secs(1), false),
            Probe::Connected
        ));
        assert!(matches!(
            probe(&endpoint, Duration::from_secs(1), true),
            Probe::Internal(_)
        ));
        assert!(matches!(
            connect_addresses(&[], Instant::now() + Duration::from_secs(1)),
            Probe::Failed(_)
        ));
    }

    #[test]
    fn jump_config_disables_multiplexing_before_user_config() {
        let options = ScanOptions {
            custom_config: Some(PathBuf::from("/x/my config")),
            timeout: Duration::from_secs(1),
            attempts: 1,
            jobs: 1,
            skip_private: false,
            via_proxyjump: true,
            jump_timeout: Duration::from_secs(1),
        };
        let file = jump_config(&options).unwrap();
        let text = std::fs::read_to_string(file.path()).unwrap();
        let control = text.find("ControlMaster no").unwrap();
        assert!(text.contains("ControlPath none"), "{text}");
        let include = text.find("Include \"/x/my config\"").unwrap();
        assert!(control < include, "{text}");
        assert!(!text.contains("/etc/ssh/ssh_config"), "{text}");
    }

    #[test]
    fn splits_jump_hops() {
        for (hop, destination, port) in [
            ("bastion", "bastion", None),
            ("me@bastion:922", "me@bastion", Some("922")),
            ("me@[::1]:22", "me@::1", Some("22")),
            ("::1", "::1", None),
            ("ssh://me@b:2", "ssh://me@b:2", None),
        ] {
            assert_eq!(split_hop(hop), (destination.to_owned(), port), "{hop}");
        }
    }

    #[test]
    fn classifies_jump_results() {
        let auth = "Authenticated to b ([1.2.3.4]:22) using \"publickey\".\n";
        let refused = format!(
            "{auth}channel 0: open failed: connect failed: Connection refused\nstdio forwarding failed\n"
        );
        assert!(matches!(
            classify_jump(&refused, false, true, 1, "b"),
            Probe::Failed(r) if r == "via b: connect failed: Connection refused"
        ));
        let confirm = format!("{auth}debug2: channel 0: open confirm rwindow 1 rmax 1\n");
        assert!(matches!(
            classify_jump(&confirm, false, false, 1, "b"),
            Probe::Connected
        ));
        assert!(matches!(
            classify_jump(auth, true, false, 1, "b"),
            Probe::Connected
        ));
        assert!(matches!(
            classify_jump(auth, false, false, 1, "b"),
            Probe::Failed(_)
        ));
        // The jump host itself failing must never make the target a candidate.
        let down = "ssh: connect to host b port 22: Connection timed out\n";
        assert!(matches!(
            classify_jump(down, false, true, 1, "b"),
            Probe::Uncertain(_)
        ));
        // A failure on an earlier hop of a chain is the jump path, not the target.
        assert!(matches!(
            classify_jump(&refused, false, true, 2, "b"),
            Probe::Uncertain(_)
        ));
        let prohibited =
            format!("{auth}channel 0: open failed: administratively prohibited: open failed\n");
        assert!(matches!(
            classify_jump(&prohibited, false, true, 1, "b"),
            Probe::Uncertain(_)
        ));
    }

    #[test]
    fn classifies_internal_addresses() {
        for internal in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.10",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_internal(internal.parse().unwrap()), "{internal}");
        }
        for public in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_internal(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn kills_config_commands_that_exceed_the_deadline() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30"]);
        let start = Instant::now();
        let error = run_bounded(command, Duration::from_millis(50)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
