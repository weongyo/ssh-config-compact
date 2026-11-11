use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

use platform::FileState;

/// OpenSSH uses the OS account's home, not the HOME environment variable.
/// Match it so the file we edit is the file evaluated by `ssh -G`.
pub fn default_config_path() -> Result<PathBuf> {
    let home = platform::home_dir()?;
    if !home.is_absolute() {
        bail!("SSH home directory is not absolute; use --config PATH");
    }
    Ok(home.join(".ssh").join("config"))
}

/// The system-wide client configuration, which plain `ssh` reads after the
/// user's own: `/etc/ssh/ssh_config`, or `%ProgramData%\ssh\ssh_config` with
/// Win32-OpenSSH.
pub fn system_config_path() -> Result<PathBuf> {
    platform::system_config_path()
}

/// `path` quoted as the argument of an ssh_config `Include` line.
pub fn include_arg(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .filter(|p| !p.contains(['"', '\n', '\r']))
        .with_context(|| format!("unsupported config path {}", path.display()))?;
    // ssh_config reads `\` as an escape character, and Win32-OpenSSH accepts
    // `/` as a path separator.
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    };
    Ok(format!("\"{text}\""))
}

/// `fs::canonicalize`, but on Windows without the `\\?\` prefix whenever the
/// familiar `C:\...` form names the same file.
fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    fs::canonicalize(path).map(platform::simplify)
}

pub struct Snapshot {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    original: Vec<u8>,
    state: FileState,
}

impl Snapshot {
    pub fn load(path: &Path) -> Result<Self> {
        let canonical_path = canonicalize(path)
            .with_context(|| format!("cannot open SSH config {}", path.display()))?;
        let mut file = File::open(&canonical_path)?;
        if !file.metadata()?.is_file() {
            bail!("SSH config must be a regular file");
        }
        let state = FileState::of(&file)?;
        let mut original = Vec::new();
        file.read_to_end(&mut original)?;
        Ok(Self {
            requested_path: path.to_owned(),
            canonical_path,
            original,
            state,
        })
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.original
    }

    pub fn text(&self) -> Result<&str> {
        std::str::from_utf8(&self.original).context("SSH config must contain valid UTF-8")
    }

    fn ensure_unchanged(&self) -> Result<()> {
        if canonicalize(&self.requested_path)? != self.canonical_path {
            bail!("config symlink changed during the scan; refusing to overwrite it");
        }
        let mut file = File::open(&self.canonical_path)?;
        if FileState::of(&file)? != self.state {
            bail!("config metadata changed during the scan; refusing to overwrite it");
        }
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        if contents != self.original {
            bail!("config changed during the scan; refusing to overwrite it");
        }
        Ok(())
    }

    /// Call only after the user has reviewed and confirmed the exact removals.
    pub fn apply(&self, replacement: &str) -> Result<PathBuf> {
        self.ensure_unchanged()?;
        if self.state.links() != 1 {
            bail!("config has multiple hard links; refusing to replace it");
        }
        let parent = self
            .canonical_path
            .parent()
            .context("config has no parent directory")?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".ssh-config-compact-")
            .tempfile_in(parent)?;
        // Same owner and permissions as the original, or refuse.
        self.state
            .preserve_on(temporary.as_file(), temporary.path())?;
        temporary.write_all(replacement.as_bytes())?;
        temporary.as_file().sync_all()?;

        self.ensure_unchanged()?;
        let (backup_path, mut backup) = self.create_backup()?;
        let commit = || -> Result<()> {
            backup.write_all(&self.original)?;
            backup.sync_all()?;
            // Persist the backup directory entry before replacing the config.
            platform::sync_dir(parent)?;
            self.ensure_unchanged()?;
            temporary
                .persist(&self.canonical_path)
                .map_err(|error| error.error)
                .context("could not atomically replace SSH config")?;
            platform::sync_dir(parent)?;
            Ok(())
        };
        commit().with_context(|| format!("backup path: {}", backup_path.display()))?;
        Ok(backup_path)
    }

    fn create_backup(&self) -> Result<(PathBuf, File)> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        for sequence in 0..100 {
            let mut name = OsString::from(
                self.canonical_path
                    .file_name()
                    .context("invalid config path")?,
            );
            name.push(format!(
                ".bak.{timestamp}.{}.{sequence}",
                std::process::id()
            ));
            let path = self.canonical_path.with_file_name(name);
            match self.state.create_backup(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).context("cannot create config backup; nothing was changed");
                }
            }
        }
        bail!("could not allocate a unique backup filename");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn backs_up_exact_bytes_preserves_mode_and_follows_symlink() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("actual-config");
        let link = dir.path().join("config");
        let original = "# original\r\nHost old\r\n  Port 22\r\n";
        fs::write(&target, original).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &link).unwrap();
        let snapshot = Snapshot::load(&link).unwrap();
        let backup = snapshot.apply("# original\r\n").unwrap();
        assert_eq!(fs::read_to_string(backup.clone()).unwrap(), original);
        assert_eq!(fs::metadata(backup).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fs::read_to_string(&link).unwrap(), "# original\r\n");
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    }

    /// Run `icacls path args...`.
    #[cfg(windows)]
    fn icacls(path: &Path, args: &[&str]) {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "icacls {args:?}: {output:?}");
    }

    /// The access control list as `icacls` lists it, without the file name.
    #[cfg(windows)]
    fn acl(path: &Path) -> String {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let listing = String::from_utf8_lossy(&output.stdout);
        let listing = listing.split("\r\n\r\n").next().unwrap();
        listing
            .strip_prefix(&*path.to_string_lossy())
            .unwrap_or_else(|| panic!("{listing}"))
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[cfg(windows)]
    #[test]
    fn backs_up_exact_bytes_and_preserves_the_access_control_list() {
        let user = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap(),
            std::env::var("USERNAME").unwrap()
        );
        for protect in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            // Like a profile directory: entries that new files inherit, for
            // SYSTEM, Administrators, and the user.
            icacls(
                dir.path(),
                &[
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)(F)",
                    "*S-1-5-32-544:(OI)(CI)(F)",
                    &format!("{user}:(OI)(CI)(F)"),
                ],
            );
            icacls(dir.path(), &["/inheritance:r"]);
            let path = dir.path().join("config");
            let original = "# original\r\nHost old\r\n  Port 22\r\n";
            fs::write(&path, original).unwrap();
            if protect {
                // Like a config fixed for Win32-OpenSSH's permission check:
                // no longer inheriting, and without the Administrators entry,
                // which inheriting would bring back.
                icacls(&path, &["/inheritance:d"]);
                icacls(&path, &["/remove:g", "*S-1-5-32-544"]);
            } else {
                // An explicit entry next to the inherited ones, neither of
                // which may be lost or duplicated.
                icacls(&path, &["/grant", "*S-1-5-32-545:(R)"]);
            }
            let expected = acl(&path);
            assert_eq!(expected.contains("(I)"), !protect, "{expected}");
            assert_eq!(expected.contains("Administrators"), !protect, "{expected}");
            let snapshot = Snapshot::load(&path).unwrap();
            let backup = snapshot.apply("# original\r\n").unwrap();
            assert_eq!(fs::read_to_string(&backup).unwrap(), original);
            assert_eq!(fs::read_to_string(&path).unwrap(), "# original\r\n");
            assert_eq!(acl(&path), expected);
            assert_eq!(acl(&backup), expected);
            // Printed paths keep the familiar form, without a `\\?\` prefix.
            assert!(!backup.to_string_lossy().starts_with(r"\\?\"), "{backup:?}");
        }
    }

    #[test]
    fn refuses_concurrent_edits_without_creating_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, "Host old\n").unwrap();
        let snapshot = Snapshot::load(&path).unwrap();
        fs::write(&path, "Host edited\n").unwrap();
        assert!(
            snapshot
                .apply("")
                .unwrap_err()
                .to_string()
                .contains("changed")
        );
        assert_eq!(fs::read_to_string(path).unwrap(), "Host edited\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn backup_creation_failure_leaves_the_original_untouched() {
        let dir = tempfile::tempdir().unwrap();
        // This is a valid config filename, but adding the backup suffix exceeds
        // the 255-unit name limit. The replacement tempfile can still be
        // created normally.
        let path = dir.path().join("c".repeat(240));
        fs::write(&path, "Host old\n").unwrap();
        let snapshot = Snapshot::load(&path).unwrap();
        assert!(
            snapshot
                .apply("")
                .unwrap_err()
                .to_string()
                .contains("backup")
        );
        assert_eq!(fs::read_to_string(path).unwrap(), "Host old\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_retargeted_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let link = dir.path().join("config");
        fs::write(&first, "Host old\n").unwrap();
        fs::write(&second, "Host other\n").unwrap();
        symlink(&first, &link).unwrap();
        let snapshot = Snapshot::load(&link).unwrap();
        fs::remove_file(&link).unwrap();
        symlink(&second, &link).unwrap();
        assert!(snapshot.apply("").is_err());
        assert_eq!(fs::read_to_string(&first).unwrap(), "Host old\n");
        assert_eq!(fs::read_to_string(&second).unwrap(), "Host other\n");
    }

    #[test]
    fn refuses_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        fs::write(&first, "Host old\n").unwrap();
        fs::hard_link(&first, dir.path().join("hardlink")).unwrap();
        let snapshot = Snapshot::load(&first).unwrap();
        assert!(
            snapshot
                .apply("")
                .unwrap_err()
                .to_string()
                .contains("hard links")
        );
    }

    #[test]
    fn quotes_include_paths() {
        assert_eq!(
            include_arg(Path::new("/x/my config")).unwrap(),
            "\"/x/my config\""
        );
        #[cfg(windows)]
        assert_eq!(
            include_arg(Path::new(r"C:\Users\me\.ssh\config")).unwrap(),
            "\"C:/Users/me/.ssh/config\""
        );
        assert!(include_arg(Path::new("/x/\"quoted\"")).is_err());
        assert!(include_arg(Path::new("/x/new\nline")).is_err());
    }
}
