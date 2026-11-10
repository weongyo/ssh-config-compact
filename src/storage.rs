use anyhow::{Context, Result, bail};
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// OpenSSH uses the OS account's home, not the HOME environment variable.
/// Match it so the file we edit is the file evaluated by `ssh -G`.
pub fn default_config_path() -> Result<PathBuf> {
    let mut buffer_size = 4096;
    loop {
        let mut buffer = vec![0_u8; buffer_size];
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: entry, result, and buffer are valid writable storage, and the
        // supplied length is exactly the allocated buffer size.
        let code = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE && buffer_size < 1024 * 1024 {
            buffer_size *= 2;
            continue;
        }
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code))
                .context("cannot look up SSH home directory; use --config PATH");
        }
        if result.is_null() {
            bail!("current OS account is missing; use --config PATH");
        }
        // SAFETY: a successful getpwuid_r with a non-null result initialized
        // entry. Its string fields remain valid while buffer is alive.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_dir.is_null() {
            bail!("current OS account has no home directory; use --config PATH");
        }
        // SAFETY: pw_dir is the NUL-terminated string returned by getpwuid_r.
        let home = unsafe { CStr::from_ptr(entry.pw_dir) };
        let home = PathBuf::from(OsStr::from_bytes(home.to_bytes()));
        if !home.is_absolute() {
            bail!("SSH home directory is not absolute; use --config PATH");
        }
        return Ok(home.join(".ssh/config"));
    }
}

pub struct Snapshot {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    original: Vec<u8>,
    metadata: Metadata,
}

impl Snapshot {
    pub fn load(path: &Path) -> Result<Self> {
        let canonical_path = fs::canonicalize(path)
            .with_context(|| format!("cannot open SSH config {}", path.display()))?;
        let mut file = File::open(&canonical_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("SSH config must be a regular file");
        }
        let mut original = Vec::new();
        file.read_to_end(&mut original)?;
        Ok(Self {
            requested_path: path.to_owned(),
            canonical_path,
            original,
            metadata,
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
        if fs::canonicalize(&self.requested_path)? != self.canonical_path {
            bail!("config symlink changed during the scan; refusing to overwrite it");
        }
        let mut file = File::open(&self.canonical_path)?;
        let current = file.metadata()?;
        if current.dev() != self.metadata.dev()
            || current.ino() != self.metadata.ino()
            || current.mode() != self.metadata.mode()
            || current.uid() != self.metadata.uid()
            || current.gid() != self.metadata.gid()
            || current.nlink() != self.metadata.nlink()
        {
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
        if self.metadata.nlink() != 1 {
            bail!("config has multiple hard links; refusing to replace it");
        }
        let parent = self
            .canonical_path
            .parent()
            .context("config has no parent directory")?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".ssh-config-compact-")
            .tempfile_in(parent)?;
        let temporary_metadata = temporary.as_file().metadata()?;
        if temporary_metadata.uid() != self.metadata.uid()
            || temporary_metadata.gid() != self.metadata.gid()
        {
            bail!("cannot preserve config ownership; refusing to replace it");
        }
        temporary.write_all(replacement.as_bytes())?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(self.metadata.mode()))?;
        temporary.as_file().sync_all()?;

        self.ensure_unchanged()?;
        let (backup_path, mut backup) = self.create_backup()?;
        let commit = || -> Result<()> {
            backup.write_all(&self.original)?;
            backup.sync_all()?;
            // Persist the backup directory entry before replacing the config.
            File::open(parent)?.sync_all()?;
            self.ensure_unchanged()?;
            temporary
                .persist(&self.canonical_path)
                .map_err(|error| error.error)
                .context("could not atomically replace SSH config")?;
            File::open(parent)?.sync_all()?;
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
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
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
    use std::os::unix::fs::symlink;

    #[test]
    fn backs_up_exact_bytes_preserves_mode_and_follows_symlink() {
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
        // NAME_MAX. The replacement tempfile can still be created normally.
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

    #[test]
    fn refuses_retargeted_symlinks_and_hard_links() {
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
}
