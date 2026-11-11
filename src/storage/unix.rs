//! Unix side of locating and replacing the config.

use anyhow::{Context, Result, bail};
use std::ffi::{CStr, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The home directory of the current OS account, as OpenSSH looks it up.
pub(super) fn home_dir() -> Result<PathBuf> {
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
            return Err(io::Error::from_raw_os_error(code))
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
        return Ok(PathBuf::from(OsStr::from_bytes(home.to_bytes())));
    }
}

pub(super) fn system_config_path() -> Result<PathBuf> {
    Ok(PathBuf::from("/etc/ssh/ssh_config"))
}

/// Canonical paths need no simplification on Unix.
pub(super) fn simplify(path: PathBuf) -> PathBuf {
    path
}

/// Make the directory entries of `dir` durable.
pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Identity, permissions, and owner of the config when it was read.
pub(super) struct FileState(Metadata);

impl FileState {
    pub(super) fn of(file: &File) -> io::Result<Self> {
        file.metadata().map(Self)
    }

    pub(super) fn links(&self) -> u64 {
        self.0.nlink()
    }

    /// Give `file`, new in the config's directory, the config's mode. Its
    /// owner cannot be changed, so it must already match.
    pub(super) fn preserve_on(&self, file: &File, _path: &Path) -> Result<()> {
        let metadata = file.metadata()?;
        if metadata.uid() != self.0.uid() || metadata.gid() != self.0.gid() {
            bail!("cannot preserve config ownership; refusing to replace it");
        }
        file.set_permissions(fs::Permissions::from_mode(self.0.mode()))?;
        Ok(())
    }

    /// Create the backup file at `path`, readable only by its owner.
    pub(super) fn create_backup(&self, path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
}

impl PartialEq for FileState {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (&self.0, &other.0);
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mode() == b.mode()
            && a.uid() == b.uid()
            && a.gid() == b.gid()
            && a.nlink() == b.nlink()
    }
}
