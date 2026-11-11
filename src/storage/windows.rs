//! Windows side of locating and replacing the config.

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl,
    GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

/// The profile directory of the account running this process. Win32-OpenSSH
/// uses it as the home directory: it reads the same `ProfileImagePath`
/// registry value and ignores %HOME% and %USERPROFILE%.
pub(super) fn home_dir() -> Result<PathBuf> {
    profile_dir().context("cannot look up SSH home directory; use --config PATH")
}

fn profile_dir() -> io::Result<PathBuf> {
    let mut token = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing,
    // and token is writable storage for the opened token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken succeeded, so token is an open handle we own.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut buffer = vec![0_u16; 260];
    loop {
        let mut size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: buffer has room for size UTF-16 units, the NUL included.
        let found = unsafe {
            GetUserProfileDirectoryW(token.as_raw_handle(), buffer.as_mut_ptr(), &mut size)
        };
        if found != 0 {
            let end = buffer.iter().position(|&unit| unit == 0);
            return Ok(PathBuf::from(OsString::from_wide(
                &buffer[..end.unwrap_or(buffer.len())],
            )));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || size as usize <= buffer.len()
        {
            return Err(error);
        }
        buffer.resize(size as usize, 0);
    }
}

/// Win32-OpenSSH reads `%ProgramData%\ssh\ssh_config`.
pub(super) fn system_config_path() -> Result<PathBuf> {
    let data = std::env::var_os("ProgramData")
        .filter(|value| !value.is_empty())
        .context("ProgramData is not set")?;
    Ok(PathBuf::from(data).join("ssh").join("ssh_config"))
}

/// `\\?\C:\dir\config`, as returned by `fs::canonicalize`, as `C:\dir\config`
/// when that names the same file.
pub(super) fn simplify(path: PathBuf) -> PathBuf {
    let Some(plain) = path.to_str().and_then(|p| p.strip_prefix(r"\\?\")) else {
        return path;
    };
    let bytes = plain.as_bytes();
    let drive = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == br":\";
    // Win32 path parsing changes names with trailing dots or spaces, device
    // names such as CON, and over-long paths; those stay verbatim.
    if drive
        && plain.len() < 260
        && std::path::absolute(plain).is_ok_and(|parsed| parsed.as_os_str() == plain)
    {
        return PathBuf::from(plain);
    }
    path
}

/// NTFS journals its metadata, and directories cannot be flushed on Windows.
pub(super) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Identity, permissions, and owner of the config when it was read.
pub(super) struct FileState {
    volume: u32,
    index: u64,
    links: u32,
    attributes: u32,
    /// Owner and DACL. None when the file system keeps no security
    /// information; such a config is never replaced.
    security: Option<SecurityDescriptor>,
}

impl FileState {
    pub(super) fn of(file: &File) -> io::Result<Self> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle stays open while file is borrowed, and info is
        // writable storage of the expected type.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            links: info.nNumberOfLinks,
            attributes: info.dwFileAttributes,
            security: SecurityDescriptor::of(file).ok(),
        })
    }

    pub(super) fn links(&self) -> u64 {
        self.links.into()
    }

    fn security(&self) -> Result<&SecurityDescriptor> {
        self.security
            .as_ref()
            .context("cannot read config permissions; refusing to replace it")
    }

    /// Give `file` at `path`, new in the config's directory, the config's
    /// access control list. Its owner cannot be changed, so it must already
    /// match.
    pub(super) fn preserve_on(&self, file: &File, path: &Path) -> Result<()> {
        let original = self.security()?;
        let created = SecurityDescriptor::of(file)?;
        // SAFETY: both owner SIDs point into live security descriptors.
        if unsafe { EqualSid(original.owner, created.owner) } == 0 {
            bail!("cannot preserve config ownership; refusing to replace it");
        }
        original
            .apply_dacl(path)
            .context("cannot preserve config permissions; refusing to replace it")
    }

    /// Create the backup file at `path`, with the access control list of the
    /// config it backs up.
    pub(super) fn create_backup(&self, path: &Path) -> io::Result<File> {
        let security = self.security.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "cannot read config permissions")
        })?;
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        if let Err(error) = security.apply_dacl(path) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(file)
    }
}

impl PartialEq for FileState {
    fn eq(&self, other: &Self) -> bool {
        self.volume == other.volume
            && self.index == other.index
            && self.links == other.links
            && self.attributes == other.attributes
            && self.security.as_ref().map(SecurityDescriptor::bytes)
                == other.security.as_ref().map(SecurityDescriptor::bytes)
    }
}

/// A file's owner and DACL, as allocated by `GetSecurityInfo`.
struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl SecurityDescriptor {
    fn of(file: &File) -> io::Result<Self> {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the handle has READ_CONTROL access (every readable or
        // writable std::fs::File does), and the out pointers are writable.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self {
            descriptor,
            owner,
            dacl,
        })
    }

    /// The self-relative descriptor, for comparisons.
    fn bytes(&self) -> &[u8] {
        // SAFETY: GetSecurityInfo returns a self-relative descriptor, one
        // contiguous allocation of exactly this length.
        unsafe {
            let length = GetSecurityDescriptorLength(self.descriptor);
            std::slice::from_raw_parts(self.descriptor.cast::<u8>(), length as usize)
        }
    }

    /// Give the file at `path` this DACL. It inherits from its directory
    /// exactly when this one does, so a file in the same directory ends up
    /// with the same entries.
    fn apply_dacl(&self, path: &Path) -> io::Result<()> {
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: the descriptor is live and the out pointers are writable.
        if unsafe { GetSecurityDescriptorControl(self.descriptor, &mut control, &mut revision) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let inheritance = if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: path is NUL-terminated, and dacl points into the live
        // descriptor (or is null for a null DACL, which is copied as such).
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | inheritance,
                ptr::null_mut(),
                ptr::null_mut(),
                self.dacl,
                ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc,
        // and owner and dacl point into it, so nothing uses it afterwards.
        unsafe { LocalFree(self.descriptor) };
    }
}
