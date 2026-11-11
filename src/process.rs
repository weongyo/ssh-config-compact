//! A child process that can be stopped together with everything it started,
//! such as a stalled `Match exec` command or the ssh of an earlier ProxyJump
//! hop.

use std::io;
use std::process::{Child, Command, ExitStatus};

pub(crate) struct ProcessTree {
    child: Child,
    /// Holds the child and its descendants; closing it kills them all.
    #[cfg(windows)]
    job: Option<job::Job>,
}

impl ProcessTree {
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // A process group of its own, which kill() signals as a whole.
            let child = command.process_group(0).spawn()?;
            Ok(Self { child })
        }
        #[cfg(windows)]
        {
            let child = command.spawn()?;
            // Processes started by the child join its job. Without a job (it
            // may be refused, e.g. inside a restricted job), only the child
            // itself can be killed.
            let job = job::Job::new(&child).ok();
            Ok(Self { child, job })
        }
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Kill the child and its descendants. Call before [`Self::wait`].
    pub(crate) fn kill(&mut self) {
        #[cfg(unix)]
        // SAFETY: kill accepts this numeric process-group id and no pointers.
        // The still-unreaped child owns this process-group id.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL)
        };
        #[cfg(windows)]
        match &self.job {
            Some(job) => job.terminate(),
            None => {
                let _ = self.child.kill();
            }
        }
    }

    /// Reap the child.
    pub(crate) fn wait(&mut self) {
        let _ = self.child.wait();
    }
}

#[cfg(windows)]
mod job {
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Child;
    use std::ptr;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };

    /// A job object whose processes are killed when it is closed.
    pub(super) struct Job(OwnedHandle);

    impl Job {
        pub(super) fn new(child: &Child) -> io::Result<Self> {
            // SAFETY: an unnamed job with default security; both pointers may
            // be null.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: CreateJobObjectW succeeded, so handle is open and ours.
            let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: limits is the structure this information class expects,
            // and the length passed is its size.
            let limited = unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    ptr::from_ref(&limits).cast(),
                    size_of_val(&limits) as u32,
                )
            };
            if limited == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: both handles are open for the duration of the call.
            if unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), child.as_raw_handle()) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub(super) fn terminate(&self) {
            // SAFETY: the job handle is open. Failure leaves nothing to undo.
            unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) };
        }
    }
}
