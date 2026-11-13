//! Drop process privileges after binding, and optionally `chroot`.
//!
//! A long-running server typically needs root only to bind privileged ports
//! (80/443) and, optionally, to `chroot`. Once those binds are done it should
//! shed root and run as an unprivileged user. [`PrivDrop`] performs that in the
//! security-critical order (`chroot` → `setgid` + drop supplementary groups →
//! `setuid`), then verifies the drop actually stuck (root cannot be regained).
//!
//! `setuid`/`setgid` must take effect process-wide, so the caller must ensure
//! **all** privileged binds — the main TCP listener, any HTTP redirect listener,
//! and the HTTP/3 UDP socket — have completed before calling
//! [`PrivDrop::apply`]. See [`Server::notify_bound`](crate::Server) for the
//! bind-readiness handshake used by the CLI.
//!
//! The Linux kernel only changes the credentials of the *calling thread*; it is
//! libc that makes the change process-wide, by signalling every thread to
//! repeat the syscall. On ordinary Unix targets that is what `libc::setuid`
//! does for us. On the libc-free `fullrust` target (`target_os = "fullrust"`)
//! there is no libc, so this module carries its own all-threads broadcast (see
//! the `sys` module): without it, the worker threads that already exist when
//! the drop runs would keep running as root.
//!
//! The actual syscalls are Unix-only; on other platforms [`PrivDrop::apply`]
//! returns an error if any drop was requested.

#![allow(unsafe_code)]

use std::path::PathBuf;

use crate::error::{Error, Result};

/// A resolved set of privilege-dropping actions: switch to `uid`/`gid` and,
/// optionally, `chroot` into a directory. Build one with [`PrivDrop::parse`],
/// then [`apply`](PrivDrop::apply) it once, after all listeners are bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivDrop {
    /// Target user id, if a user was requested.
    pub uid: Option<u32>,
    /// Target group id, if a group (or a user with a primary group) was
    /// requested.
    pub gid: Option<u32>,
    /// Directory to `chroot` into before dropping, if any.
    pub chroot: Option<PathBuf>,
}

impl PrivDrop {
    /// Parse a `user` spec and an optional `chroot` path into a [`PrivDrop`].
    ///
    /// `user` accepts `NAME`, `UID`, `NAME:GROUP`, or `UID:GID`. A non-numeric
    /// `NAME` is resolved to its uid via `getpwnam_r`; if no group is given the
    /// user's primary gid is adopted. A non-numeric `GROUP` is resolved via
    /// `getgrnam_r`. Numeric components are used directly.
    pub fn parse(user: Option<&str>, chroot: Option<&str>) -> Result<PrivDrop> {
        let mut uid = None;
        let mut gid = None;

        if let Some(spec) = user {
            let spec = spec.trim();
            if spec.is_empty() {
                return Err(Error::Config("empty --user value".into()));
            }
            let (user_part, group_part) = match spec.split_once(':') {
                Some((u, g)) => (u, Some(g)),
                None => (spec, None),
            };
            let (resolved_uid, primary_gid) = resolve_user(user_part)?;
            uid = Some(resolved_uid);
            gid = match group_part {
                Some(g) => Some(resolve_group(g)?),
                None => primary_gid,
            };
        }

        Ok(PrivDrop {
            uid,
            gid,
            chroot: chroot.map(PathBuf::from),
        })
    }

    /// Apply the drop, in the security-critical order: `chroot`+`chdir("/")`,
    /// then `setgroups`+`setgid`, then `setuid`, then verify root cannot be
    /// regained. Unix only.
    pub fn apply(&self) -> Result<()> {
        #[cfg(any(unix, target_os = "fullrust"))]
        {
            self.apply_unix()
        }
        #[cfg(not(any(unix, target_os = "fullrust")))]
        {
            if self.uid.is_some() || self.gid.is_some() || self.chroot.is_some() {
                return Err(Error::Config(
                    "privilege dropping is only supported on unix".into(),
                ));
            }
            Ok(())
        }
    }

    #[cfg(any(unix, target_os = "fullrust"))]
    fn apply_unix(&self) -> Result<()> {
        // 0. Anything the credential change needs from the *current* root
        // filesystem must be acquired before the chroot hides it.
        let creds = if self.uid.is_some() || self.gid.is_some() {
            Some(sys::Creds::prepare().map_err(|e| ctx("preparing privilege drop", e))?)
        } else {
            None
        };

        // 1. chroot, then chdir("/") so the cwd is inside the new root.
        if let Some(path) = &self.chroot {
            sys::chroot(path).map_err(|e| ctx("chroot", e))?;
            sys::chdir_root().map_err(|e| ctx("chdir(\"/\")", e))?;
        }

        // 2. Drop supplementary groups, then set the primary group. This must
        // happen before setuid — once we drop the uid we lose the privilege to
        // change groups. Supplementary groups are deliberately reset to just the
        // primary gid (a single-entry `setgroups`) rather than reconstructed
        // from the target user's group memberships via `initgroups`: keeping no
        // supplementary groups is the more restrictive, safer choice (finding
        // 2, informational).
        if let (Some(gid), Some(creds)) = (self.gid, &creds) {
            creds.setgroups_only(gid).map_err(|e| ctx("setgroups", e))?;
            creds.setgid(gid).map_err(|e| ctx("setgid", e))?;
            // Verify the gid drop stuck: both the real and effective gid must
            // now be the target. (setgid as root sets both.)
            let egid = sys::getegid();
            let rgid = sys::getgid();
            if egid != gid || rgid != gid {
                return Err(Error::Config(format!(
                    "privilege drop failed: gid is rgid={rgid}/egid={egid}, expected {gid}"
                )));
            }
        }

        // 3. Drop the user id.
        if let (Some(uid), Some(creds)) = (self.uid, &creds) {
            creds.setuid(uid).map_err(|e| ctx("setuid", e))?;
        }

        // 4. Verify the drop stuck: a non-root target must now be both the
        // real and effective uid, and regaining root via setuid(0) must fail.
        if let Some(uid) = self.uid
            && uid != 0
        {
            let euid = sys::geteuid();
            let ruid = sys::getuid();
            if euid != uid || ruid != uid {
                return Err(Error::Config(format!(
                    "privilege drop failed: uid is ruid={ruid}/euid={euid}, expected {uid}"
                )));
            }
            // Best effort: if we can still become root, the drop is unsafe.
            if sys::can_regain_root() {
                return Err(Error::Config(
                    "privilege drop failed: regained root via setuid(0)".into(),
                ));
            }
        }

        // 5. A drop was requested (any of user/group/chroot) but the process is
        // still effectively root, and root was not explicitly requested. This
        // happens e.g. when only a group or chroot is configured: the sequence
        // above succeeds yet leaves uid 0. Treat it as a hard error so the
        // caller never reports "dropped privileges" while still root.
        let euid = sys::geteuid();
        if still_root_after_drop(self.uid, self.gid, self.chroot.is_some(), euid) {
            return Err(Error::Config(
                "privilege drop requested but process is still uid 0 (specify a non-root user)"
                    .into(),
            ));
        }

        Ok(())
    }
}

/// Decide whether a completed drop left the process unsafely at root.
///
/// Returns `true` when a drop was *requested* (any of user/group/chroot set)
/// but the resulting effective uid is still `0`, **unless** root was explicitly
/// requested (`uid == Some(0)`). Factored out of the syscall path so it can be
/// unit-tested without dropping real privileges.
///
/// Only the `apply_unix` path calls this, so on non-unix targets it has no
/// non-test caller; keep it compiled (and unit-tested) everywhere regardless.
#[cfg_attr(not(any(unix, target_os = "fullrust")), allow(dead_code))]
fn still_root_after_drop(
    uid: Option<u32>,
    gid: Option<u32>,
    chroot: bool,
    resulting_euid: u32,
) -> bool {
    let drop_requested = uid.is_some() || gid.is_some() || chroot;
    let root_explicitly_requested = uid == Some(0);
    drop_requested && resulting_euid == 0 && !root_explicitly_requested
}

/// Resolve a user spec component to `(uid, primary_gid)`. Numeric values parse
/// directly (with no primary gid); names are looked up.
fn resolve_user(s: &str) -> Result<(u32, Option<u32>)> {
    if let Ok(uid) = s.parse::<u32>() {
        return Ok((uid, None));
    }
    #[cfg(any(unix, target_os = "fullrust"))]
    {
        sys::lookup_user(s)
    }
    #[cfg(not(any(unix, target_os = "fullrust")))]
    {
        Err(Error::Config(format!(
            "cannot resolve user name {s:?}: name lookup is only supported on unix"
        )))
    }
}

/// Resolve a group spec component to a gid. Numeric values parse directly;
/// names are looked up.
fn resolve_group(s: &str) -> Result<u32> {
    if let Ok(gid) = s.parse::<u32>() {
        return Ok(gid);
    }
    #[cfg(any(unix, target_os = "fullrust"))]
    {
        sys::lookup_group(s)
    }
    #[cfg(not(any(unix, target_os = "fullrust")))]
    {
        Err(Error::Config(format!(
            "cannot resolve group name {s:?}: name lookup is only supported on unix"
        )))
    }
}

/// Attach the failing operation's name to an OS error.
#[cfg(any(unix, target_os = "fullrust"))]
fn ctx(what: &str, e: std::io::Error) -> Error {
    Error::Config(format!("{what}: {e}"))
}

/// libc backend: every Unix except the libc-free `fullrust` target.
///
/// `setuid`/`setgid`/`setgroups` here are libc's process-wide versions, and
/// names are resolved through NSS (`getpwnam_r`/`getgrnam_r`).
#[cfg(unix)]
mod sys {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use crate::error::{Error, Result};

    fn check(rc: libc::c_int) -> io::Result<()> {
        if rc == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn chroot(path: &Path) -> io::Result<()> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "chroot path contains an interior NUL",
            )
        })?;
        check(unsafe { libc::chroot(c.as_ptr()) })
    }

    pub fn chdir_root() -> io::Result<()> {
        check(unsafe { libc::chdir(c"/".as_ptr()) })
    }

    /// Handle for changing credentials. libc needs no preparation.
    pub struct Creds;

    impl Creds {
        pub fn prepare() -> io::Result<Creds> {
            Ok(Creds)
        }

        /// Reset the supplementary groups to exactly `[gid]`.
        pub fn setgroups_only(&self, gid: u32) -> io::Result<()> {
            let groups = [gid as libc::gid_t];
            check(unsafe { libc::setgroups(1, groups.as_ptr()) })
        }

        pub fn setgid(&self, gid: u32) -> io::Result<()> {
            check(unsafe { libc::setgid(gid as libc::gid_t) })
        }

        pub fn setuid(&self, uid: u32) -> io::Result<()> {
            check(unsafe { libc::setuid(uid as libc::uid_t) })
        }
    }

    pub fn getuid() -> u32 {
        unsafe { libc::getuid() }
    }
    pub fn geteuid() -> u32 {
        unsafe { libc::geteuid() }
    }
    pub fn getgid() -> u32 {
        unsafe { libc::getgid() }
    }
    pub fn getegid() -> u32 {
        unsafe { libc::getegid() }
    }

    /// Whether `setuid(0)` still succeeds (it must not, after a real drop).
    pub fn can_regain_root() -> bool {
        unsafe { libc::setuid(0) == 0 }
    }

    pub fn lookup_user(name: &str) -> Result<(u32, Option<u32>)> {
        let cname = CString::new(name)
            .map_err(|_| Error::Config("user name contains a NUL byte".into()))?;
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if result.is_null() {
            if rc == 0 {
                return Err(Error::Config(format!("unknown user: {name}")));
            }
            return Err(Error::Config(format!(
                "getpwnam_r({name}): {}",
                io::Error::from_raw_os_error(rc)
            )));
        }
        Ok((pwd.pw_uid, Some(pwd.pw_gid)))
    }

    pub fn lookup_group(name: &str) -> Result<u32> {
        let cname = CString::new(name)
            .map_err(|_| Error::Config("group name contains a NUL byte".into()))?;
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 4096];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if result.is_null() {
            if rc == 0 {
                return Err(Error::Config(format!("unknown group: {name}")));
            }
            return Err(Error::Config(format!(
                "getgrnam_r({name}): {}",
                io::Error::from_raw_os_error(rc)
            )));
        }
        Ok(grp.gr_gid)
    }
}

/// Raw-syscall backend for the libc-free `fullrust` target (x86-64 Linux).
///
/// Two things libc normally does are done here by hand:
///
/// - **Process-wide credential changes.** The kernel's `setuid`/`setgid`/
///   `setgroups` affect only the calling thread. [`Creds`] repeats the syscall
///   on every thread of the process, the same way glibc's `setxid` and Go's
///   `AllThreadsSyscall` do: it walks `/proc/self/task`, sends each thread a
///   signal whose handler performs the syscall, and waits for all of them to
///   acknowledge. It fails closed — a thread that errors, or does not answer in
///   time, turns the whole drop into an error.
/// - **Name lookup.** With no NSS, `--user NAME` is resolved from `/etc/passwd`
///   and `/etc/group` only (as a static musl binary would).
#[cfg(target_os = "fullrust")]
mod sys {
    use std::fs::File;
    use std::io::{self, Seek};
    use std::os::fd::AsRawFd;
    use std::os::fullrust::syscall::{self, errno, nr};
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use crate::error::{Error, Result};

    pub fn chroot(path: &Path) -> io::Result<()> {
        // Threads share one `fs_struct` (CLONE_FS), so this is process-wide.
        std::os::unix::fs::chroot(path)
    }

    pub fn chdir_root() -> io::Result<()> {
        std::env::set_current_dir("/")
    }

    /// The signal used to make other threads run the credential syscall. A
    /// real-time signal nothing else in a libc-free process claims (it is the
    /// number glibc reserves for the same job).
    const SIG_SETXID: usize = 33;
    const SA_RESTART: usize = 0x1000_0000;
    const SA_RESTORER: usize = 0x0400_0000;
    /// How long every thread has to acknowledge one broadcast.
    const ACK_TIMEOUT: Duration = Duration::from_secs(10);

    /// The syscall being broadcast (number + two arguments), the number of
    /// threads that have not acknowledged yet, and the first errno reported.
    static CALL_NR: AtomicUsize = AtomicUsize::new(0);
    static CALL_A1: AtomicUsize = AtomicUsize::new(0);
    static CALL_A2: AtomicUsize = AtomicUsize::new(0);
    static PENDING: AtomicUsize = AtomicUsize::new(0);
    static FAILED: AtomicUsize = AtomicUsize::new(0);
    /// The one-entry group list handed to `setgroups`. A static rather than a
    /// stack slot so a handler that runs late never reads a dead frame.
    static GROUP: AtomicU32 = AtomicU32::new(0);
    /// Serializes broadcasts: the statics above describe one call at a time.
    static BROADCAST: Mutex<()> = Mutex::new(());

    /// Runs on each signalled thread. Async-signal-safe: one raw syscall and
    /// atomic stores — no allocation, no locks, no I/O.
    extern "C" fn on_setxid(_sig: i32) {
        // SAFETY: the broadcaster published a credential syscall and arguments
        // that are valid on any thread (plain ids, or a pointer to a static).
        let r = unsafe {
            syscall::syscall2(
                CALL_NR.load(Ordering::SeqCst),
                CALL_A1.load(Ordering::SeqCst),
                CALL_A2.load(Ordering::SeqCst),
            )
        };
        if let Err(e) = r {
            let code = e.raw_os_error().unwrap_or(errno::EPERM) as usize;
            let _ = FAILED.compare_exchange(0, code, Ordering::SeqCst, Ordering::SeqCst);
        }
        PENDING.fetch_sub(1, Ordering::SeqCst);
    }

    /// `rt_sigreturn` trampoline. x86-64 has no kernel-provided one, so every
    /// handler must supply `sa_restorer`.
    #[unsafe(naked)]
    unsafe extern "C" fn restorer() -> ! {
        core::arch::naked_asm!("mov eax, 15", "syscall", "ud2")
    }

    /// The kernel's `struct sigaction` on x86-64.
    #[repr(C)]
    struct KSigaction {
        handler: usize,
        flags: usize,
        restorer: usize,
        mask: u64,
    }

    fn install_handler() -> io::Result<()> {
        let act = KSigaction {
            handler: on_setxid as *const () as usize,
            flags: SA_RESTART | SA_RESTORER,
            restorer: restorer as *const () as usize,
            mask: 0,
        };
        // SAFETY: `act` is a live, correctly laid-out kernel sigaction; the
        // last argument is the kernel sigset size (8 bytes).
        unsafe {
            syscall::syscall4(
                nr::RT_SIGACTION,
                SIG_SETXID,
                &act as *const KSigaction as usize,
                0,
                8,
            )
        }?;
        Ok(())
    }

    /// Handle for changing credentials on every thread of the process.
    ///
    /// Holds `/proc/self/task` open, taken *before* any chroot so the thread
    /// list stays reachable afterwards.
    pub struct Creds {
        tasks: File,
    }

    impl Creds {
        pub fn prepare() -> io::Result<Creds> {
            let tasks = File::open("/proc/self/task").map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("/proc/self/task (needed to drop privileges on every thread): {e}"),
                )
            })?;
            Ok(Creds { tasks })
        }

        /// Reset the supplementary groups to exactly `[gid]`.
        pub fn setgroups_only(&self, gid: u32) -> io::Result<()> {
            let _guard = BROADCAST.lock().unwrap_or_else(|e| e.into_inner());
            GROUP.store(gid, Ordering::SeqCst);
            self.all_threads(nr::SETGROUPS, 1, GROUP.as_ptr() as usize)
        }

        pub fn setgid(&self, gid: u32) -> io::Result<()> {
            let _guard = BROADCAST.lock().unwrap_or_else(|e| e.into_inner());
            self.all_threads(nr::SETGID, gid as usize, 0)
        }

        pub fn setuid(&self, uid: u32) -> io::Result<()> {
            let _guard = BROADCAST.lock().unwrap_or_else(|e| e.into_inner());
            self.all_threads(nr::SETUID, uid as usize, 0)
        }

        /// Run `syscall(call, a1, a2)` on every thread. Caller holds `BROADCAST`.
        fn all_threads(&self, call: usize, a1: usize, a2: usize) -> io::Result<()> {
            install_handler()?;
            // This thread first: if the call is refused outright, nothing else
            // has been touched yet.
            // SAFETY: a credential syscall with plain-integer / static-pointer
            // arguments.
            unsafe { syscall::syscall2(call, a1, a2) }?;

            CALL_NR.store(call, Ordering::SeqCst);
            CALL_A1.store(a1, Ordering::SeqCst);
            CALL_A2.store(a2, Ordering::SeqCst);
            PENDING.store(0, Ordering::SeqCst);
            FAILED.store(0, Ordering::SeqCst);

            // SAFETY: argument-less syscalls that cannot fail.
            let pid = unsafe { syscall::syscall0(nr::GETPID) }?;
            let me = unsafe { syscall::syscall0(nr::GETTID) }?;

            // Signal every thread not yet handled, wait for the acks, and look
            // again: a thread spawned by a not-yet-signalled thread inherits
            // the old credentials, but it exists by the time its parent has
            // acknowledged, so the next pass finds it. Stop once a pass finds
            // nothing new — from then on every thread descends from one that
            // already changed.
            let mut handled = vec![me];
            loop {
                let mut signalled = false;
                for tid in self.thread_ids()? {
                    if handled.contains(&tid) {
                        continue;
                    }
                    handled.push(tid);
                    PENDING.fetch_add(1, Ordering::SeqCst);
                    // SAFETY: tgkill only takes integers.
                    match unsafe { syscall::syscall3(nr::TGKILL, pid, tid, SIG_SETXID) } {
                        Ok(_) => signalled = true,
                        Err(e) => {
                            PENDING.fetch_sub(1, Ordering::SeqCst);
                            // The thread exited between the listing and now.
                            if e.raw_os_error() != Some(errno::ESRCH) {
                                return Err(e);
                            }
                        }
                    }
                }
                if !signalled {
                    break;
                }
                let deadline = Instant::now() + ACK_TIMEOUT;
                while PENDING.load(Ordering::SeqCst) != 0 {
                    if Instant::now() > deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "not every thread acknowledged the credential change",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }

            match FAILED.load(Ordering::SeqCst) {
                0 => Ok(()),
                code => Err(io::Error::from_raw_os_error(code as i32)),
            }
        }

        /// The thread ids currently listed in `/proc/self/task`.
        fn thread_ids(&self) -> io::Result<Vec<usize>> {
            (&self.tasks).rewind()?;
            let fd = self.tasks.as_raw_fd() as usize;
            let mut tids = Vec::new();
            // u64 storage keeps the kernel's `linux_dirent64` records aligned.
            let mut buf = [0u64; 512];
            let cap = std::mem::size_of_val(&buf);
            loop {
                // SAFETY: the kernel writes at most `cap` bytes into `buf`.
                let n = unsafe {
                    syscall::syscall3(nr::GETDENTS64, fd, buf.as_mut_ptr() as usize, cap)
                }?;
                if n == 0 {
                    return Ok(tids);
                }
                // SAFETY: the kernel initialized the first `n <= cap` bytes.
                let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen;
                //                         u8 d_type; char d_name[]; }
                let mut off = 0;
                while off + 19 <= n {
                    let reclen = u16::from_ne_bytes([bytes[off + 16], bytes[off + 17]]) as usize;
                    if reclen < 19 || off + reclen > n {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed directory entry in /proc/self/task",
                        ));
                    }
                    let name = &bytes[off + 19..off + reclen];
                    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                    // Skips "." and "..", which are not numeric.
                    if let Some(tid) = std::str::from_utf8(name)
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                    {
                        tids.push(tid);
                    }
                    off += reclen;
                }
            }
        }
    }

    fn id(call: usize) -> u32 {
        // SAFETY: get*id take no arguments and cannot fail.
        unsafe { syscall::syscall0(call) }.unwrap_or(0) as u32
    }

    pub fn getuid() -> u32 {
        id(nr::GETUID)
    }
    pub fn geteuid() -> u32 {
        id(nr::GETEUID)
    }
    pub fn getgid() -> u32 {
        id(nr::GETGID)
    }
    pub fn getegid() -> u32 {
        id(nr::GETEGID)
    }

    /// Whether `setuid(0)` still succeeds (it must not, after a real drop).
    /// Probes the calling thread only; a success is a failed drop either way.
    pub fn can_regain_root() -> bool {
        // SAFETY: setuid takes a plain integer.
        unsafe { syscall::syscall1(nr::SETUID, 0) }.is_ok()
    }

    /// Find `name` in a colon-separated account database (`/etc/passwd`,
    /// `/etc/group`) and return its fields.
    fn lookup(db: &str, name: &str) -> Result<Option<Vec<String>>> {
        let text =
            std::fs::read_to_string(db).map_err(|e| Error::Config(format!("reading {db}: {e}")))?;
        Ok(text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f[0] == name)
            .map(|f| f.into_iter().map(String::from).collect()))
    }

    fn field(db: &str, name: &str, fields: &[String], idx: usize) -> Result<u32> {
        fields
            .get(idx)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Config(format!("malformed entry for {name} in {db}")))
    }

    pub fn lookup_user(name: &str) -> Result<(u32, Option<u32>)> {
        const DB: &str = "/etc/passwd";
        let f = lookup(DB, name)?.ok_or_else(|| Error::Config(format!("unknown user: {name}")))?;
        Ok((field(DB, name, &f, 2)?, Some(field(DB, name, &f, 3)?)))
    }

    pub fn lookup_group(name: &str) -> Result<u32> {
        const DB: &str = "/etc/group";
        let f = lookup(DB, name)?.ok_or_else(|| Error::Config(format!("unknown group: {name}")))?;
        field(DB, name, &f, 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_numeric_uid_only() {
        let pd = PrivDrop::parse(Some("1000"), None).unwrap();
        assert_eq!(pd.uid, Some(1000));
        assert_eq!(pd.gid, None);
        assert_eq!(pd.chroot, None);
    }

    #[test]
    fn parse_numeric_uid_gid() {
        let pd = PrivDrop::parse(Some("1000:2000"), None).unwrap();
        assert_eq!(pd.uid, Some(1000));
        assert_eq!(pd.gid, Some(2000));
    }

    #[test]
    fn parse_with_chroot() {
        let pd = PrivDrop::parse(Some("1000:2000"), Some("/var/empty")).unwrap();
        assert_eq!(pd.uid, Some(1000));
        assert_eq!(pd.gid, Some(2000));
        assert_eq!(
            pd.chroot.as_deref(),
            Some(std::path::Path::new("/var/empty"))
        );
    }

    #[test]
    fn parse_chroot_only() {
        let pd = PrivDrop::parse(None, Some("/var/empty")).unwrap();
        assert_eq!(pd.uid, None);
        assert_eq!(pd.gid, None);
        assert_eq!(
            pd.chroot.as_deref(),
            Some(std::path::Path::new("/var/empty"))
        );
    }

    #[test]
    fn parse_empty_user_rejected() {
        assert!(PrivDrop::parse(Some("  "), None).is_err());
    }

    // Name resolution: `root` exists with uid 0 on every unix. We only parse —
    // never apply — so no privileges are touched.
    #[cfg(any(unix, target_os = "fullrust"))]
    #[test]
    fn parse_user_name_root() {
        let pd = PrivDrop::parse(Some("root"), None).unwrap();
        assert_eq!(pd.uid, Some(0));
        // root's primary group should resolve too (commonly gid 0).
        assert!(pd.gid.is_some());
    }

    // Numeric uid with a named group component is accepted; mix forms freely.
    #[cfg(any(unix, target_os = "fullrust"))]
    #[test]
    fn parse_unknown_user_name_errors() {
        let r = PrivDrop::parse(Some("definitely-not-a-real-user-xyz"), None);
        assert!(r.is_err());
    }

    #[test]
    fn still_root_group_or_chroot_only_is_error() {
        // Group-only drop that leaves euid 0 is a still-root error.
        assert!(still_root_after_drop(None, Some(2000), false, 0));
        // Chroot-only drop that leaves euid 0 is a still-root error.
        assert!(still_root_after_drop(None, None, true, 0));
    }

    #[test]
    fn still_root_dropped_to_nonroot_is_ok() {
        // A drop to a non-root uid that took effect is fine.
        assert!(!still_root_after_drop(Some(1000), Some(2000), false, 1000));
    }

    #[test]
    fn still_root_explicit_root_is_allowed() {
        // Admin explicitly asked for uid 0 ("root"): not an error even at euid 0.
        assert!(!still_root_after_drop(Some(0), Some(0), false, 0));
        assert!(!still_root_after_drop(Some(0), None, true, 0));
    }

    #[test]
    fn still_root_no_drop_requested_is_not_error() {
        // Nothing was requested; euid 0 is just the status quo, not a failure.
        assert!(!still_root_after_drop(None, None, false, 0));
    }
}
