//! Drop process privileges after binding, and optionally `chroot`.
//!
//! A long-running server typically needs root only to bind privileged ports
//! (80/443) and, optionally, to `chroot`. Once those binds are done it should
//! shed root and run as an unprivileged user. [`PrivDrop`] performs that in the
//! security-critical order (`chroot` → `setgid` + drop supplementary groups →
//! `setuid`), then verifies the drop actually stuck (root cannot be regained).
//!
//! `setuid`/`setgid` are process-wide (glibc broadcasts them to every thread),
//! so the caller must ensure **all** privileged binds — the main TCP listener,
//! any HTTP redirect listener, and the HTTP/3 UDP socket — have completed before
//! calling [`PrivDrop::apply`]. See [`Server::notify_bound`](crate::Server) for
//! the bind-readiness handshake used by the CLI.
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
        #[cfg(unix)]
        {
            self.apply_unix()
        }
        #[cfg(not(unix))]
        {
            if self.uid.is_some() || self.gid.is_some() || self.chroot.is_some() {
                return Err(Error::Config(
                    "privilege dropping is only supported on unix".into(),
                ));
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    fn apply_unix(&self) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        // 1. chroot, then chdir("/") so the cwd is inside the new root.
        if let Some(path) = &self.chroot {
            let c = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| Error::Config("chroot path contains an interior NUL".into()))?;
            check(unsafe { libc::chroot(c.as_ptr()) }, "chroot")?;
            let root = CString::new("/").expect("\"/\" has no NUL");
            check(unsafe { libc::chdir(root.as_ptr()) }, "chdir(\"/\")")?;
        }

        // 2. Drop supplementary groups, then set the primary group. This must
        // happen before setuid — once we drop the uid we lose the privilege to
        // change groups.
        if let Some(gid) = self.gid {
            let gid = gid as libc::gid_t;
            let groups = [gid];
            check(unsafe { libc::setgroups(1, groups.as_ptr()) }, "setgroups")?;
            check(unsafe { libc::setgid(gid) }, "setgid")?;
        }

        // 3. Drop the user id.
        if let Some(uid) = self.uid {
            check(unsafe { libc::setuid(uid as libc::uid_t) }, "setuid")?;
        }

        // 4. Verify the drop stuck: a non-root target must now be both the
        // real and effective uid, and regaining root via setuid(0) must fail.
        if let Some(uid) = self.uid
            && uid != 0
        {
            let want = uid as libc::uid_t;
            let euid = unsafe { libc::geteuid() };
            let ruid = unsafe { libc::getuid() };
            if euid != want || ruid != want {
                return Err(Error::Config(format!(
                    "privilege drop failed: uid is ruid={ruid}/euid={euid}, expected {uid}"
                )));
            }
            // Best effort: if we can still become root, the drop is unsafe.
            if unsafe { libc::setuid(0) } == 0 {
                return Err(Error::Config(
                    "privilege drop failed: regained root via setuid(0)".into(),
                ));
            }
        }

        Ok(())
    }
}

/// Resolve a user spec component to `(uid, primary_gid)`. Numeric values parse
/// directly (with no primary gid); names are looked up.
fn resolve_user(s: &str) -> Result<(u32, Option<u32>)> {
    if let Ok(uid) = s.parse::<u32>() {
        return Ok((uid, None));
    }
    #[cfg(unix)]
    {
        getpwnam(s)
    }
    #[cfg(not(unix))]
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
    #[cfg(unix)]
    {
        getgrnam(s)
    }
    #[cfg(not(unix))]
    {
        Err(Error::Config(format!(
            "cannot resolve group name {s:?}: name lookup is only supported on unix"
        )))
    }
}

#[cfg(unix)]
fn getpwnam(name: &str) -> Result<(u32, Option<u32>)> {
    use std::ffi::CString;

    let cname =
        CString::new(name).map_err(|_| Error::Config("user name contains a NUL byte".into()))?;
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
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    Ok((pwd.pw_uid, Some(pwd.pw_gid)))
}

#[cfg(unix)]
fn getgrnam(name: &str) -> Result<u32> {
    use std::ffi::CString;

    let cname =
        CString::new(name).map_err(|_| Error::Config("group name contains a NUL byte".into()))?;
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
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    Ok(grp.gr_gid)
}

/// Map a `-1` libc return into an errno-carrying [`Error`].
#[cfg(unix)]
fn check(rc: libc::c_int, what: &str) -> Result<()> {
    if rc == -1 {
        Err(Error::Config(format!(
            "{what}: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
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
    #[cfg(unix)]
    #[test]
    fn parse_user_name_root() {
        let pd = PrivDrop::parse(Some("root"), None).unwrap();
        assert_eq!(pd.uid, Some(0));
        // root's primary group should resolve too (commonly gid 0).
        assert!(pd.gid.is_some());
    }

    // Numeric uid with a named group component is accepted; mix forms freely.
    #[cfg(unix)]
    #[test]
    fn parse_unknown_user_name_errors() {
        let r = PrivDrop::parse(Some("definitely-not-a-real-user-xyz"), None);
        assert!(r.is_err());
    }
}
