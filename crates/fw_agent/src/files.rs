//! Descriptor-relative, private credential storage. Refuse aliases and shared
//! directories instead of repairing permission mistakes behind the user's back.
use crate::Result;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::{
    ffi::CString,
    fs,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
};

pub const LIMIT: usize = 65_536;

pub struct Directory {
    pub path: PathBuf,
    #[cfg(unix)]
    descriptor: File,
}

#[cfg(unix)]
fn private(metadata: &fs::Metadata) -> Result<()> {
    // geteuid only reads the effective identity of this process.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err("credential ownership or permissions are not private".into());
    }
    Ok(())
}

#[cfg(unix)]
fn name(value: &str) -> Result<CString> {
    if value.is_empty() || value == "." || value == ".." || value.contains('/') {
        return Err("invalid credential filename".into());
    }
    CString::new(value).map_err(|_| "invalid credential filename".into())
}

#[cfg(unix)]
fn io_result(value: i32) -> Result<()> {
    if value < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

impl Directory {
    #[cfg(unix)]
    pub fn open(path: &Path, create: bool, require_private: bool) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let components: Vec<_> = absolute.components().collect();
        if components
            .iter()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            return Err("credential directories cannot contain parent traversal".into());
        }
        let mut current = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let mut normalized = PathBuf::from("/");
        for component in components {
            let Component::Normal(part) = component else {
                continue;
            };
            let part = part.to_str().ok_or("credential path must be UTF-8")?;
            let c_name = name(part)?;
            if create {
                // The parent descriptor anchors creation even if a path is renamed.
                let created = unsafe { libc::mkdirat(current.as_raw_fd(), c_name.as_ptr(), 0o700) };
                if created < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            let descriptor = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err("credential directory is missing, aliased, or inaccessible".into());
            }
            // openat returned a fresh owned descriptor.
            current = unsafe { File::from_raw_fd(descriptor) };
            let metadata = current.metadata()?;
            let mode = metadata.permissions().mode();
            // A sticky temporary directory is safe to traverse with anchored descriptors, but
            // is never accepted as the private final credential directory.
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err("credential path has a writable shared ancestor".into());
            }
            normalized.push(part);
        }
        if require_private {
            private(&current.metadata()?)?;
        }
        Ok(Self {
            path: normalized,
            descriptor: current,
        })
    }

    #[cfg(not(unix))]
    pub fn open(_: &Path, _: bool, _: bool) -> Result<Self> {
        Err("protected device credentials are currently supported only on Unix".into())
    }

    #[cfg(unix)]
    fn open_file(&self, filename: &str) -> Result<Option<File>> {
        let filename = name(filename)?;
        let fd = unsafe {
            libc::openat(
                self.descriptor.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err("credential file is aliased or inaccessible".into());
        }
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    }

    #[cfg(unix)]
    pub fn read_optional(&self, filename: &str, require_private: bool) -> Result<Option<Vec<u8>>> {
        let Some(file) = self.open_file(filename)? else {
            return Ok(None);
        };
        let metadata = file.metadata()?;
        if require_private {
            private(&metadata)?;
        }
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > LIMIT as u64 {
            return Err("credential must be a bounded regular file with one link".into());
        }
        let mut bytes = Vec::new();
        file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > LIMIT {
            return Err("credential file is too large".into());
        }
        Ok(Some(bytes))
    }

    #[cfg(not(unix))]
    pub fn read_optional(&self, _: &str, _: bool) -> Result<Option<Vec<u8>>> {
        Err("protected device credentials are currently supported only on Unix".into())
    }

    pub fn read(&self, filename: &str) -> Result<Vec<u8>> {
        self.read_optional(filename, true)?
            .ok_or_else(|| "required credential file is missing".into())
    }

    #[cfg(unix)]
    pub fn write(&self, filename: &str, bytes: &[u8], replace: bool) -> Result<()> {
        private(&self.descriptor.metadata()?)?;
        if bytes.len() > LIMIT {
            return Err("credential output is too large".into());
        }
        let destination = name(filename)?;
        if self.read_optional(filename, true)?.is_some() && !replace {
            return Err("credential already exists; refusing to overwrite it".into());
        }
        let temporary = name(&format!(".write-{}.tmp", uuid::Uuid::new_v4()))?;
        let fd = unsafe {
            libc::openat(
                self.descriptor.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            if replace {
                // Atomic replacement changes the directory entry, never a link's target.
                io_result(unsafe {
                    libc::renameat(
                        self.descriptor.as_raw_fd(),
                        temporary.as_ptr(),
                        self.descriptor.as_raw_fd(),
                        destination.as_ptr(),
                    )
                })?;
            } else {
                // linkat is an atomic publish-if-absent operation on Unix.
                io_result(unsafe {
                    libc::linkat(
                        self.descriptor.as_raw_fd(),
                        temporary.as_ptr(),
                        self.descriptor.as_raw_fd(),
                        destination.as_ptr(),
                        0,
                    )
                })?;
                io_result(unsafe {
                    libc::unlinkat(self.descriptor.as_raw_fd(), temporary.as_ptr(), 0)
                })?;
            }
            self.descriptor.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.descriptor.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        result
    }

    #[cfg(not(unix))]
    pub fn write(&self, _: &str, _: &[u8], _: bool) -> Result<()> {
        Err("protected device credentials are currently supported only on Unix".into())
    }

    #[cfg(unix)]
    pub fn lock(&self) -> Result<File> {
        let filename = name(".agent.lock")?;
        let fd = unsafe {
            libc::openat(
                self.descriptor.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("cannot open device identity lock".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        private(&metadata)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err("invalid device identity lock".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another device command is using this identity".into());
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    pub fn lock(&self) -> Result<File> {
        Err("protected device credentials are currently supported only on Unix".into())
    }
}

pub fn read_path(path: &Path, require_private: bool) -> Result<Vec<u8>> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid credential path")?;
    Directory::open(parent, false, require_private)?
        .read_optional(file, require_private)?
        .ok_or_else(|| "required credential file is missing".into())
}
