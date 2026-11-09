use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
    process::Stdio,
};
use tokio::{
    io::unix::AsyncFd,
    process::{Child, Command},
};

use super::Size;

pub(super) struct Pty(AsyncFd<File>);

#[cfg(target_os = "macos")]
extern "C" {
    // Available since macOS 10.13.4, before the application's minimum version.
    fn ptsname_r(fd: libc::c_int, name: *mut libc::c_char, len: libc::size_t) -> libc::c_int;
}
#[cfg(not(target_os = "macos"))]
use libc::ptsname_r;

fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Pty {
    pub(super) fn spawn(args: &[String], size: Size) -> io::Result<(Self, Child)> {
        let master = unsafe {
            let fd = libc::posix_openpt(
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            );
            check(fd)?;
            File::from_raw_fd(fd)
        };
        let fd = master.as_raw_fd();
        let mut name = [0; 1024];
        unsafe {
            check(libc::grantpt(fd))?;
            check(libc::unlockpt(fd))?;
            match ptsname_r(fd, name.as_mut_ptr(), name.len()) {
                0 => {}
                -1 => return Err(io::Error::last_os_error()),
                errno => return Err(io::Error::from_raw_os_error(errno)),
            }
        }
        let path = unsafe { CStr::from_ptr(name.as_ptr()) };
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())))?;
        unsafe {
            let mut modes = std::mem::MaybeUninit::uninit();
            check(libc::tcgetattr(slave.as_raw_fd(), modes.as_mut_ptr()))?;
            let mut modes = modes.assume_init();
            // OpenSSH copies these modes to the remote PTY, including UTF-8 erase.
            modes.c_iflag |= libc::IUTF8;
            check(libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &modes))?;
        }
        // AsyncFd owns the File, which keeps this descriptor open until deregistration.
        let pty = Self(unsafe { AsyncFd::register(master) }?);
        pty.resize(size)?;

        let mut ssh = Command::new("/usr/bin/ssh");
        ssh.args(args)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave))
            .kill_on_drop(true);
        unsafe {
            // Give OpenSSH a controlling terminal so TIOCSWINSZ signals its foreground
            // group. The mux client relays SIGWINCH to the existing OpenSSH master.
            ssh.pre_exec(|| {
                check(libc::setsid())?;
                check(libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0))
            });
        }
        let child = ssh.spawn()?;
        Ok((pty, child))
    }

    pub(super) fn resize(&self, size: Size) -> io::Result<()> {
        let window = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        check(unsafe { libc::ioctl(self.0.as_raw_fd(), libc::TIOCSWINSZ, &window) })
    }

    pub(super) async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.0.readable().await?;
            match ready.try_io(|fd| fd.get_ref().read(buf)) {
                // Linux reports EIO when the last slave descriptor closes.
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub(super) async fn write(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut ready = self.0.writable().await?;
            match ready.try_io(|fd| fd.get_ref().write(bytes)) {
                Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Ok(n)) => bytes = &bytes[n..],
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
        Ok(())
    }
}
