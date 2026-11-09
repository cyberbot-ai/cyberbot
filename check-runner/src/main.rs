#[path = "../../src-tauri/src/check_engine.rs"]
#[allow(dead_code)]
mod check_engine;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::{Read, Write},
    sync::atomic::{AtomicUsize, Ordering},
};
// This allocator belongs only to the small worker, never to the desktop process.
struct Capped;
static USED: AtomicUsize = AtomicUsize::new(0);
const HEAP: usize = 16 * 1024 * 1024;
unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let mut old = USED.load(Ordering::Relaxed);
        loop {
            let Some(next) = old.checked_add(l.size()).filter(|n| *n <= HEAP) else {
                return std::ptr::null_mut();
            };
            match USED.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(n) => old = n,
            }
        }
        let p = System.alloc(l);
        if p.is_null() {
            USED.fetch_sub(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        USED.fetch_sub(l.size(), Ordering::Relaxed);
    }
}
#[global_allocator]
static ALLOCATOR: Capped = Capped;
fn main() {
    #[cfg(unix)]
    unsafe {
        let cpu = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let size = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0
            || libc::setrlimit(libc::RLIMIT_FSIZE, &size) != 0
        {
            std::process::exit(2);
        }
        libc::alarm(3);
        libc::nice(10);
    }
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--isolation-probe") && args.len() == 4 {
        let read = std::fs::read(&args[2]).is_ok();
        let write = std::fs::write(format!("{}.write", args[2]), b"probe").is_ok();
        let network = std::net::TcpStream::connect(&args[3]).is_ok();
        let shell = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .status()
            .is_ok();
        let env = std::env::var_os("SSH_AUTH_SOCK").is_some()
            || std::env::var_os("CYBERBOT_MCP_TOKEN").is_some();
        println!(
            "{}",
            serde_json::json!({"isolated":!read&&!write&&!network&&!shell&&!env,"read":read,"write":write,"network":network,"shell":shell,"env":env})
        );
        return;
    }
    if args.get(1).map(String::as_str) == Some("--heap-probe") {
        let size = std::hint::black_box(32 * 1024 * 1024);
        let v = vec![1u8; size];
        std::hint::black_box(v);
        std::process::exit(4);
    }
    if args.get(1).map(String::as_str) == Some("--cpu-probe") {
        loop {
            std::hint::black_box(123_u64.wrapping_mul(std::hint::black_box(456)));
        }
    }
    if args.get(1).map(String::as_str) == Some("--wall-probe") {
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(4);
    }
    if args.len() != 1 {
        std::process::exit(2);
    }
    let result = (|| -> Result<_, String> {
        let mut bytes = vec![];
        std::io::stdin()
            .take(147457)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 147456 {
            return Err("input limit".into());
        }
        let requests: Vec<check_engine::Request> =
            serde_json::from_slice(&bytes).map_err(|_| "invalid request")?;
        if requests.is_empty()
            || requests.len() > 8
            || requests.len() > 1 && requests.iter().any(|r| r.test)
        {
            return Err("batch limit".into());
        }
        requests
            .into_iter()
            .map(check_engine::execute)
            .collect::<Result<Vec<_>, _>>()
    })();
    match result {
        Ok(value) => {
            let bytes = serde_json::to_vec(&value).unwrap();
            if bytes.len() > 8192 {
                std::process::exit(2);
            }
            let _ = std::io::stdout().write_all(&bytes);
        }
        Err(_) => {
            eprintln!("check rejected");
            std::process::exit(2);
        }
    }
}
