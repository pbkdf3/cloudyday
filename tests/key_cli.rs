//! Exercise actual running-inode replacement, not just trailer serialization.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let dir =
            std::env::temp_dir().join(format!("cloudyday-cli-{:032x}", u128::from_ne_bytes(nonce)));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_cloudyday"), dir.join("cloudyday")).unwrap();
        Self(dir)
    }

    fn exe(&self) -> PathBuf {
        self.0.join("cloudyday")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(self.exe());
        command
            .current_dir(&self.0)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1");
        command
    }

    fn genkey(&self) {
        let output = self
            .command()
            .args(["server", "--genkey"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("embedded a new shared secret"));
    }

    fn start(&self, args: &[&str], ready: &str) -> Running {
        let log = self.0.join(format!("{}-log", args[0]));
        let child = self
            .command()
            .args(args)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let mut running = Running(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = fs::read_to_string(&log).unwrap();
            if text.contains(ready) {
                return running;
            }
            assert!(
                running.0.try_wait().unwrap().is_none(),
                "exited before ready: {text}"
            );
            assert!(Instant::now() < deadline, "timed out: {text}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn assert_private(path: &Path) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o7777,
        0o700
    );
}

const SERVER: &[&str] = &[
    "server",
    "--domain",
    "t.example.com",
    "--listen",
    "127.0.0.1:0",
];
const CLIENT: &[&str] = &[
    "client",
    "--domain",
    "t.example.com",
    "--resolver",
    "127.0.0.1:5353",
    "--listen",
    "127.0.0.1:0",
];

#[test]
fn first_server_start_embeds_and_reuses_key() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.exe()).unwrap();
    // Legacy working-directory keys are ignored, even if present.
    fs::write(fixture.0.join("shared.key"), [42; 32]).unwrap();
    let output = fixture.command().args(CLIENT).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no embedded key"));
    assert_eq!(fs::read(fixture.exe()).unwrap(), original);
    // Invoke through a symlink; it must replace the executable, not the link.
    let alias = fixture.0.join("alias");
    symlink(fixture.exe(), &alias).unwrap();
    let child = Command::new(&alias)
        .current_dir(&fixture.0)
        .env("RUST_LOG", "info")
        .args(SERVER)
        .stderr(fs::File::create(fixture.0.join("first-log")).unwrap())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut running = Running(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = fs::read_to_string(fixture.0.join("first-log")).unwrap();
        if text.contains("server ready") {
            break;
        }
        assert!(running.0.try_wait().unwrap().is_none(), "{text}");
        assert!(Instant::now() < deadline, "{text}");
        std::thread::sleep(Duration::from_millis(20));
    }
    let first = fs::read(fixture.exe()).unwrap();
    assert!(first.starts_with(&original));
    assert_eq!(first.len(), original.len() + 32 + 32);
    assert_eq!(
        &first[first.len() - 32..],
        b"\x29\xd9\x31\xf3\x21\xc2\xdf\xe2\xd1\x45\x98\x63\xbc\x8f\xd3\x5b\xd0\x92\x63\x86\xc0\x7d\x02\xa8\x55\x98\xb5\x0a\xba\xb0\x58\xd8"
    );
    assert_private(&fixture.exe());
    assert!(
        fs::symlink_metadata(alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    drop(running);
    // No writes needed when an embedded key already exists.
    fs::set_permissions(fixture.exe(), fs::Permissions::from_mode(0o500)).unwrap();
    drop(fixture.start(SERVER, "server ready"));
    drop(fixture.start(CLIENT, "client ready"));
    assert_eq!(fs::read(fixture.exe()).unwrap(), first);
    assert_eq!(fs::read(fixture.0.join("shared.key")).unwrap(), [42; 32]);
}

#[test]
fn first_running_server_authenticates_a_copied_executable() {
    let server = Fixture::new();
    let _server = server.start(SERVER, "server ready");
    let log = fs::read_to_string(server.0.join("server-log")).unwrap();
    let listen = log
        .split("listen=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let client = Fixture::new();
    fs::copy(server.exe(), client.exe()).unwrap();
    let _client = client.start(
        &[
            "client",
            "--domain",
            "t.example.com",
            "--resolver",
            listen,
            "--listen",
            "127.0.0.1:0",
        ],
        "session established",
    );
    assert!(
        fs::read_to_string(server.0.join("server-log"))
            .unwrap()
            .contains("session established")
    );
}

#[test]
fn genkey_creates_then_rotates_without_growing_executable() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.exe()).unwrap();
    fixture.genkey();
    let first = fs::read(fixture.exe()).unwrap();
    assert!(first.starts_with(&original));
    assert_private(&fixture.exe());
    fixture.genkey();
    let second = fs::read(fixture.exe()).unwrap();
    assert_eq!(first.len(), second.len());
    assert!(second.starts_with(&original));
    assert_ne!(
        &first[original.len()..original.len() + 32],
        &second[original.len()..original.len() + 32]
    );
    assert_private(&fixture.exe());
    assert_eq!(
        fs::read_dir(&fixture.0).unwrap().count(),
        1,
        "no key file or temporary files"
    );
    drop(fixture.start(SERVER, "server ready"));
    drop(fixture.start(CLIENT, "client ready"));
}
