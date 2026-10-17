//! Exercise embedded-key loading from the actual running executable.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
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

    fn rekey(&self) {
        let output = Command::new("python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/rekey.py"))
            .arg(self.exe())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
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
fn missing_key_exits_without_modifying_executable() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.exe()).unwrap();
    // Legacy working-directory keys are ignored, even if present.
    fs::write(fixture.0.join("shared.key"), [42; 32]).unwrap();

    for args in [SERVER, CLIENT] {
        let output = fixture.command().args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("no embedded key; add a key with rekey.py")
        );
        assert_eq!(fs::read(fixture.exe()).unwrap(), original);
    }
}

#[test]
fn rekeyed_read_only_executable_runs_without_changes() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    fixture.rekey();
    let keyed = fs::read(fixture.exe()).unwrap();
    fs::set_permissions(fixture.exe(), fs::Permissions::from_mode(0o500)).unwrap();

    drop(fixture.start(SERVER, "server ready"));
    drop(fixture.start(CLIENT, "client ready"));
    assert_eq!(fs::read(fixture.exe()).unwrap(), keyed);
}

#[test]
fn server_authenticates_a_copy_keyed_by_rekey_script() {
    let server = Fixture::new();
    server.rekey();
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
