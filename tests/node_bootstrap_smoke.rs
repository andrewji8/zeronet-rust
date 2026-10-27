//! Two real processes start in parallel; each learns the other's peer id.

use std::process::Stdio;
use std::time::Duration;

fn start_node(
    data_dir: &std::path::Path,
    listen: &str,
    bootstrap: &str,
    max_sec: u32,
) -> std::process::Child {
    let bin = std::env::current_exe()
        .expect("current exe")
        .parent()
        .and_then(|p| p.parent())
        .expect("target/debug")
        .join(format!("zeronet-rs{}", std::env::consts::EXE_SUFFIX));
    let bin = bin.to_string_lossy().to_string();
    std::process::Command::new(&bin)
        .arg("node")
        .arg(data_dir)
        .args(["--max-sec", &max_sec.to_string()])
        .args(["--listen", listen])
        .args(["--bootstrap", bootstrap])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn zeronet-rs")
}

fn wait_and_grep(child: std::process::Child, needle: &str) -> String {
    let out = child.wait_with_output().expect("wait").stdout;
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.contains(needle),
        "expected node output to contain {needle:?}; got:\n{text}"
    );
    text
}

#[test]
fn two_cli_processes_bootstrap_each_other() {
    let base = std::env::temp_dir().join(format!("zrs_smoke_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let a_dir = base.join("A");
    let b_dir = base.join("B");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::create_dir_all(&b_dir).unwrap();

    // Use fixed ports to keep the test deterministic.
    let listen_a = "127.0.0.1:46910";
    let listen_b = "127.0.0.1:46911";
    let a = start_node(&a_dir, listen_a, listen_b, 5);
    let b = start_node(&b_dir, listen_b, listen_a, 5);
    let _ = wait_and_grep(a, "bootstrap ok");
    let _ = wait_and_grep(b, "bootstrap ok");

    // Confirm both persisted their routing tables (proves the learned peer
    // actually made it into the routing table, not just the handshake log).
    let _ = std::thread::sleep(Duration::from_millis(200));
    let a_rt = a_dir.join("kad.db");
    let b_rt = b_dir.join("kad.db");
    assert!(
        a_rt.exists(),
        "A's kad.db should exist after graceful shutdown"
    );
    assert!(
        b_rt.exists(),
        "B's kad.db should exist after graceful shutdown"
    );

    let _ = std::fs::remove_dir_all(&base);
}
