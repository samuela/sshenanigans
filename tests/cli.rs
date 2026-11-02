use std::process::Command;

#[test]
fn empty_gatekeeper_command_is_a_usage_error() {
  for gatekeeper in ["", " \t\n "] {
    let output = Command::new(env!("CARGO_BIN_EXE_sshenanigans"))
      .args(["--host-key-path", "unused", "--gatekeeper", gatekeeper])
      .output()
      .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("gatekeeper command must not be empty"));
    assert!(!stderr.contains("panicked"));
  }
}
