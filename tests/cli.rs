use rand::{Rng as _, seq::SliceRandom as _};
use std::{
    fmt::Write as _,
    process::{Command, Stdio},
};

/// Generate and verify a FROST signature.
///
/// For more details on the process, see `contracts.t.sol` end-to-end test.
#[test]
fn roundtrip() {
    clean_frost_output_directory();

    // Generate a secret and prepare for the signing rounds.
    safe_frost("split", &["--threshold", "3", "--signers", "5"]);
    safe_frost("info", &["public-key"]);

    let message = random_message();
    let participants = random_signers(3, 5);

    // Round 1.
    for participant in &participants {
        safe_frost("commit", &["--share-index", participant]);
    }
    safe_frost("prepare", &["--message", &message]);

    // Round 2.
    for participant in &participants {
        safe_frost("sign", &["--share-index", participant]);
    }
    safe_frost("aggregate", &[]);

    // Verify the signature.
    safe_frost("verify", &[]);
    safe_frost("info", &["signature"]);
}

/// Cleans the `.frost/` directory.
fn clean_frost_output_directory() {
    let exit_code = Command::new("git")
        .args(["clean", "-Xf", "--", ".frost/"])
        .stdout(Stdio::null())
        .status()
        .expect("Failed to execute `git clean`");
    assert!(exit_code.success(), "`git clean` command failed");
}

/// Execute the `safe-frost` CLI command.
fn safe_frost(subcommand: &str, options: &[&str]) {
    let output = Command::new("cargo")
        .args(["run", "-q", "--"])
        .arg(subcommand)
        .args(options)
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to execute `safe-frost`");
    assert!(output.status.success(), "`safe-frost` command failed");
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

/// Generates a random message for signing.
fn random_message() -> String {
    let mut rng = rand::thread_rng();
    let mut message = [0_u8; 32];
    rng.fill(&mut message);
    let mut buffer = String::with_capacity(2 + message.len() * 2);
    for byte in &message {
        write!(&mut buffer, "{:02x}", byte).unwrap();
    }
    buffer
}

/// Pick a random set of signers from a larger group.
fn random_signers(threshold: usize, signers: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut signers = (0..signers).collect::<Vec<_>>();
    signers.shuffle(&mut rng);
    signers
        .iter()
        .take(threshold)
        .map(ToString::to_string)
        .collect()
}
