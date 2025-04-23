use rand::{Rng as _, seq::SliceRandom as _};
use std::{
    fmt::Write as _,
    path::Path,
    process::{Command, Stdio},
};

/// Generate and verify a FROST signature.
///
/// For more details on the process, see `contracts.t.sol` end-to-end test.
#[test]
fn roundtrip() {
    let safe_frost = SafeFrost::with_root_directory("roundtrip");

    // Generate a secret and prepare for the signing rounds.
    safe_frost.exec("split", &["--threshold", "3", "--signers", "5"]);
    safe_frost.exec("info", &["public-key"]);

    let message = random_message();
    let participants = random_signers(3, 5);

    // Round 1.
    for participant in &participants {
        safe_frost.exec("commit", &["--share-index", participant]);
    }
    safe_frost.exec("prepare", &["--message", &message]);

    // Round 2.
    for participant in &participants {
        safe_frost.exec("sign", &["--share-index", participant]);
    }
    safe_frost.exec("aggregate", &[]);

    // Verify the signature.
    safe_frost.exec("verify", &[]);
    safe_frost.exec("info", &["signature"]);
}

struct SafeFrost {
    root: String,
}

impl SafeFrost {
    fn with_root_directory(tag: &str) -> Self {
        let root = Path::new(".frost")
            .join(tag)
            .into_os_string()
            .into_string()
            .unwrap();
        let exit_code = Command::new("git")
            .args(["clean", "-Xf", "--", &root])
            .stdout(Stdio::null())
            .status()
            .expect("Failed to execute `git clean`");
        assert!(exit_code.success(), "`git clean` command failed");
        Self { root }
    }

    fn exec(&self, subcommand: &str, options: &[&str]) {
        print!("$ safe-frost {subcommand}");
        for option in options {
            print!(" {option}");
        }
        println!();
        let output = Command::new("cargo")
            .args(["run", "-q", "--"])
            .args(["--root-directory", &self.root])
            .arg(subcommand)
            .args(options)
            .stderr(Stdio::inherit())
            .output()
            .expect("Failed to execute `safe-frost`");
        assert!(output.status.success(), "`safe-frost` command failed");
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
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
