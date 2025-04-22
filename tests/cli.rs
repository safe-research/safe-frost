use rand::{Rng as _, seq::SliceRandom as _};
use std::{
    fmt::Write as _,
    process::{Command, Stdio},
};

#[test]
fn roundtrip() {
    clean_frost_output_directory();

    // First things first, generate a secret and, from this secret split it
    // into `--signers` shares with a threshold of `--threshold`.
    //
    // In the real world - this part is kind of complicated as _either_:
    // - You trust a single party to generate a secret and split it into shares
    //   before distributing them to each signer
    // - You use a distributed key generation protocol to trustlessly set up
    //   key shares across the various signers [0]
    //
    // [0]: <https://frost.zfnd.org/tutorial/dkg.html>
    safe_frost("split", &["--threshold", "3", "--signers", "5"]);
    safe_frost("info", &["public-key"]);

    // Choose a random message and the random threshold of signers that will
    // participate.
    let message = random_message();
    let signers = random_signers(3, 5);

    // # Round 1
    //
    // Now, you perform round 1 of the FROST threshold signature scheme and
    // build the Signing Package.
    //
    // Each Participant (i.e. key share holder) computes random nonces and
    // signing commitments. The commitments are then sent over an authenticated
    // channel (which needs to further be encrypted in case a secret message is
    // being signed) to the Coordinator. The nonces are kept secret to each
    // Participant and will be used later. As a small point of clarification,
    // each Participant generates nonces and commitments _plural_. Both nonces
    // and commitments are generated as a pair of hiding and binding values.
    //
    // Once a threshold of signing commitments are collected, a signing package
    // can be created for collecting signatures from the committed Participants.
    // The Coordinator prepares this signing package and sends it over an
    // authenticated channel to each Participant (again, the channel needs to be
    // encrypted in case the message being signed is secret).
    for signer in &signers {
        safe_frost("commit", &["--share-index", signer]);
    }
    safe_frost("prepare", &["--message", &message]);

    // # Round 2
    //
    // Once the Signing Package is ready and distributed to the Participants,
    // each can perform their round 2 signature over:
    // - The Signing Package from round 1
    // - The randomly generated nonces from round 1
    // - The secret share
    //
    // The Participant sends their signature share with the Coordinator over,
    // you guessed it, an authenticated (and possible encrypted) channel.
    //
    // Once the threshold of signature shares have been collected, the
    // Coordinator can generate a Schnorr signature.
    for signer in &signers {
        safe_frost("sign", &["--share-index", signer]);
    }
    safe_frost("aggregate", &[]);

    // Finally, we double check that everything worked as expected and can
    // successfully verify the generated signature.
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
