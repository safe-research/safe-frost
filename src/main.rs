//! Sample Frost threshold signature generation.

mod address;
mod cmd;
mod data;
mod fmt;
mod hex;
mod keccak;

use argh::FromArgs;

#[derive(FromArgs)]
/// generate a FROST threshold signature
struct Args {
    #[argh(subcommand)]
    subcommand: cmd::Subcommand,
}

fn main() {
    let args = argh::from_env::<Args>();
    if let Err(err) = args.subcommand.run() {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}

#[cfg(any())]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = argh::from_env::<Args>();
    let mut rng = rand::thread_rng();

    // First things first, generate a secret and, from this secret split it
    // into `args.signers` shares with a threshold of `args.threshold`.
    //
    // In the real world - this part is kind of complicated as _either_:
    // - You trust a single party to generate a secret and split it into shares
    //   before distributing them to each signer
    // - You use a distributed key generation protocol to trustlessly set up
    //   key shares across the various signers [0]
    //
    // [0]: <https://frost.zfnd.org/tutorial/dkg.html>

    let secret = frost::SigningKey::new(&mut rng);
    let (shares, pubkey_package) = frost::keys::split(
        &secret,
        args.signers,
        args.threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // # Round 1
    //
    // Now, you perform round 1 of the FROST threshold signature scheme and
    // build the "signing package".
    //
    // Each Participant (i.e. key share holder) computes random nonces and
    // signing commitments. The commitments are then sent over an authenticated
    // channel (which needs to further be encrypted in case a secret message is
    // being signed) to the Coordinator. The nonces are kept secret to each
    // Participant and will be used later.
    //
    // As a small point of clarification, each Participant generates nonces and
    // commitments _plural_. Both nonces and commitments are generated as a pair
    // of hiding and binding values.
    //
    // NOTE: for demonstration purposes, just use the first `threshold` signers.

    let round1 = shares
        .iter()
        .take(args.threshold as _)
        .map(|(&id, secret)| {
            let (nonces, commitments) = frost::round1::commit(secret.signing_share(), &mut rng);
            (id, nonces, commitments)
        })
        .collect::<Vec<_>>();

    // Once a threshold of signing commitments are collected, a signing package
    // can be created for collecting signatures from the committed Participants.
    // The Coordinator prepares this signing package and sends it over an
    // authenticated channel to each Participant (again, the channel needs to be
    // encrypted in case the message being signed is secret).

    let signing_package = frost::SigningPackage::new(
        round1
            .iter()
            .map(|(id, _, commitments)| (*id, *commitments))
            .collect(),
        args.message.as_ref(),
    );

    // # Round 2
    //
    // Once the signing package is ready and distributed to the Participants,
    // each can perform their round 2 signature over:
    // - The signing package
    // - The randomly generated nonces from round 1
    // - The secret share
    //
    // The Participant sends their signature share with the Coordinator over,
    // you guessed it, an authenticated (and possible encrypted) channel.

    let signature_shares = round1
        .iter()
        .map(|(id, nonces, _)| {
            let share = shares.get(id).unwrap().clone();
            let key_package = frost::keys::KeyPackage::try_from(share)?;
            let signature = frost::round2::sign(&signing_package, nonces, &key_package)?;
            Ok((*id, signature))
        })
        .collect::<Result<BTreeMap<_, _>, frost::Error>>()?;

    // Once the threshold of signature shares have been collected, the
    // Coordinator can generate a Schnorr signature.

    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
    assert!(
        pubkey_package
            .verifying_key()
            .verify(args.message.as_ref(), &signature)
            .is_ok(),
    );

    println!("---------------------------------------------------------------------");
    let address = Address::from_key(pubkey_package.verifying_key());
    println!("address:    {address}");
    let public_key = Coord::from_key(pubkey_package.verifying_key());
    println!("public key: {public_key}");
    let r = Coord::from_point(signature.R());
    let z = U256::from_scalar(signature.z());
    println!("signature:  {r}");
    println!("            {z}");
    println!("---------------------------------------------------------------------");
    println!(
        "Frost.verify({}, {}, {}, {}, {}, {}) == {}",
        args.message, public_key.x, public_key.y, r.x, r.y, z, address,
    );
    println!("---------------------------------------------------------------------");

    Ok(())
}
