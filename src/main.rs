//! Sample Frost threshold signature generation.

use argh::{FromArgValue, FromArgs};
use frost_secp256k1 as frost;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha3::{Digest as _, Keccak256};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    str,
};

#[derive(FromArgs)]
/// generate a FROST threshold signature
struct Args {
    /// signer threshold
    #[argh(option, default = "50")]
    threshold: u16,
    /// signer count
    #[argh(option, default = "100")]
    signers: u16,
    /// the message to sign
    #[argh(positional)]
    message: Message,
}

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

struct Message(Vec<u8>);

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:#}", Hex(&self.0))
    }
}

impl FromArgValue for Message {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let hex = value.strip_prefix("0x").unwrap_or(value);
        if hex.len() % 2 != 0 {
            return Err("odd number of hex digits".to_string());
        }
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            b => Err(format!("invalid hex digit {b:#02x}")),
        };
        hex.as_bytes()
            .chunks(2)
            .map(|b| Ok((nibble(b[0])? << 4) | nibble(b[1])?))
            .collect::<Result<Vec<_>, _>>()
            .map(Message)
    }
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Address([u8; 20]);

impl Address {
    fn from_key(pubkey: &frost::VerifyingKey) -> Self {
        let p = pubkey.to_element().to_affine().to_encoded_point(false);
        let bytes = keccak256(&p.as_bytes()[1..])[12..].try_into().unwrap();
        Self(bytes)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let addr = format!("{}", Hex(&self.0));
        let digest = keccak256(addr.as_bytes());
        let mut checksummed = *b"0x0000000000000000000000000000000000000000";
        for (i, (c, a)) in checksummed[2..].iter_mut().zip(addr.as_bytes()).enumerate() {
            let byte = digest[i / 2];
            let nibble = 0xf & if i % 2 == 0 { byte >> 4 } else { byte };
            *c = if nibble >= 8 {
                a.to_ascii_uppercase()
            } else {
                a.to_ascii_lowercase()
            };
        }

        f.write_str(str::from_utf8(&checksummed).unwrap())
    }
}

struct U256(k256::U256);

impl U256 {
    fn from_bytes(b: &[u8]) -> Self {
        Self(k256::U256::from_be_slice(b))
    }

    fn from_scalar(s: &k256::Scalar) -> Self {
        Self(k256::U256::from(s))
    }
}

impl Display for U256 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "0x{:032x}", self.0)
    }
}

struct Coord {
    x: U256,
    y: U256,
}

impl Coord {
    fn from_key(pubkey: &frost::VerifyingKey) -> Self {
        Self::from_point(&pubkey.to_element())
    }

    fn from_point(point: &k256::ProjectivePoint) -> Self {
        let p = point.to_encoded_point(false);
        let x = U256::from_bytes(&p.as_bytes()[1..33]);
        let y = U256::from_bytes(&p.as_bytes()[33..65]);
        Self { x, y }
    }
}

impl Display for Coord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{{{},{}}}", self.x, self.y)
    }
}

struct Hex<'a>(&'a [u8]);

impl Display for Hex<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
