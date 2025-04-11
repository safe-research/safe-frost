use argh::{FromArgValue, FromArgs};
use elliptic_curve::{hash2curve, sec1::ToEncodedPoint as _};
use frost_secp256k1::{self as frost, Ciphersuite as _, Group as _};
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
    // TODO(nlordell): use an actual RNG, just making deterministic to make
    // testing easier during development.
    //let mut rng = rand::thread_rng();
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);

    let secret = frost::SigningKey::new(&mut rng);
    let (shares, pubkey_package) = frost::keys::split(
        &secret,
        args.signers,
        args.threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // NOTE: for demonstration purposes, just use the first `threshold` signers.

    let round1 = shares
        .iter()
        .take(args.threshold as _)
        .map(|(&id, secret)| {
            let (nonces, commitments) = frost::round1::commit(secret.signing_share(), &mut rng);
            (id, nonces, commitments)
        })
        .collect::<Vec<_>>();

    let signing_package = frost::SigningPackage::new(
        round1
            .iter()
            .map(|(id, _, commitments)| (*id, *commitments))
            .collect(),
        args.message.as_ref(),
    );

    let signature_shares = round1
        .iter()
        .map(|(id, nonces, _)| {
            let share = shares.get(id).unwrap().clone();
            let key_package = frost::keys::KeyPackage::try_from(share)?;
            let signature = frost::round2::sign(&signing_package, nonces, &key_package)?;
            Ok((*id, signature))
        })
        .collect::<Result<BTreeMap<_, _>, frost::Error>>()?;

    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    assert!(
        pubkey_package
            .verifying_key()
            .verify(&args.message.as_ref(), &signature)
            .is_ok(),
    );

    println!("secret:    {}", Hex(&secret.serialize()));
    println!(
        "address:   {}",
        Address::from_verifying_key(pubkey_package.verifying_key()),
    );
    println!(
        "signature: {}",
        "------------------------------------------------------------------",
    );

    println!(
        "pubkey:    {}",
        pubkey_package
            .verifying_key()
            .to_element()
            .to_affine()
            .to_encoded_point(false)
    );
    println!(
        "R:         {}",
        signature.R().to_affine().to_encoded_point(false)
    );
    println!("z:         {:?}", signature.z());
    println!(
        "preimage:  {}",
        Hex(&{
            let mut preimage = vec![];
            preimage.extend_from_slice(frost::Secp256K1Group::serialize(signature.R())?.as_ref());
            preimage.extend_from_slice(
                frost::Secp256K1Group::serialize(&pubkey_package.verifying_key().to_element())?
                    .as_ref(),
            );
            preimage.extend_from_slice(args.message.as_ref());
            preimage
        }),
    );
    println!(
        "challenge: {:?}",
        frost::Secp256K1Sha256::challenge(
            signature.R(),
            pubkey_package.verifying_key(),
            args.message.as_ref()
        )?,
    );
}

struct Message(Vec<u8>);

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
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
    fn from_verifying_key(pubkey: &frost::VerifyingKey) -> Self {
        let point = pubkey.to_element().to_affine().to_encoded_point(false);
        let bytes = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
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
