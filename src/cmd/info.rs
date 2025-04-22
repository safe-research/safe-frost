use crate::{
    address::Address,
    cmd,
    fmt::{Coord, Hex, Scalar},
};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "info")]
/// display information
pub struct Command {
    #[argh(subcommand)]
    subcommand: Subcommand,

    /// output in Solidity ABI encoded format, intended for use with Foundry
    /// `ffi` cheatcodes.
    #[argh(switch, short = 'e')]
    abi_encode: bool,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    PublicKey(PublicKey),
    Signature(Signature),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "public-key")]
/// display information of a FROST public key
struct PublicKey {
    /// public key file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".into()"#)]
    public_key_path: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "signature")]
/// display information of a FROST signature
struct Signature {
    /// round-2 aggregate signature file
    #[argh(option, short = '2', default = r#"".frost/round2".into()"#)]
    signature_path: PathBuf,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        match self.subcommand {
            Subcommand::PublicKey(cmd) => {
                let data = fs::read(&cmd.public_key_path)?;
                let key = frost::keys::PublicKeyPackage::deserialize(&data)?;
                let key = key.verifying_key();

                if self.abi_encode {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&abi::address(Address::from_key(key)));
                    buf.extend_from_slice(&abi::coord(&key.to_element()));
                    print!("{}", Hex(&buf))
                } else {
                    println!("address:    {}", Address::from_key(key));
                    println!("public key: {}", Coord(&key.to_element()));
                }
            }
            Subcommand::Signature(cmd) => {
                let data = fs::read(&cmd.signature_path)?;
                let signature = frost::Signature::deserialize(&data)?;

                if self.abi_encode {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&abi::coord(signature.R()));
                    buf.extend_from_slice(&abi::scalar(signature.z()));
                    print!("{}", Hex(&buf))
                } else {
                    println!("R: {}", Coord(signature.R()));
                    println!("z: {}", Scalar(signature.z()));
                }
            }
        }
        Ok(())
    }
}

/// Poor man's Solidity ABI encoding.
mod abi {
    use crate::address::Address;
    use k256::elliptic_curve::{bigint::Encoding as _, sec1::ToEncodedPoint as _};

    pub fn address(a: Address) -> [u8; 32] {
        let mut b = [0_u8; 32];
        b[12..].copy_from_slice(a.as_slice());
        b
    }

    pub fn scalar(a: &k256::Scalar) -> [u8; 32] {
        k256::U256::from(a).to_be_bytes()
    }

    pub fn coord(a: &k256::ProjectivePoint) -> [u8; 64] {
        a.to_encoded_point(false).as_bytes()[1..]
            .try_into()
            .unwrap()
    }
}
