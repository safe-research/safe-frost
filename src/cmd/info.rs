use crate::{address::Address, cmd, fmt::Coord};
use argh::FromArgs;
use std::fs;

#[derive(FromArgs)]
#[argh(subcommand, name = "info")]
/// generate a FROST public key and signing shares
pub struct Command {
    /// public key file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".to_string()"#)]
    public_key_path: String,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let data = fs::read(&self.public_key_path)?;
        let package = frost::keys::PublicKeyPackage::deserialize(&data)?;
        let key = package.verifying_key();

        println!("address:    {}", Address::from_key(key));
        println!("public key: {}", Coord(&key.to_element()));

        Ok(())
    }
}

#[cfg(any())]
mod todo {
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
}
