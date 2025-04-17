use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::fmt::{self, Display, Formatter};

/// Format a byte slice as a hexadecimal string.
pub struct Hex<'a>(pub &'a [u8]);

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

/// Format a secp256k1 scalar.
pub struct Scalar<'a>(pub &'a k256::Scalar);

impl Display for Scalar<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "0x{:032x}", k256::U256::from(self.0))
    }
}

/// Format a secp256k1 coordinate.
pub struct Coord<'a, P>(pub &'a P);

impl<P> Display for Coord<'_, P>
where
    P: ToEncodedPoint<k256::Secp256k1>,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let p = self.0.to_encoded_point(false);
        let x = k256::U256::from_be_slice(&p.as_bytes()[1..33]);
        let y = k256::U256::from_be_slice(&p.as_bytes()[33..65]);
        write!(f, "{{0x{x:032x},0x{y:032x}}}")
    }
}
