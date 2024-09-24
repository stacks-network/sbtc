#![allow(missing_docs)]
mod generated;

pub use generated::stacks::signer::v1::*;
pub use generated::stacks::signer::*;
pub use generated::stacks::*;

impl From<[u8; 32]> for Uint256 {
    fn from(value: [u8; 32]) -> Self {
        let mut part0 = [0u8; 8];
        let mut part1 = [0u8; 8];
        let mut part2 = [0u8; 8];
        let mut part3 = [0u8; 8];

        part0.copy_from_slice(&value[..8]);
        part1.copy_from_slice(&value[8..16]);
        part2.copy_from_slice(&value[16..24]);
        part3.copy_from_slice(&value[24..32]);

        Uint256 {
            bits_part0: u64::from_le_bytes(part0),
            bits_part1: u64::from_le_bytes(part1),
            bits_part2: u64::from_le_bytes(part2),
            bits_part3: u64::from_le_bytes(part3),
        }
    }
}

impl From<Uint256> for [u8; 32] {
    fn from(value: Uint256) -> Self {
        let mut bytes = [0u8; 32];

        bytes[..8].copy_from_slice(&value.bits_part0.to_le_bytes());
        bytes[8..16].copy_from_slice(&value.bits_part1.to_le_bytes());
        bytes[16..24].copy_from_slice(&value.bits_part2.to_le_bytes());
        bytes[24..32].copy_from_slice(&value.bits_part3.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::Fake;
    use fake::Faker;
    use rand::rngs::OsRng;

    #[test]
    fn conversion_between_bytes_and_uint256() {
        let number = Uint256 {
            bits_part0: Faker.fake_with_rng(&mut OsRng),
            bits_part1: Faker.fake_with_rng(&mut OsRng),
            bits_part2: Faker.fake_with_rng(&mut OsRng),
            bits_part3: Faker.fake_with_rng(&mut OsRng),
        };

        let bytes = <[u8; 32]>::from(number);
        let round_trip_number = Uint256::from(bytes);
        assert_eq!(round_trip_number, number);
    }

    #[test]
    fn conversion_between_uint256_and_bytes() {
        let bytes: [u8; 32] = Faker.fake_with_rng(&mut OsRng);
        let number = Uint256::from(bytes);

        let rount_trip_bytes = <[u8; 32]>::from(number);
        assert_eq!(rount_trip_bytes, bytes);
    }
}
