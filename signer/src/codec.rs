use std::io;

pub trait Encode: Sized {
    fn encode<W: io::Write>(self, writer: W) -> Result<(), Error>;
    fn encode_to_vec(self) -> Result<Vec<u8>, Error> {
        let mut buff = Vec::new();
        self.encode(&mut buff)?;
        Ok(buff)
    }
}

pub trait Decode: Sized {
    fn decode<R: io::Read>(reader: R) -> Result<Self, Error>;
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes)
    }
}

impl<T: serde::Serialize> Encode for &T {
    fn encode<W: io::Write>(self, writer: W) -> Result<(), Error> {
        bincode::serialize_into(writer, self)
    }
}

impl<T: serde::de::DeserializeOwned> Decode for T {
    fn decode<R: io::Read>(reader: R) -> Result<Self, Error> {
        bincode::deserialize_from(reader)
    }
}

pub type Error = bincode::Error;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_should_be_able_to_encode_and_decode_correctly() {
        let message = "Article 107: A Bro never leaves another Bro hanging";

        let encoded = message.encode_to_vec().unwrap();

        let decoded = String::decode_from_bytes(&encoded).unwrap();

        assert_eq!(decoded, message);
    }
}
