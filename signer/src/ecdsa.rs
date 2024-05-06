use p256k1::ecdsa;
use p256k1::scalar::Scalar;

pub trait SignECDSA: Sized {
    fn sign_ecdsa(self, private_key: &Scalar) -> Result<Signed<Self>, Error>;
}

impl<T: wsts::net::Signable> SignECDSA for T {
    fn sign_ecdsa(self, private_key: &Scalar) -> Result<Signed<Self>, Error> {
        let signer_pub_key = ecdsa::PublicKey::new(private_key)?;
        let signature = self.sign(private_key)?;

        Ok(Signed {
            inner: self,
            signer_pub_key,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Signed<T> {
    /// The signed structure
    pub inner: T,
    /// The public key of the signer
    pub signer_pub_key: ecdsa::PublicKey,
    /// A signature over the hash of the inner structure
    pub signature: Vec<u8>,
}

impl<T: wsts::net::Signable> Signed<T> {
    pub fn verify(&self) -> bool {
        self.inner.verify(&self.signature, &self.signer_pub_key)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("KeyError")]
    KeyError(#[from] p256k1::keys::Error),
    #[error("SignError")]
    SignError(#[from] ecdsa::Error),
}
