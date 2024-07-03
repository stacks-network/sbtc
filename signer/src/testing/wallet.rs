//! Helper module for constructing the signers multi-sig wallet.
//!

use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::util::secp256k1::Secp256k1PublicKey;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use secp256k1::Keypair;

use crate::config::NetworkKind;
use crate::stacks::wallet::SignerWallet;

/// Helper function for generating a test 2-3 multi-sig wallet
pub fn generate_wallet() -> (SignerWallet, [Keypair; 3]) {
    let mut rng = StdRng::seed_from_u64(100);

    let key_pairs = [
        Keypair::new_global(&mut rng),
        Keypair::new_global(&mut rng),
        Keypair::new_global(&mut rng),
    ];

    for kp in key_pairs {
        let secret_key = blockstack_lib::util::hash::to_hex(kp.secret_key().as_ref());
        let public_key = Secp256k1PublicKey::from_slice(&kp.public_key().serialize()).unwrap();
        let stx_address = StacksAddress::p2pkh(false, &public_key);
        println!("secret_key: {secret_key}");
        println!("stx_address: {stx_address}");
    }

    let public_keys = key_pairs.map(|kp| kp.public_key());
    let wallet = SignerWallet::new(&public_keys, 2, NetworkKind::Testnet).unwrap();

    println!("wallet stx_address: {}", wallet.address());
    (wallet, key_pairs)
}
