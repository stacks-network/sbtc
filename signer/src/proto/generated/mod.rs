// This file is @generated by prost-build.
pub mod bitcoin {
    include!("bitcoin.rs");
}
pub mod crypto {
    include!("crypto.rs");
    pub mod wsts {
        include!("crypto.wsts.rs");
    }
}
pub mod stacks {
    include!("stacks.rs");
    pub mod signer {
        pub mod v1 {
            include!("stacks.signer.v1.rs");
        }
    }
}
