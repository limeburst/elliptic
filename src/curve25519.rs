use elliptic_sys::{curve25519_keygen, curve25519_sign, curve25519_verify};

pub fn keygen(private_key: &[u8; 32]) -> [u8; 32] {
    let mut public_key = [0u8; 32];
    unsafe {
        curve25519_keygen(public_key.as_mut_ptr(), private_key.as_ptr());
    }
    public_key
}

pub fn sign(private_key: &[u8; 32], message: &Vec<u8>, random: &[u8; 64]) -> Option<[u8; 64]> {
    let mut signature = [0u8; 64];
    let result = unsafe {
        curve25519_sign(
            signature.as_mut_ptr(),
            private_key.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            random.as_ptr()
            )
    };
    if result == 0 {
        Some(signature)
    } else {
        None
    }
}

pub fn verify(signature: &[u8; 64], public_key: &[u8; 32], message: &Vec<u8>) -> bool {
    let result = unsafe {
        curve25519_verify(
            signature.as_ptr(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len() as u64
            )
    };
    if result == 0 {
        true
    } else {
        false
    }
}
