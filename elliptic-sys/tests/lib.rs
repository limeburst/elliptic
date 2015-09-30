extern crate elliptic_sys;

use elliptic_sys::{curve25519_keygen, curve25519_sign, curve25519_verify};

const CURVE25519_PRIVKEY_IN: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
];

const CURVE25519_PUBKEY_OUT_CORRECT: [u8; 32] = [
    0x59, 0x95, 0xf4, 0x64, 0xe9, 0xd3, 0x4d, 0x5c,
    0xa5, 0x6b, 0x99, 0x05, 0xb9, 0xa3, 0xcc, 0x37,
    0xc4, 0x56, 0xb2, 0xd8, 0xd3, 0x13, 0xed, 0xbc,
    0xf5, 0x84, 0xb7, 0x05, 0xb5, 0xc0, 0x49, 0x55, 
];

const CURVE25519_SIGNATURE_OUT_CORRECT: [u8; 64] = [
    0xcf, 0x87, 0x3d, 0x03, 0x79, 0xac, 0x20, 0xe8,
    0x89, 0x3e, 0x55, 0x67, 0xee, 0x0f, 0x89, 0x51,
    0xf8, 0xdb, 0x84, 0x0d, 0x26, 0xb2, 0x43, 0xb4,
    0x63, 0x52, 0x66, 0x89, 0xd0, 0x1c, 0xa7, 0x18,
    0xac, 0x18, 0x9f, 0xb1, 0x67, 0x85, 0x74, 0xeb,
    0xdd, 0xe5, 0x69, 0x33, 0x06, 0x59, 0x44, 0x8b,
    0x0b, 0xd6, 0xc1, 0x97, 0x3f, 0x7d, 0x78, 0x0a,
    0xb3, 0x95, 0x18, 0x62, 0x68, 0x03, 0xd7, 0x82, 
];

const CURVE25519_MESSAGE: [u8; 200] = [0u8; 200];
const CURVE25519_RANDOM_BYTES: [u8; 64] = [0u8; 64];

#[test]
fn test_curve25519_keygen() {
    let mut curve25519_pubkey_out = [0u8; 32];
    unsafe {
        curve25519_keygen(curve25519_pubkey_out.as_mut_ptr(), CURVE25519_PRIVKEY_IN.as_ptr());
    }
    assert_eq!(CURVE25519_PUBKEY_OUT_CORRECT, curve25519_pubkey_out);
}

#[test]
fn test_curve25519_sign() {
    let mut signature_out = [0u8; 64];
    let sign = unsafe {
        curve25519_sign(
            signature_out.as_mut_ptr(),
            CURVE25519_PRIVKEY_IN.as_ptr(),
            CURVE25519_MESSAGE.as_ptr(),
            CURVE25519_MESSAGE.len() as u64,
            CURVE25519_RANDOM_BYTES.as_ptr()
            )
    };
    assert_eq!(0, sign);
    assert_eq!(&CURVE25519_SIGNATURE_OUT_CORRECT[..], &signature_out[..]);
}

#[test]
fn test_curve25519_verify() {
    let verify_good = unsafe {
        curve25519_verify(
            CURVE25519_SIGNATURE_OUT_CORRECT.as_ptr(),
            CURVE25519_PUBKEY_OUT_CORRECT.as_ptr(),
            CURVE25519_MESSAGE.as_ptr(),
            CURVE25519_MESSAGE.len() as u64
            )
    };
    assert_eq!(0, verify_good);
    let mut bad_signature = CURVE25519_SIGNATURE_OUT_CORRECT;
    bad_signature[0] ^= 1;
    let verify_bad = unsafe {
        curve25519_verify(
            bad_signature.as_ptr(),
            CURVE25519_PUBKEY_OUT_CORRECT.as_ptr(),
            CURVE25519_MESSAGE.as_ptr(),
            CURVE25519_MESSAGE.len() as u64
            )
    };
    assert_eq!(-1, verify_bad);
}
