extern crate libc;

use libc::{c_int, c_ulong, c_uchar};

#[test]
fn it_works() {
}

#[link(name = "curve25519-donna")]
extern {
    pub fn curve25519_donna(mypublic: *mut c_uchar,
                            secret: *const c_uchar,
                            basepoint: *const c_uchar) -> c_int;
}

#[link(name = "ref10_extract")]
extern {
    pub fn curve25519_keygen(curve25519_pubkey_out: *mut c_uchar,
                             curve25519_privkey_in: *const c_uchar);
    pub fn curve25519_sign(signature_out: *mut c_uchar,
                           curve25519_privkey: *const c_uchar,
                           msg: *const c_uchar,
                           msg_len: c_ulong,
                           random: *const c_uchar) -> c_int;
    pub fn curve25519_verify(signature: *const c_uchar,
                             curve25519_pubkey: *const c_uchar,
                             msg: *const c_uchar,
                             msg_len: c_ulong) -> c_int;
}
