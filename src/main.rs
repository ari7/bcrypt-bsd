extern crate libc;
extern crate rand;

use libc::{c_int};
use rand::{Rng};
use rand::os::OsRng;
use std::str::from_utf8_unchecked;

extern {
    // result is a 30-byte C string of base64 code
    fn gen_salt(cost: u8, random16: *const u8, result: *mut u8) -> c_int;

    // result is a 61-byte C string of base64 code
    fn hash(key: *const u8, salt: *const u8, result: *mut u8) -> c_int;

    fn test();
}

fn main() {

    let mut salt: [u8; 30] = [0; 30];
    let mut pw_hash: [u8; 61] = [0; 61];
    unsafe {
        gen_salt(12, random16().as_ptr(), salt.as_mut_ptr());
        println!("[R] salt: {}", from_utf8_unchecked(&salt));

        hash(b"Password\0".as_ptr(), salt.as_ptr(), pw_hash.as_mut_ptr());
        println!("[R] hash: {}", from_utf8_unchecked(&pw_hash));
    }

}

fn random16() -> [u8; 16] {
    let mut random_bytes: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut random_bytes);

    random_bytes
}
