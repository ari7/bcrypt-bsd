//! Rust wrapper around the BCrypt hashing algorithm implementation [written in C
//! by Solar Designer][src].
//!
//! The C code is embedded into this crate and compiled using build script.
//!
//! # Example
//!
//! ```
//! use bcrypt_bsd::{gen_salt, hash};
//! 
//! let salt = gen_salt(12).unwrap();
//! let bcrypt_hash = hash("Password", salt).unwrap();
//! println!("hash: {}", bcrypt_hash);
//! 
//! ```
//!
//! [src]: http://www.openwall.com/crypt/
//!

extern crate libc;
extern crate rand;

use std::str::from_utf8_unchecked;
use std::ffi::{CString, CStr};
use std::error::Error;
use std::fmt;
use libc::{c_int, strerror};
use rand::Rng;
use rand::os::OsRng;

extern "C" {
    // result is a 30-byte C string of base64 code
    fn c_gen_salt(cost: u8, random16: *const u8, result: *mut u8) -> c_int;

    // result is a 61-byte C string of base64 code
    fn c_hash(key: *const u8, salt: *const u8, result: *mut u8) -> c_int;
}

/// Generate salt for a BCrypt hash.
///
/// 
pub fn gen_salt(cost: u8) -> Result<[u8; 30], CryptError> {
    let mut salt: [u8; 30] = [0; 30];
    let mut random: [u8; 16] = [0; 16];

    fill_random(&mut random);

    unsafe {
        match c_gen_salt(cost, random.as_ptr(), salt.as_mut_ptr()) {
            0 => Ok(salt),
            errno => Err(CryptError::new(errno, None)),
        }
    }
}

// NOTE: password longer than 72 characters are truncated
/// Compute BCrypt hash from a password and salt.
///
///
pub fn hash(password: &str, salt: &[u8]) -> Result<[u8; 61], CryptError> {
    if password.len() == 0 {
        return Err(CryptError::invalid_arg("password cannot be empty".into()));
    }
    if password.len() > 72 {
        return Err(CryptError::invalid_arg("password length must not exceed 72".into()));
    }
    if salt.len() < 30 {
        return Err(CryptError::invalid_arg("salt must be at least 30 bytes long".into()));
    }

    let c_password = if let Ok(c) = CString::new(password) {
        c
    } else {
        return Err(CryptError::invalid_arg("password must not contain NULL characters".into()));
    };

    unsafe {
        let mut result: [u8; 61] = [0; 61];
        match c_hash(c_password.as_bytes().as_ptr(),
                     salt.as_ptr(),
                     result.as_mut_ptr()) {
            0 => Ok(result),
            errno => Err(CryptError::new(errno, None)),
        }
    }
}

/// Convert a nul-terminated byte slice into a borrowed string.
pub fn to_str<'a>(bytes: &'a [u8]) -> Result<&'a str, CryptError> {
    match CStr::from_bytes_with_nul(bytes) {
        Ok(c_str) => {
            match c_str.to_str() {
                Ok(s) => Ok(s),
                Err(e) => Err(CryptError::invalid_arg(e.to_string())),
            }
        }
        Err(e) => Err(CryptError::invalid_arg(e.to_string())),
    }
}


/// BCrypt hashing error.
///
/// 
#[derive(Debug)]
pub struct CryptError {
    /// C error code
    errno: c_int,

    /// optional message
    desc: Option<String>,
}

impl CryptError {
    pub fn new(errno: c_int, desc: Option<String>) -> CryptError {
        CryptError { errno, desc }
    }

    pub fn invalid_arg(desc: String) -> CryptError {
        CryptError {
            errno: libc::EINVAL,
            desc: Some(desc),
        }
    }

    pub fn errno(&self) -> c_int {
        self.errno
    }
}

impl Error for CryptError {
    fn description(&self) -> &str {
        "bcrypt error"
    }
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = if let Some(ref desc) = self.desc {
            desc.clone()
        } else {
            unsafe { errno_to_string(self.errno) }
        };

        write!(f, "bcrypt error: {} ({})", desc, self.errno)
    }
}

fn fill_random(random: &mut [u8]) {
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(random);
}

unsafe fn errno_to_string(errno: c_int) -> String {
    from_utf8_unchecked(CStr::from_ptr(strerror(errno)).to_bytes()).into()
}


#[cfg(test)]
mod tests {
    use super::{to_str, gen_salt, hash};

    #[test]
    fn test_to_str() {
        assert_eq!(to_str(&[114, 117, 115, 116, 097, 099, 101, 097, 110, 0]).unwrap(),
                   "rustacean");
        assert!(to_str(&[114, 117, 115, 116, 097, 099, 101, 097, 110]).is_err());
        assert!(to_str(&[114, 117, 115, 116, 097, 099, 101, 097, 0, 110, 0]).is_err());
    }

    #[test]
    fn test_gen_salt() {
        let salt = gen_salt(4).unwrap();
        assert_eq!(to_str(&salt).unwrap().len(), 29);
    }

    #[test]
    fn test_hash() {
        let pwhash = hash("Password", &gen_salt(4).unwrap()).unwrap();
        assert_eq!(to_str(&pwhash).unwrap().len(), 60);

        assert!(hash("Password", &[0; 15]).is_err());
        assert!(hash("", &gen_salt(4).unwrap()).is_err());
    }
}
