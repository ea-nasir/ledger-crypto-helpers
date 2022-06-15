use core::default::Default;
use core::fmt;
use nanos_sdk::bindings::*;
use zeroize::{Zeroize, Zeroizing};

pub trait Hasher<const N: usize> {
    fn new() -> Self;
    fn update(&mut self, bytes: &[u8]);
    fn finalize(&mut self) -> Zeroizing<Hash<N>>;
    fn clear(&mut self);
}

#[derive(Clone, Copy)]
pub struct Hash<const N: usize>(pub [u8; N]);

impl <const N: usize> fmt::Display for Hash<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl <const N: usize> Zeroize for Hash<N> {
    fn zeroize(&mut self) { self.0.zeroize(); }
}

#[derive(Clone, Copy)]
pub struct SHA256(cx_sha256_s);

impl Hasher<32> for SHA256 {
    fn new() -> Self {
        let mut rv = cx_sha256_s::default();
        unsafe { cx_sha256_init_no_throw(&mut rv) };
        Self(rv)
    }

    fn clear(&mut self) {
        unsafe { cx_sha256_init_no_throw(&mut self.0) };
    }

    fn update(&mut self, bytes: &[u8]) {
        unsafe {
            cx_hash_update(
                &mut self.0 as *mut cx_sha256_s as *mut cx_hash_t,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
        }
    }

    fn finalize(&mut self) -> Zeroizing<Hash<32>> {
        let mut rv = Zeroizing::new(Hash([0; 32]));
        unsafe {
            cx_hash_final(
                &mut self.0 as *mut cx_sha256_s as *mut cx_hash_t,
                rv.0.as_mut_ptr(),
            )
        };
        rv
    }
}

#[derive(Clone, Copy)]
pub struct SHA512(cx_sha512_s);

impl Hasher<64> for SHA512 {
    fn new() -> SHA512 {
        let mut rv = cx_sha512_s::default();
        unsafe { cx_sha512_init_no_throw(&mut rv) };
        Self(rv)
    }

    fn clear(&mut self) {
        unsafe { cx_sha512_init_no_throw(&mut self.0) };
    }

    fn update(&mut self, bytes: &[u8]) {
        unsafe {
            cx_hash_update(
                &mut self.0 as *mut cx_sha512_s as *mut cx_hash_t,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
        }
    }

    fn finalize(&mut self) -> Zeroizing<Hash<64>> {
        let mut rv = Zeroizing::new(Hash([0; 64]));
        unsafe {
            cx_hash_final(
                &mut self.0 as *mut cx_sha512_s as *mut cx_hash_t,
                rv.0.as_mut_ptr(),
            )
        };
        rv
    }
}

#[derive(Clone, Copy)]
pub struct Blake2b(cx_blake2b_s);

impl Hasher<32> for Blake2b {
    fn new() -> Self {
        let mut rv = cx_blake2b_s::default();
        unsafe { cx_blake2b_init_no_throw(&mut rv, 256) };
        Self(rv)
    }

    fn clear(&mut self) {
        unsafe { cx_blake2b_init_no_throw(&mut self.0, 256) };
    }

    fn update(&mut self, bytes: &[u8]) {
        unsafe {
            cx_hash_update(
                &mut self.0 as *mut cx_blake2b_s as *mut cx_hash_t,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
        }
    }

    fn finalize(&mut self) -> Zeroizing<Hash<32>> {
        let mut rv = Zeroizing::new(Hash([0; 32]));
        unsafe {
            cx_hash_final(
                &mut self.0 as *mut cx_blake2b_s as *mut cx_hash_t,
                rv.0.as_mut_ptr(),
            )
        };
        rv
    }
}
