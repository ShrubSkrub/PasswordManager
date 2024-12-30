use std::str;

use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString}
};
use rand_core::OsRng;

// Use Argon2id with a minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism.
// This is the defaults: https://docs.rs/argon2/latest/argon2/struct.Params.html
pub fn hash_master_password(password: &String) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        // For some reason, argon2::password_hash::Error does not implement std::error:Error
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

    Ok(password_hash.to_string())
}


pub fn verify_password(hashed: &str, password: &str) -> bool {
    unimplemented!()
}

pub fn derive_encryption_key(master_password: &str) -> String {
    unimplemented!()
}

pub fn encrypt_password(password: &str) -> String {
    // Encrypt the password using AES or some other method
    unimplemented!()
}

pub fn decrypt_password(encrypted_password: &str) -> String {
    unimplemented!()
}