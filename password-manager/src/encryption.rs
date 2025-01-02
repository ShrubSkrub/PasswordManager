use anyhow::{Error, Result};
use argon2::{
    password_hash::{Encoding, PasswordHasher, SaltString}, Argon2, PasswordHash, PasswordVerifier
};
use block_padding::generic_array::GenericArray;
use rand::RngCore;
use rand_core::OsRng;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce
};

// Use Argon2id with a minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism.
// This is the defaults: https://docs.rs/argon2/latest/argon2/struct.Params.html
pub fn hash_master_password(password: &String) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        // For some reason, argon2::password_hash::Error does not implement std::error:Error
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

    let hash_string = password_hash.to_string();
    Ok(hash_string)
}


pub fn verify_master_password(stored_b64_hash: &String, password: &String) -> bool {
    let argon2 = Argon2::default();

    match PasswordHash::new(stored_b64_hash) {
        Ok(parsed_hash) => {
            argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
        }
        Err(_) => false
    }
}

const AES_KEY_SIZE: usize = 32;  // 256-bit key size for AES-256
const NONCE_SIZE: usize = 12;  // AES-GCM uses 12-byte nonce

// This function assumes correct master password input
// Validate password before passing, will panic on fail
fn derive_aes_key_from_master_password(password: &String) -> [u8; AES_KEY_SIZE] {
    let salt = SaltString::generate(&mut OsRng);
    let salt_input = salt.as_str().as_bytes();
    let mut output_key = [0u8; AES_KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_input, &mut output_key)
        .expect("Error hashing password!");

    output_key
}


// Encrypt the password using AES-GCM
pub fn encrypt_password(master_password: &String, password: &String) -> Vec<u8> {
    let key = derive_aes_key_from_master_password(master_password);
    let key = GenericArray::from_slice(&key);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, password.as_bytes().as_ref()).expect("Failed encrypting password");

    // Prepend the nonce for storage
    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);

    encrypted_data
}

// Decrypt the password using AES-GCM
pub fn decrypt_password(master_password: &String, encrypted_data: Vec<u8>) -> String {
    // Split nonce and ciphertext
    // The nonce is the first 12 bytes
    let (nonce, ciphertext) = encrypted_data.split_at(12);  

    let key = derive_aes_key_from_master_password(master_password);
    let key = GenericArray::from_slice(&key);

    let cipher = Aes256Gcm::new(&key);

    let decrypted_data = cipher.decrypt(nonce.into(), ciphertext)
        .expect("Failed to decrypt the password");

    let decrypted_password = String::from_utf8(decrypted_data)
        .expect("Failed to convert decrypted bytes to String");

    decrypted_password
}