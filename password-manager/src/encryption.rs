use anyhow::Result;
use argon2::{
    password_hash::{PasswordHasher, SaltString}, Argon2, PasswordHash, PasswordVerifier
};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use rand_core::OsRng;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key
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


/// Verifies if input password matches the hashed master password
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

/// Generates an AES key using password and random salt
/// 
/// This function assumes correct master password input
/// 
/// Validate password before passing, will panic on fail
/// 
/// # Returns
/// 
/// Returns AES key and salt
fn create_aes_key_from_master_password(master_password: &String) -> ([u8; AES_KEY_SIZE], String) {
    let salt = SaltString::generate(&mut OsRng);
    let salt = salt.as_str();

    let mut output_key = [0u8; AES_KEY_SIZE];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), salt.as_bytes(), &mut output_key)
        .expect("Error hashing password!");

    (output_key, salt.to_string())
}

fn derive_aes_key_from_master_password_and_salt(master_password: &String, salt: &str) -> [u8; AES_KEY_SIZE] {
    let mut output_key = [0u8; AES_KEY_SIZE];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), salt.as_bytes(), &mut output_key)
        .expect("Error hashing password!");

    output_key
}


/// Encrypt the password using AES-GCM
/// 
/// # Arguments
/// 
/// * master_password: Plaintext master password for account password belongs to
/// * password: Plaintext password to be encrypted
/// 
/// # Returns
/// 
/// Returns a base-64 encoded string of the encrypted password, with nonce and salt prepended
/// 
/// ie. "nonce + salt + encrypted_password"
pub fn encrypt_password(master_password: &String, password: &String) -> String {
    let (key, salt) = create_aes_key_from_master_password(master_password);
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, password.as_bytes()).expect("Failed encrypting password");

    // Prepend the nonce for storage
    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);

    // Append the salt for storage
    encrypted_data.extend_from_slice(salt.as_bytes());

    // Convert to base64 string
    let encrypted_data_string = URL_SAFE.encode(encrypted_data);

    encrypted_data_string
}

/// Decrypt the password using AES-GCM
/// 
/// # Arguments
/// 
/// * master_password: Plaintext master password for account password belongs to
/// * encrypted_data_string: Base64 encoded string of encrypted password
/// 
/// # Returns
/// 
/// Returns the plaintext password
pub fn decrypt_password(master_password: &String, encrypted_data_string: &String) -> String {
    // Decode from base64 first
    let encrypted_data = URL_SAFE.decode(encrypted_data_string).expect("Failed to decode password string");

    // Split salt and ciphertext
    // Salt is last 22 bytes
    let (remaining_string, salt) = encrypted_data.split_at(encrypted_data.len() - 22);  
    let salt = std::str::from_utf8(salt).unwrap();

    // Split nonce and ciphertext
    // The nonce is the first 12 bytes
    let (nonce, ciphertext) = remaining_string.split_at(12);  

    let key = derive_aes_key_from_master_password_and_salt(master_password, salt);
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(&key);

    // Attempt decryption and capture the error
    match cipher.decrypt(nonce.into(), ciphertext) {
        Ok(decrypted_data) => {
            let decrypted_password = String::from_utf8_lossy(&decrypted_data).to_string();
            decrypted_password
        }
        Err(e) => {
            eprintln!("Decryption failed with error: {:?}", e);
            panic!("Failed to decrypt the password");
        }
    }
}