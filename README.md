# Password Manager
A simple password manager built for fun in Rust. This application securely stores your passwords using AES-GCM encryption for passwords and Argon2 for password hashing. All data is stored locally in a PostgreSQL database, allowing for ease of use.

The system supports basic CRUD operations. Other features such as MFA and toolchain support may come later. (Maybe even a real UI!)

Main Menu:
```
Password Manager:
1. List accounts
2. Search accounts
3. Get account details
4. Add account
5. Update account
6. Delete account
7. Change master password
x. Exit
Please choose an option: 
```

## Security Overview

### Encryption of Stored Passwords
When adding an account, the password is encrypted using AES-256-GCM. The password is never stored in plain text.
The encryption key is derived from your master password using Argon2. Argon2 was chosen for its security robustness.
The encrypted password is stored in the database along with a nonce and the salt.

### Master Password Security
Your master password is the key to decrypting all stored passwords.
The master password is never stored directly. The hash is stored using Argon2.

Since the passwords are encrypted and the master password is hashed, even if someone gains access to the database, they will not be able to decrypt the passwords without the master password.

### Secure Memory Handling
When passwords go out of scope, the system zeroizes them from memory using the zeroize crate. This way, the passwords do not remain in memory longer than necessary.

## Database Setup
You can use the provided `db_setup.sh` script to setup the Postgres database.

```bash
# Run the database setup script
./db_setup.sh
```

Make sure to adjust the configuration in the script if necessary.

## Running the Application
Run program with:

```bash
cargo run
```

This will start the password manager and present you with the main menu.

## Dependencies

| Dependency     | Description                                      |
|----------------|--------------------------------------------------|
| `aes-gcm`      | For AES-GCM encryption.                          |
| `anyhow`       | For error handling.                              |
| `argon2`       | For Argon2 password hashing.                     |
| `base64`       | For base64 encoding and decoding.                |
| `rand`         | For random number generation.                    |
| `rand_core`    | For core random number generation traits.        |
| `rpassword`    | For securely reading passwords from the terminal.|
| `serde`        | For serialization and deserialization.           |
| `serde_json`   | For working with JSON data.                      |
| `sqlx`         | For interacting with the PostgreSQL database.    |
| `tokio`        | For asynchronous runtime.                        |
| `zeroize`      | For securely zeroing memory.                     |
