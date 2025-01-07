# Password Manager
A simple, locally hosted password manager built for fun in Rust. This application securely stores your passwords using AES-GCM encryption for passwords and Argon2 for password hashing. All data is stored locally in a SQLite database, allowing for ease of use.

The system supports basic CRUD operations.  Other features such as MFA and toolchain support may come later. (Maybe even a real UI!)

Main Menu:
```
Password Manager:
1. Add an account
2. List accounts
3. Retrieve an account
4. Update an account
5. Delete an account
6. Change master password
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
