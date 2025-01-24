use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPool};
use anyhow;

use password_manager_shared::{encryption::{hash_master_password, verify_master_password, reencrypt_password}, models::{Account, AccountSummary, Master}};

pub async fn initialize_db() -> anyhow::Result<PgPool> {
    let options = PgConnectOptions::from_str(crate::compile_config::DB_PATH)?;
    let pool = PgPool::connect_with(options).await?;

    // Run migrations
    sqlx::migrate!().run(&pool).await?;

    // Insert the default account only if there are no accounts in the table
    let default_master_password_hash = hash_master_password(&"changethis".to_string()).expect("Error hashing password!");
    sqlx::query!(
        "INSERT INTO masters (username, password)
        SELECT 'default', $1
        WHERE NOT EXISTS (SELECT 1 FROM masters)",
        default_master_password_hash
    )
    .execute(&pool)
    .await?; 

    Ok(pool)
}

// ----------------------------------------------------------------------------
// Accounts -------------------------------------------------------------------

/// Adds an [`Account`] to the database
/// 
/// Does not encrypt the password, must be encrypted before calling this function
pub async fn add_account(pool: &PgPool, master_id: i32, account: &Account) -> anyhow::Result<()> {
    // Account id assigned automatically
    match sqlx::query!(
        "INSERT INTO accounts (name, username, password, url, description, master_id) 
        VALUES ($1, $2, $3, $4, $5, $6)",
        account.name,
        account.username,
        account.password,
        account.url,
        account.description,
        master_id
    )
    .execute(pool)
    .await
    {
        Ok(_) => Ok(()), // Query succeeded
        Err(err) => {
            if let sqlx::Error::Database(db_err) = &err {
                if let Some(constraint) = db_err.constraint() {
                    // Handle unique constraint violation for name
                    if constraint == "accounts_name_key" {
                        return Err(anyhow::anyhow!("Name must be unique"));
                    }
                    // Handle foreign key constraint violation for master_id
                    if constraint == "accounts_master_id_fkey" {
                        return Err(anyhow::anyhow!("Master ID must exist in the masters table"));
                    }
                }
                // Handle length violations for required fields
                if db_err.message().contains("violates check constraint") {
                    if db_err.message().contains("accounts_name") {
                        return Err(anyhow::anyhow!("Name is required"));
                    } else if db_err.message().contains("accounts_username") {
                        return Err(anyhow::anyhow!("Username is required"));
                    } else if db_err.message().contains("accounts_password") {
                        return Err(anyhow::anyhow!("Password is required"));
                    }
                }
            }
            // Propagate other errors
            Err(err.into())
        }
    }
}

/// Returns an [`Account`] from the database by its id
///
/// Password is base64 encoded and encrypted, must be decoded before use
pub async fn get_account_by_id(pool: &PgPool, master_id: i32, id: i32) -> anyhow::Result<Account> {
    let account = sqlx::query_as!(Account,
        "SELECT id, name, username, password, url, description, master_id
        FROM accounts WHERE id = $1 AND master_id = $2",
        id,
        master_id
    )
    .fetch_one(pool)
    .await?;

    Ok(account)
}

/// Returns an [`Account`] from the database by its name
/// 
/// Password is base64 encoded and encrypted, must be decoded before use
pub async fn get_account_by_name(pool: &PgPool, master_id: i32, name: &String) -> anyhow::Result<Account> {
    let row = sqlx::query!(
        "SELECT id, name, username, password, url, description, master_id
        FROM accounts WHERE name = $1 AND master_id = $2",
        name,
        master_id
    )
    .fetch_one(pool)
    .await?;

    let account = Account {
        id: row.id,
        name: row.name,
        username: row.username,
        password: row.password,
        url: row.url,
        description: row.description,
        master_id: row.master_id,
    };

    Ok(account)
}

// TODO Make return account, and handle printing in user_interface.rs instead
pub async fn delete_account_by_id(pool: &PgPool, master_id: i32, id: i32) -> anyhow::Result<()> {
    match get_account_by_id(pool, master_id, id).await {
        Ok(returned_account) => {
            let query_result = sqlx::query!(
                "DELETE FROM accounts WHERE id = $1 AND master_id = $2",
                id,
                master_id
            )
            .execute(pool)
            .await?;

            // Sanity check
            if query_result.rows_affected() == 0 {
                return Err(anyhow::anyhow!("DELETE failed: No account found with ID: {}", id))
            }
            
            println!("Account deleted: {:?}", returned_account);
            Ok(())
        },
        Err(err) => {
            println!("No account found with ID: {}", id);
            Err(err)
        }
    }
}

// TODO Make return account, and handle printing in user_interface.rs instead
pub async fn delete_account_by_name(pool: &PgPool, master_id: i32, name: &String) -> anyhow::Result<()> {
    match get_account_by_name(pool, master_id, name).await {
        Ok(returned_account) => {
            let query_result = sqlx::query!(
                "DELETE FROM accounts WHERE name = $1 AND master_id = $2",
                name,
                master_id
            )
            .execute(pool)
            .await?;

            // Sanity check
            if query_result.rows_affected() == 0 {
                return Err(anyhow::anyhow!("DELETE failed: No account found with name: {}", name))
            }
            
            println!("Account deleted: {:?}", returned_account);
            Ok(())
        },
        Err(err) => {
            println!("No account found with name: {}", name);
            Err(err)
        }
    }
}

/// Returns a list of all accounts in the form of 
/// [`AccountSummary`] from the database
/// 
/// TODO Add a function for pagination
pub async fn list_accounts(pool: &PgPool, master_id: i32) -> anyhow::Result<Vec<AccountSummary>> {
    // List all account ids, names, and descriptions from the database
    let summaries = sqlx::query_as!(AccountSummary,
        "SELECT id, name, description FROM accounts WHERE master_id = $1",
        master_id
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}

/// Returns a list of all accounts in the form of 
/// [`AccountSummary`] from the database
/// 
/// TODO Add a function for pagination
pub async fn search_accounts(pool: &PgPool, master_id: i32, search_term: &String) -> anyhow::Result<Vec<AccountSummary>> {
    let summaries = sqlx::query_as!(AccountSummary,
        "SELECT id, name, description 
        FROM accounts 
        WHERE master_id = $1 AND (name ILIKE $2 OR description ILIKE $2)",
        master_id,
        format!("%{}%", search_term)
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}

/// Updates an account with the given id to the values of the given [`Account`]
/// 
/// Returns an error if the UPDATE query fails
pub async fn update_account(pool: &PgPool, master_id: i32, account: &Account) -> anyhow::Result<()> {
    let query_result = sqlx::query!(
        "UPDATE accounts 
        SET name = $1, username = $2, password = $3, url = $4, description = $5, master_id = $6
        WHERE id = $7 AND master_id = $8",
        account.name,
        account.username,
        account.password,
        account.url,
        account.description,
        account.master_id,
        account.id,
        master_id
    )
    .execute(pool)
    .await?; 

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"))
    }

    Ok(())
}

/// Helper function for [`update_master`]
/// 
/// Reads each input [`ids_and_passwords`] tuple and updates the password for the account with the given id
pub async fn update_accounts_passwords(pool: &PgPool, master_id: i32, ids_and_passwords: &Vec<(i32, String)>) -> anyhow::Result<()> {
    let mut query = String::from("UPDATE accounts SET password = CASE id ");
    let mut ids = Vec::new();

    for (id, new_password) in ids_and_passwords {
        query.push_str(&format!("WHEN {} THEN '{}' ", id, new_password));
        ids.push(id);
    }

    query.push_str("END WHERE master_id = $1 AND id IN (");
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        query.push_str(&id.to_string());
    }
    query.push_str(")");

    let query_result = sqlx::query(&query).bind(master_id).execute(pool).await?;

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"));
    }

    Ok(())
}


// ----------------------------------------------------------------------------
// Masters --------------------------------------------------------------------

/// Adds a [`Master`] account to the database
///
/// Does not hash the password, must be hashed before calling this function
pub async fn add_master(pool: &PgPool, master: &Master) -> anyhow::Result<()> {
    // Master id assigned automatically
    sqlx::query!(
        "INSERT INTO masters (username, password) 
        VALUES ($1, $2)",
        master.username,
        master.password
    )
    .execute(pool)
    .await?; 

    Ok(())
}

/// Returns a [`Master`] account from the database by its id
/// 
/// Password is hashed
pub async fn get_master_by_id(pool: &PgPool, id: i32) -> anyhow::Result<Master> {
    let master = sqlx::query_as!(Master,
        "SELECT id, username, password
        FROM masters WHERE id = $1",
        id
    )
    .fetch_one(pool)
    .await?;

    Ok(master)
}

/// Returns a [`Master`] account from the database by its username
/// 
/// Password is hashed
pub async fn get_master_by_username(pool: &PgPool, username: &String) -> anyhow::Result<Master> {
    let master = sqlx::query_as!(Master,
        "SELECT id, username, password
        FROM masters WHERE username = $1",
        username
    )
    .fetch_one(pool)
    .await?;

    Ok(master)
}

/// Deletes a master account by its id
/// 
/// Returns an error if the DELETE query fails
pub async fn delete_master_by_id(pool: &PgPool, id: i32) -> anyhow::Result<()> {
    match get_master_by_id(pool, id).await {
        Ok(returned_master) => {
            let query_result = sqlx::query!(
                "DELETE FROM masters WHERE id = $1",
                id
            )
            .execute(pool)
            .await?;

            // Sanity check
            if query_result.rows_affected() == 0 {
                return Err(anyhow::anyhow!("DELETE failed: No master account found with ID: {}", id))
            }

            println!("Master account deleted: {:?}", returned_master);
            Ok(())
        },
        Err(err) => {
            println!("No master account found with ID: {}", id);
            Err(err)
        }
    }
}

/// Deletes a master account by its username
/// 
/// Returns an error if the DELETE query fails
pub async fn delete_master_by_username(pool: &PgPool, username: &String) -> anyhow::Result<()> {
    match get_master_by_username(pool, username).await {
        Ok(returned_master) => {
            let query_result = sqlx::query!(
                "DELETE FROM masters WHERE username = $1",
                username
            )
            .execute(pool)
            .await?;

            // Sanity check
            if query_result.rows_affected() == 0 {
                return Err(anyhow::anyhow!("DELETE failed: No master account found with username: {}", username))
            }

            println!("Master account deleted: {:?}", returned_master);
            Ok(())
        },
        Err(err) => {
            println!("No master account found with username: {}", username);
            Err(err)
        }
    }
}

/// Returns a list of all master accounts in the form of
/// [`Master`] from the database
/// 
/// Passwords are hashed
/// 
/// TODO Add a function for pagination
pub async fn list_master_accounts(pool: &PgPool) -> anyhow::Result<Vec<Master>> {
    let summaries = sqlx::query_as!(Master,
        "SELECT id, username, password FROM masters"
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}


/// Updates the master account with the given id of [`old_master`] to the values of [`new_master`]
/// 
/// Updates all accounts associated with [`old_master`].id to use [`new_master`].password
/// 
/// [`old_master`].password and [`new_master`].password must be **plaintext**
///
/// Returns an error if the UPDATE query fails or if the re-encryption of the account passwords fails
///
/// TODO Move this function to client-side; the database should not take in plaintext passwords
pub async fn update_master(pool: &PgPool, old_master: &Master, new_master: &Master) -> anyhow::Result<()> {
    let hashed_password = hash_master_password(&new_master.password).expect("Error hashing password");
    let query_result = sqlx::query!(
        "UPDATE masters 
        SET username = $1, password = $2
        WHERE id = $3",
        new_master.username,
        hashed_password,
        old_master.id // Use old master id, since this is an update
    )
    .execute(pool)
    .await?; 

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"))
    }

    let ids_and_passwords = sqlx::query!(
        "SELECT id, password FROM accounts WHERE master_id = $1",
        old_master.id
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| (row.id, row.password))
    .collect::<Vec<(i32, String)>>();

    let mut ids_and_encrypted_pass = Vec::new();
    for (id, encrypted_password) in ids_and_passwords {
        match reencrypt_password(&old_master.password, &new_master.password, &encrypted_password) {
            Ok(new_encrypted_password) => {
                ids_and_encrypted_pass.push((id, new_encrypted_password));
            }
            Err(e) => {
                eprintln!("Failed to re-encrypt password for account ID {}: {:?}", id, e);
                return Err(anyhow::anyhow!("Failed to re-encrypt password for account ID {}: {:?}", id, e));
            }
        }
    }
    update_accounts_passwords(pool, old_master.id, &ids_and_encrypted_pass).await?;

    Ok(())
}

/// Verifies the master account with the given username and password
/// 
/// password is the plaintext password
pub async fn verify_master(pool: &PgPool, username: &String, password: &String) -> anyhow::Result<bool> {
    let stored_master = get_master_by_username(pool, username).await?;

    if verify_master_password(&stored_master.password, &password){
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Verifies the master account with the given username and password
/// and returns the master account id if successful
/// 
/// password is the plaintext password
pub async fn verify_master_and_get_id(pool: &PgPool, username: &String, password: &String) -> anyhow::Result<i32> {
    let stored_master = get_master_by_username(pool, username).await?;

    if verify_master_password(&stored_master.password, &password){
        Ok(stored_master.id)
    } else {
        Err(anyhow::anyhow!("Failed to verify master account"))
    }
}


/*
    Tests ======================================================================
     ________
    |__   __|      __      
      | | ___  ___| |_ ___ 
      | |/ _ \/ __| __/ __|
      | |  __/\__ \ |_\__ \
      |_|\___||___/\__|___/
    ============================================================================
*/


#[cfg(test)]
mod tests {
    use password_manager_shared::encryption::decrypt_password;

    use crate::test_functions::{create_test_account, setup_database};

    use super::*;

    /// Adds an account to the database and checks if it was added using SQL
    #[tokio::test]
    async fn test_add_account() {
        let (pool, _node) = setup_database().await.unwrap();

        let account = create_test_account();

        let result = add_account(&pool, 1, &account).await;
        assert!(result.is_ok());

        // Check if the account was really added
        let account_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4
            )"
        )
        .bind(&account.name)
        .bind(&account.username)
        .bind(&account.password)
        .bind(account.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account exists");

        assert!(account_exists, "Account was not added");
    }

    /// Adds multiple accounts to the database and checks if they were added using SQL
    #[tokio::test]
    async fn test_add_multiple_accounts() {
        let (pool, _node) = setup_database().await.unwrap();

        let account1 = create_test_account();
        let mut account2 = create_test_account();
        account2.name = "test_account_2".to_string();
        account2.username = "test_user_2".to_string();

        let result1 = add_account(&pool, 1, &account1).await;
        assert!(result1.is_ok());

        let result2 = add_account(&pool, 1, &account2).await;
        assert!(result2.is_ok());

        // Check if the first account was really added
        let account1_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4
            )"
        )
        .bind(&account1.name)
        .bind(&account1.username)
        .bind(&account1.password)
        .bind(account1.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account1 exists");

        assert!(account1_exists, "Account1 was not added");

        // Check if the second account was really added
        let account2_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4
            )"
        )
        .bind(&account2.name)
        .bind(&account2.username)
        .bind(&account2.password)
        .bind(account2.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account2 exists");

        assert!(account2_exists, "Account2 was not added");
    }

    /// Tests the unique constraint violation for name in add_account
    #[tokio::test]
    async fn test_add_account_unique_name_violation() {
        let (pool, _node) = setup_database().await.unwrap();

        let account = create_test_account();

        add_account(&pool, 1, &account).await.expect("Failed to add account");

        let result = add_account(&pool, 1, &account).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Name must be unique");
    }

    /// Tests the foreign key constraint violation for master_id in add_account
    #[tokio::test]
    async fn test_add_account_foreign_key_violation() {
        let (pool, _node) = setup_database().await.unwrap();

        let mut account = create_test_account();
        account.master_id = 999; // Non-existent master_id

        let result = add_account(&pool, 999, &account).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Master ID must exist in the masters table");
    }

    /// Tests the length violation for required fields in add_account
    #[tokio::test]
    async fn test_add_account_length_violation() {
        let (pool, _node) = setup_database().await.unwrap();

        let mut account = create_test_account();
        account.name = "".to_string(); // Name is required

        let result = add_account(&pool, 1, &account).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Name is required");

        account.name = "test_account".to_string();
        account.username = "".to_string(); // Username is required

        let result = add_account(&pool, 1, &account).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Username is required");

        account.username = "test_user".to_string();
        account.password = "".to_string(); // Password is required

        let result = add_account(&pool, 1, &account).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Password is required");
    }

    /// Tests the invalid type for master_id in add_account
    #[tokio::test]
    async fn test_add_account_invalid_master_id_type() {
        let (pool, _node) = setup_database().await.unwrap();

        let mut account = create_test_account();
        account.master_id = "invalid".parse().unwrap_or(0); // Invalid master_id type

        let result = add_account(&pool, 0, &account).await;
        assert!(result.is_err());
    }

    /// Adds an account to the database and checks if it was added using get_account_by_id
    #[tokio::test]
    async fn test_get_account_by_id() {
        let (pool, _node) = setup_database().await.unwrap();

        let account = create_test_account();

        add_account(&pool, 1, &account).await.expect("Failed to add account");

        let fetched_account = get_account_by_id(&pool, 1, 1).await.expect("Failed to get account by id");
        assert_eq!(fetched_account.name, account.name);
        assert_eq!(fetched_account.username, account.username);
        assert_eq!(fetched_account.password, account.password);
        assert_eq!(fetched_account.url, account.url);
        assert_eq!(fetched_account.description, account.description);
        assert_eq!(fetched_account.master_id, account.master_id);
    }

    /// Adds a master to the database and checks if the plaintext password works with verify_master
    #[tokio::test]
    async fn test_verify_master() {
        let (pool, _node) = setup_database().await.unwrap();

        let username = "test_user".to_string();
        let password = "test_password".to_string();

        let master = Master {
            id: 1,
            username: username.clone(),
            password: hash_master_password(&password).expect("Error hashing password"),
        };

        add_master(&pool, &master).await.expect("Failed to add master account");

        let result = verify_master(&pool, &username, &password).await.expect("Failed to verify master account");
        assert!(result);
    }

    /// Adds an account to the database, then updates the default master account. 
    /// Checks if master account was updated and if the account password was re-encrypted
    #[tokio::test]
    async fn test_update_master() {
        let (pool, _node) = setup_database().await.unwrap();

        let account = create_test_account();
        add_account(&pool, 1, &account).await.expect("Failed to add account");

        let old_master = get_master_by_id(&pool, 1).await.expect("Failed to get master by id");

        let old_master_decrypted = Master {
            id: old_master.id,
            username: old_master.username.clone(),
            password: "changethis".to_string()
        };

        let new_master = Master {
            id: 0,
            username: "new_master_username".to_string(),
            password: "new_master_password".to_string(),
        };

        update_master(&pool, &old_master_decrypted, &new_master).await.expect("Failed to update master account");

        let updated_master = get_master_by_id(&pool, old_master.id).await.expect("Failed to get master by id");
        assert_eq!(updated_master.username, new_master.username);

        assert_eq!(verify_master(&pool, &new_master.username, &new_master.password).await.expect("Failed to verify new master account"), true);

        let updated_account = get_account_by_id(&pool, 1, 1).await.expect("Failed to get account by id");
        let decrypted_password = decrypt_password(&new_master.password, &updated_account.password).expect("Failed to decrypt password");
        // Update this value if create_test_account() changes
        assert_eq!(decrypted_password, "test_account_password123!!");
    }
}