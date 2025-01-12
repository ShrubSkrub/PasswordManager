use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPool};
use anyhow;

use password_manager_shared::{encryption::{hash_master_password, verify_master_password, reencrypt_password}, models::{Account, AccountSummary, Master}};
use crate::compile_config::DB_PATH;

pub async fn initialize_db() -> anyhow::Result<PgPool> {
    let options = PgConnectOptions::from_str(DB_PATH)?;
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
pub async fn add_account(pool: &PgPool, account: &Account) -> anyhow::Result<()> {
    // Account id assigned automatically
    sqlx::query!(
        "INSERT INTO accounts (name, username, password, url, description, master_id) 
        VALUES ($1, $2, $3, $4, $5, $6)",
        account.name,
        account.username,
        account.password,
        account.url,
        account.description,
        account.master_id
    )
    .execute(pool)
    .await?; 

    Ok(())
}

/// Retrieves an account from the database by its id
///
/// password returned is base64 encoded and encrypted, must be decoded before use
pub async fn get_account_by_id(pool: &PgPool, id: i32) -> anyhow::Result<Account> {
    let account = sqlx::query_as!(Account,
        "SELECT id, name, username, password, url, description, master_id
        FROM accounts WHERE id = $1",
        id
    )
    .fetch_one(pool)
    .await?;

    Ok(account)
}

pub async fn get_account_by_name(pool: &PgPool, name: &String) -> anyhow::Result<Account> {
    let row = sqlx::query!(
        "SELECT id, name, username, password, url, description, master_id
        FROM accounts WHERE name = $1",
        name
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
pub async fn delete_account_by_id(pool: &PgPool, id: i32) -> anyhow::Result<()> {
    match get_account_by_id(pool, id).await {
        Ok(returned_account) => {
            let query_result = sqlx::query!(
                "DELETE FROM accounts WHERE id = $1",
                id
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
pub async fn delete_account_by_name(pool: &PgPool, name: &String) -> anyhow::Result<()> {
    match get_account_by_name(pool, name).await {
        Ok(returned_account) => {
            let query_result = sqlx::query!(
                "DELETE FROM accounts WHERE name = $1",
                name
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

// TODO Add a function for pagination
pub async fn list_accounts(pool: &PgPool) -> anyhow::Result<Vec<AccountSummary>> {
    // List all account ids, names, and descriptions from the database
    let summaries = sqlx::query_as!(AccountSummary,
        "SELECT id, name, description FROM accounts"
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}

pub async fn search_accounts(pool: &PgPool, search_term: &String) -> anyhow::Result<Vec<AccountSummary>> {
    let summaries = sqlx::query_as!(AccountSummary,
        "SELECT id, name, description 
        FROM accounts 
        WHERE name ILIKE $1 OR description ILIKE $1",
        format!("%{}%", search_term)
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}

pub async fn update_account(pool: &PgPool, account: &Account) -> anyhow::Result<()> {
    let query_result = sqlx::query!(
        "UPDATE accounts 
        SET name = $1, username = $2, password = $3, url = $4, description = $5, master_id = $6
        WHERE id = $7",
        account.name,
        account.username,
        account.password,
        account.url,
        account.description,
        account.master_id,
        account.id
    )
    .execute(pool)
    .await?; 

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"))
    }

    Ok(())
}

async fn update_accounts_passwords(pool: &PgPool, ids_and_passwords: &Vec<(i32, String)>) -> anyhow::Result<()> {
    let mut query = String::from("UPDATE accounts SET password = CASE id ");
    let mut ids = Vec::new();

    for (id, new_password) in ids_and_passwords {
        query.push_str(&format!("WHEN {} THEN '{}' ", id, new_password));
        ids.push(id);
    }

    query.push_str("END WHERE id IN (");
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        query.push_str(&id.to_string());
    }
    query.push_str(")");

    let query_result = sqlx::query(&query).execute(pool).await?;

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"));
    }

    Ok(())
}


// ----------------------------------------------------------------------------
// Masters --------------------------------------------------------------------
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

// TODO Don't return password? Maybe make another struct
pub async fn list_master_accounts(pool: &PgPool) -> anyhow::Result<Vec<Master>> {
    let summaries = sqlx::query_as!(Master,
        "SELECT id, username, password FROM masters"
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}


/// Updates the master account with the given id of old_master to the values of new_master
/// 
/// Updates all accounts associated with the old master account to use the new master account's password
/// 
/// old_master.password and new_master.password should be plaintext
///
/// Returns an error if the UPDATE query fails or if the re-encryption of the account passwords fails
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
    update_accounts_passwords(pool, &ids_and_encrypted_pass).await?;

    Ok(())
}

/// Verifies the master account with the given username and password
/// password is the plaintext password
pub async fn verify_master(pool: &PgPool, username: &String, password: &String) -> anyhow::Result<bool> {
    let stored_master = get_master_by_username(pool, username).await?;

    if verify_master_password(&stored_master.password, &password){
        Ok(true)
    } else {
        Ok(false)
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
    use sqlx::PgPool;
    use testcontainers::ContainerAsync;
    use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};
    use password_manager_shared::{encryption::{decrypt_password, encrypt_password}, models::Account};
    use std::str::FromStr;

    use super::*;

    /// Creates a test account
    /// 
    /// # Returns
    /// 
    /// An `Account` struct with the following fields:
    /// 
    /// ```rust
    /// Account {
    ///     id: 0,
    ///     name: "test_account"
    ///     username: "test_account_username"
    ///     password: "test_account_password123!!" (but encrypted)
    ///     url: Some("http://test.com")
    ///     description: Some("test description")
    ///     master_id: 1,
    /// }
    /// ```
    fn create_test_account() -> Account {
        let password = "test_account_password123!!".to_string();
        // Use the default master password
        let master_password = "changethis".to_string();
        let encrypted_password = encrypt_password(&master_password, &password);
        // Account id is assigned automatically, so 0 is fine
        Account {
            id: 0,
            name: "test_account".to_string(),
            username: "test_account_username".to_string(),
            password: encrypted_password,
            url: Some("http://test.com".to_string()),
            description: Some("test description".to_string()),
            master_id: 1,
        }
    }

    #[tokio::test]
    async fn test_if_testcontainers_modules_works() {
        println!("Starting container");
        let node = postgres::Postgres::default().start().await.unwrap();
        println!("Container started");
        println!("Ip address: {}", node.get_bridge_ip_address().await.unwrap());

        let connection_string = format!(
            "postgres://{user}:{password}@{host}:{port}/{database}",
            user = "postgres",
            password = "postgres",
            host = node.get_host().await.unwrap(),
            port = node.get_host_port_ipv4(5432).await.unwrap(),
            database = "postgres"
        );

        println!("Connection string: {}", connection_string);

        let options = sqlx::postgres::PgConnectOptions::from_str(&connection_string).unwrap();
        let pool = PgPool::connect_with(options).await.unwrap();

        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("Failed to execute query");

        assert_eq!(row.0, 1);

    }

    /// Returns a tuple containing a connection pool and a container
    /// 
    /// Initializes with no accounts in the database
    /// 
    /// Default master account credentials are:
    /// 
    /// * id: 1
    /// * username: "default"
    /// * password: "changethis"
    /// 
    /// Container is returned so it isn't closed due to going out of scope
    async fn setup_database() -> anyhow::Result<(PgPool, ContainerAsync<testcontainers_modules::postgres::Postgres>)> {
        let node = postgres::Postgres::default().start().await.unwrap();
        println!("Ip address: {}", node.get_bridge_ip_address().await.unwrap());
    
        let connection_string = format!(
            "postgres://{user}:{password}@{host}:{port}/{database}",
            user = "postgres",
            password = "postgres",
            host = node.get_host().await.unwrap(),
            port = node.get_host_port_ipv4(5432).await.unwrap(),
            database = "postgres"
        );
    
        println!("Connection string: {}", connection_string);
    
        let options = sqlx::postgres::PgConnectOptions::from_str(&connection_string).unwrap();
        let pool = PgPool::connect_with(options).await.unwrap();

        // From initialize_db(), since it creates its own pool
        // Create tables
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

        println!("Database setup complete");

        // Return the container along with the pool so it isn't dropped
        Ok((pool, node)) 
    }
    
    #[tokio::test]
    async fn test_setup_database() {
        let (pool, _node) = setup_database().await.unwrap();
    
        // Check if can query the database
        let row: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("Failed to execute query");
    
        assert_eq!(row, 1);

        // Check if the accounts table was created
        let accounts_table_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'accounts'
            )"
        )
        .fetch_one(&pool)
        .await
        .expect("Failed to check if accounts table exists");

        assert!(accounts_table_exists, "Accounts table was not created");

        // Check if the masters table was created
        let masters_table_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'masters'
            )"
        )
        .fetch_one(&pool)
        .await
        .expect("Failed to check if masters table exists");

        assert!(masters_table_exists, "Masters table was not created");

        // Check if the default master account was created
        let default_master_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM masters 
            WHERE id = 1 AND username = 'default'
            )"
        )
        .fetch_one(&pool)
        .await
        .expect("Failed to check if default master account exists");

        assert!(default_master_exists, "Default master account was not created");
    }
    
    /// Adds an account to the database and checks if it was added using SQL
    #[tokio::test]
    async fn test_add_account() {
        let (pool, _node) = setup_database().await.unwrap();

        let account = create_test_account();

        let result = add_account(&pool, &account).await;
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

    /// Adds an account to the database and checks if it was added using get_account_by_id
    #[tokio::test]
    async fn test_get_account_by_id() {
        let (pool, _node) = setup_database().await.unwrap();

        let account = create_test_account();

        add_account(&pool, &account).await.expect("Failed to add account");

        let fetched_account = get_account_by_id(&pool, 1).await.expect("Failed to get account by id");
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
        add_account(&pool, &account).await.expect("Failed to add account");

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

        let updated_account = get_account_by_id(&pool, 1).await.expect("Failed to get account by id");
        let decrypted_password = decrypt_password(&new_master.password, &updated_account.password).expect("Failed to decrypt password");
        // Update this value if create_test_account() changes
        assert_eq!(decrypted_password, "test_account_password123!!");
    }


}