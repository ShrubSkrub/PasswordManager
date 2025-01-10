use std::str::FromStr;

use sqlx::prelude::FromRow;
use sqlx::postgres::{PgConnectOptions, PgPool};
use zeroize::Zeroize;
use anyhow;

use crate::{compile_config::DB_PATH, encryption::{hash_master_password, verify_master_password, reencrypt_password}};

#[derive(Debug, FromRow)]
pub struct Account {
    pub id: i32,  // PostgreSQL uses `i32` for integer keys
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub description: Option<String>,
    pub master_id: i32,
}

impl Account {
    pub fn new(name: String, username: String, password: String, url: Option<String>, description: Option<String>, master_id: i32) -> Self {
        Account {
            id: 0, // Placeholder value, ID will be assigned automatically
            name,
            username,
            password,
            url,
            description,
            master_id,
        }
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();

        if let Some(ref mut url) = self.url {
            url.zeroize();
        }
    }
}

#[derive(Debug, FromRow)]
pub struct AccountSummary {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

// For now, this will be used to define a set of users who are able to access the passwords
// TODO Add a way to match masters to their own accounts
#[derive(Debug, FromRow)]
pub struct Master {
    pub id: i32,
    pub username: String,
    pub password: String
}

// impl Master {
//     pub fn new(username: String, password: String) -> Self {
//         Master {
//             id: 0, // Placeholder value, ID will be assigned automatically
//             username,
//             password
//         }
//     }
// }

impl Drop for Master {
    fn drop(&mut self) {
        self.id.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

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

pub async fn search_accounts_by_id(pool: &PgPool, id: i32) -> anyhow::Result<Vec<AccountSummary>>{
    unimplemented!()
}

pub async fn search_accounts_by_name(pool: &PgPool, name: &String) -> anyhow::Result<Vec<AccountSummary>>{
    unimplemented!()
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

pub async fn update_accounts_passwords(pool: &PgPool, ids_and_passwords: &Vec<(i32, String)>) -> anyhow::Result<()> {
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


pub async fn update_master(pool: &PgPool, old_master: &Master, new_master: &Master) -> anyhow::Result<()> {
    let hashed_password = hash_master_password(&new_master.password).expect("Error hashing password");
    let query_result = sqlx::query!(
        "UPDATE masters 
        SET username = $1, password = $2
        WHERE id = $3",
        new_master.username,
        hashed_password,
        new_master.id
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

pub async fn verify_master(pool: &PgPool, username: &String, password: &String) -> anyhow::Result<bool> {
    let stored_master = get_master_by_username(pool, username).await?;

    if verify_master_password(&stored_master.password, &password){
        Ok(true)
    } else {
        Ok(false)
    }
}