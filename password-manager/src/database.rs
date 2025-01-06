use std::str::FromStr;

use sqlx::prelude::FromRow;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use zeroize::Zeroize;
use anyhow;

use crate::{compile_config::DB_PATH, encryption::{hash_master_password, verify_master_password}};

#[derive(Debug, FromRow)]
pub struct Account {
    pub id: i64,  // SQLite uses `i64` for integer keys
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub description: Option<String>,
}

impl Account {
    pub fn new(name: String, username: String, password: String, url: Option<String>, description: Option<String>) -> Self {
        Account {
            id: 0, // Placeholder value, ID will be assigned automatically
            name,
            username,
            password,
            url,
            description,
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
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
}

// For now, this will be used to define a set of users who are able to access the passwords
// TODO Add a way to match masters to their own accounts
#[derive(Debug, FromRow)]
pub struct Master {
    pub id: i64,
    pub username: String,
    pub password: String
}

impl Master {
    pub fn new(username: String, password: String) -> Self {
        Master {
            id: 0, // Placeholder value, ID will be assigned automatically
            username,
            password
        }
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        self.id.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

pub async fn initialize_db() -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(DB_PATH)?
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = SqlitePool::connect_with(options).await?;

    sqlx::query!(
        "CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            url TEXT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            description TEXT
        )"
    )
    .execute(&pool)
    .await?; 

    sqlx::query!(
        "create table if not exists masters (
            id integer primary key,
            username text not null,
            password text not null
        )"
    )
    .execute(&pool)
    .await?; 

    // Insert the default account only if there are no accounts in the table
    let default_master_password_hash = hash_master_password(&"changethis".to_string()).expect("Error hashing password!");
    sqlx::query!(
        "insert into masters (username, password)
        select 'default', ?
        where not exists (select 1 from masters)",
        default_master_password_hash
    )
    .execute(&pool)
    .await?; 

    Ok(pool)
}

// ----------------------------------------------------------------------------
// Accounts -------------------------------------------------------------------

pub async fn add_account(pool: &SqlitePool, account: &Account) -> anyhow::Result<()> {
    // Account id assigned automatically
    sqlx::query!(
        "INSERT INTO accounts (name, username, password, url, description) 
        VALUES (?1, ?2, ?3, ?4, ?5)",
        account.name,
        account.username,
        account.password,
        account.url,
        account.description
    )
    .execute(pool)
    .await?; 

    Ok(())
}

pub async fn get_account_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<Account> {
    let account = sqlx::query_as!(Account,
        "SELECT id, name, username, password, url, description
        FROM accounts WHERE id = ?",
        id
    )
    .fetch_one(pool)
    .await?;

    Ok(account)
}

pub async fn get_account_by_name(pool: &SqlitePool, name: &String) -> anyhow::Result<Account> {
    let row = sqlx::query!(
        "SELECT id, name, username, password, url, description
        FROM accounts WHERE name = ?",
        name
    )
    .fetch_one(pool)
    .await?;

    let account = Account {
        id: row.id.expect("account.id was null"), // sqlx interprets id as Option
        name: row.name,
        username: row.username,
        password: row.password,
        url: row.url,
        description: row.description,
    };

    Ok(account)
}

// TODO Make return account, and handle printing in user_interface.rs instead
pub async fn delete_account_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    match get_account_by_id(pool, id).await {
        Ok(returned_account) => {
            let query_result = sqlx::query!(
                "DELETE FROM accounts WHERE id = ?",
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
pub async fn delete_account_by_name(pool: &SqlitePool, name: &String) -> anyhow::Result<()> {
    match get_account_by_name(pool, name).await {
        Ok(returned_account) => {
            let query_result = sqlx::query!(
                "DELETE FROM accounts WHERE name = ?",
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
pub async fn list_accounts(pool: &SqlitePool) -> anyhow::Result<Vec<AccountSummary>> {
    // List all account ids, names, and descriptions from the database
    let summaries = sqlx::query_as!(AccountSummary,
        "SELECT id, name, description FROM accounts"
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}

pub async fn search_accounts_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<Vec<AccountSummary>>{
    unimplemented!()
}

pub async fn search_accounts_by_name(pool: &SqlitePool, name: &String) -> anyhow::Result<Vec<AccountSummary>>{
    unimplemented!()
}

pub async fn update_account(pool: &SqlitePool, account: &Account) -> anyhow::Result<()> {
    let query_result = sqlx::query!(
        "UPDATE accounts 
        SET name = ?, username = ?, password = ?, url = ?, description = ? 
        WHERE id = ?",
        account.name,
        account.username,
        account.password,
        account.url,
        account.description,
        account.id
    )
    .execute(pool)
    .await?; 

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"))
    }

    Ok(())
}


// ----------------------------------------------------------------------------
// Masters --------------------------------------------------------------------
pub async fn add_master(pool: &SqlitePool, master: &Master) -> anyhow::Result<()> {
    // Master id assigned automatically
    sqlx::query!(
        "INSERT INTO masters (username, password) 
        VALUES (?, ?)",
        master.username,
        master.password
    )
    .execute(pool)
    .await?; 

    Ok(())
}
pub async fn get_master_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<Master> {
    let master = sqlx::query_as!(Master,
        "SELECT id, username, password
        FROM masters WHERE id = ?",
        id
    )
    .fetch_one(pool)
    .await?;

    Ok(master)
}

pub async fn get_master_by_username(pool: &SqlitePool, username: &String) -> anyhow::Result<Master> {
    let master = sqlx::query_as!(Master,
        "SELECT id, username, password
        FROM masters WHERE username = ?",
        username
    )
    .fetch_one(pool)
    .await?;

    Ok(master)
}

pub async fn delete_master_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    match get_master_by_id(pool, id).await {
        Ok(returned_master) => {
            let query_result = sqlx::query!(
                "DELETE FROM masters WHERE id = ?",
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

pub async fn delete_master_by_username(pool: &SqlitePool, username: &String) -> anyhow::Result<()> {
    match get_master_by_username(pool, username).await {
        Ok(returned_master) => {
            let query_result = sqlx::query!(
                "DELETE FROM masters WHERE username = ?",
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
pub async fn list_master_accounts(pool: &SqlitePool) -> anyhow::Result<Vec<Master>> {
    let summaries = sqlx::query_as!(Master,
        "SELECT id, username, password FROM masters"
    )
    .fetch_all(pool)
    .await?;

    Ok(summaries)
}


pub async fn update_master(pool: &SqlitePool, master: &Master) -> anyhow::Result<()> {
    let query_result = sqlx::query!(
        "UPDATE masters 
        SET username = ?, password = ?
        WHERE id = ?",
        master.username,
        master.password,
        master.id
    )
    .execute(pool)
    .await?; 

    if query_result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("UPDATE failed: Query returned no rows"))
    }

    Ok(())
}

pub async fn verify_master(pool: &SqlitePool, username: &String, password: &String) -> anyhow::Result<bool> {
    let stored_master = get_master_by_username(pool, username).await?;

    if verify_master_password(&stored_master.password, &password){
        Ok(true)
    } else {
        Ok(false)
    }
}