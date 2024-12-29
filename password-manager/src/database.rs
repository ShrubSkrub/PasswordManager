use rusqlite::{Connection, Result, Row};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::compile_config::DB_PATH;

#[derive(Debug)]
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

    // Helper function to map a row to an Account struct
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Account {
            id: row.get(0)?,
            name: row.get(1)?,
            username: row.get(2)?,
            password: row.get(3)?,
            url: row.get(4)?,
            description: row.get(5)?,
        })
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

#[derive(Debug)]
pub struct AccountSummary {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
}

impl AccountSummary {
    // Helper function to map a row to an AccountSummary struct
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(AccountSummary {
            id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?
        })
    }
}

pub fn initialize_db() -> Result<Connection> {
    let conn = Connection::open(DB_PATH)?;

    conn.execute(
        "create table if not exists accounts (
            account integer primary key,
            name text not null unique,
            url text,
            username text not null,
            password text not null,
            description text
        )",
        [],
    )?;

    Ok(conn)
}


pub fn add_account(conn: &Connection, account: &Account) -> Result<()> {
    let sql = "INSERT INTO accounts (name, username, password, url, description) 
                     VALUES (?1, ?2, ?3, ?4, ?5)";

    // Account id assigned automatically
    let params = rusqlite::params![
        account.name,
        account.username,
        account.password,
        account.url,
        account.description
    ];
    conn.execute(sql, params)?;
    Ok(())
}

pub fn get_account_by_id(conn: &Connection, id: i64) -> Result<Account> {
    let sql = "SELECT account, name, username, password, url, description
                     FROM accounts WHERE account = ?1";
    conn.query_row(sql, rusqlite::params![id], |row| {
        Account::from_row(row)
    })
}

pub fn get_account_by_name(conn: &Connection, name: &String) -> Result<Account> {
    let sql = "SELECT account, name, username, password, url, description
                     FROM accounts WHERE name = ?1";
    conn.query_row(sql, rusqlite::params![name], |row| {
        Account::from_row(row)
    })
}

pub fn delete_account_by_id(conn: &Connection, id: i64) -> Result<()> {
    match get_account_by_id(conn, id) {
        Ok(account) => {
            let delete_sql = "DELETE FROM accounts WHERE account = ?1";
            conn.execute(delete_sql, rusqlite::params![id])?;
            
            println!("Account deleted: {:?}", account);
            Ok(())
        },
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            println!("No account found with ID: {}", id);
            Err(rusqlite::Error::QueryReturnedNoRows)
        },
        Err(err) => {
            Err(err)
        }
    }
}

pub fn delete_account_by_name(conn: &Connection, name: &String) -> Result<()> {
    match get_account_by_name(conn, name) {
        Ok(account) => {
            let delete_sql = "DELETE FROM accounts WHERE name = ?1";
            conn.execute(delete_sql, rusqlite::params![name])?;
            
            println!("Account deleted: {:?}", account);
            Ok(())
        },
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            println!("No account found with name: {}", name);
            Err(rusqlite::Error::QueryReturnedNoRows)
        },
        Err(err) => {
            Err(err)
        }
    }
}

// TODO Add a function for pagination
pub fn list_accounts(conn: &Connection) -> Result<Vec<AccountSummary>> {
    // List all account ids, names, and descriptions from the database
    let sql = "SELECT account, name, description FROM accounts";
    let mut stmt = conn.prepare(sql)?;

    let account_iter = stmt.query_map([], |row| AccountSummary::from_row(row))?;

    let mut summaries = Vec::new();
    for account in account_iter {
        summaries.push(account?);
    }

    Ok(summaries)
}

pub fn search_accounts_by_id(conn: &Connection, id: i64) -> Result<Vec<AccountSummary>>{
    unimplemented!()
}

pub fn search_accounts_by_name(conn: &Connection, name: &String) -> Result<Vec<AccountSummary>>{
    unimplemented!()
}
