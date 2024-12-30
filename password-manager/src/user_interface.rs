use std::{io::{self, Write}, process};
use rusqlite::{Connection, Result, Row};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{compile_config::DEBUG_FLAG, database::{add_account, delete_account_by_id, delete_account_by_name, get_account_by_id, get_account_by_name, list_accounts, update_account, verify_master, Account, AccountSummary}};

fn print_separator() {
    println!("------------------------------");
}
fn display_main_menu() {
    print_separator();
    println!("Password Manager:");
    println!("1. Add an account");
    println!("2. List accounts");
    println!("3. Retrieve an account");
    println!("4. Update an account");
    println!("5. Delete an account");
    println!("6. Change master password");
    println!("x. Exit");
}

pub fn start_ui_loop(conn: Connection) {
    handle_verify_master(&conn);
    loop {
        display_main_menu();

        print!("Please choose an option: ");
        let user_choice = get_user_input();

        match user_choice.as_str() {
            "1" => {
                handle_add_account(&conn);
            }
            "2" => {
                handle_list_accounts(&conn);
            }
            "3" => {
                handle_get_account(&conn);
            }
            "4" => {
                handle_update_account(&conn);
            }
            "5" => {
                handle_delete_account(&conn);
            }
            "6" => {
                handle_change_master_password(&conn);
            }
            "x" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid option, please try again."),
        }
    }
}

fn get_user_input() -> String {
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn get_password() -> String {
    if DEBUG_FLAG {
        get_user_input()
    } else {
        io::stdout().flush().unwrap();
        rpassword::read_password().unwrap()
    }
}

fn handle_add_account(conn: &Connection) {
    println!("Enter account name (ie. Google, X, Discord): ");
    let name = get_user_input();

    println!("(Optional) Enter url for account (ie. google.com, x.com, login.live.com): ");
    let url_input = get_user_input();
    // If the user enters an empty string, set url to None
    let url = if url_input.is_empty() { None } else { Some(url_input) };

    println!("Enter username: ");
    let username = get_user_input();
    
    println!("Enter password: ");
    let password = get_password();

    println!("(Optional) Enter description for account: ");
    let description_input = get_user_input();
    // If the user enters an empty string, set description to None
    let description = if description_input.is_empty() { None } else { Some(description_input) };

    // TODO Encrypt username and password before adding
    let account = Account::new(name, username, password, url, description);

    match add_account(conn, &account) {
        Ok(_result) => { ()
        },
        Err(err) => {
            println!("Failed to list accounts: {}", err);
        }
    }
}

fn print_account_summary_details(account: &AccountSummary) {
    println!("Account ID: {}", account.id);
    println!("Name: {}", account.name);
    match &account.description {
        Some(desc) => println!("Description: {}", desc),
        None => println!("Description: N/A"),
    }
}

fn print_account_details(account: &Account) {
    println!("Account Details:");
    println!("ID: {}", account.id);
    println!("Name: {}", account.name);
    println!("Username: {}", account.username);
    println!("Password: {}", account.password);
    match &account.url {
        Some(url) => println!("URL: {}", url),
        None => println!("URL: N/A"),
    }
    match &account.description {
        Some(description) => println!("Description: {}", description),
        None => println!("Description: N/A"),
    }
}

fn handle_list_accounts(conn: &Connection) {
    println!("Listing accounts: ");

    match list_accounts(conn) {
        Ok(results) => {
            for account in results {
                print_account_summary_details(&account);
                print_separator();
            }
        },
        Err(err) => {
            println!("Failed to list accounts: {}", err);
        }
    }
}

fn handle_get_account(conn: &Connection) {
    println!("Enter account ID or name:");
    let user_input = get_user_input();

    // Automatically determine if id or name
    if let Ok(id) = user_input.parse::<i64>() {
        match get_account_by_id(conn, id) {
            Ok(account) => {
                print_account_details(&account);
            },
            Err(err) => {
                println!("Error fetching account by ID: {}", err);
            }
        }
    } else {
        match get_account_by_name(conn, &user_input) {
            Ok(account) => {
                print_account_details(&account);
            },
            Err(err) => {
                println!("Error fetching account by name: {}", err);
            }
        }
    }
}

fn handle_delete_account(conn: &Connection) {
    println!("Enter account ID or name:");
    let user_input = get_user_input();

    // Automatically determine if id or name
    if let Ok(id) = user_input.parse::<i64>() {
        match delete_account_by_id(conn, id) {
            Ok(account) => {
                account
            },
            Err(err) => {
                println!("Error fetching account by ID: {}", err);
            }
        }
    } else {
        match delete_account_by_name(conn, &user_input) {
            Ok(account) => {
                account
            },
            Err(err) => {
                println!("Error fetching account by name: {}", err);
            }
        }
    }
}

fn handle_update_account(conn: &Connection) {
    println!("Enter the account ID or name to update:");

    let input = get_user_input();
    
    match input.parse::<i64>() {
        Ok(id) => {
            match get_account_by_id(conn, id) {
                Ok(mut account) => {
                    update_account_details(conn, &mut account);
                }
                Err(_) => {
                    println!("No account found with ID: {}", id);
                }
            }
        }
        Err(_) => {
            let name = input.trim().to_string();
            match get_account_by_name(conn, &name) {
                Ok(mut account) => {
                    update_account_details(conn, &mut account);
                }
                Err(_) => {
                    println!("No account found with name: {}", name);
                }
            }
        }
    }
}

// Helper function for handle_update_account()
fn update_account_details(conn: &Connection, account: &mut Account) {
    println!("\nCurrent account details:");
    println!("Name: {}", account.name);
    println!("Username: {}", account.username);
    if let Some(url) = &account.url {
        println!("URL: {}", url);
    } else {
        println!("URL: N/A");
    }
    if let Some(description) = &account.description {
        println!("Description: {}", description);
    } else {
        println!("Description: N/A");
    }

    // Step 3: Ask for new values
    println!("\nEnter the new account name (leave empty to keep current):");
    let name = get_user_input();
    let name = if name.is_empty() { account.name.clone() } else { name };

    println!("Enter the new username (leave empty to keep current):");
    let username = get_user_input();
    let username = if username.is_empty() { account.username.clone() } else { username };

    println!("Enter the new password (leave empty to keep current):");
    let password = get_user_input();
    let password = if password.is_empty() { account.password.clone() } else { password };

    println!("Enter the new URL (leave empty to keep current):");
    let url = get_user_input();
    let url = if url.is_empty() { account.url.clone() } else { Some(url) };

    println!("Enter the new description (leave empty to keep current):");
    let description = get_user_input();
    let description = if description.is_empty() { account.description.clone() } else { Some(description) };

    let updated_account = Account {
        id: account.id, // Keep the same ID
        name,
        username,
        password,
        url,
        description,
    };

    match update_account(conn, &updated_account) {
        Ok(_) => {
            println!("Account with ID {} was updated successfully.", updated_account.id);
        }
        Err(e) => {
            println!("Failed to update account with ID {}: {:?}", updated_account.id, e);
        }
    }
}

fn handle_verify_master(conn: &Connection) {
    let mut attempts = 3;

    loop {
        print!("Enter master username: ");
        let username = get_user_input();
        print!("Enter master password: ");
        let password = get_password();

        match verify_master(conn, &username, &password) {
            Ok(true) => {
                println!("Logging in...");
                break;
            },
            Ok(false) | Err(_) => {
                attempts -= 1;
                if attempts <= 0 {
                    println!("Max attempts reached. Exiting...");
                    process::exit(1);
                }
                println!("Invalid credentials. Please try again. {} attempts remaining", attempts);
            }
        }
    }
}

fn handle_change_master_password(conn: &Connection) {
    unimplemented!()
}
