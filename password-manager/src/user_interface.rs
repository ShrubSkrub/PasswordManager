use std::{io::{self, Write}, process};
use sqlx::postgres::PgPool;

use crate::{compile_config::DEBUG_FLAG, database::{add_account, delete_account_by_id, delete_account_by_name, get_account_by_id, get_account_by_name, get_master_by_username, list_accounts, search_accounts, update_account, update_master, verify_master, Account, AccountSummary, Master}, encryption::{decrypt_password, encrypt_password}};

fn print_separator() {
    println!("------------------------------");
}
fn display_main_menu() {
    println!("==============================");
    println!("Password Manager:");
    println!("1. List accounts");
    println!("2. Search accounts");
    println!("3. Get account details");
    println!("4. Add account");
    println!("5. Update account");
    println!("6. Delete account");
    println!("7. Change master password");
    println!("x. Exit");
}

pub async fn start_ui_loop(pool: &PgPool) {
    let _result = obtain_master_credentials(pool).await;
    loop {
        display_main_menu();

        print!("Please choose an option: ");
        let user_choice = get_user_input().to_lowercase();
        println!("==============================");
        print!("\x1B[2J\x1B[1;1H"); // ANSI escape code to clear the screen

        match user_choice.as_str() {
            "1" | "list" => {
                handle_list_accounts(pool).await;
            }
            "2" | "search" => {
                handle_search_accounts(pool).await;
            }
            "3" | "get" => {
                handle_get_account(pool).await;
            }
            "4" | "add" => {
                handle_add_account(pool).await;
            }
            "5" | "update" => {
                handle_update_account(pool).await;
            }
            "6" | "delete" => {
                handle_delete_account(pool).await;
            }
            "7" | "change" => {
                handle_change_master_password(pool).await;
            }
            "x" | "exit" => {
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

async fn handle_add_account(pool: &PgPool) {
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

    // Encrypt password before adding
    let master = obtain_master_credentials(pool).await;
    let encrypted_password = encrypt_password(&master.password, &password);

    let account = Account::new(name, username, encrypted_password, url, description, master.id);

    match add_account(pool, &account).await {
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

fn print_account_details(account: &Account, master_password: &String) {
    println!("Account Details:");
    println!("ID: {}", account.id);
    println!("Name: {}", account.name);
    println!("Username: {}", account.username);

    // Decrypt password before showing
    let decrypted_password = match decrypt_password(master_password, &account.password) {
        Ok(password) => password,
        Err(err) => {
            println!("Failed to decrypt password: {}", err);
            return;
        }
    };
    println!("Password: {}", decrypted_password);
    match &account.url {
        Some(url) => println!("URL: {}", url),
        None => println!("URL: N/A"),
    }
    match &account.description {
        Some(description) => println!("Description: {}", description),
        None => println!("Description: N/A"),
    }
}

async fn handle_list_accounts(pool: &PgPool) {
    println!("Listing accounts: ");

    match list_accounts(pool).await {
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

async fn handle_get_account(pool: &PgPool) {
    println!("Enter account ID or name:");
    let user_input = get_user_input();

    // Automatically determine if id or name
    if let Ok(id) = user_input.parse::<i32>() {
        match get_account_by_id(pool, id).await {
            Ok(account) => {
                let master = obtain_master_credentials(pool).await;
                print_account_details(&account, &master.password);
            },
            Err(err) => {
                println!("Error fetching account by ID: {}", err);
            }
        }
    } else {
        match get_account_by_name(pool, &user_input).await {
            Ok(account) => {
                let master = obtain_master_credentials(pool).await;
                print_account_details(&account, &master.password);
            },
            Err(err) => {
                println!("Error fetching account by name: {}", err);
            }
        }
    }
}

async fn handle_delete_account(pool: &PgPool) {
    println!("Enter account ID or name:");
    let user_input = get_user_input();

    // Automatically determine if id or name
    if let Ok(id) = user_input.parse::<i32>() {
        match delete_account_by_id(pool, id).await {
            Ok(account) => {
                account
            },
            Err(err) => {
                println!("Error fetching account by ID: {}", err);
            }
        }
    } else {
        match delete_account_by_name(pool, &user_input).await {
            Ok(account) => {
                account
            },
            Err(err) => {
                println!("Error fetching account by name: {}", err);
            }
        }
    }
}

async fn handle_update_account(pool: &PgPool) {
    println!("Enter the account ID or name to update:");

    let input = get_user_input();
    
    match input.parse::<i32>() {
        Ok(id) => {
            match get_account_by_id(pool, id).await {
                Ok(mut account) => {
                    update_account_details(pool, &mut account).await;
                }
                Err(_) => {
                    println!("No account found with ID: {}", id);
                }
            }
        }
        Err(_) => {
            let name = input.trim().to_string();
            match get_account_by_name(pool, &name).await {
                Ok(mut account) => {
                    update_account_details(pool, &mut account).await;
                }
                Err(_) => {
                    println!("No account found with name: {}", name);
                }
            }
        }
    }
}

/// Helper function for handle_update_account()
async fn update_account_details(pool: &PgPool, account: &mut Account) {
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
    let password = get_password();
    let password = if password.is_empty() { account.password.clone() } else { password };

    println!("Enter the new URL (leave empty to keep current):");
    let url = get_user_input();
    let url = if url.is_empty() { account.url.clone() } else { Some(url) };

    println!("Enter the new description (leave empty to keep current):");
    let description = get_user_input();
    let description = if description.is_empty() { account.description.clone() } else { Some(description) };

    // Encrypt password before adding
    let master = obtain_master_credentials(pool).await;
    let encrypted_password = encrypt_password(&master.password, &password);

    let updated_account = Account {
        id: account.id, // Keep the same ID
        name: name,
        username: username,
        password: encrypted_password,
        url: url,
        description: description,
        master_id: account.master_id, // Keep the same master_id
    };

    match update_account(pool, &updated_account).await {
        Ok(_) => {
            println!("Account with ID {} was updated successfully.", updated_account.id);
        }
        Err(e) => {
            println!("Failed to update account with ID {}: {:?}", updated_account.id, e);
        }
    }
}

/// Takes user input
/// 
/// Returns a Master struct
async fn obtain_master_credentials(pool: &PgPool) -> Master {
    let mut attempts = 3;

    loop {
        print!("Enter master username: ");
        let username = get_user_input();

        print!("Enter master password: ");
        let password = get_password();
        
        match verify_master(pool, &username, &password).await {
            Ok(true) => {
                println!("Logging in...");
                let id = get_master_by_username(pool, &username).await.unwrap().id;
                return Master { id, username, password };
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

async fn handle_change_master_password(pool: &PgPool) {
    println!("Login with master account to update:");

    let master_creds = obtain_master_credentials(pool).await;

    match get_master_by_username(pool, &master_creds.username).await {
        Ok(master) => {
            println!("Enter the new username (leave empty to keep current):");
            let input_username = get_user_input();
            let username = if input_username.is_empty() { master.username.clone() } else { input_username };

            println!("Enter the new password:");
            let plaintext_password = get_password();

            let updated_master = Master {
                id: master.id,
                username: username,
                password: plaintext_password
            };

            match update_master(pool, &master_creds, &updated_master).await {
                Ok(_) => {
                    println!("Account with ID {} was updated successfully.", updated_master.id);
                }
                Err(e) => {
                    println!("Failed to update account with ID {}: {:?}", updated_master.id, e);
                }
            }
        }
        Err(_) => {
            println!("No master found with that username: {}", master_creds.username);
        }
    }
}

async fn handle_search_accounts(pool: &PgPool) {
    print!("Enter search term: ");
    let search_query = get_user_input();

    match search_accounts(pool, &search_query).await {
        Ok(results) => {
            for account in results {
                print_account_summary_details(&account);
                print_separator();
            }
        },
        Err(err) => {
            println!("Failed to search accounts: {}", err);
        }
    }
}
