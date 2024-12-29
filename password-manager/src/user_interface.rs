use std::io::{self, Write};
use rusqlite::Connection;

fn display_main_menu() {
    println!("Password Manager:");
    println!("1. Add an account");
    println!("2. List accounts");
    println!("3. Retrieve a password");
    println!("4. Exit");
}

pub fn start_ui_loop(conn: Connection) {
    loop {
        display_main_menu();
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
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid option, please try again."),
        }
    }
}

fn get_user_input() -> String {
    print!("Please choose an option: ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn get_master_password() -> String {
    rpassword::prompt_password("Enter master password: ").unwrap()
}

fn handle_add_account(conn: &Connection) {
    println!("Enter account name (identifier): ");
    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    
    unimplemented!()
}

fn handle_list_accounts(conn: &Connection) {
    // List all passwords from the database
    unimplemented!()
}

fn handle_get_account(conn: &Connection) {
    // Get a password by account name
    unimplemented!()
}
