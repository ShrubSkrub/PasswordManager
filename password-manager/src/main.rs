mod database;
mod encryption;
mod user_interface;
mod compile_config;

use database::initialize_db;
use user_interface::start_ui_loop;
use std::process;

#[tokio::main]
async fn main() {
    // Initialize the database connection
    let pool = match initialize_db().await {
        Ok(valid_pool) => valid_pool,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            process::exit(1);
        }
    };

    // Start the user interface loop
    start_ui_loop(&pool);
}
