mod database;
mod compile_config;

use database::initialize_db;
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

    // TODO Start the server
    unimplemented!()
}
