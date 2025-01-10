use user_interface::start_ui_loop;

mod user_interface;
mod compile_config;
use std::process;

#[tokio::main]
async fn main() {
    // Connect to the database
    let pool = match connect_to_db().await {
        Ok(valid_pool) => valid_pool,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            process::exit(1);
        }
    };

    // Start the user interface
    start_ui_loop(&pool).await;
}

async fn connect_to_db() -> Result<sqlx::PgPool, sqlx::Error> {
    let db_url = compile_config::DB_PATH;
    sqlx::PgPool::connect(db_url).await
}