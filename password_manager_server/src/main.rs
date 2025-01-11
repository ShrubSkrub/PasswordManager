mod database;
mod compile_config;
mod routes;

use database::initialize_db;
use std::process;
use actix_web::{web, App, HttpServer};

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

    // Start the Actix web server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(routes::config)
    })
    .bind("127.0.0.1:8080")
    .expect("Cannot bind to port 8080")
    .run()
    .await
    .expect("Failed to run server");
}
