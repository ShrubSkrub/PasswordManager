use sqlx::PgPool;
use testcontainers::ContainerAsync;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};
use password_manager_shared::{encryption::{encrypt_password, hash_master_password}, models::Account};
use std::str::FromStr;

/// Creates a test account
/// 
/// # Returns
/// 
/// An `Account` struct with the following fields:
/// 
/// ```rust
/// Account {
///     id: 0,
///     name: "test_account"
///     username: "test_account_username"
///     password: "test_account_password123!!" (but encrypted)
///     url: Some("http://test.com")
///     description: Some("test description")
///     master_id: 1,
/// }
/// ```
pub fn create_test_account() -> Account {
    let password = "test_account_password123!!".to_string();
    // Use the default master password
    let master_password = "changethis".to_string();
    let encrypted_password = encrypt_password(&master_password, &password);
    // Account id is assigned automatically, so 0 is fine
    Account {
        id: 0,
        name: "test_account".to_string(),
        username: "test_account_username".to_string(),
        password: encrypted_password,
        url: Some("http://test.com".to_string()),
        description: Some("test description".to_string()),
        master_id: 1,
    }
}


/// Returns a tuple containing a connection pool and a container
/// 
/// Initializes with no accounts in the database
/// 
/// Default master account credentials are:
/// 
/// * id: 1
/// * username: "default"
/// * password: "changethis"
/// 
/// Container is returned so it isn't closed due to going out of scope
pub async fn setup_database() -> anyhow::Result<(PgPool, ContainerAsync<testcontainers_modules::postgres::Postgres>)> {
    let node = postgres::Postgres::default().start().await.unwrap();
    // println!("Ip address: {}", node.get_bridge_ip_address().await.unwrap());

    let connection_string = format!(
        "postgres://{user}:{password}@{host}:{port}/{database}",
        user = "postgres",
        password = "postgres",
        host = node.get_host().await.unwrap(),
        port = node.get_host_port_ipv4(5432).await.unwrap(),
        database = "postgres"
    );

    // println!("Connection string: {}", connection_string);

    let options = sqlx::postgres::PgConnectOptions::from_str(&connection_string).unwrap();
    let pool = PgPool::connect_with(options).await.unwrap();

    // From initialize_db(), since it creates its own pool
    // Create tables
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

    // println!("Database setup complete");

    // Return the container along with the pool so it isn't dropped
    Ok((pool, node)) 
}

/*
    Tests ======================================================================
     ________
    |__   __|      __      
      | | ___  ___| |_ ___ 
      | |/ _ \/ __| __/ __|
      | |  __/\__ \ |_\__ \
      |_|\___||___/\__|___/
    ============================================================================
*/

#[tokio::test]
async fn test_if_testcontainers_modules_works() {
    println!("Starting container");
    let node = postgres::Postgres::default().start().await.unwrap();
    println!("Container started");
    println!("Ip address: {}", node.get_bridge_ip_address().await.unwrap());

    let connection_string = format!(
        "postgres://{user}:{password}@{host}:{port}/{database}",
        user = "postgres",
        password = "postgres",
        host = node.get_host().await.unwrap(),
        port = node.get_host_port_ipv4(5432).await.unwrap(),
        database = "postgres"
    );

    println!("Connection string: {}", connection_string);

    let options = sqlx::postgres::PgConnectOptions::from_str(&connection_string).unwrap();
    let pool = PgPool::connect_with(options).await.unwrap();

    let row: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("Failed to execute query");

    assert_eq!(row.0, 1);
}

/// Ensure that the database is being set up correctly
#[tokio::test]
async fn test_setup_database() {
    let (pool, _node) = setup_database().await.unwrap();

    // Check if can query the database
    let row: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("Failed to execute query");

    assert_eq!(row, 1);

    // Check if the accounts table was created
    let accounts_table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'accounts'
        )"
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check if accounts table exists");

    assert!(accounts_table_exists, "Accounts table was not created");

    // Check if the masters table was created
    let masters_table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'masters'
        )"
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check if masters table exists");

    assert!(masters_table_exists, "Masters table was not created");

    // Check if the default master account was created
    let default_master_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
        SELECT 1 FROM masters 
        WHERE id = 1 AND username = 'default'
        )"
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check if default master account exists");

    assert!(default_master_exists, "Default master account was not created");
}
