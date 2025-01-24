use actix_web::{delete, get, patch, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use sqlx::PgPool;
use jsonwebtoken::{Header, EncodingKey};

use password_manager_shared::models::{Account, Master, LoginResponse, Claims};
use crate::database;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/status")
            // Health check routes
            .service(health_check)
            .service(db_health_check)
    );
    cfg.service(
        web::scope("/api/auth")
            // Health check routes
            .service(get_jwt_token)
    );
    cfg.service(
        web::scope("/api")
            // Require master authentication for all routes in this scope
            .wrap(actix_web::middleware::from_fn(crate::middleware::auth_master))
            // Accounts routes
            .service(add_account)
            .service(get_account_by_id)
            .service(get_account_by_name)
            .service(delete_account_by_id)
            .service(delete_account_by_name)
            .service(list_accounts)
            .service(search_accounts)
            .service(update_account)
            // Masters routes
            // TODO Split masters routes into their own module with their own authentication middleware
            .service(add_master)
            .service(get_master_by_id)
            .service(get_master_by_username)
            .service(delete_master_by_id)
            .service(delete_master_by_username)
            .service(list_master_accounts)
            .service(update_master)
    );
}

async fn get_master_id_from_token(req: &HttpRequest) -> Result<i32, HttpResponse> {
    match req.extensions().get::<String>() {
        Some(id_str) => match id_str.parse::<i32>() {
            Ok(id) => Ok(id),
            Err(_) => Err(HttpResponse::InternalServerError().body("Invalid master ID format")),
        },
        None => Err(HttpResponse::Unauthorized().body("Unauthorized")),
    }
}

macro_rules! token_to_id {
    ($req:expr) => {
        match get_master_id_from_token(&$req).await {
            Ok(id) => id,
            Err(e) => return e,
        }
    };
}

#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("Server is up")
}

#[get("/db_health")]
async fn db_health_check(pool: web::Data<PgPool>) -> impl Responder {
    match sqlx::query("SELECT 1").execute(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().body("Database connection is healthy"),
        Err(_) => HttpResponse::InternalServerError().body("Failed to connect to the database"),
    }
}


#[get("/token")]
async fn get_jwt_token(req: actix_web::HttpRequest, pool: web::Data<PgPool>) -> impl Responder {
    let username = req.headers().get("Username").and_then(|v| v.to_str().ok());
    let password = req.headers().get("Password").and_then(|v| v.to_str().ok());

    // Check if username and password are provided
    if let (Some(username), Some(password)) = (username, password) {
        match database::verify_master_and_get_id(&pool, &username.to_string(), &password.to_string()).await {
            Ok(master_id) => {
                // Create claims for the JWT
                let claims = Claims {
                    id: master_id.to_string(),
                    exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize, // token expires in 1 hour
                };

                // Encode the claims into a JWT
                // TODO Change the secret key to use AWS Secrets Manager
                // TODO Update to RSA key pair for DecodingKey
                let encoding_key = EncodingKey::from_secret("temporary_secret_key".as_ref());
                match jsonwebtoken::encode(&Header::default(), &claims, &encoding_key) {
                    Ok(token) => {
                        // Return the JWT token in the response
                        let response = LoginResponse { token };
                        return HttpResponse::Ok().json(response);
                    }
                    Err(_) => {
                        return HttpResponse::InternalServerError().body("Failed to generate token");
                    }
                }
            }
            Err(_) => {
                HttpResponse::Unauthorized().body("Invalid credentials")
            }
        }
    } else {
        HttpResponse::Unauthorized().body("Missing username or password")
    }
}

#[post("/accounts")]
async fn add_account(pool: web::Data<PgPool>, account: web::Json<Account>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::add_account(&pool, master_id, &account).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts/{id}")]
async fn get_account_by_id(pool: web::Data<PgPool>, id: web::Path<i32>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::get_account_by_id(&pool, master_id, id.into_inner()).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts/name/{name}")]
async fn get_account_by_name(pool: web::Data<PgPool>, name: web::Path<String>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::get_account_by_name(&pool, master_id, &name).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/accounts/{id}")]
async fn delete_account_by_id(pool: web::Data<PgPool>, id: web::Path<i32>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::delete_account_by_id(&pool, master_id, id.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/accounts/name/{name}")]
async fn delete_account_by_name(pool: web::Data<PgPool>, name: web::Path<String>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::delete_account_by_name(&pool, master_id, &name).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts")]
async fn list_accounts(pool: web::Data<PgPool>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::list_accounts(&pool, master_id).await {
        Ok(accounts) => HttpResponse::Ok().json(accounts),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts/search/{term}")]
async fn search_accounts(pool: web::Data<PgPool>, search_term: web::Path<String>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::search_accounts(&pool, master_id, &search_term).await {
        Ok(accounts) => HttpResponse::Ok().json(accounts),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[patch("/accounts")]
async fn update_account(pool: web::Data<PgPool>, account: web::Json<Account>, req: HttpRequest) -> impl Responder {
    let master_id = token_to_id!(req);
    match database::update_account(&pool, master_id, &account).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/masters")]
async fn add_master(pool: web::Data<PgPool>, master: web::Json<Master>) -> impl Responder {
    match database::add_master(&pool, &master).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/masters/{id}")]
async fn get_master_by_id(pool: web::Data<PgPool>, id: web::Path<i32>) -> impl Responder {
    match database::get_master_by_id(&pool, id.into_inner()).await {
        Ok(master) => HttpResponse::Ok().json(master),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/masters/username/{username}")]
async fn get_master_by_username(pool: web::Data<PgPool>, username: web::Path<String>) -> impl Responder {
    match database::get_master_by_username(&pool, &username).await {
        Ok(master) => HttpResponse::Ok().json(master),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/masters/{id}")]
async fn delete_master_by_id(pool: web::Data<PgPool>, id: web::Path<i32>) -> impl Responder {
    match database::delete_master_by_id(&pool, id.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/masters/username/{username}")]
async fn delete_master_by_username(pool: web::Data<PgPool>, username: web::Path<String>) -> impl Responder {
    match database::delete_master_by_username(&pool, &username).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/masters")]
async fn list_master_accounts(pool: web::Data<PgPool>) -> impl Responder {
    match database::list_master_accounts(&pool).await {
        Ok(masters) => HttpResponse::Ok().json(masters),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[patch("/masters")]
async fn update_master(_pool: web::Data<PgPool>, _master: web::Json<Master>) -> impl Responder {
    HttpResponse::NotImplemented().body("Unimplemented!")
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

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use actix_web::{web, App};
    use actix_web::test::{self, TestRequest};
    use password_manager_shared::models::AccountSummary;

    use super::*;
    use crate::test_functions::{create_test_account, setup_database};

    /// Creates a test instance Actix web application
    /// 
    /// Not an actual http server, but a test instance of the Actix web application
    #[macro_export]
    macro_rules! create_test_app {
        () => {{
            async {
                // Set up the database pool
                let (pool, node) = setup_database().await.unwrap();
        
                // Create the Actix web application
                let app = App::new()
                    .app_data(web::Data::new(pool.clone()))
                    .configure(config);
        
                // Initialize the service
                let app_service = test::init_service(app).await;

                // Return the node so it isn't dropped, which would stop the container
                (app_service, pool, node)

            }
        }};
    }

    /// For getting JWT token for master
    /// 
    /// If no username and password are provided, default master credentials are used
    #[macro_export]
    macro_rules! get_jwt_token_from_route {
        ($app:expr, $route:expr) => {
            {
                let req = TestRequest::get()
                    .uri($route)
                    .append_header(("Username", "default"))
                    .append_header(("Password", "changethis"))
                    .to_request();
        
                // Send the request and check the response
                let response = test::call_service($app, req).await;
                let body: LoginResponse = test::read_body_json(response).await;
                body.token
            }
        };
        ($app:expr, $route:expr, $username:expr, $password:expr) => {
            {
                let req = TestRequest::get()
                    .uri($route)
                    .append_header(("Username", $username))
                    .append_header(("Password", $password))
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
                let body: LoginResponse = test::read_body_json(response).await;
                body.token
            }
        };
    }

    #[macro_export]
    macro_rules! response_from_route {
        ($type:ident, $app:expr, $route:expr, $token:expr) => {
            {
                let req = TestRequest::$type()
                    .uri($route)
                    .append_header(("Authorization", format!("Bearer {}", $token)))
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
            }
        };
        ($type:ident, $app:expr, $route:expr, $token:expr, $json:expr) => {
            {
                let req = TestRequest::$type()
                    .uri($route)
                    .append_header(("Authorization", format!("Bearer {}", $token)))
                    .set_json($json)
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
            }
        };
    }

    #[macro_export]
    macro_rules! get_response_from_route {
        ($app:expr, $route:expr) => {
            {
                let req = TestRequest::get()
                    .uri($route)
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
            }
        };
    }

    #[tokio::test]
    async fn test_db_health_check_route() {
        let (mut app, _pool, _node) = create_test_app!().await;

        let response = get_response_from_route!(&mut app, "/api/status/db_health");
        
        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = test::read_body(response).await;
        assert_eq!(body, "Database connection is healthy");
    }

    #[tokio::test]
    async fn test_health_check_route() {
        let (mut app, _pool, _node) = create_test_app!().await;

        let response = get_response_from_route!(&mut app, "/api/status/health");

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = test::read_body(response).await;
        assert_eq!(body, "Server is up");
    }

    #[tokio::test]
    async fn test_jwt_route() {
        let (mut app, _pool, _node) = create_test_app!().await;

        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        println!("Token: {}", token);

        // TODO Update to RSA key pair for DecodingKey
        let token_message = jsonwebtoken::decode::<Claims>(&token, &jsonwebtoken::DecodingKey::from_secret("temporary_secret_key".as_ref()), &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256)).expect("Failed to decode the JWT token");
        println!("Token Claims id: {}", token_message.claims.id);
        assert_eq!(token_message.claims.id, "1");

        // TODO Test another master for different id
    }

    #[tokio::test]
    async fn test_add_account_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        let account = create_test_account();

        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the account was really added
        let account_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4
            )"
        )
        .bind(&account.name)
        .bind(&account.username)
        .bind(&account.password)
        .bind(account.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account exists");

        assert!(account_exists, "Account was not added");
    }

    #[tokio::test]
    async fn test_delete_account_by_id_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test account
        let account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // Get the account ID
        let account_id: i32 = sqlx::query_scalar(
            "SELECT id FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4"
        )
        .bind(&account.name)
        .bind(&account.username)
        .bind(&account.password)
        .bind(account.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get account ID");

        // Delete the account by ID
        let delete_route = format!("/api/accounts/{}", account_id);
        let response = response_from_route!(delete, &mut app, &delete_route, token);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the account was really deleted
        let account_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE id = $1
            )"
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account exists");

        assert!(!account_exists, "Account was not deleted");
    }

    #[tokio::test]
    async fn test_add_multiple_accounts_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        let account1 = create_test_account();
        let mut account2 = create_test_account();
        account2.name = "test_account_2".to_string();
        account2.username = "test_user_2".to_string();

        let response1 = response_from_route!(post, &mut app, "/api/accounts", token, &account1);
        let response2 = response_from_route!(post, &mut app, "/api/accounts", token, &account2);

        // Assert the status codes
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);

        // Check if the first account was really added
        let account1_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4
            )"
        )
        .bind(&account1.name)
        .bind(&account1.username)
        .bind(&account1.password)
        .bind(account1.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account1 exists");

        assert!(account1_exists, "Account1 was not added");

        // Check if the second account was really added
        let account2_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4
            )"
        )
        .bind(&account2.name)
        .bind(&account2.username)
        .bind(&account2.password)
        .bind(account2.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account2 exists");

        assert!(account2_exists, "Account2 was not added");
    }

    #[tokio::test]
    async fn test_get_account_by_id_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test account
        let account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // Get the account ID
        let account_id: i32 = sqlx::query_scalar(
            "SELECT id FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4"
        )
        .bind(&account.name)
        .bind(&account.username)
        .bind(&account.password)
        .bind(account.master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to get account ID");

        // Get the account by ID
        let get_route = format!("/api/accounts/{}", account_id);
        let response = response_from_route!(get, &mut app, &get_route, token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Account = test::read_body_json(response).await;
        assert_eq!(body.name, account.name);
        assert_eq!(body.username, account.username);
        assert_eq!(body.password, account.password);
        assert_eq!(body.master_id, account.master_id);
    }

    #[tokio::test]
    async fn test_get_account_by_name_route() {
        let (mut app, _pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test account
        let account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // Get the account by name
        let get_route = format!("/api/accounts/name/{}", account.name);
        let response = response_from_route!(get, &mut app, &get_route, token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Account = test::read_body_json(response).await;
        assert_eq!(body.name, account.name);
        assert_eq!(body.username, account.username);
        assert_eq!(body.password, account.password);
        assert_eq!(body.master_id, account.master_id);
    }

    #[tokio::test]
    async fn test_delete_account_by_name_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test account
        let account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // Delete the account by name
        let delete_route = format!("/api/accounts/name/{}", account.name);
        let response = response_from_route!(delete, &mut app, &delete_route, token);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the account was really deleted
        let account_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM accounts 
            WHERE name = $1
            )"
        )
        .bind(&account.name)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if account exists");

        assert!(!account_exists, "Account was not deleted");
    }

    #[tokio::test]
    async fn test_list_accounts_route() {
        let (mut app, _pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // Add a test account
        let account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // List accounts
        let response = response_from_route!(get, &mut app, "/api/accounts", token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Vec<AccountSummary> = test::read_body_json(response).await;
        assert!(!body.is_empty(), "No accounts found");
    }

    #[tokio::test]
    async fn test_search_accounts_route() {
        let (mut app, _pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // Add a test account
        let account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // Search accounts
        let search_term = "test";
        let search_route = format!("/api/accounts/search/{}", search_term);
        let response = response_from_route!(get, &mut app, &search_route, token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Vec<AccountSummary> = test::read_body_json(response).await;
        assert!(!body.is_empty(), "No accounts found");
    }

    #[tokio::test]
    async fn test_update_account_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // Add a test account
        let mut account = create_test_account();
        let response = response_from_route!(post, &mut app, "/api/accounts", token, &account);
        assert_eq!(response.status(), StatusCode::OK);

        // Update the account
        account.username = "updated_user".to_string();
        account.id = 1;
        let response = response_from_route!(patch, &mut app, "/api/accounts", token, &account);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the account was really updated
        let updated_account: Account = sqlx::query_as!(Account,
            "SELECT * FROM accounts 
            WHERE name = $1 AND username = $2 AND password = $3 AND master_id = $4",
            account.name,
            account.username,
            account.password,
            account.master_id
        )
        .fetch_one(&pool)
        .await
        .expect("Failed to get updated account");

        assert_eq!(updated_account.username, "updated_user");
    }

    #[tokio::test]
    async fn test_add_master_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        let master = Master {
            id: 0,
            username: "test_master".to_string(),
            password: "test_password".to_string(),
        };

        let response = response_from_route!(post, &mut app, "/api/masters", token, &master);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the master was really added
        let master_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM masters 
            WHERE username = $1 AND password = $2
            )"
        )
        .bind(&master.username)
        .bind(&master.password)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if master exists");

        assert!(master_exists, "Master was not added");
    }

    #[tokio::test]
    async fn test_get_master_by_id_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test master
        let master = Master {
            id: 0,
            username: "test_master".to_string(),
            password: "test_password".to_string(),
        };
        let response = response_from_route!(post, &mut app, "/api/masters", token, &master);
        assert_eq!(response.status(), StatusCode::OK);

        // Get the master ID
        let master_id: i32 = sqlx::query_scalar(
            "SELECT id FROM masters 
            WHERE username = $1 AND password = $2"
        )
        .bind(&master.username)
        .bind(&master.password)
        .fetch_one(&pool)
        .await
        .expect("Failed to get master ID");

        // Get the master by ID
        let get_route = format!("/api/masters/{}", master_id);
        let response = response_from_route!(get, &mut app, &get_route, token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Master = test::read_body_json(response).await;
        assert_eq!(body.username, master.username);
        assert_eq!(body.password, master.password);
    }

    #[tokio::test]
    async fn test_get_master_by_username_route() {
        let (mut app, _pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test master
        let master = Master {
            id: 0,
            username: "test_master".to_string(),
            password: "test_password".to_string(),
        };
        let response = response_from_route!(post, &mut app, "/api/masters", token, &master);
        assert_eq!(response.status(), StatusCode::OK);

        // Get the master by username
        let get_route = format!("/api/masters/username/{}", master.username);
        let response = response_from_route!(get, &mut app, &get_route, token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Master = test::read_body_json(response).await;
        assert_eq!(body.username, master.username);
        assert_eq!(body.password, master.password);
    }

    #[tokio::test]
    async fn test_delete_master_by_id_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test master
        let master = Master {
            id: 0,
            username: "test_master".to_string(),
            password: "test_password".to_string(),
        };
        let response = response_from_route!(post, &mut app, "/api/masters", token, &master);
        assert_eq!(response.status(), StatusCode::OK);

        // Get the master ID
        let master_id: i32 = sqlx::query_scalar(
            "SELECT id FROM masters 
            WHERE username = $1 AND password = $2"
        )
        .bind(&master.username)
        .bind(&master.password)
        .fetch_one(&pool)
        .await
        .expect("Failed to get master ID");

        // Delete the master by ID
        let delete_route = format!("/api/masters/{}", master_id);
        let response = response_from_route!(delete, &mut app, &delete_route, token);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the master was really deleted
        let master_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM masters 
            WHERE id = $1
            )"
        )
        .bind(master_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if master exists");

        assert!(!master_exists, "Master was not deleted");
    }

    #[tokio::test]
    async fn test_delete_master_by_username_route() {
        let (mut app, pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // First, add a test master
        let master = Master {
            id: 0,
            username: "test_master".to_string(),
            password: "test_password".to_string(),
        };
        let response = response_from_route!(post, &mut app, "/api/masters", token, &master);
        assert_eq!(response.status(), StatusCode::OK);

        // Delete the master by username
        let delete_route = format!("/api/masters/username/{}", master.username);
        let response = response_from_route!(delete, &mut app, &delete_route, token);

        // Assert the status code
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the master was really deleted
        let master_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
            SELECT 1 FROM masters 
            WHERE username = $1
            )"
        )
        .bind(&master.username)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if master exists");

        assert!(!master_exists, "Master was not deleted");
    }

    #[tokio::test]
    async fn test_list_master_accounts_route() {
        let (mut app, _pool, _node) = create_test_app!().await;
        let token = get_jwt_token_from_route!(&mut app, "/api/auth/token");

        // Add a test master
        let master = Master {
            id: 0,
            username: "test_master".to_string(),
            password: "test_password".to_string(),
        };
        let response = response_from_route!(post, &mut app, "/api/masters", token, &master);
        assert_eq!(response.status(), StatusCode::OK);

        // List masters
        let response = response_from_route!(get, &mut app, "/api/masters", token);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body: Vec<Master> = test::read_body_json(response).await;
        assert!(!body.is_empty(), "No masters found");
    }
}
