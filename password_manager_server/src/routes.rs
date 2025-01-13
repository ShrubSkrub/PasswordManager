use actix_web::{web, HttpResponse, Responder, get, post, delete, patch};
use sqlx::PgPool;
use password_manager_shared::models::{Account, Master};
use crate::database;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
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
            .service(add_master)
            .service(get_master_by_id)
            .service(get_master_by_username)
            .service(delete_master_by_id)
            .service(delete_master_by_username)
            .service(list_master_accounts)
            .service(update_master)
            // Health check routes
            .service(health_check)
            .service(db_health_check)
    );
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

#[post("/accounts")]
async fn add_account(pool: web::Data<PgPool>, account: web::Json<Account>) -> impl Responder {
    match database::add_account(&pool, &account).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts/{id}")]
async fn get_account_by_id(pool: web::Data<PgPool>, id: web::Path<i32>) -> impl Responder {
    match database::get_account_by_id(&pool, id.into_inner()).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts/name/{name}")]
async fn get_account_by_name(pool: web::Data<PgPool>, name: web::Path<String>) -> impl Responder {
    match database::get_account_by_name(&pool, &name).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/accounts/{id}")]
async fn delete_account_by_id(pool: web::Data<PgPool>, id: web::Path<i32>) -> impl Responder {
    match database::delete_account_by_id(&pool, id.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/accounts/name/{name}")]
async fn delete_account_by_name(pool: web::Data<PgPool>, name: web::Path<String>) -> impl Responder {
    match database::delete_account_by_name(&pool, &name).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts")]
async fn list_accounts(pool: web::Data<PgPool>) -> impl Responder {
    match database::list_accounts(&pool).await {
        Ok(accounts) => HttpResponse::Ok().json(accounts),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/accounts/search/{term}")]
async fn search_accounts(pool: web::Data<PgPool>, search_term: web::Path<String>) -> impl Responder {
    match database::search_accounts(&pool, &search_term).await {
        Ok(accounts) => HttpResponse::Ok().json(accounts),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[patch("/accounts")]
async fn update_account(pool: web::Data<PgPool>, account: web::Json<Account>) -> impl Responder {
    match database::update_account(&pool, &account).await {
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

    #[macro_export]
    macro_rules! post_response_from_route {
        ($app:expr, $route:expr, $json:expr) => {
            {
                let req = TestRequest::post()
                    .uri($route)
                    .set_json($json)
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
            }
        };
    }
    #[macro_export]
    macro_rules! delete_response_from_route {
        ($app:expr, $route:expr) => {
            {
                let req = TestRequest::delete()
                    .uri($route)
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
            }
        };
    }
    #[macro_export]
    macro_rules! patch_response_from_route {
        ($app:expr, $route:expr, $json:expr) => {
            {
                let req = TestRequest::patch()
                    .uri($route)
                    .set_json($json)
                    .to_request();
        
                // Send the request and check the response
                test::call_service($app, req).await
            }
        };
    }

    #[tokio::test]
    async fn test_db_health_check_route() {
        let (mut app, _pool, _node) = create_test_app!().await;

        let response = get_response_from_route!(&mut app, "/api/db_health");
        
        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = test::read_body(response).await;
        assert_eq!(body, "Database connection is healthy");
    }
    #[tokio::test]
    async fn test_add_account_route() {
        let (mut app, pool, _node) = create_test_app!().await;

        let account = create_test_account();

        let response = post_response_from_route!(&mut app, "/api/accounts", &account);

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

        // First, add a test account
        let account = create_test_account();
        let response = post_response_from_route!(&mut app, "/api/accounts", &account);
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
        let response = delete_response_from_route!(&mut app, &delete_route);

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
}
