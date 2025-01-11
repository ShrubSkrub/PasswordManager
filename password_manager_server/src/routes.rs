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
