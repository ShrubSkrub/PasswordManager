use actix_web::{body::MessageBody, dev::{ServiceRequest, ServiceResponse}, web, Error, HttpMessage, HttpRequest, HttpResponse, Result};
use actix_service::Service;
use futures::future::{ok, Ready};
use actix_web::middleware::{self, Next};
use actix_web::error::InternalError;
use crate::database;

use sqlx::PgPool;


pub async fn auth_master(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let username = req.headers().get("Username").and_then(|v| v.to_str().ok());
    let password = req.headers().get("Password").and_then(|v| v.to_str().ok());

    // Check if username and password are provided
    if let (Some(username), Some(password)) = (username, password) {
        match database::verify_master_and_get_id(
            req.app_data::<web::Data<PgPool>>().unwrap(),
            &username.to_string(),
            &password.to_string(),
        )
        .await
        {
            Ok(master_id) => {
                // Attach the master ID to the request so it can be used later in routes
                req.extensions_mut().insert(master_id);
                next.call(req).await
            }
            Err(_) => {
                let err = InternalError::from_response(
                    "Invalid credentials",
                    HttpResponse::Unauthorized().finish(),
                );
                Err(err.into())
            }
        }
    } else {
        let err = InternalError::from_response(
            "Missing username or password",
            HttpResponse::Unauthorized().body("Missing username or password"),
        );
        Err(err.into())
    }
}