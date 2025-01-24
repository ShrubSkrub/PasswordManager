use actix_web::{body::MessageBody, dev::{ServiceRequest, ServiceResponse}, Error, HttpMessage, HttpResponse, Result};
use actix_web::middleware::Next;
use actix_web::error::InternalError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use password_manager_shared::models::Claims;

pub async fn auth_master(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let authorization = req.headers().get("Authorization").and_then(|v| v.to_str().ok());
    let token = authorization.and_then(|auth| auth.strip_prefix("Bearer "));

    // Check if authorization header is present
    if let Some(token) = token {
        // TODO Update to RSA key pair for DecodingKey
        match jsonwebtoken::decode::<Claims>(&token, &DecodingKey::from_secret("temporary_secret_key".as_ref()), &Validation::new(Algorithm::HS256)) {
            Ok(token) => {
                // Attach the master ID to the request so it can be used later in routes
                req.extensions_mut().insert(token.claims.id);
                next.call(req).await
            }
            Err(jwterr) => {
                let err = InternalError::from_response(
                    format!("Decoding error: {}", jwterr),
                    HttpResponse::Unauthorized().body(format!("Decoding error: {}", jwterr)),
                );
                Err(err.into())
            }
        }
    } else {
        let err = InternalError::from_response(
            "Missing JWT",
            HttpResponse::Unauthorized().body("Missing JWT"),
        );
        Err(err.into())
    }
}