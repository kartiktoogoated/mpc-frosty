use actix_web::{FromRequest, HttpRequest};
use futures_util::future::{Ready, ready};

pub struct AuthToken(pub String);

impl FromRequest for AuthToken {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        if let Some(hv) = req.headers().get("Authorization") {
            if let Ok(auth_header) = hv.to_str() {
                if auth_header.starts_with("Bearer ") {
                    let token = &auth_header[7..]; 
                    return ready(Ok(AuthToken(token.to_string())));
                }
            }
        }
        ready(Err(actix_web::error::ErrorUnauthorized(
            "Missing or invalid Authorization header",
        )))
    }
}
