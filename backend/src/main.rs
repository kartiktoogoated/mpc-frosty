use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use sqlx::PgPool;
use std::env;

mod routes;
use routes::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let db_url = "postgres://postgres:postgres@localhost:5432/universal";
    let pool = PgPool::connect(db_url).await.expect("db connect");

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{port}");
    println!("API up at http://{addr}");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(sign_up)
            .service(sign_in)
            .service(get_user)
            .service(quote)
            .service(swap)
            .service(send)
            .service(get_sol_balance)
            .service(get_token_balances)
    })
    .bind(addr)?
    .run()
    .await
}
