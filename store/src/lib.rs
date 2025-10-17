pub mod mpc_store;
pub mod user;
use sqlx::PgPool;
pub mod mpc_key;
#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
