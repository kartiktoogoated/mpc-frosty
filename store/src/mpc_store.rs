use sqlx::PgPool;

#[derive(Clone)]
pub struct MPCStore {
    pub pool: PgPool,
}

impl MPCStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
