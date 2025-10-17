use sqlx::PgPool;
use store::{Store, mpc_key::SaveKeyRequest, mpc_store::MPCStore, user::CreateUserRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let user_pool = PgPool::connect(&std::env::var("USER_DATABASE_URL")?).await?;
    let user_store = Store::new(user_pool);

    let mpc1_pool = PgPool::connect(&std::env::var("MPC1_DATABASE_URL")?).await?;
    let mpc2_pool = PgPool::connect(&std::env::var("MPC2_DATABASE_URL")?).await?;
    let mpc3_pool = PgPool::connect(&std::env::var("MPC3_DATABASE_URL")?).await?;

    let mpc1_store = MPCStore::new(mpc1_pool);
    let mpc2_store = MPCStore::new(mpc2_pool);
    let mpc3_store = MPCStore::new(mpc3_pool);

    let request = CreateUserRequest {
        email: "kartiktomar1212@gmail.com".into(),
        password: "password".into(),
    };
    let user = user_store.create_user(request).await?;
    println!("Created user: {:?}", user);

    let save_req1 = SaveKeyRequest {
        pubkey: "agg_pubkey_123".into(),
        user_email: user.email.clone(),
        node_id: 1,
        key_pkg: vec![1, 2, 3, 4],
    };
    mpc1_store.save_mpc_key(save_req1).await?;

    let save_req2 = SaveKeyRequest {
        pubkey: "agg_pubkey_123".into(),
        user_email: user.email.clone(),
        node_id: 2,
        key_pkg: vec![5, 6, 7, 8],
    };
    mpc2_store.save_mpc_key(save_req2).await?;

    let save_req3 = SaveKeyRequest {
        pubkey: "agg_pubkey_123".into(),
        user_email: user.email,
        node_id: 3,
        key_pkg: vec![9, 10, 11, 12],
    };
    mpc3_store.save_mpc_key(save_req3).await?;

    println!("Saved MPC keys into all 3 MPC DBs");

    Ok(())
}
