use dotenvy::dotenv;
use reqwest::Client;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use sqlx::PgPool;
use std::collections::HashSet;
use std::env;
use std::str::FromStr;

// Helius API structures - using flexible JSON parsing
type HeliusTransaction = serde_json::Value;
type NativeTransfer = serde_json::Value;
type TokenTransfer = serde_json::Value;

async fn load_tracked_pubkeys(pool: &PgPool) -> anyhow::Result<HashSet<Pubkey>> {
    let rows = sqlx::query!(r#"SELECT publickey FROM "User""#)
        .fetch_all(pool)
        .await?;

    let mut tracked_pubkeys = HashSet::new();
    let mut invalid_pubkeys = Vec::new();

    for row in rows {
        match Pubkey::from_str(&row.publickey) {
            Ok(pubkey) => {
                tracked_pubkeys.insert(pubkey);
            }
            Err(e) => {
                invalid_pubkeys.push((row.publickey, e));
            }
        }
    }

    if !invalid_pubkeys.is_empty() {
        eprintln!(
            "Warning: Found {} invalid public keys in database:",
            invalid_pubkeys.len()
        );
        for (pubkey_str, error) in invalid_pubkeys {
            eprintln!("  - {}: {}", pubkey_str, error);
        }
    }

    Ok(tracked_pubkeys)
}

async fn ensure_sol_asset(pool: &PgPool) -> anyhow::Result<()> {
    const SOL_MINT: &str = "So11111111111111111111111111111111111111112";

    // Check if SOL asset exists
    let exists = sqlx::query!(r#"SELECT id FROM "Asset" WHERE mintAddress = $1"#, SOL_MINT)
        .fetch_optional(pool)
        .await?;

    if exists.is_none() {
        println!("SOL asset not found, creating it...");
        sqlx::query!(
            r#"
            INSERT INTO "Asset" (mintAddress, decimals, name, symbol, logoUrl)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            SOL_MINT,
            9i32,
            "Solana",
            "SOL",
            "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/So11111111111111111111111111111111111111112/logo.png"
        )
        .execute(pool)
        .await?;
        println!("SOL asset created successfully");
    } else {
        println!("SOL asset already exists");
    }

    Ok(())
}

async fn fetch_helius_transactions(
    client: &Client,
    api_key: &str,
    address: &str,
    network: &str,
) -> anyhow::Result<Vec<HeliusTransaction>> {
    let url = format!(
        "https://api.helius.xyz/v0/addresses/{}/transactions?api-key={}&cluster={}",
        address, api_key, network
    );

    println!(
        "Fetching transactions for {} on {}: {}",
        address, network, url
    );

    let response = client.get(&url).send().await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Helius API error: {} - {}",
            status,
            error_text
        ));
    }

    let response_text = response.text().await?;
    println!(
        "Raw Helius API response: {}",
        &response_text[..500.min(response_text.len())]
    );

    let transactions: Vec<HeliusTransaction> = serde_json::from_str(&response_text)?;
    println!("Parsed {} transactions", transactions.len());
    Ok(transactions)
}

async fn fetch_transaction_by_signature(
    client: &Client,
    api_key: &str,
    signature: &str,
    network: &str,
) -> anyhow::Result<Option<HeliusTransaction>> {
    let url = format!(
        "https://api.helius.xyz/v0/transactions?api-key={}&cluster={}&signature={}",
        api_key, network, signature
    );

    println!("Looking up transaction by signature: {}", url);

    let response = client.get(&url).send().await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Helius API error: {} - {}",
            status,
            error_text
        ));
    }

    let response_text = response.text().await?;
    println!(
        "Raw transaction lookup response: {}",
        &response_text[..500.min(response_text.len())]
    );

    let transactions: Vec<HeliusTransaction> = serde_json::from_str(&response_text)?;
    Ok(transactions.into_iter().next())
}

async fn fetch_rpc_transactions(
    rpc_client: &RpcClient,
    address: &Pubkey,
) -> anyhow::Result<Vec<serde_json::Value>> {
    println!("Fetching transactions from Solana RPC for {}", address);

    // Get the current SOL balance from the blockchain
    let current_balance = rpc_client
        .get_balance(address)
        .map_err(|e| anyhow::anyhow!("RPC error getting balance: {}", e))?;

    println!(
        "💰 Current SOL balance for {}: {} lamports",
        address, current_balance
    );

    // Create a single transaction entry that represents the current balance sync
    let mut tx_json = serde_json::Map::new();
    tx_json.insert(
        "signature".to_string(),
        serde_json::Value::String("balance_sync".to_string()),
    );
    tx_json.insert(
        "slot".to_string(),
        serde_json::Value::Number(serde_json::Number::from(0)),
    );
    tx_json.insert(
        "blockTime".to_string(),
        serde_json::Value::Number(serde_json::Number::from(0)),
    );

    // Create a native transfer entry with the current balance
    let mut native_transfers = Vec::new();
    let mut transfer = serde_json::Map::new();
    transfer.insert(
        "fromUserAccount".to_string(),
        serde_json::Value::String(address.to_string()),
    );
    transfer.insert(
        "toUserAccount".to_string(),
        serde_json::Value::String(address.to_string()),
    );
    transfer.insert(
        "amount".to_string(),
        serde_json::Value::Number(serde_json::Number::from(current_balance)),
    );
    native_transfers.push(serde_json::Value::Object(transfer));
    tx_json.insert(
        "nativeTransfers".to_string(),
        serde_json::Value::Array(native_transfers),
    );

    let mut transactions = Vec::new();
    transactions.push(serde_json::Value::Object(tx_json));

    Ok(transactions)
}

async fn process_helius_transaction(
    pool: &PgPool,
    transaction: &HeliusTransaction,
    tracked_pubkeys: &HashSet<Pubkey>,
) -> anyhow::Result<()> {
    // Process native transfers (SOL)
    if let Some(native_transfers) = transaction
        .get("nativeTransfers")
        .and_then(|v| v.as_array())
    {
        for transfer in native_transfers {
            if let (Some(from_pubkey), Some(to_pubkey), Some(amount)) = (
                transfer.get("fromUserAccount").and_then(|v| v.as_str()),
                transfer.get("toUserAccount").and_then(|v| v.as_str()),
                transfer.get("amount").and_then(|v| v.as_u64()),
            ) {
                // Check if either account is tracked
                let from_tracked = Pubkey::from_str(from_pubkey)
                    .ok()
                    .map(|pk| tracked_pubkeys.contains(&pk))
                    .unwrap_or(false);
                let to_tracked = Pubkey::from_str(to_pubkey)
                    .ok()
                    .map(|pk| tracked_pubkeys.contains(&pk))
                    .unwrap_or(false);

                if from_tracked || to_tracked {
                    if amount > 0 {
                        println!(
                            "Processing SOL transfer: {} -> {} ({} lamports)",
                            from_pubkey, to_pubkey, amount
                        );

                        // Check if this is a balance sync (same from/to address)
                        if from_pubkey == to_pubkey {
                            // This is a balance sync, set the balance directly
                            println!(
                                "Syncing SOL balance for {}: {} lamports",
                                from_pubkey, amount
                            );
                            sync_sol_balance(pool, from_pubkey, amount as i64).await?;
                        } else {
                            // This is a real transfer, update balances
                            if from_tracked {
                                update_sol_balance(pool, from_pubkey, -(amount as i64)).await?;
                            }
                            if to_tracked {
                                update_sol_balance(pool, to_pubkey, amount as i64).await?;
                            }
                        }
                    } else {
                        println!(
                            "Skipping zero-amount transfer: {} -> {} ({} lamports)",
                            from_pubkey, to_pubkey, amount
                        );
                    }
                }
            }
        }
    }

    // Process token transfers
    if let Some(token_transfers) = transaction.get("tokenTransfers").and_then(|v| v.as_array()) {
        for transfer in token_transfers {
            if let (Some(from_pubkey), Some(to_pubkey), Some(token_amount), Some(mint)) = (
                transfer.get("fromUserAccount").and_then(|v| v.as_str()),
                transfer.get("toUserAccount").and_then(|v| v.as_str()),
                transfer.get("tokenAmount").and_then(|v| v.as_str()),
                transfer.get("mint").and_then(|v| v.as_str()),
            ) {
                // Check if either account is tracked
                let from_tracked = Pubkey::from_str(from_pubkey)
                    .ok()
                    .map(|pk| tracked_pubkeys.contains(&pk))
                    .unwrap_or(false);
                let to_tracked = Pubkey::from_str(to_pubkey)
                    .ok()
                    .map(|pk| tracked_pubkeys.contains(&pk))
                    .unwrap_or(false);

                if from_tracked || to_tracked {
                    println!(
                        "Processing token transfer: {} -> {} ({} {})",
                        from_pubkey, to_pubkey, token_amount, mint
                    );

                    // Update token balance for the tracked account
                    if from_tracked {
                        update_token_balance(
                            pool,
                            from_pubkey,
                            mint,
                            -(token_amount.parse::<i64>().unwrap_or(0)),
                        )
                        .await?;
                    }
                    if to_tracked {
                        update_token_balance(
                            pool,
                            to_pubkey,
                            mint,
                            token_amount.parse::<i64>().unwrap_or(0),
                        )
                        .await?;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn update_sol_balance(pool: &PgPool, pubkey: &str, amount_change: i64) -> anyhow::Result<()> {
    // Get current balance
    let current_balance = sqlx::query!(
        r#"
        SELECT b.amount
        FROM "Balance" b
        JOIN "User" u ON b.userId = u.id
        JOIN "Asset" a ON b.assetId = a.id
        WHERE u.publickey = $1 AND a.mintAddress = 'So11111111111111111111111111111111111111112'
        "#,
        pubkey
    )
    .fetch_optional(pool)
    .await?
    .map(|row| row.amount)
    .unwrap_or(0);

    let new_balance = (current_balance + amount_change).max(0);

    // Use upsert to create or update balance
    sqlx::query!(
        r#"
        INSERT INTO "Balance" (userId, assetId, amount, createdAt, updatedAt)
        VALUES (
            (SELECT id FROM "User" WHERE publickey = $1),
            (SELECT id FROM "Asset" WHERE mintAddress = 'So11111111111111111111111111111111111111112'),
            $2,
            NOW(),
            NOW()
        )
        ON CONFLICT (userId, assetId)
        DO UPDATE SET amount = $2, updatedAt = NOW()
        "#,
        pubkey,
        new_balance
    )
    .execute(pool)
    .await?;

    println!(
        "Updated SOL balance for {}: {} lamports",
        pubkey, new_balance
    );
    Ok(())
}

async fn sync_sol_balance(pool: &PgPool, pubkey: &str, balance: i64) -> anyhow::Result<()> {
    // Set the balance directly (for balance sync)
    sqlx::query!(
        r#"
        INSERT INTO "Balance" (userId, assetId, amount, createdAt, updatedAt)
        VALUES (
            (SELECT id FROM "User" WHERE publickey = $1),
            (SELECT id FROM "Asset" WHERE mintAddress = 'So11111111111111111111111111111111111111112'),
            $2,
            NOW(),
            NOW()
        )
        ON CONFLICT (userId, assetId)
        DO UPDATE SET amount = $2, updatedAt = NOW()
        "#,
        pubkey,
        balance
    )
    .execute(pool)
    .await?;

    println!("Synced SOL balance for {}: {} lamports", pubkey, balance);
    Ok(())
}

async fn update_token_balance(
    pool: &PgPool,
    pubkey: &str,
    mint: &str,
    amount_change: i64,
) -> anyhow::Result<()> {
    // Ensure asset exists
    let asset_exists = sqlx::query!(r#"SELECT id FROM "Asset" WHERE mintAddress = $1"#, mint)
        .fetch_optional(pool)
        .await?;

    if asset_exists.is_none() {
        // Create asset if it doesn't exist
        sqlx::query!(
            r#"
            INSERT INTO "Asset" (mintAddress, decimals, name, symbol)
            VALUES ($1, $2, $3, $4)
            "#,
            mint,
            6i32, // Default decimals
            "Unknown Token",
            "UNK"
        )
        .execute(pool)
        .await?;
    }

    // Get current balance
    let current_balance = sqlx::query!(
        r#"
        SELECT b.amount
        FROM "Balance" b
        JOIN "User" u ON b.userId = u.id
        JOIN "Asset" a ON b.assetId = a.id
        WHERE u.publickey = $1 AND a.mintAddress = $2
        "#,
        pubkey,
        mint
    )
    .fetch_optional(pool)
    .await?
    .map(|row| row.amount)
    .unwrap_or(0);

    let new_balance = (current_balance + amount_change).max(0);

    sqlx::query!(
        r#"
        UPDATE "Balance"
        SET amount = $1, updatedAt = NOW()
        WHERE userId = (SELECT id FROM "User" WHERE publickey = $2)
        AND assetId = (SELECT id FROM "Asset" WHERE mintAddress = $3)
        "#,
        new_balance,
        pubkey,
        mint
    )
    .execute(pool)
    .await?;

    println!(
        "Updated token balance for {}: {} {}",
        pubkey, new_balance, mint
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    let db_url = env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&db_url).await?;

    let mut tracked_pubkeys = load_tracked_pubkeys(&pool).await?;
    println!(
        "Loaded {} valid tracked pubkeys from DB",
        tracked_pubkeys.len()
    );

    if tracked_pubkeys.is_empty() {
        println!("No users found in database. Indexer will wait for users to be added.");
        println!(
            "You can add users through the backend API, and the indexer will automatically start tracking them."
        );
    }

    // Ensure SOL asset exists in database
    ensure_sol_asset(&pool).await?;

    let helius_api_key = env::var("HELIUS_API_KEY")
        .unwrap_or_else(|_| "63ae33a5-5979-4f58-bca8-9140418a4a8b".to_string());
    let network = env::var("SOLANA_NETWORK").unwrap_or_else(|_| "devnet".to_string());

    // Create HTTP client for Helius API
    let http_client = Client::new();

    // Create RPC client as fallback
    let rpc_url = match network.as_str() {
        "devnet" => "https://api.devnet.solana.com",
        "mainnet-beta" => "https://api.mainnet-beta.solana.com",
        _ => "https://api.devnet.solana.com",
    };
    let rpc_client = RpcClient::new(rpc_url.to_string());

    println!("Starting Helius-based indexer...");
    println!("Using Helius API key: {}...", &helius_api_key[..8]);
    println!("Network: {}", network);

    // Test lookup of the specific transaction signature
    let test_signature =
        "3aPkVkR8fj4qsycKVTaD2BtekbAM1fgfeCrMqdtW3RS2yXDXJxyyS39TsLrs41RA2MdbQbcDsyNrRaVNB68ED3Lb";
    println!(
        "Testing transaction lookup for signature: {}",
        test_signature
    );
    match fetch_transaction_by_signature(&http_client, &helius_api_key, test_signature, &network)
        .await
    {
        Ok(Some(transaction)) => {
            println!("Found transaction by signature!");
            if let Err(e) = process_helius_transaction(&pool, &transaction, &tracked_pubkeys).await
            {
                eprintln!("Error processing test transaction: {}", e);
            }
        }
        Ok(None) => {
            println!("Transaction not found by signature");
        }
        Err(e) => {
            eprintln!("Error looking up transaction by signature: {}", e);
        }
    }

    // Main indexing loop
    let mut last_refresh = std::time::Instant::now();
    let mut last_helius_poll = std::time::Instant::now();
    let refresh_interval = std::time::Duration::from_secs(60); // Refresh every minute
    let helius_poll_interval = std::time::Duration::from_secs(30); // Poll Helius every 30 seconds

    loop {
        // Refresh tracked pubkeys periodically
        if last_refresh.elapsed() >= refresh_interval {
            println!("Refreshing tracked public keys from database...");
            let new_tracked_pubkeys = load_tracked_pubkeys(&pool).await?;
            if new_tracked_pubkeys.len() != tracked_pubkeys.len() {
                println!(
                    "Found {} new public keys to track (total: {})",
                    new_tracked_pubkeys.len() - tracked_pubkeys.len(),
                    new_tracked_pubkeys.len()
                );
                tracked_pubkeys = new_tracked_pubkeys;
            }
            last_refresh = std::time::Instant::now();
        }

        // Poll Helius API for recent transactions
        if last_helius_poll.elapsed() >= helius_poll_interval {
            println!("Polling for recent transactions...");
            for pubkey in &tracked_pubkeys {
                let pubkey_str = pubkey.to_string();

                // Try Helius API first
                let mut transactions = Vec::new();
                match fetch_helius_transactions(
                    &http_client,
                    &helius_api_key,
                    &pubkey_str,
                    &network,
                )
                .await
                {
                    Ok(helius_txs) => {
                        if !helius_txs.is_empty() {
                            println!(
                                "Found {} transactions via Helius for {}",
                                helius_txs.len(),
                                pubkey_str
                            );
                            transactions = helius_txs;
                        } else {
                            println!(
                                "Helius returned empty results for {}, trying RPC fallback...",
                                pubkey_str
                            );
                            // Fallback to RPC
                            match fetch_rpc_transactions(&rpc_client, pubkey).await {
                                Ok(rpc_txs) => {
                                    println!(
                                        "Found {} transactions via RPC for {}",
                                        rpc_txs.len(),
                                        pubkey_str
                                    );
                                    transactions = rpc_txs;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Error fetching RPC transactions for {}: {}",
                                        pubkey_str, e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Error fetching Helius transactions for {}: {}, trying RPC fallback...",
                            pubkey_str, e
                        );
                        // Fallback to RPC
                        match fetch_rpc_transactions(&rpc_client, pubkey).await {
                            Ok(rpc_txs) => {
                                println!(
                                    "Found {} transactions via RPC for {}",
                                    rpc_txs.len(),
                                    pubkey_str
                                );
                                transactions = rpc_txs;
                            }
                            Err(rpc_e) => {
                                eprintln!(
                                    "Error fetching RPC transactions for {}: {}",
                                    pubkey_str, rpc_e
                                );
                            }
                        }
                    }
                }

                // Process all found transactions
                for transaction in &transactions {
                    if let Err(e) =
                        process_helius_transaction(&pool, transaction, &tracked_pubkeys).await
                    {
                        eprintln!("Error processing transaction: {}", e);
                    }
                }
            }
            last_helius_poll = std::time::Instant::now();
        }

        // Sleep for a short interval before next poll
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
