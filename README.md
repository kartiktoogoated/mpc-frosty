# Solana MPC Trading Platform

A complete Solana trading platform with Multi-Party Computation (MPC) signing, real-time balance indexing, and Jupiter DEX integration.

## 🚀 Features

- **MPC Authentication**: 3-party threshold signature scheme for secure key management
- **Real-time Indexing**: Yellowstone gRPC integration for live balance updates
- **Jupiter Integration**: Token swaps with 0.5% slippage protection
- **RESTful API**: Complete trading and balance management endpoints
- **PostgreSQL**: Robust database with proper migrations and relationships

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Backend API   │    │   Indexer       │    │   MPC Nodes     │
│   (Port 3000)   │    │   (Yellowstone) │    │   (8081-8083)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   PostgreSQL    │
                    │   (Port 5432)   │
                    └─────────────────┘
```

## 📊 Database Schema

### Core Tables
- **User**: User accounts with MPC public keys
- **Asset**: Token definitions (SOL, USDC, etc.)
- **Balance**: User token balances (real-time updated)

### MPC Tables
- **mpc_keys**: Distributed key storage across 3 nodes
- **dkg_state**: Distributed key generation state

## 🛠️ Setup

### Prerequisites
- Rust 1.70+
- PostgreSQL 15+
- Docker & Docker Compose

### 1. Database Setup
```bash
# Start PostgreSQL with Docker
docker-compose up -d

# Create main database
createdb universal

# Run migrations
cd store && sqlx migrate run
```

### 2. Environment Variables
Create `.env` files in each service directory:

**Backend (.env)**
```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/universal
JWT_SECRET=your-secret-key
```

**Indexer (.env)**
```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/universal
YELLOWSTONE_ENDPOINT=https://solana-rpc.parafi.tech:10443
QUICKNODE_TOKEN=your-token
```

### 3. Build & Run
```bash
# Build all services
cargo build

# Start MPC nodes (3 terminals)
cargo run --bin mpc

# Start indexer
cargo run --bin indexer

# Start backend
cargo run --bin backend
```

## 📡 API Endpoints

### Authentication
- `POST /api/v1/signup` - Register user with MPC key generation
- `POST /api/v1/signin` - Authenticate and get JWT token
- `GET /api/v1/user` - Get user profile (requires auth)

### Trading
- `POST /api/v1/quote` - Get swap quotes via Jupiter
- `POST /api/v1/swap` - Execute token swaps with MPC signing

### Transfers
- `POST /api/v1/send` - Send SOL/tokens using MPC signing

### Balances
- `GET /api/v1/balance/sol` - Get SOL balance
- `GET /api/v1/balance/tokens` - Get all token balances

## 🔐 MPC Security

- **3-Party Threshold**: Requires 2 of 3 nodes to sign transactions
- **DKG Protocol**: Distributed key generation during signup
- **State Persistence**: DKG state saved across all nodes
- **FROST Signatures**: Ed25519 threshold signatures

## 📈 Real-time Indexing

- **Yellowstone gRPC**: Live Solana account updates
- **Automatic Balance Updates**: Real-time balance tracking
- **Reconnection Logic**: Robust connection handling
- **SOL Asset Management**: Automatic SOL asset creation

## 🧪 Testing

### Test User Registration
```bash
curl -X POST http://localhost:3000/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "test@example.com", "password": "testpass123"}'
```

### Test Authentication
```bash
curl -X POST http://localhost:3000/api/v1/signin \
  -H "Content-Type: application/json" \
  -d '{"username": "test@example.com", "password": "testpass123"}'
```

### Test Quote
```bash
curl -X POST http://localhost:3000/api/v1/quote \
  -H "Content-Type: application/json" \
  -d '{
    "inputMint": "So11111111111111111111111111111111111111112",
    "outputMint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "inAmount": 1000000
  }'
```

## 🔧 Development

### Project Structure
```
├── backend/          # REST API server
├── indexer/          # Real-time balance indexer
├── mpc/             # MPC signing nodes
├── store/           # Database layer
└── migrations/      # Database migrations
```

### Key Dependencies
- **actix-web**: HTTP server framework
- **sqlx**: Async PostgreSQL driver
- **frost-ed25519**: Threshold signatures
- **solana-sdk**: Solana blockchain integration
- **yellowstone-grpc**: Solana indexing

## 🚨 Production Notes

- Set strong JWT secrets
- Use production PostgreSQL
- Configure proper TLS for gRPC
- Monitor MPC node health
- Implement proper logging

## 📝 License

MIT License - see LICENSE file for details
# mpc-frosty
