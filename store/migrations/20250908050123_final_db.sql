-- Add migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE "User" (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    createdAt   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updatedAt   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    publicKey   TEXT NOT NULL UNIQUE
);

CREATE TABLE "Asset" (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mintAddress TEXT NOT NULL UNIQUE,
    decimals    INT NOT NULL,
    name        TEXT NOT NULL,
    symbol      TEXT NOT NULL,
    logoUrl     TEXT,
    createdAt   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updatedAt   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE "Balance" (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    amount      BIGINT NOT NULL DEFAULT 0,
    createdAt   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updatedAt   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Foreign Keys
    userId      UUID NOT NULL,
    assetId     UUID NOT NULL,

    CONSTRAINT fk_user FOREIGN KEY(userId) REFERENCES "User"(id) ON DELETE CASCADE,
    CONSTRAINT fk_asset FOREIGN KEY(assetId) REFERENCES "Asset"(id) ON DELETE CASCADE,
    CONSTRAINT uq_user_asset UNIQUE(userId, assetId) -- one balance per asset per user
);

CREATE INDEX idx_balance_user ON "Balance"(userId);
CREATE INDEX idx_balance_asset ON "Balance"(assetId);
CREATE INDEX idx_asset_mintAddress ON "Asset"(mintAddress);
