FROM rust:slim-bullseye as builder
WORKDIR /app

# Copy workspace + local deps
COPY . .

# Ensure curv is copied too (if it’s outside workspace root)
COPY ../curv ./curv

RUN cargo build --release -p mpc

FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/target/release/mpc /usr/local/bin/mpc
CMD ["mpc"]
