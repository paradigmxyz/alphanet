FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/paradigmxyz/alphanet
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Builds a cargo-chef plan
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE $BUILD_PROFILE

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES $FEATURES

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

# Builds dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin alphanet

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/alphanet /app/alphanet

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

# Copy alphanet over from the build stage
COPY --from=builder /app/alphanet /usr/local/bin

# Copy licenses
COPY LICENSE-* ./

# Copy the genesis file
ADD etc/alphanet-genesis.json ./etc/alphanet-genesis.json

EXPOSE 30303 30303/udp 9001 8545 9000 8546
ENTRYPOINT ["/usr/local/bin/alphanet", "--chain", "./etc/alphanet-genesis.json"]
