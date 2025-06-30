FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
    g++ \
    make \
    git \
    curl \
    libsodium-dev \
    libsqlite3-dev \
    libboost-all-dev \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app


COPY *.cpp ./
COPY *.h ./



RUN g++ main.cpp crypto_utils.cpp password_utils.cpp vault_manager.cpp \
    -std=c++17 -lsodium -lsqlite3 -o vault


CMD ["./vault"]