FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y \
    g++ \
    cmake \
    libboost-all-dev \
    libssl-dev \
    curl \
    git \
    make \
    libpqxx-dev \
    libsodium-dev \
    libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# crow header
RUN curl -L https://github.com/CrowCpp/Crow/releases/latest/download/crow_all.h -o crow_all.h

# install ASIO (crow dependency)
RUN curl -L https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-28-2.tar.gz | tar xz && \
    cp -r asio-asio-1-28-2/asio/include/* /usr/local/include/ && \
    rm -rf asio-asio-1-28-2

COPY backend/*.cpp .
COPY backend/*.h .
COPY frontend/*.html .

# compile with C++17 (crow require)
RUN g++ main.cpp crypto_utils.cpp vault_manager.cpp -std=c++17 -I/usr/local/include -o app -pthread -lboost_system -lssl -lcrypto -lsodium -lpqxx -lpq

EXPOSE 18080
CMD ["./app"]