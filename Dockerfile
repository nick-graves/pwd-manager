FROM gcc:latest

RUN apt-get update && \
    apt-get install -y libsodium-dev libsqlite3-dev

WORKDIR /app

COPY *.cpp ./
COPY *.h ./

RUN g++ main.cpp crypto_utils.cpp password_utils.cpp vault_manager.cpp -lsodium -lsqlite3 -o vault

CMD ["./vault"]