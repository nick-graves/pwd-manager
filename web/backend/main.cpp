#include "crow_all.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <memory>
#include <pqxx/pqxx>
#include <unordered_map>
#include <mutex>
#include <random>

# include "crypto_utils.h"


std::string load_html(const std::string& filepath) 
{
    std::ifstream file(filepath);
    if (!file)
    {
        return "<h1>Failed to load HTML</h1>";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// parser for html input
std::unordered_map<std::string, std::string> parse_url_encoded(const std::string& body)
{
    std::unordered_map<std::string, std::string> result;
    std::stringstream ss(body);
    std::string pair;

    while (std::getline(ss, pair, '&')) {
        size_t eq_pos = pair.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = pair.substr(0, eq_pos);
            std::string val = pair.substr(eq_pos + 1);
            result[key] = val;
        }
    }
    return result;
}


std::string generate_session_token() 
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::string token;
    for (int i = 0; i < 64; ++i) 
    {
        int val = dis(gen);
        token += "0123456789abcdef"[val];
    }
    return token;
}

std::optional<std::string> extract_session_token(const crow::request& req) 
{
    auto cookie = req.get_header_value("Cookie");
    auto pos = cookie.find("session=");
    if (pos == std::string::npos) 
    {
        return std::nullopt;
    }
    auto end = cookie.find(';', pos);
    return cookie.substr(pos + 8, end - (pos + 8));
}



int main()
{
    std::unordered_map<std::string, int> session_store;
    std::unordered_map<int, std::vector<unsigned char>> user_keys;
    std::mutex session_mutex;

    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([]()
    {
        return crow::response(load_html("login.html"));
    });

    CROW_ROUTE(app, "/login").methods("POST"_method)([&](const crow::request& req)
    {
        std::cout << "Raw POST body: " << req.body << std::endl;
        auto params = parse_url_encoded(req.body);
        std::string username = params["username"];
        std::string password = params["password"];

        std::cout << "Parsed username: " << username << std::endl;
        std::cout << "Parsed password: " << password << std::endl;

        if (username.empty() || password.empty()) 
        {
            return crow::response(400, "Missing username or password.");
        }


        const char* db_host = std::getenv("DB_HOST");
        const char* db_port = std::getenv("DB_PORT");
        const char* db_user = std::getenv("DB_USER");
        const char* db_pass = std::getenv("DB_PASS");
        const char* db_name = std::getenv("DB_NAME");
        std::stringstream conn_str;
        conn_str << "host=" << db_host
                << " port=" << db_port
                << " user=" << db_user
                << " password=" << db_pass
                << " dbname=" << db_name;
        
        try
        {
            pqxx::connection conn(conn_str.str());
            pqxx::work txn(conn);

            pqxx::result res = txn.exec_params(
                "SELECT id, password_hash, salt FROM users WHERE username = $1",
                username
            );

            if (res.empty()) 
            {
                return crow::response(401, "Invalid username or password.");
            }

            auto row = res[0];
            int user_id = row["id"].as<int>();
            const auto& hash_field = row["password_hash"];
            const auto& salt_field = row["salt"];

            std::cout << "Retrieved hash: " << hash_field.as<std::string>() << std::endl;
            std::cout << "Retrieved salt: " << salt_field.as<std::string>() << std::endl;

            std::string hash_hex = hash_field.c_str();
            std::string salt_hex = salt_field.c_str();

            std::vector<unsigned char> stored_hash = from_hex(hash_hex.substr(2));
            std::vector<unsigned char> salt = from_hex(salt_hex.substr(2));


            std::cout << "Stored hash size: " << stored_hash.size() << std::endl;
            std::cout << "Stored salt size: " << salt.size() << std::endl;
            std::cout << "passowrd: " << password << std::endl;

            if (verify_master_password(password, salt, stored_hash)) 
            {
                std::vector<unsigned char> key = derive_key_from_password(password, salt);

                std::string session_token = generate_session_token();
                std::lock_guard<std::mutex> lock(session_mutex);
                session_store[session_token] = user_id;
                user_keys[user_id] = key;

                crow::response http_res;
                http_res.code = 302;
                http_res.add_header("Location", "/vault");
                http_res.add_header("Set-Cookie", "session=" + session_token + "; HttpOnly; Path=/");
                http_res.body = "Redirecting...";
                return http_res;
            } 
            else 
            {
                return crow::response(401, "Invalid username or password.");
            }
        } 
        catch (const std::exception& e) 
        {
            std::cerr << "Database error: " << e.what() << std::endl;
            return crow::response(500, "Internal server error.");
        }


    });




    CROW_ROUTE(app, "/signup")([]()
    {
        return crow::response(load_html("signup.html"));
    });


    CROW_ROUTE(app, "/signup").methods("POST"_method)
    ([](const crow::request& req)
    {
        const char* db_host = std::getenv("DB_HOST");
        const char* db_port = std::getenv("DB_PORT");
        const char* db_user = std::getenv("DB_USER");
        const char* db_pass = std::getenv("DB_PASS");
        const char* db_name = std::getenv("DB_NAME");

        std::stringstream conn_str;
        conn_str << "host=" << db_host
                << " port=" << db_port
                << " user=" << db_user
                << " password=" << db_pass
                << " dbname=" << db_name;


        
        std::cerr << "Request body: " << req.body << std::endl;
        auto form = parse_url_encoded(req.body);
        std::string username = form["username"];
        std::string password = form["password"];
        std::string confirm  = form["confirm"];

        auto salt = generate_salt(16);
        auto hashed_password = hash_master_password(password, salt);



        if (username.empty() || password.empty() || confirm.empty()) 
        {
            return crow::response(400, "Missing required fields.");
        }



        try 
        {
            pqxx::connection conn(conn_str.str());
            pqxx::work txn(conn);

            txn.exec_params(
                "INSERT INTO users (username, password_hash, salt) VALUES ($1, $2, $3)",
                std::string(username), 
                pqxx::binarystring(hashed_password.data(), hashed_password.size()), 
                pqxx::binarystring(salt.data(), salt.size())
            );

            txn.commit();
            return crow::response(200, "Account created successfully. <a href='/'>Login</a>");

        } 
        catch (const std::exception& e) 
        {
            std::cerr << "Signup error: " << e.what() << std::endl;
            return crow::response(500, "Internal server error.");
        }
    });



    CROW_ROUTE(app, "/vault").methods("GET"_method)([&](const crow::request& req)
    {

        const char* db_host = std::getenv("DB_HOST");
        const char* db_port = std::getenv("DB_PORT");
        const char* db_user = std::getenv("DB_USER");
        const char* db_pass = std::getenv("DB_PASS");
        const char* db_name = std::getenv("DB_NAME");

        std::stringstream conn_str;
        conn_str << "host=" << db_host
                << " port=" << db_port
                << " user=" << db_user
                << " password=" << db_pass
                << " dbname=" << db_name;


        auto token_opt = extract_session_token(req);
        if (!token_opt) 
        {
            return crow::response(401, "Unauthorized");
        }

        std::string token = *token_opt;
        int user_id = -1;

        std::lock_guard<std::mutex> lock(session_mutex);
        auto it = session_store.find(token);
        if (it == session_store.end()) 
        {
            return crow::response(401, "Invalid session");
        }
        user_id = it->second;

        std::vector<unsigned char> key;

        auto kit = user_keys.find(user_id);
        if (kit == user_keys.end()) 
        {
            return crow::response(401, "Missing key");
        }
        key = kit->second;

        std::ostringstream rows_html;

        try
        {
            pqxx::connection conn(conn_str.str());
            pqxx::work txn(conn);

            pqxx::result res = txn.exec_params(
                "SELECT name, username, password FROM credentials WHERE user_id = $1",
                user_id
            );


            for (auto row : res) 
            {
                std::string name = row["name"].c_str();
                std::string uname = row["username"].c_str();
                const auto& blob = row["password"];
                std::vector<unsigned char> enc(
                    reinterpret_cast<const unsigned char*>(blob.c_str()),
                    reinterpret_cast<const unsigned char*>(blob.c_str()) + blob.size()
                );

                std::string decrypted;
                try 
                {

                    decrypted = decrypt_password(enc, key);
                } 
                catch (...) 
                {
                    decrypted = "<decryption error>";
                }

                rows_html << "<tr><td>" << name << "</td><td>" << uname << "</td><td>" << decrypted << "</td></tr>";


            }
        }
        
        catch (const std::exception& e) 
        {
            std::cerr << "Vault error: " << e.what() << std::endl;
            return crow::response(500, "Server error");
        }

        std::ifstream file("vault.html");
        if (!file) 
        {
            return crow::response(500, "Failed to load vault template");
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string html_template = buffer.str();

        // Replace placeholder with credential rows
        size_t pos = html_template.find("{{rows}}");
        if (pos != std::string::npos) 
        {
            html_template.replace(pos, 8, rows_html.str());
        }

        return crow::response{html_template};



    });

        

    app.port(18080).multithreaded().run();
    return 0;
}
