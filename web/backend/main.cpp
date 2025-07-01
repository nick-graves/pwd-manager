#include "crow_all.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <memory>
#include <pqxx/pqxx>


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



int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([]()
    {
        return crow::response(load_html("login.html"));
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
                std::string(username), std::string(password), "plaintext"
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

        

    app.port(18080).multithreaded().run();
    return 0;
}
