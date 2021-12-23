#include <exception>
#include <iostream>
#include <map>

#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

typedef websocketpp::config::asio::message_type::ptr message_ptr;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
typedef websocketpp::server<websocketpp::config::asio_tls> server;

using websocketpp::connection_hdl;
using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

struct connection_data {
    int sessionid;
    std::string name;
};
    std::string get_password() {
        return "test";
    }


class print_server {
public:
    print_server() : m_next_sessionid(1) {
        m_server.init_asio();

//        m_server.set_http_handler(bind(&print_server::on_http,&echo_server,::_1));
        m_server.set_tls_init_handler(bind(&print_server::on_tls_init,this, MOZILLA_INTERMEDIATE,::_1));
        m_server.set_open_handler(bind(&print_server::on_open,this,::_1));
        m_server.set_close_handler(bind(&print_server::on_close,this,::_1));
        m_server.set_message_handler(bind(&print_server::on_message,this,::_1,::_2));
    }

    void on_open(connection_hdl hdl) {
        connection_data data;

        data.sessionid = m_next_sessionid++;
        data.name.clear();

        m_connections[hdl] = data;
    }

    void on_close(connection_hdl hdl) {
        connection_data& data = get_data_from_hdl(hdl);

        std::cout << "Closing connection " << data.name
                  << " with sessionid " << data.sessionid << std::endl;

        m_connections.erase(hdl);
    }

    void on_message(connection_hdl hdl, message_ptr msg) {
        std::cout << "on_message called with hdl: " << hdl.lock().get()
            << " and message: " << msg->get_payload()
            << std::endl;

        try {
            m_server.send(hdl, msg->get_payload(), msg->get_opcode());
        } catch (websocketpp::exception const & e) {
            std::cout << "Echo failed because: "
                << "(" << e.what() << ")" << std::endl;
        }

//        connection_data& data = get_data_from_hdl(hdl);
//
//        if (data.name.empty()) {
//            data.name = msg->get_payload();
//            std::cout << "Setting name of connection with sessionid "
//                      << data.sessionid << " to " << data.name << std::endl;
//        } else {
//            std::cout << "Got a message from connection " << data.name
//                      << " with sessionid " << data.sessionid << std::endl;
//        }
    }

    connection_data& get_data_from_hdl(connection_hdl hdl) {
        auto it = m_connections.find(hdl);

        if (it == m_connections.end()) {
            // this connection is not in the list. This really shouldn't happen
            // and probably means something else is wrong.
            throw std::invalid_argument("No data available for session");
        }

        return it->second;
    }

    void run(uint16_t port) {
        m_server.listen(port);
        m_server.start_accept();
        m_server.run();
    }
private:
    void on_http(server* s, websocketpp::connection_hdl hdl) {
        server::connection_ptr con = s->get_con_from_hdl(hdl);

        con->set_body("Hello World!");
        con->set_status(websocketpp::http::status_code::ok);
    }

    // See https://wiki.mozilla.org/Security/Server_Side_TLS for more details about
    // the TLS modes. The code below demonstrates how to implement both the modern
    enum tls_mode {
        MOZILLA_INTERMEDIATE = 1,
        MOZILLA_MODERN = 2
    };

    context_ptr on_tls_init(tls_mode mode, websocketpp::connection_hdl hdl) {
        namespace asio = websocketpp::lib::asio;

        std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << std::endl;
        std::cout << "using TLS mode: " << (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate") << std::endl;

        context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

        try {
            if (mode == MOZILLA_MODERN) {
                // Modern disables TLSv1
                ctx->set_options(asio::ssl::context::default_workarounds |
                        asio::ssl::context::no_sslv2 |
                        asio::ssl::context::no_sslv3 |
                        asio::ssl::context::no_tlsv1 |
                        asio::ssl::context::single_dh_use);
            } else {
                ctx->set_options(asio::ssl::context::default_workarounds |
                        asio::ssl::context::no_sslv2 |
                        asio::ssl::context::no_sslv3 |
                        asio::ssl::context::single_dh_use);
            }
            ctx->set_password_callback(bind(&get_password));
            ctx->use_certificate_chain_file("server.pem");
            ctx->use_private_key_file("server.pem", asio::ssl::context::pem);

            // Example method of generating this file:
            // `openssl dhparam -out dh.pem 2048`
            // Mozilla Intermediate suggests 1024 as the minimum size to use
            // Mozilla Modern suggests 2048 as the minimum size to use.
            ctx->use_tmp_dh_file("dh.pem");

            std::string ciphers;

            if (mode == MOZILLA_MODERN) {
                ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
            } else {
                ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
            }

            if (SSL_CTX_set_cipher_list(ctx->native_handle() , ciphers.c_str()) != 1) {
                std::cout << "Error setting cipher list" << std::endl;
            }
        } catch (std::exception& e) {
            std::cout << "Exception: " << e.what() << std::endl;
        }
        return ctx;
    }

private:
    typedef std::map<connection_hdl,connection_data,std::owner_less<connection_hdl>> con_list;

    int m_next_sessionid;
    server m_server;
    con_list m_connections;
};

int main() {
    print_server server;
    server.run(9002);
}
