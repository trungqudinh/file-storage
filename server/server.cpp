#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/serialization/string.hpp>
#include <boost/filesystem.hpp>

#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

#include <checksum_handler.hpp>
#include <db_handler.hpp>
#include <transfering_package.hpp>

#include <utility.hpp>
#include <storage_handler.hpp>

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
    std::string user_id;
};


class print_server {
public:
    print_server() : m_next_sessionid(1) {
        m_server.set_error_channels(websocketpp::log::elevel::all);
        m_server.init_asio();

        m_server.set_tls_init_handler(bind(&print_server::on_tls_init,this, ::_1));
        m_server.set_validate_handler(bind(&print_server::on_validate,this,::_1));
        m_server.set_open_handler(bind(&print_server::on_open,this,::_1));
        m_server.set_close_handler(bind(&print_server::on_close,this,::_1));
        m_server.set_message_handler(bind(&print_server::on_message,this,::_1,::_2));
    }

    void on_open(connection_hdl hdl) {
        connection_data data;

        data.sessionid = m_next_sessionid++;
        data.name.clear();

        server::connection_ptr con = m_server.get_con_from_hdl(hdl);
        std::string path = con->get_resource();
        auto curr_uri = con->get_uri();
        auto query = curr_uri->get_query();
        std::cout << "Get resource from " << path << std::endl;
        std::cout << "Get query " << query << std::endl;


        regex regexp("[^,]*(user_id=[a-zA-z0-9]*)");
        smatch m;
        if (regex_search(query, m, regexp))
        {
            data.user_id = m[0];
            data.user_id = data.user_id.substr(data.user_id.find("=") + 1);
        }

        m_connections[hdl] = data;
    }

    void on_close(connection_hdl hdl) {
        connection_data& data = get_data_from_hdl(hdl);

        std::cout << "Closing connection " << data.name
                  << " with sessionid " << data.sessionid << std::endl;

        m_connections.erase(hdl);
    }

    void on_message(connection_hdl hdl, message_ptr msg) {
        std::cout << "Receving file on hdl: " << hdl.lock().get()
            << std::endl;

        std::cout << "Deserialize" << std::endl;
        TransferingPackage data = TransferingPackage::deserialize(msg->get_payload());
        StorageHandler storage_handler;
        storage_handler.storing_path = "data/";

        std::cout << data.request_id << std::endl;

        auto const stored_file = storage_handler.store(data.checksum, data.data, true);

        bool checksum_matched = (stored_file.second == data.checksum);

        Record rec;
        rec.user_id = m_connections[hdl].user_id;
        rec.request_id = data.request_id;
        rec.checksum = data.checksum;
        rec.received_date = get_current_time();
        rec.file_name = data.file_name;

        DatabaseIOStream& dbs = DatabaseIOStream::Instance();
        dbs.initialize();
        dbs.insert({rec});

        auto file_size = boost::filesystem::file_size(boost::filesystem::path(stored_file.first));

        try {
            if (checksum_matched)
            {
                std::cout << "Stored at " << stored_file.first << std::endl;
                m_server.send(hdl, "Received successful. File size = " + std::to_string(file_size) + " bytes", websocketpp::frame::opcode::text);
            }
            else
            {
                std::cout << "Checksum of " << stored_file.first << " not matched" << std::endl;
                m_server.send(hdl, "Checksum not matched. File size = " + std::to_string(file_size) + " bytes", websocketpp::frame::opcode::text);
            }
        } catch (websocketpp::exception const & e) {
            std::cout << "Echo failed because: "
                << "(" << e.what() << ")" << std::endl;
        }
    }

    connection_data& get_data_from_hdl(connection_hdl hdl) {
        auto it = m_connections.find(hdl);

        if (it == m_connections.end()) {
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
    std::string get_password() {
        return "test";
    }

    bool on_validate(connection_hdl hdl) {
        server::connection_ptr con = m_server.get_con_from_hdl(hdl);
        std::string path = con->get_resource();
        auto curr_uri = con->get_uri();
        if (path.rfind("/client/ws?content-type=audio/x-raw,user_id=") != std::string::npos )
        {
            return true;
        }
        else
        {
            std::cout << "Got invalid " << path << std::endl;
            auto ec = websocketpp::error::make_error_code(websocketpp::error::invalid_uri);
            m_server.send(hdl, "Invalide URI. Try again", websocketpp::frame::opcode::text, ec);
            m_server.send_http_response(hdl, ec);
            return false;
        }
    }

    context_ptr on_tls_init(websocketpp::connection_hdl hdl) {
        namespace asio = websocketpp::lib::asio;

        std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << std::endl;

        context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

        try {
            ctx->set_options(asio::ssl::context::default_workarounds |
                    asio::ssl::context::no_sslv2 |
                    asio::ssl::context::no_sslv3 |
                    asio::ssl::context::single_dh_use);
            ctx->set_password_callback(bind(&print_server::get_password, this));
            ctx->use_certificate_chain_file("server.pem");
            ctx->use_private_key_file("server.pem", asio::ssl::context::pem);

            std::string ciphers;

            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";

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
