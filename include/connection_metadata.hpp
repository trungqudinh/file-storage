#pragma once

#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>

#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

using std::cout;
using std::endl;

class ConnectionMetadata
{
    public:
        typedef websocketpp::lib::shared_ptr<ConnectionMetadata> ptr;

        ConnectionMetadata(int id, websocketpp::connection_hdl hdl, std::string uri)
            : m_id(id)
              , m_hdl(hdl)
              , m_status("Connecting")
              , m_uri(uri)
              , m_server("N/A")
        {}

        void on_open(client * c, websocketpp::connection_hdl hdl)
        {
            m_status = "Open";

            client::connection_ptr con = c->get_con_from_hdl(hdl);
            m_server = con->get_response_header("Server");
        }

        void on_fail(client * c, websocketpp::connection_hdl hdl)
        {
            m_status = "Failed";

            client::connection_ptr con = c->get_con_from_hdl(hdl);
            m_server = con->get_response_header("Server");
            m_error_reason = con->get_ec().message();
        }

        void on_close(client * c, websocketpp::connection_hdl hdl)
        {
            m_status = "Closed";
            client::connection_ptr con = c->get_con_from_hdl(hdl);
            std::stringstream s;
            s << "close code: " << con->get_remote_close_code() << " ("
                << websocketpp::close::status::get_string(con->get_remote_close_code())
                << "), close reason: " << con->get_remote_close_reason();
            m_error_reason = s.str();
        }

        void on_message(websocketpp::connection_hdl, client::message_ptr msg)
        {
            if (msg->get_opcode() == websocketpp::frame::opcode::TEXT)
            {
//                m_messages.push_back("<< " + msg->get_payload());
                const std::string& message = msg->get_payload();
                std::cout << "> [Server respond] \n" << msg->get_payload() << std::endl;
                if (!received_expected_message())
                {
                    received_expected_message_ = (message == expected_waiting_message_);
                }
                if (message == "STREAMING_ON_EXISTING_FILE")
                {
                    is_streaming_on_existing_file_ = true;
                }
            }
            else

            {
//                m_messages.push_back("<< " + websocketpp::utility::to_hex(msg->get_payload()));
//                std::cout << "Received hex from server: " << websocketpp::utility::to_hex(msg->get_payload());
            }
            waiting_for_incomming_message_ = false;
        }

        context_ptr on_tls_init(websocketpp::connection_hdl)
        {
            context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);

            try
            {
                ctx->set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::single_dh_use);

                ctx->set_verify_mode(boost::asio::ssl::verify_none);
                ctx->load_verify_file("server.pem");
            } catch (std::exception& e)
            {
                std::cerr << e.what() << std::endl;
            }
            return ctx;
        }

        websocketpp::connection_hdl get_hdl() const
        {
            return m_hdl;
        }

        int get_id() const
        {
            return m_id;
        }

        std::string get_status() const
        {
            return m_status;
        }

        void record_sent_message(std::string message)
        {
            m_messages.push_back(">> " + message);
        }

        void wait_for_next_incomming_message(bool keep_waiting = true)
        {
            waiting_for_incomming_message_ = keep_waiting;
        }

        void expect_message(const std::string& message, bool keep_waiting = true)
        {
            received_expected_message_ = !keep_waiting;
            if (!received_expected_message_)
            {
                expected_waiting_message_ = message;
            }
        }

        bool is_waiting_message()
        {
            return waiting_for_incomming_message_;
        }

        bool received_expected_message()
        {
            return received_expected_message_;
        }

        bool is_streaming_on_existing_file()
        {
            return is_streaming_on_existing_file_;
        }

        void open_streaming()
        {
            is_streaming = true;
        }

        void close_streaming()
        {
            is_streaming = false;
            is_streaming_on_existing_file_ = false;
        }

        friend std::ostream & operator<< (std::ostream & out, ConnectionMetadata const & data);
    private:
        int m_id;
        websocketpp::connection_hdl m_hdl;
        bool waiting_for_incomming_message_ = false;
        bool received_expected_message_ = true;
        bool server_accept_sreaming = true;
        bool is_streaming = false;
        bool is_streaming_on_existing_file_ = false;
        std::string expected_waiting_message_ = "";
        std::string m_status;
        std::string m_uri;
        std::string m_server;
        std::string m_error_reason;
        std::vector<std::string> m_messages;
};

std::ostream & operator<< (std::ostream & out, ConnectionMetadata const & data)
{
    out << "> URI: " << data.m_uri << "\n"
        << "> Status: " << data.m_status << "\n"
        << "> Remote Server: " << (data.m_server.empty() ? "None Specified" : data.m_server) << "\n"
        << "> Error/close reason: " << (data.m_error_reason.empty() ? "N/A" : data.m_error_reason) << "\n";
    out << "> Messages Processed: (" << data.m_messages.size() << ") \n";

    std::vector<std::string>::const_iterator it;
    for (it = data.m_messages.begin(); it != data.m_messages.end(); ++it)
    {
        out << *it << "\n";
    }

    return out;
}

