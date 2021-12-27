#pragma once

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/serialization/string.hpp>
#include <boost/filesystem.hpp>

#include <connection_metadata.hpp>
#include <transfering_package.hpp>
#include <utility.hpp>
#include <tls_verification.hpp>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <sstream>

class ClientEndpoint
{
    public:
        ClientEndpoint () : m_next_id(0)
        {
            m_endpoint.clear_access_channels(websocketpp::log::alevel::all);
            m_endpoint.clear_error_channels(websocketpp::log::elevel::all);
            m_endpoint.set_error_channels(websocketpp::log::elevel::all);

            m_endpoint.init_asio();
            m_endpoint.start_perpetual();

            m_thread = websocketpp::lib::make_shared<websocketpp::lib::thread>(&client::run, &m_endpoint);
        }

        ~ClientEndpoint()
        {
            m_endpoint.stop_perpetual();

            for (con_list::const_iterator it = m_connection_list.begin(); it != m_connection_list.end(); ++it)
            {
                if (it->second->get_status() != "Open")
                {
                    // Only close open connections
                    continue;
                }

                std::cout << "> Closing connection " << it->second->get_id() << std::endl;

                websocketpp::lib::error_code ec;
                m_endpoint.close(it->second->get_hdl(), websocketpp::close::status::going_away, "", ec);
                if (ec)
                {
                    std::cout << "> Error closing connection " << it->second->get_id() << ": "
                        << ec.message() << std::endl;
                }
            }


            m_thread->join();
        }

        void log_info(const std::string& msg)
        {
            m_endpoint.get_elog().write(websocketpp::log::elevel::info, msg);
        }

        void log_error(const std::string& msg)

        {
            m_endpoint.get_elog().write(websocketpp::log::elevel::info, msg);
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

        void on_fail(websocketpp::connection_hdl hdl)
        {
            client::connection_ptr con = m_endpoint.get_con_from_hdl(hdl);
            std::cout << "Fail " << con->get_ec().message() << std::endl;
        }

        int connect(std::string const & uri)
        {
            websocketpp::lib::error_code ec;

            m_endpoint.set_tls_init_handler(bind(&ClientEndpoint::on_tls_init, this, ::_1));
            m_endpoint.set_fail_handler(bind(&ClientEndpoint::on_fail, this, ::_1));
            client::connection_ptr con = m_endpoint.get_connection(uri, ec);

            if (ec)
            {
                std::cout << "> Connect initialization error: " << ec.message() << std::endl;
                return -1;
            }

            int new_id = m_next_id++;
            ConnectionMetadata::ptr metadata_ptr = websocketpp::lib::make_shared<ConnectionMetadata>(new_id, con->get_handle(), uri);
            m_connection_list[new_id] = metadata_ptr;

            con->set_open_handler(websocketpp::lib::bind(
                        &ConnectionMetadata::on_open,
                        metadata_ptr,
                        &m_endpoint,
                        websocketpp::lib::placeholders::_1
                        ));
            con->set_fail_handler(websocketpp::lib::bind(
                        &ConnectionMetadata::on_fail,
                        metadata_ptr,
                        &m_endpoint,
                        websocketpp::lib::placeholders::_1
                        ));
            con->set_close_handler(websocketpp::lib::bind(
                        &ConnectionMetadata::on_close,
                        metadata_ptr,
                        &m_endpoint,
                        websocketpp::lib::placeholders::_1
                        ));
            con->set_message_handler(websocketpp::lib::bind(
                        &ConnectionMetadata::on_message,
                        metadata_ptr,
                        websocketpp::lib::placeholders::_1,
                        websocketpp::lib::placeholders::_2
                        ));

            m_endpoint.connect(con);

            return new_id;
        }

        void close(int id, websocketpp::close::status::value code, std::string reason)
        {
            websocketpp::lib::error_code ec;

            con_list::iterator metadata_it = m_connection_list.find(id);
            if (metadata_it == m_connection_list.end())
            {
                std::cout << "> No connection found with id " << id << std::endl;
                return;
            }

            m_endpoint.close(metadata_it->second->get_hdl(), code, reason, ec);
            if (ec)
            {
                std::cout << "> Error initiating close: " << ec.message() << std::endl;
            }
        }

        websocketpp::lib::error_code send_message(int id, const std::string& message)
        {
            websocketpp::lib::error_code ec;

            con_list::iterator metadata_it = m_connection_list.find(id);
            if (metadata_it == m_connection_list.end())
            {
                std::cout << "> No connection found with id " << id << std::endl;
                return make_error_code(websocketpp::error::bad_connection);
            }

            m_endpoint.send(metadata_it->second->get_hdl(), message, websocketpp::frame::opcode::TEXT, ec);
            if (ec)
            {
                std::cout << "> Error sending message: " << ec.message() << std::endl;
                return ec;
            }

            //metadata_it->second->record_sent_message(message);
            return websocketpp::lib::error_code();
        }

        std::string parse_user_id(const std::string& query)
        {
            std::ostringstream user_id;
            auto&& it = query.begin();
            it += query.find("user_id=") + std::string("user_id=").length();
            for ( ; it != query.end() && *it != ','; ++it)

            {
                user_id << *it;
            }
            return user_id.str();
        };

        websocketpp::lib::error_code send_package(int id, TransferingPackage package)
        {
            websocketpp::lib::error_code ec;

            con_list::iterator metadata_it = m_connection_list.find(id);
            if (metadata_it == m_connection_list.end())
            {
                std::cout << "> No connection found with id " << id << std::endl;
                return make_error_code(websocketpp::error::bad_connection);
            }

            const auto hdl = metadata_it->second->get_hdl();

            RawDataBuffer sent_data = TransferingPackage::serialize(package);
            std::cout << "> [user_id=" << package.user_id << "] Sending package" << " with size " << sent_data.size() << std::endl;

            m_endpoint.send(hdl, sent_data, websocketpp::frame::opcode::BINARY, ec);
            if (ec)
            {
                log_error("[user_id=" + package.user_id + "] Package sending failure");
                std::cout << "> Error sending data: " << ec.message() << std::endl;
                return ec;
            }

            return websocketpp::lib::error_code();
        }

        std::string get_user_id(int id)
        {
            con_list::iterator metadata_it = m_connection_list.find(id);
            if (metadata_it == m_connection_list.end())
            {
                std::cerr << "> No connection found with id " << id << std::endl;
                return "";
            }

            const auto hdl = metadata_it->second->get_hdl();
            return parse_user_id(m_endpoint.get_con_from_hdl(hdl)->get_uri()->get_query());
        }

        void send_file(const int& id, std::vector<std::string> file_paths)
        {
            for (auto const& file : file_paths)
            {
                send_file(id, file);
            }
        }

        void send_file_by_chunks(const int& id, std::vector<std::string> file_paths)
        {
            for (auto const& file : file_paths)
            {
                send_file_by_chunks(id, file);
            }
        }

        void send_file(const int& id, std::string file_path)
        {
            boost::trim(file_path);
            struct stat buffer;
            if (stat(file_path.c_str(), &buffer) != 0)

            {
                log_error("File " + file_path + " does not exist" );
                return;
            }

            std::ifstream fin{file_path, std::ios::in | std::ios::binary};
            std::cout << "Reading:" << file_path << std::endl;

            std::istreambuf_iterator<char> it(fin);
            std::istreambuf_iterator<char> end;

            std::vector<char> bytes;
            while(it != end)
            {
                bytes.push_back(*it);
                ++it;
            }

            fin.close();

            TransferingPackage data;
            data.user_id = get_user_id(id);
            data.request_id = generator_uuid();
            data.file_checksum = get_checksum_from_file(file_path);
            data.file_name = boost::filesystem::path(file_path).filename().string();
            data.data = std::move(bytes);

            send_package(id, data);
        }

        void send_file_by_chunks(const int& id, std::string file_path)
        {
            boost::trim(file_path);
            struct stat buffer;
            if (stat(file_path.c_str(), &buffer) != 0)
            {
                log_error("File " + file_path + " does not exist" );
                return;
            }

            static const size_t BUFFER_SIZE = 1024 * 1024 * 10;
            std::string file_checkum = get_checksum_from_file(file_path);

            std::ifstream fin{file_path, std::ios::in | std::ios::binary};
            std::cout << "Reading:" << file_path << std::endl;

            std::istreambuf_iterator<char> it(fin);
            std::istreambuf_iterator<char> end;

            TransferingPackage base_package;
            base_package.request_type = "STREAMING";
            base_package.user_id = get_user_id(id);
            base_package.request_id = generator_uuid();
            base_package.previous_checksum = "";
            base_package.file_checksum = get_checksum_from_file(file_path);
            base_package.file_name = boost::filesystem::path(file_path).filename().string();

            std::vector<char> bytes;
            get_metadata(id)->open_streaming();
            log_info("Open streaming");
            int chunk_count = 0;
            while (it != end && !get_metadata(id)->is_streaming_on_existing_file())
            {
                while (it != end && bytes.size() < BUFFER_SIZE)
                {
                    bytes.push_back(*it);
                    ++it;
                }
                TransferingPackage chunk = base_package;
                chunk.data = std::move(bytes);
//                chunk.previous_checksum = chunk.current_checksum;
                chunk.current_checksum = get_checksum_from_string(chunk.data);

                log_info("Sending chunk " + std::to_string(chunk_count++) + " " + chunk.current_checksum);
                send_package(id, chunk);

                bytes.clear();
                wait_for_message(id, std::string("previous_checksum=") + chunk.current_checksum);
                base_package.previous_checksum = chunk.current_checksum;
            }
            log_info("Close streaming");
            get_metadata(id)->close_streaming();
            fin.close();
        }

        ConnectionMetadata::ptr get_metadata(int id) const
        {
            con_list::const_iterator metadata_it = m_connection_list.find(id);
            if (metadata_it == m_connection_list.end())
            {
                return ConnectionMetadata::ptr();
            } else
            {
                return metadata_it->second;
            }
        }

        bool wait_for_respond(int id, int remaining_retry = 5)
        {
            get_metadata(id)->wait_for_next_incomming_message();
            while (remaining_retry-- && get_metadata(id)->is_waiting_message())
            {
                wait_a_bit();
            }
            return get_metadata(id)->is_waiting_message();
        }

        void wait_for_message(int id, const std::string& message, int remaining_retry = 5)
        {
            get_metadata(id)->expect_message(message);
            while (remaining_retry-- && !get_metadata(id)->received_expected_message())
            {
                wait_a_bit();
            }
        }

    private:
        typedef std::map<int,ConnectionMetadata::ptr> con_list;

        client m_endpoint;
        websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;

        con_list m_connection_list;
        int m_next_id;
};


