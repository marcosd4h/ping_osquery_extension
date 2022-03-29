#pragma once

#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <mutex>

using boost::asio::ip::icmp;
using boost::asio::steady_timer;
namespace chrono = boost::asio::chrono;

namespace utils
{
    namespace ping
    {
        //icmp echo response data object
        typedef struct ping_response_data_unit
        {
            typedef enum
            {
                REPLY_DATA = 0,
                TARGET_HOST_NOT_FOUND,
                TIMEOUT,
                EMPTY
            } RESPONSE_TYPE;

            ping_response_data_unit()
            {
                clear();
            }

            void clear()
            {
                ready = false;
                type = RESPONSE_TYPE::EMPTY;
                valid_checksum = false;
                time_to_live = 0;
                packet_identifier = 0;
                sequence_number = 0;
                round_trip_time = 0;
                target_hostname.clear();
                response_address.clear();
            }

            bool is_ready() { return ready; }

            bool ready;
            RESPONSE_TYPE type;
            bool valid_checksum;
            unsigned int time_to_live;
            unsigned int packet_identifier;
            unsigned int sequence_number;
            size_t round_trip_time;
            std::string target_hostname;
            std::string response_address;

        } ping_response_data;

        typedef std::vector<ping_response_data> ping_response_data_collection;

        //ICMP V4 Echo Request/Reply helper class
        class icmp_v4_ping_executor
        {
        public:

            icmp_v4_ping_executor() :
                m_reply_available(false),
                m_async_engine_ptr(nullptr),
                m_socket_ptr(nullptr),
                m_timer_ptr(nullptr),
                m_sequence_number(0),
                m_packet_identifier(0) {}

            bool execute(const std::string& target_host, const size_t nr_of_ping_requests, ping_response_data_collection& response_data);

        private:
            //private helper methods
            bool send_one_ping_request(const std::string& target_host, ping_response_data_unit& execution_result);
            bool reset_internal_state();
            bool trigger_icmp_ping_async_flow(const std::string& target_host, bool& should_run_callbacks);
            bool get_icmp_echo_request_packet_bytes(boost::asio::streambuf& packet_bytes);
            bool is_ready();
            unsigned short get_packet_identifier();

            //member vars
            bool m_reply_available;
            boost::shared_ptr<boost::asio::io_context> m_async_engine_ptr;
            boost::shared_ptr<icmp::socket> m_socket_ptr;
            boost::shared_ptr<steady_timer> m_timer_ptr;
            unsigned short m_sequence_number;
            unsigned short m_packet_identifier;
            std::mutex m_serialize_execute_mutex;
            chrono::steady_clock::time_point m_request_sent_time;
            boost::asio::streambuf m_reply_buffer;
            ping_response_data_unit m_work_execution_result;
        };

    }
}


