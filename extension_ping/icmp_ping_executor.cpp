#include <random>
#include <sstream>
#include <thread>
#include <chrono>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include "icmp_ping_executor.h"
#include "ipv4_packet.h"
#include "icmp_packet.h"

using boost::asio::ip::icmp;
using boost::asio::steady_timer;
namespace chrono = boost::asio::chrono;

namespace utils
{
	namespace ping
	{
		//It executes the requested nr of ping requests
		bool icmp_v4_ping_executor::execute(const std::string& target_host, const size_t nr_of_ping_requests, ping_response_data_collection& response_data)
		{
			bool ret = false;

			std::lock_guard<std::mutex> guard(m_serialize_execute_mutex);

			//defense programming sanity check
			if ((!target_host.empty()) &&
				(nr_of_ping_requests > 0))
			{
				try
				{
					//now executing the given ICMP echo requests
					for (size_t it = 0; it < nr_of_ping_requests; ++it)
					{
						ping_response_data new_data;
						if ((send_one_ping_request(target_host, new_data)) &&
							(new_data.is_ready()))
						{
							response_data.push_back(new_data);
						}
					}

					//checking if execution conditions where the expected ones
					if (!response_data.empty())
					{
						ret = true;
					}
					else
					{
						response_data.clear();
					}
				}
				catch (boost::system::system_error const& ex)
				{
					auto test = ex.code().value();
					std::string exception_data = boost::diagnostic_information(ex); //mjo log this
					ret = false;
				}
			}

			return ret;
		}

		//It sends one ICMP ping request at the time
		//This function uses an async flow through Boost ASIO
		bool icmp_v4_ping_executor::send_one_ping_request(const std::string& target_host, ping_response_data& execution_result)
		{
			bool ret = false;

			if (!target_host.empty())
			{
				//making sure we are always starting from a known state
				if (reset_internal_state())
				{
					//starting ICMP Echo Request and ICMP Echo Reply Async flows
					bool should_run_callbacks = false;
					if (trigger_icmp_ping_async_flow(target_host, should_run_callbacks))
					{
						//Checking if callbacks should be run
						if (should_run_callbacks)
						{
							//now just asking the ASIO execution engine to run until one callback handler is executed
							//the handlers will be hit under ICMP echo request timeout and ICMP echo response scenarios
							boost::asio::io_context::count_type exec_count = m_async_engine_ptr->run_one();
							if (exec_count == 1)
							{
								//check if there is a execution result ready
								if (m_work_execution_result.is_ready())
								{
									//and saving the async execution result if this is the case
									execution_result = m_work_execution_result;
									ret = true;
								}
							}
						}
						else
						{
							//it seems callbacks are not required

							//check if there is a execution result ready
							if (m_work_execution_result.is_ready())
							{
								//and saving the async execution result if this is the case
								execution_result = m_work_execution_result;
								ret = true;
							}
						}
					}
				}
			}

			return ret;
		}

		//Check if executor is ready
		bool icmp_v4_ping_executor::is_ready()
		{
			bool ret = false;

			if ((m_timer_ptr) &&
				(m_socket_ptr) &&
				(m_async_engine_ptr))
			{
				ret = true;
			}

			return ret;
		}

		//Reset internal executor state
		bool icmp_v4_ping_executor::reset_internal_state()
		{
			bool ret = false;

			m_reply_available = false;

			//We need to make sure that async engine and its users (timer and socket) gets properly initialized
			if (!m_async_engine_ptr)
			{
				//first run scenario, just create all the required instances
				m_async_engine_ptr = boost::shared_ptr<boost::asio::io_context>(new boost::asio::io_context());
				if (m_async_engine_ptr)
				{
					m_timer_ptr = boost::shared_ptr<steady_timer>(new steady_timer(*m_async_engine_ptr));
					m_socket_ptr = boost::shared_ptr<icmp::socket>(new icmp::socket(*m_async_engine_ptr, icmp::v4()));

					if ((m_timer_ptr) &&
						(m_socket_ptr))
					{
						m_packet_identifier = get_packet_identifier();
						m_work_execution_result.clear();
						m_reply_buffer.consume(m_reply_buffer.size());  //clearing the buffer

						ret = true;
					}
				}		
			}
			else
			{
				//There was a previous run, so let's make sure that everything is properly stopped and re-initialized

				//stopping previous timer if needed
				if (m_timer_ptr)
				{
					m_timer_ptr->cancel();
				}

				//stopping previous socket if needed
				if (m_socket_ptr)
				{
					m_async_engine_ptr->stop();
					m_async_engine_ptr->reset();
					m_socket_ptr->close();
				}
			
				//now reinitializing everything
				m_async_engine_ptr.reset(new boost::asio::io_context());
				if (m_async_engine_ptr)
				{
					m_timer_ptr.reset(new steady_timer(*m_async_engine_ptr));
					m_socket_ptr.reset(new icmp::socket(*m_async_engine_ptr, icmp::v4()));

					if ((m_timer_ptr) &&
						(m_socket_ptr))
					{
						m_packet_identifier = get_packet_identifier();
						m_work_execution_result.clear();
						m_reply_buffer.consume(m_reply_buffer.size()); //clearing the buffer

						ret = true;
					}
				}
			}

			return ret;
		}

		//get bytes for an ICMP Echo Request packet
		bool icmp_v4_ping_executor::get_icmp_echo_request_packet_bytes(boost::asio::streambuf& packet_bytes)
		{
			bool ret = false;			

			icmp_header echo_request_packet;

			std::string payload("Hello from OSQUERY");	

			//Build the ICMP packet header
			echo_request_packet.type(icmp_header::ICMP_HEADER_CODE_TYPE::ECHO_REQUEST);
			echo_request_packet.code(0);
			echo_request_packet.identifier(m_packet_identifier);
			if (m_sequence_number == ipv4_header::MAX_IDENTIFIER_POSSIBLE)
			{
				m_sequence_number = 0;
				echo_request_packet.sequence_number(++m_sequence_number);
			}
			else
			{
				echo_request_packet.sequence_number(++m_sequence_number);
			}

			//then update the packet checksum 
			if (echo_request_packet.update_checksum(payload))
			{
				//check if packet is ready
				if (echo_request_packet.is_ready())
				{
					//and finally grab the packet bytes
					boost::asio::streambuf work_bytes(ipv4_header::MAX_PACKET_SIZE);
					std::ostream output_stream_bytes(&packet_bytes);
					output_stream_bytes << echo_request_packet << payload;

					if (packet_bytes.size() > 0)
					{
						ret = true;
					}
				}	
			}

			return ret;
		}

		//This function triggers the ICMP Echo Request and 
		//sets the async callback handlers to grab the ICMP Echo Reply or timeout if reply packet does not arrive on time
		bool icmp_v4_ping_executor::trigger_icmp_ping_async_flow(const std::string& target_host, bool& should_run_callbacks)
		{
			bool ret = false;
			unsigned short NR_SECS_TO_WAIT_FOR_TIMEOUT = 5;

			if ((!target_host.empty()) &&
				(is_ready()))
			{
				boost::asio::streambuf reply_buffer;

				try
				{
					//let's first try check if target hostname can be resolved 
					icmp::resolver dns_resolver(*m_async_engine_ptr);
					icmp::endpoint resolved_endpoint = *(dns_resolver.resolve(icmp::v4(), target_host, "").begin());
					if (resolved_endpoint.size() > 0)
					{
						//Before sending the actual ICMP Echo request, better set first the async callback
						//that will handle the ICMP Echo response message once the request goes live
						m_socket_ptr->async_receive(

							m_reply_buffer.prepare(ipv4_header::MAX_PACKET_SIZE),

							//inline callback
							[this, target_host](boost::system::error_code error_code, std::size_t receive_length)
							{
								if ((!error_code) &&
									(receive_length > 0))
								{
									// making sure that bytes will be available later
									m_reply_buffer.commit(receive_length);

									// And now decoding the ICMP Echo Reply packet
									std::istream is(&m_reply_buffer);
									ipv4_header ipv4_hdr;
									icmp_header icmp_hdr;
									is >> ipv4_hdr >> icmp_hdr;

									// Filter the message to make sure we found the expected one
									if ((is) &&
										(ipv4_hdr.is_ready()) &&
										(icmp_hdr.is_ready()) &&
										(icmp_hdr.type() == icmp_header::ICMP_HEADER_CODE_TYPE::ECHO_REPLY) &&
										(icmp_hdr.identifier() == m_packet_identifier) &&
										(icmp_hdr.sequence_number() == m_sequence_number))
									{
										m_reply_available = true;

										//Getting the round trip time and save data from the ICMP Reply packet
										chrono::steady_clock::duration round_trip_time = chrono::steady_clock::now() - m_request_sent_time;
										if (round_trip_time.count() > 0)
										{
											//storing execution result
											m_work_execution_result.type = ping_response_data::RESPONSE_TYPE::REPLY_DATA;
											m_work_execution_result.valid_checksum = true;
											m_work_execution_result.time_to_live = ipv4_hdr.time_to_live();
											m_work_execution_result.packet_identifier = icmp_hdr.identifier();
											m_work_execution_result.sequence_number = icmp_hdr.sequence_number();
											m_work_execution_result.round_trip_time = chrono::duration_cast<chrono::milliseconds>(round_trip_time).count();
											m_work_execution_result.response_address.assign(ipv4_hdr.source_address().to_string());
											m_work_execution_result.target_hostname.assign(target_host);
											m_work_execution_result.ready = true;
										}
									}
								}
							});


						//Ok now let's just generate and send the ICMP Echo Request data
						boost::asio::streambuf echo_request_packet_bytes;
						if ((get_icmp_echo_request_packet_bytes(echo_request_packet_bytes)) &&
							(echo_request_packet_bytes.size() > 0))
						{
							std::size_t bytes_sent = m_socket_ptr->send_to(echo_request_packet_bytes.data(), resolved_endpoint);

							//Our request is out, so we inmmediataely grab when it was sent
							m_request_sent_time = steady_timer::clock_type::now();

							//Let's check if the expected bytes where transmitted
							if ((bytes_sent > 0) &&
								(bytes_sent == echo_request_packet_bytes.size()))
							{
								//and then set a timeout for the ICMP Echo Reply packqets
								m_timer_ptr->expires_at(m_request_sent_time + chrono::seconds(NR_SECS_TO_WAIT_FOR_TIMEOUT));

								//And finally set the callback to handle the scenario where ICMP Echo Response packet never came 
								//and our timeout timer fires
								m_timer_ptr->async_wait(

									//inline callback
									[this, target_host](const boost::system::error_code& error_code)
									{
										if ((error_code == boost::system::errc::success) &&
											(!m_reply_available)) //reply never came
										{
											//storing execution result
											m_work_execution_result.type = ping_response_data::RESPONSE_TYPE::TIMEOUT;
											m_work_execution_result.target_hostname.assign(target_host);
											m_work_execution_result.ready = true;
										}
									});
							}
						}

						//callbacks should be run through async engine
						should_run_callbacks = true;
						ret = true;
					}
				}
				catch (boost::system::system_error const& ex)
				{
					//catching the host not found scenario
					if (ex.code().value() == boost::asio::error::host_not_found)
					{
						//host cannot be resolved, storing result
						m_work_execution_result.type = ping_response_data::RESPONSE_TYPE::TARGET_HOST_NOT_FOUND;
						m_work_execution_result.target_hostname.assign(target_host);
						m_work_execution_result.ready = true;
						should_run_callbacks = false; //we are not running the callbacks when this happens
						ret = true;
					}
					else
					{
						//A different exception happened - let's just return false
						ret = false;
					}
				}
			}

			return ret;
		}

		unsigned short icmp_v4_ping_executor::get_packet_identifier()
		{
			unsigned short ret = 0;

			// produces randomness out of thin air
			std::random_device rd;
			std::mt19937 rng(rd());

			// unsigned short range
			std::uniform_int_distribution<> ushort_dist_range(1, ipv4_header::MAX_IDENTIFIER_POSSIBLE);

			// get random value from range
			ret = ushort_dist_range(rng);

			return ret;
		}
	}
}
