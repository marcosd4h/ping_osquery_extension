#pragma once

#include <vector>
#include <string>
#include "icmp_ping_executor.h"

namespace utils
{		 
	bool send_icmp_ping_to_target(const std::string& target_host, const size_t nr_of_ping_requests, ping::ping_response_data_collection& response_data);
}