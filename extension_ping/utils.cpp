#include "utils.h"
#include "icmp_ping_executor.h"

namespace utils
{
	bool send_icmp_ping_to_target(const std::string& target_host, const size_t nr_of_ping_requests, ping::ping_response_data_collection& response_data)
	{
		bool ret = false;

		//defense programming sanity check
		if ((!target_host.empty()) &&
			(nr_of_ping_requests > 0))
		{
			ping::icmp_v4_ping_executor pinger;
			if ((pinger.execute(target_host, nr_of_ping_requests, response_data)) &&
				(!response_data.empty()))
			{
				ret = true;
			}
		}

		return ret;
	}
}
