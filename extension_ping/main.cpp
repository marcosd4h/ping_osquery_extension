/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include "utils.h"

using namespace osquery;

namespace ping_definitions {
    static const char* EXTENSION_NAME = "ping";
    static const char* EXTENSION_VERSION = "0.0.3";
    static const char* REGISTRY_NAME = "table";
    static const char* COLUMN_NAME_HOST = "host";
    static const char* COLUMN_NAME_RESULT = "result";
    static const char* COLUMN_NAME_IP_ADDRESS = "ip_address";
    static const char* COLUMN_NAME_SEQUENCE_NUMBER = "sequence_number";
    static const char* COLUMN_NAME_TIME_TO_LIVE = "time_to_live";
    static const char* COLUMN_NAME_LATENCY = "latency";
}


class PingTable : public TablePlugin 
{
 private:

  // It return the table's column name and type pairs
  TableColumns columns() const {
    return {
        std::make_tuple(ping_definitions::COLUMN_NAME_HOST,
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::REQUIRED),

        std::make_tuple(ping_definitions::COLUMN_NAME_RESULT,
                        TEXT_TYPE,
                        ColumnOptions::DEFAULT),

        std::make_tuple(ping_definitions::COLUMN_NAME_IP_ADDRESS,
                        TEXT_TYPE,
                        ColumnOptions::DEFAULT),

        std::make_tuple(ping_definitions::COLUMN_NAME_SEQUENCE_NUMBER,
                        INTEGER_TYPE,
                        ColumnOptions::DEFAULT),

        std::make_tuple(ping_definitions::COLUMN_NAME_TIME_TO_LIVE,
                        INTEGER_TYPE,
                        ColumnOptions::DEFAULT),

        std::make_tuple(ping_definitions::COLUMN_NAME_LATENCY,
                        UNSIGNED_BIGINT_TYPE,
                        ColumnOptions::DEFAULT)
    };
  }


  //It generates a complete table representation
  TableRows generate(QueryContext& request) 
  {
    TableRows results;
    size_t default_number_of_ping_requests = 1;

    auto hosts = request.constraints[ping_definitions::COLUMN_NAME_HOST].getAll(osquery::EQUALS); 

    try {
      for (const auto& target_host : hosts) {
        utils::ping::ping_response_data_collection result_ping_data;

        //Sending the actual ping request
        if ((utils::send_icmp_ping_to_target(target_host, default_number_of_ping_requests, result_ping_data) &&
            (!result_ping_data.empty()))) {

          //Parsing the ping response data
          for (const auto& ping_data : result_ping_data) {
            auto new_row = make_table_row();
            
            if (ping_data.type == ping_data.TARGET_HOST_NOT_FOUND) { //Checking if this is a host not found scenario
              new_row[ping_definitions::COLUMN_NAME_HOST] = 
                  ping_data.target_hostname;
              new_row[ping_definitions::COLUMN_NAME_RESULT] =
                  "Target host was not found";
              results.push_back(std::move(new_row));


            } else if (ping_data.type == ping_data.TIMEOUT) { //Checking if this is a timeout scenario
              new_row[ping_definitions::COLUMN_NAME_HOST] = 
                  ping_data.target_hostname;
              new_row[ping_definitions::COLUMN_NAME_RESULT] =
                  "There was a timeout waiting for response from target host";
              new_row[ping_definitions::COLUMN_NAME_IP_ADDRESS] = 
                  ping_data.response_address;
              results.push_back(std::move(new_row));

            } else if (ping_data.type == ping_data.REPLY_DATA) { //Checking if this is a new data scenario
              new_row[ping_definitions::COLUMN_NAME_HOST] =
                  ping_data.target_hostname;
              new_row[ping_definitions::COLUMN_NAME_RESULT] = 
                  "Success";
              new_row[ping_definitions::COLUMN_NAME_IP_ADDRESS] =
                  INTEGER(ping_data.response_address);
              new_row[ping_definitions::COLUMN_NAME_SEQUENCE_NUMBER] =
                  INTEGER(ping_data.sequence_number);
              new_row[ping_definitions::COLUMN_NAME_TIME_TO_LIVE] =
                  INTEGER(ping_data.time_to_live);
              new_row[ping_definitions::COLUMN_NAME_LATENCY] =
                  UNSIGNED_BIGINT(ping_data.round_trip_time);
              results.push_back(std::move(new_row));
            }
          }
        }
      }
    } 
    catch (std::exception& error) 
    {
      LOG(WARNING) << "There was a problem running ping request: " << error.what();
    }

    return results;
  }
};

//Extension registration
REGISTER_EXTERNAL(PingTable,
                  ping_definitions::REGISTRY_NAME,
                  ping_definitions::EXTENSION_NAME);

int main(int argc, char* argv[]) 
{
  int ret = EXIT_FAILURE;

  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension(ping_definitions::EXTENSION_NAME,
                               ping_definitions::EXTENSION_VERSION);

  if (status.ok()) 
  {
    //Wait for a shutdown signal
    runner.waitForShutdown();

    //ant then ask to shut it down
    ret = runner.shutdown(0);

  } else {

    //Extension cannot be properly initialize, shut down
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  return ret;
}
