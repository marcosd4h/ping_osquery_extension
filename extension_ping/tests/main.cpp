#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>
#include <gtest/gtest.h>
#include "../utils.h"

namespace osquery {

class PingTableTests : public testing::Test {

  void TearDown() override {
    result_data.clear();
  }

 protected:
  utils::ping::icmp_v4_ping_executor pinger;
  utils::ping::ping_response_data_collection result_data;
};

TEST_F(PingTableTests, successful_ping_test) {
  utils::ping::ping_response_data_collection result_data;
  
  EXPECT_TRUE(utils::send_icmp_ping_to_target("google.com", 1, result_data));
  EXPECT_EQ(1U, result_data.size());
  EXPECT_EQ(utils::ping::ping_response_data::RESPONSE_TYPE::REPLY_DATA,
            result_data[0].type);
  EXPECT_GT(result_data[0].round_trip_time, 0U);
}

TEST_F(PingTableTests, timeout_test) {
  utils::ping::ping_response_data_collection result_data;

  EXPECT_TRUE(utils::send_icmp_ping_to_target("2.2.2.2", 1, result_data));
  EXPECT_EQ(1U, result_data.size());
  EXPECT_EQ(utils::ping::ping_response_data::RESPONSE_TYPE::TIMEOUT, 
      result_data[0].type);

}

TEST_F(PingTableTests, host_not_valid) {
  utils::ping::ping_response_data_collection result_data;

  EXPECT_TRUE(utils::send_icmp_ping_to_target("gaglee.com", 1, result_data));
  EXPECT_EQ(1U, result_data.size());
  EXPECT_EQ(
      utils::ping::ping_response_data::RESPONSE_TYPE::TARGET_HOST_NOT_FOUND,
      result_data[0].type);
}

TEST_F(PingTableTests, multiple_request_ping_test) {
  utils::ping::ping_response_data_collection result_data;

  EXPECT_TRUE(utils::send_icmp_ping_to_target("google.com", 4, result_data));
  EXPECT_EQ(4U, result_data.size());
}

TEST_F(PingTableTests, pinger_reuse_test) {
  utils::ping::ping_response_data_collection result_data1;
  utils::ping::ping_response_data_collection result_data2;
  utils::ping::ping_response_data_collection result_data3;

  EXPECT_TRUE(pinger.execute("google.com", 1, result_data1));
  EXPECT_EQ(1U, result_data1.size());
  EXPECT_TRUE(pinger.execute("gaglee.com", 1, result_data2));
  EXPECT_EQ(1U, result_data2.size());
  EXPECT_TRUE(pinger.execute("bing.com", 1, result_data3));
  EXPECT_EQ(1U, result_data3.size());
}

TEST_F(PingTableTests, pinger_thread_safe_test) {
  std::vector<std::thread> threads;

  for (int i = 0; i < 5; i++) {    
    threads.push_back(std::thread([this]() {
      pinger.execute("google.com", 1, result_data);    
    }));    
  }

  for (auto& th : threads) {
    th.join();
  }

  EXPECT_EQ(5U, result_data.size());
}

} // namespace osquery
