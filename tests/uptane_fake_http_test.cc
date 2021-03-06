#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <string>

#include "fsstorage.h"
#include "httpclient.h"
#include "logger.h"
#include "test_utils.h"
#include "uptane/uptanerepository.h"
#include "utils.h"

bool doInit(const std::string &device_register_state, const std::string &ecu_register_state, Config &conf) {
  conf.provision.expiry_days = device_register_state;
  conf.uptane.primary_ecu_serial = ecu_register_state;
  std::string good_url = conf.provision.server;
  if (device_register_state == "noconnection") {
    conf.provision.server = conf.provision.server.substr(conf.provision.server.size() - 2) + "11";
  }

  HttpClient http;
  FSStorage fs(conf);
  Uptane::Repository *uptane = new Uptane::Repository(conf, fs, http);
  bool result = uptane->initialize();
  delete uptane;
  if (device_register_state != "noerrors" || conf.uptane.primary_ecu_serial != "noerrors") {
    conf.provision.expiry_days = "noerrors";
    conf.uptane.primary_ecu_serial = "noerrors";
    conf.provision.server = good_url;
    Uptane::Repository *uptane = new Uptane::Repository(conf, fs, http);
    result = uptane->initialize();
    delete uptane;
    return result;
  }

  return result;
}

/**
  * \verify{\tst{158}} Check that aktualizr can complete provisioning after previous network issues
*/
TEST(SotaUptaneClientTest, partial_provision) {
  std::string port = getFreePort();

  TestHelperProcess server_process("tests/fake_http_server/fake_uptane_server.py", port);

  sleep(3);

  Config conf("tests/config_tests_prov.toml");
  conf.tls.certificates_directory = "tests/test_uptane_fake_http";
  conf.provision.server = "http://127.0.0.1:" + port;
  conf.tls.server = "http://127.0.0.1:" + port;

  EXPECT_TRUE(doInit("drop_request", "noerrors", conf));
  EXPECT_TRUE(doInit("drop_body", "noerrors", conf));
  EXPECT_TRUE(doInit("status_503", "noerrors", conf));
  EXPECT_TRUE(doInit("status_408", "noerrors", conf));
  EXPECT_TRUE(doInit("noerrors", "drop_request", conf));
  EXPECT_TRUE(doInit("noerrors", "status_503", conf));
  EXPECT_TRUE(doInit("noerrors", "status_408", conf));
  EXPECT_TRUE(doInit("noerrors", "noerrors", conf));
  EXPECT_TRUE(doInit("noconnection", "noerrors", conf));
  boost::filesystem::remove_all(conf.tls.certificates_directory);
}

#ifndef __NO_MAIN__
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  loggerSetSeverity(LVL_trace);
  return RUN_ALL_TESTS();
}
#endif
