#include <gtest/gtest.h>
#include <fstream>
#include <iostream>

#include <logger.h>
#include <boost/algorithm/hex.hpp>
#include <boost/make_shared.hpp>
#include <string>

#include "crypto.h"
#include "fsstorage.h"
#include "ostree.h"
#include "sotauptaneclient.h"
#include "uptane/uptanerepository.h"
#include "utils.h"

std::string test_manifest = "/tmp/test_aktualizr_manifest.txt";
std::string tls_server = "https://tlsserver.com";
std::string metadata_path = "tests/test_data";

enum ProvisioningResult {ProvisionOK, ProvisionFailure};
ProvisioningResult provisioningResponse = ProvisionOK;


HttpClient::HttpClient() {}
void HttpClient::setCerts(const std::string &ca, const std::string &cert, const std::string &pkey) {
  (void)ca;
  (void)cert;
  (void)pkey;
}
HttpClient::~HttpClient() {}
bool HttpClient::authenticate(const std::string &cert, const std::string &ca_file, const std::string &pkey) {
  (void)ca_file;
  (void)cert;
  (void)pkey;

  return true;
}

HttpResponse HttpClient::get(const std::string &url) {
  std::cout << "URL:" << url << "\n";
  if (url.find(tls_server) == 0) {
    std::string path = metadata_path + url.substr(tls_server.size());
    std::cout << "filetoopen: " << path << "\n\n\n";
    if (url.find("timestamp.json") != std::string::npos) {
      std::cout << "CHECK PATH: " << metadata_path + "/timestamp.json\n";
      if (boost::filesystem::exists(path)) {
        boost::filesystem::copy_file("tests/test_data/timestamp2.json", path,
                                     boost::filesystem::copy_option::overwrite_if_exists);
      } else {
        boost::filesystem::copy_file("tests/test_data/timestamp1.json", path,
                                     boost::filesystem::copy_option::overwrite_if_exists);
      }
      return HttpResponse(Utils::readFile(path), 200, CURLE_OK, "");
    } else if (url.find("targets.json") != std::string::npos) {
      Json::Value timestamp = Utils::parseJSONFile(metadata_path + "repo/timestamp.json");
      if (timestamp["signed"]["version"].asInt64() == 2) {
        return HttpResponse(Utils::readFile("tests/test_data/targets_noupdates.json"), 200, CURLE_OK, "");
      } else {
        return HttpResponse(Utils::readFile("tests/test_data/targets_hasupdates.json"), 200, CURLE_OK, "");
      }
    } else {
      return HttpResponse(Utils::readFile("tests/test_data/" + url.substr(tls_server.size())), 200, CURLE_OK, "");
    }
  }
  return HttpResponse(url, 200, CURLE_OK, "");
}

HttpResponse HttpClient::post(const std::string &url, const Json::Value &data) {
  (void)url;

  Utils::writeFile("tests/test_data_tmp/post.json", data);
  if (provisioningResponse == ProvisionOK) {
    return HttpResponse(Utils::readFile("tests/test_data/cred.p12"), 200, CURLE_OK, "");
  } else {
    return HttpResponse("", 400, CURLE_OK, "");
  }
}

HttpResponse HttpClient::put(const std::string &url, const Json::Value &data) {
  std::ofstream director_file(test_manifest.c_str());
  director_file << data;
  director_file.close();
  return HttpResponse(url, 200, CURLE_OK, "");
}

HttpResponse HttpClient::download(const std::string &url, curl_write_callback callback, void *userp) {
  (void)callback;
  (void)userp;
  std::cout << "URL: " << url << "\n";
  std::string path = "tests/test_data_tmp/" + url.substr(url.rfind("/targets/") + 9);
  std::cout << "filetoopen: " << path << "\n\n\n";

  std::string content = Utils::readFile(path);

  // Hack since the signature strangely requires non-const.
  callback(const_cast<char *>(content.c_str()), content.size(), 1, userp);
  return HttpResponse(content, 200, CURLE_OK, "");
}

Uptane::TimeStamp now("2017-01-01T01:00:00Z");

TEST(uptane, verify) {
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  Config config;
  config.uptane.metadata_path = "tests/test_data_tmp";
  config.uptane.director_server = tls_server + "/director";
  config.uptane.repo_server = tls_server + "/repo";

  FSStorage storage(config);
  Uptane::TufRepository repo("director", tls_server + "/director", config, storage);
  repo.updateRoot(Uptane::Version());

  repo.verifyRole(Uptane::Role::Root(), now, repo.getJSON("root.json"));
}

TEST(uptane, verify_data_bad) {
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  Config config;
  config.uptane.metadata_path = "tests/test_data_tmp";
  config.uptane.director_server = tls_server + "/director";
  config.uptane.repo_server = tls_server + "/repo";

  FSStorage storage(config);
  Uptane::TufRepository repo("director", tls_server + "/director", config, storage);
  Json::Value data_json = repo.getJSON("root.json");
  data_json.removeMember("signatures");

  try {
    repo.verifyRole(Uptane::Role::Root(), now, data_json);
    FAIL();
  } catch (Uptane::UnmetThreshold ex) {
  }
}

TEST(uptane, verify_data_unknow_type) {
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  Config config;
  config.uptane.metadata_path = "tests/test_data_tmp/";
  config.uptane.director_server = tls_server + "/director";
  config.uptane.repo_server = tls_server + "/repo";

  FSStorage storage(config);
  Uptane::TufRepository repo("director", tls_server + "/director", config, storage);
  Json::Value data_json = repo.getJSON("root.json");
  data_json["signatures"][0]["method"] = "badsignature";
  data_json["signatures"][1]["method"] = "badsignature";

  try {
    repo.verifyRole(Uptane::Role::Root(), now, data_json);
    FAIL();
  } catch (Uptane::SecurityException ex) {
  }
}

TEST(uptane, verify_data_bad_keyid) {
  Config config;
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  config.uptane.metadata_path = "tests/test_data_tmp/";
  config.uptane.director_server = tls_server + "/director";
  config.uptane.repo_server = tls_server + "/repo";

  FSStorage storage(config);
  Uptane::TufRepository repo("director", tls_server + "/director", config, storage);
  Json::Value data_json = repo.getJSON("root.json");

  data_json["signatures"][0]["keyid"] = "badkeyid";
  try {
    repo.verifyRole(Uptane::Role::Root(), now, data_json);
    FAIL();
  } catch (Uptane::UnmetThreshold ex) {
  }
}

TEST(uptane, verify_data_bad_threshold) {
  Config config;
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  config.uptane.metadata_path = "tests/test_data_tmp/";
  config.uptane.director_server = tls_server + "/director";
  config.uptane.repo_server = tls_server + "/repo";

  FSStorage storage(config);
  Uptane::TufRepository repo("director", tls_server + "/director", config, storage);
  Json::Value data_json = repo.getJSON("root.json");
  data_json["signed"]["roles"]["root"]["threshold"] = -1;
  try {
    repo.verifyRole(Uptane::Role::Root(), now, data_json);
    FAIL();
  } catch (Uptane::IllegalThreshold ex) {
  } catch (Uptane::UnmetThreshold ex) {
  }
}

TEST(uptane, sign) {
  Config config;
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  config.uptane.metadata_path = "tests/test_data_tmp/";
  config.uptane.director_server = tls_server + "/director";
  config.tls.certificates_directory = "tests/test_data_tmp/";
  config.uptane.repo_server = tls_server + "/repo";
  config.uptane.private_key_path = "priv.key";
  config.uptane.public_key_path = "public.key";

  FSStorage storage(config);
  Uptane::Repository uptane_repo(config, storage);

  Json::Value tosign_json;
  tosign_json["mykey"] = "value";

  Json::Value signed_json =
      Crypto::signTuf((config.tls.certificates_directory / config.uptane.private_key_path).string(),
                      (config.tls.certificates_directory / config.uptane.public_key_path).string(), tosign_json);
  EXPECT_EQ(signed_json["signed"]["mykey"].asString(), "value");
  EXPECT_EQ(signed_json["signatures"][0]["keyid"].asString(),
            "6a809c62b4f6c2ae11abfb260a6a9a57d205fc2887ab9c83bd6be0790293e187");
  EXPECT_EQ(signed_json["signatures"][0]["sig"].asString().size() != 0, true);
}

TEST(SotaUptaneClientTest, device_registered) {
  Config conf("tests/config_tests_prov.toml");

  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.client_certificate);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.ca_file);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.pkey_file);
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_ca.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_cert.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_pkey.pem");

  FSStorage storage(conf);
  Uptane::Repository uptane(conf, storage);

  bool result = uptane.deviceRegister();
  EXPECT_EQ(result, true);
  EXPECT_EQ(boost::filesystem::exists(conf.tls.certificates_directory / conf.tls.client_certificate), true);
  EXPECT_EQ(boost::filesystem::exists(conf.tls.certificates_directory / conf.tls.ca_file), true);
  EXPECT_EQ(boost::filesystem::exists(conf.tls.certificates_directory / conf.tls.pkey_file), true);
}

TEST(SotaUptaneClientTest, device_registered_fail) {
  Config conf("tests/config_tests_prov.toml");

  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.client_certificate);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.ca_file);
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_ca.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_cert.pem");

  FSStorage storage(conf);
  Uptane::Repository uptane(conf, storage);

  provisioningResponse = ProvisionFailure;
  bool result = uptane.deviceRegister();
  provisioningResponse = ProvisionOK;
  EXPECT_EQ(result, false);
}

TEST(SotaUptaneClientTest, device_registered_putmanifest) {
  Config config;
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  config.uptane.metadata_path = "tests/test_data_tmp/";
  config.uptane.repo_server = tls_server + "/director";
  config.tls.certificates_directory = "tests/test_data_tmp/";
  config.uptane.repo_server = tls_server + "/repo";
  config.uptane.primary_ecu_serial = "testecuserial";
  config.uptane.private_key_path = "private.key";

  Uptane::SecondaryConfig ecu_config;
  ecu_config.full_client_dir = boost::filesystem::path("mybasedir");
  ecu_config.ecu_serial = "secondary_ecu_serial";
  ecu_config.ecu_hardware_id = "secondary_hardware";
  ecu_config.ecu_private_key = "sec.priv";
  ecu_config.ecu_public_key = "sec.pub";
  ecu_config.firmware_path = "/tmp/firmware.txt";
  config.uptane.secondaries.push_back(ecu_config);

  FSStorage storage(config);
  Uptane::Repository uptane(config, storage);

  boost::filesystem::remove(test_manifest);

  uptane.putManifest();
  EXPECT_EQ(boost::filesystem::exists(test_manifest), true);
  Json::Value json = Utils::parseJSONFile(test_manifest);

  EXPECT_EQ(json["signatures"].size(), 1u);
  EXPECT_EQ(json["signed"]["primary_ecu_serial"].asString(), "testecuserial");
  EXPECT_EQ(json["signed"]["ecu_version_manifest"].size(), 2u);
  EXPECT_EQ(json["signed"]["ecu_version_manifest"][0]["signed"]["ecu_serial"], "secondary_ecu_serial");
  EXPECT_EQ(json["signed"]["ecu_version_manifest"][0]["signed"]["installed_image"]["filepath"], "/tmp/firmware.txt");
}

TEST(SotaUptaneClientTest, device_ecu_register) {
  Config config;
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  config.uptane.metadata_path = "tests/";
  config.uptane.repo_server = tls_server + "/director";
  config.tls.certificates_directory = "tests/test_data_tmp/certs";

  config.uptane.repo_server = tls_server + "/repo";
  config.tls.server = tls_server;

  config.uptane.primary_ecu_serial = "testecuserial";
  config.uptane.private_key_path = "private.key";

  FSStorage storage(config);
  Uptane::Repository uptane(config, storage);
  uptane.ecuRegister();
  Json::Value ecu_data = Utils::parseJSONFile("tests/test_data_tmp/post.json");
  EXPECT_EQ(ecu_data["ecus"].size(), 1);
  EXPECT_EQ(ecu_data["primary_ecu_serial"].asString(), config.uptane.primary_ecu_serial);
}

TEST(SotaUptaneClientTest, RunForeverNoUpdates) {
  Config conf("tests/config_tests_prov.toml");
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  conf.uptane.metadata_path = "tests/test_data_tmp";
  conf.uptane.director_server = tls_server + "/director";
  conf.tls.certificates_directory = "tests/test_data_tmp/";
  conf.uptane.repo_server = tls_server + "/repo";
  conf.uptane.primary_ecu_serial = "CA:FE:A6:D2:84:9D";
  conf.uptane.private_key_path = "private.key";

  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.client_certificate);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.ca_file);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.pkey_file);
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_ca.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_cert.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_pkey.pem");
  boost::filesystem::remove(metadata_path + "director/timestamp.json");
  boost::filesystem::remove(metadata_path + "repo/timestamp.json");

  conf.tls.server = tls_server;
  event::Channel events_channel;
  command::Channel commands_channel;

  commands_channel << boost::make_shared<command::GetUpdateRequests>();
  commands_channel << boost::make_shared<command::GetUpdateRequests>();
  commands_channel << boost::make_shared<command::GetUpdateRequests>();
  commands_channel << boost::make_shared<command::Shutdown>();

  FSStorage storage(conf);
  Uptane::Repository repo(conf, storage);
  SotaUptaneClient up(conf, &events_channel, repo);
  up.runForever(&commands_channel);

  boost::shared_ptr<event::BaseEvent> event;
  if (!events_channel.hasValues()) {
    FAIL();
  }
  events_channel >> event;
  EXPECT_EQ(event->variant, "UptaneTargetsUpdated");
  if (!events_channel.hasValues()) {
    FAIL();
  }
  events_channel >> event;
  EXPECT_EQ(event->variant, "UptaneTimestampUpdated");
  if (!events_channel.hasValues()) {
    FAIL();
  }
  events_channel >> event;
  EXPECT_EQ(event->variant, "UptaneTimestampUpdated");
}

TEST(SotaUptaneClientTest, RunForeverHasUpdates) {
  Config conf("tests/config_tests_prov.toml");
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  conf.uptane.metadata_path = "tests/test_data_tmp";
  conf.uptane.director_server = tls_server + "/director";
  conf.tls.certificates_directory = "tests/test_data_tmp/";
  conf.uptane.repo_server = tls_server + "/repo";
  conf.uptane.primary_ecu_serial = "CA:FE:A6:D2:84:9D";
  conf.uptane.private_key_path = "private.key";

  Uptane::SecondaryConfig ecu_config;
  ecu_config.full_client_dir = boost::filesystem::path("mybasedir");
  ecu_config.ecu_serial = "secondary_ecu_serial";
  ecu_config.ecu_hardware_id = "secondary_hardware";
  ecu_config.ecu_private_key = "sec.priv";
  ecu_config.ecu_public_key = "sec.pub";
  ecu_config.firmware_path = "tests/test_data_tmp/firmware.txt";
  conf.uptane.secondaries.push_back(ecu_config);

  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.client_certificate);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.ca_file);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.pkey_file);
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_ca.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_cert.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_pkey.pem");
  boost::filesystem::remove(metadata_path + "director/timestamp.json");
  boost::filesystem::remove(metadata_path + "repo/timestamp.json");

  conf.tls.server = tls_server;
  event::Channel events_channel;
  command::Channel commands_channel;

  commands_channel << boost::make_shared<command::GetUpdateRequests>();
  commands_channel << boost::make_shared<command::Shutdown>();
  FSStorage storage(conf);
  Uptane::Repository repo(conf, storage);
  SotaUptaneClient up(conf, &events_channel, repo);
  up.runForever(&commands_channel);

  boost::shared_ptr<event::BaseEvent> event;
  if (!events_channel.hasValues()) {
    FAIL();
  }
  events_channel >> event;
  EXPECT_EQ(event->variant, "UptaneTargetsUpdated");
  event::UptaneTargetsUpdated *targets_event = static_cast<event::UptaneTargetsUpdated *>(event.get());
  EXPECT_EQ(targets_event->packages.size(), 1u);
  if (targets_event->packages.size()) {
    EXPECT_EQ(targets_event->packages[0].filename(),
              "agl-ota-qemux86-64-a0fb2e119cf812f1aa9e993d01f5f07cb41679096cb4492f1265bff5ac901d0d");
  }
  EXPECT_EQ(Utils::readFile("tests/test_data_tmp/firmware.txt"), "This is content");
}

TEST(SotaUptaneClientTest, RunForeverInstall) {
  Config conf("tests/config_tests_prov.toml");
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  conf.uptane.primary_ecu_serial = "testecuserial";
  conf.uptane.private_key_path = "private.key";
  conf.uptane.director_server = tls_server + "/director";
  conf.tls.certificates_directory = "tests/test_data_tmp/";
  conf.uptane.repo_server = tls_server + "/repo";

  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.client_certificate);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.ca_file);
  boost::filesystem::remove(conf.tls.certificates_directory / conf.tls.pkey_file);
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_ca.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_cert.pem");
  boost::filesystem::remove(conf.tls.certificates_directory / "bootstrap_pkey.pem");
  boost::filesystem::remove(test_manifest);

  conf.tls.server = tls_server;
  event::Channel events_channel;
  command::Channel commands_channel;

  std::vector<Uptane::Target> packages_to_install;
  Json::Value ot_json;
  ot_json["custom"]["ecuIdentifier"] = "testecuserial";
  ot_json["custom"]["targetFormat"] = "OSTREE";
  ot_json["length"] = 10;
  packages_to_install.push_back(Uptane::Target("testostree", ot_json));
  commands_channel << boost::make_shared<command::UptaneInstall>(packages_to_install);
  commands_channel << boost::make_shared<command::Shutdown>();
  FSStorage storage(conf);
  Uptane::Repository repo(conf, storage);
  SotaUptaneClient up(conf, &events_channel, repo);
  up.runForever(&commands_channel);

  EXPECT_EQ(boost::filesystem::exists(test_manifest), true);

  Json::Value json;
  Json::Reader reader;
  std::ifstream ks(test_manifest.c_str());
  std::string mnfst_str((std::istreambuf_iterator<char>(ks)), std::istreambuf_iterator<char>());

  reader.parse(mnfst_str, json);
  EXPECT_EQ(json["signatures"].size(), 1u);
  EXPECT_EQ(json["signed"]["primary_ecu_serial"].asString(), "testecuserial");
  EXPECT_EQ(json["signed"]["ecu_version_manifest"].size(), 1u);
}

TEST(SotaUptaneClientTest, UptaneSecondaryAdd) {
  Config config;
  Utils::copyDir("tests/test_data", "tests/test_data_tmp");
  config.uptane.metadata_path = "tests/";
  config.uptane.repo_server = tls_server + "/director";
  config.tls.certificates_directory = "tests/test_data_tmp/";
  config.uptane.repo_server = tls_server + "/repo";
  config.tls.server = tls_server;

  config.uptane.primary_ecu_serial = "testecuserial";
  config.uptane.private_key_path = "private.key";
  config.uptane.public_key_path = "public.key";

  Uptane::SecondaryConfig ecu_config;
  ecu_config.full_client_dir = boost::filesystem::path("mybasedir");
  ecu_config.ecu_serial = "secondary_ecu_serial";
  ecu_config.ecu_hardware_id = "secondary_hardware";
  ecu_config.ecu_private_key = "sec.priv";
  ecu_config.ecu_public_key = "sec.pub";
  ecu_config.firmware_path = "/tmp/firmware.txt";
  config.uptane.secondaries.push_back(ecu_config);

  FSStorage storage(config);
  Uptane::Repository uptane(config, storage);

  uptane.ecuRegister();
  Json::Value ecu_data = Utils::parseJSONFile("tests/test_data_tmp/post.json");
  EXPECT_EQ(ecu_data["ecus"].size(), 2);
  EXPECT_EQ(ecu_data["primary_ecu_serial"].asString(), config.uptane.primary_ecu_serial);
  EXPECT_EQ(ecu_data["ecus"][1]["ecu_serial"].asString(), "secondary_ecu_serial");
  EXPECT_EQ(ecu_data["ecus"][1]["hardware_identifier"].asString(), "secondary_hardware");
  EXPECT_EQ(ecu_data["ecus"][1]["clientKey"]["keytype"].asString(), "RSA");
  EXPECT_TRUE(ecu_data["ecus"][1]["clientKey"]["keyval"]["public"].asString().size() > 0);
}

#ifndef __NO_MAIN__
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  loggerSetSeverity(LVL_trace);
  return RUN_ALL_TESTS();
}
#endif
