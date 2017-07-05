#ifndef UPTANE_REPOSITORY_H_
#define UPTANE_REPOSITORY_H_

#include <json/json.h>
#include <vector>
#include "config.h"
#include "uptane/secondary.h"
#include "uptane/testbusprimary.h"
#include "uptane/tufrepository.h"

#include "crypto.h"

namespace Uptane {

class Repository {
 public:
  Repository(const Config &config);
  void updateRoot(Version version = Version());
  void putManifest();
  void putManifest(const Json::Value &);
  void addSecondary(const std::string &ecu_serial, const std::string &hardware_identifier);

  std::vector<Uptane::Target> getNewTargets();
  bool deviceRegister();
  bool ecuRegister();
  bool authenticate();

 private:
  struct SecondaryConfig {
    std::string ecu_serial;
    std::string ecu_hardware_id;
  };
  Config config;
  TufRepository director;
  TufRepository image;
  HttpClient http;
  Json::Value manifests;
  std::vector<SecondaryConfig> registered_secondaries;

  std::vector<Secondary> secondaries;
  TestBusPrimary transport;
  friend class TestBusSecondary;
};
};

#endif