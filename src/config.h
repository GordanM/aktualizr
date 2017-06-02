#ifndef CONFIG_H_
#define CONFIG_H_

#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/uuid/uuid.hpp>             // uuid class
#include <boost/uuid/uuid_generators.hpp>  // generators
#include <boost/uuid/uuid_io.hpp>
#include <string>

#ifdef WITH_GENIVI
#include <dbus/dbus.h>
#endif

enum Auth { OAUTH2 = 0, CERTIFICATE };

enum PackageManager { PMOFF = 0, PMOSTREE };

struct CoreConfig {
  CoreConfig() : server("http://127.0.0.1:8080"), polling(true), polling_sec(10) {}

  std::string server;
  bool polling;
  unsigned long long polling_sec;
  Auth auth_type;
};

struct AuthConfig {
  AuthConfig() : server("http://127.0.0.1:9001"), client_id("client-id"), client_secret("client-secret") {}

  std::string server;
  std::string client_id;
  std::string client_secret;
};

#ifdef WITH_GENIVI
// DbusConfig depends on DBusBusType with is defined in libdbus
// We don't want to take that dependency unless it is required
struct DbusConfig {
  DbusConfig()
      : software_manager("org.genivi.SoftwareLoadingManager"),
        software_manager_path("/org/genivi/SoftwareLoadingManager"),
        path("/org/genivi/SotaClient"),
        interface("org.genivi.SotaClient"),
        timeout(0),
        bus(DBUS_BUS_SESSION) {}

  std::string software_manager;
  std::string software_manager_path;
  std::string path;
  std::string interface;
  unsigned int timeout;
  DBusBusType bus;
};
#else
struct DbusConfig {};
#endif

struct DeviceConfig {
  DeviceConfig()
      : uuid("123e4567-e89b-12d3-a456-426655440000"),
        packages_dir("/tmp/"),
        certificates_path("/tmp/aktualizr/"),
        package_manager(PMOFF) {
    createCertificatesPath();
  }
  void createCertificatesPath();

  std::string uuid;
  boost::filesystem::path packages_dir;
  boost::filesystem::path certificates_path;
  PackageManager package_manager;
};

struct GatewayConfig {
  GatewayConfig() : http(true), rvi(false), socket(false), dbus(false) {}
  bool http;
  bool rvi;
  bool socket;
  bool dbus;
};

struct NetworkConfig {
  NetworkConfig() : socket_commands_path("/tmp/sota-commands.socket"), socket_events_path("/tmp/sota-events.socket") {
    socket_events.push_back("DownloadComplete");
    socket_events.push_back("DownloadFailed");
  }
  std::string socket_commands_path;
  std::string socket_events_path;
  std::vector<std::string> socket_events;
};

struct RviConfig {
  RviConfig()
      : node_host("localhost"),
        node_port("8810"),
        device_key("device.key"),
        device_cert("device.crt"),
        ca_cert("ca.pem"),
        cert_dir(""),
        cred_dir("") {}
  std::string node_host;
  std::string node_port;
  std::string device_key;
  std::string device_cert;
  std::string ca_cert;
  std::string cert_dir;
  std::string cred_dir;
};

struct TlsConfig {
  TlsConfig() : server("localhost"), ca_file("ca.pem"), pkey_file("pkey.pem"), client_certificate("client.pem") {}
  std::string server;
  std::string ca_file;
  std::string pkey_file;
  std::string client_certificate;
};

struct ProvisionConfig {
  ProvisionConfig()
      : p12_path(""),
        p12_password(""),
        expiry_days("36000"),
        device_id(boost::lexical_cast<std::string>(boost::uuids::random_generator()())) {}
  std::string p12_path;
  std::string p12_password;
  std::string expiry_days;
  std::string device_id;
};

struct UptaneConfig {
  UptaneConfig()
      : primary_ecu_serial(""),
        primary_ecu_hardware_id(""),
        ostree_server(""),
        director_server(""),
        repo_server(""),
        metadata_path(""),
        private_key_path("ecukey.pem"),
        public_key_path("ecukey.pub"),
        disable_keyid_validation(false) {}
  std::string primary_ecu_serial;
  std::string primary_ecu_hardware_id;
  std::string ostree_server;
  std::string director_server;
  std::string repo_server;
  boost::filesystem::path metadata_path;
  std::string private_key_path;
  std::string public_key_path;
  bool disable_keyid_validation;
};

struct OstreeConfig {
  OstreeConfig() : os(""), sysroot("") {}
  std::string os;
  std::string sysroot;
};

class Config {
 public:
  void updateFromToml(const std::string& filename);
  void updateFromTomlString(const std::string& contents);
  void updateFromCommandLine(const boost::program_options::variables_map& cmd);
  std::string getUptaneRepoServer();
  std::string getUptaneDirectorServer();
  std::string getOstreeRepoServer();

  // config data structures
  CoreConfig core;
  AuthConfig auth;
  DeviceConfig device;
  DbusConfig dbus;
  GatewayConfig gateway;
  RviConfig rvi;
  NetworkConfig network;
  TlsConfig tls;
  ProvisionConfig provision;
  UptaneConfig uptane;
  OstreeConfig ostree;

 private:
  void updateFromPropertyTree(const boost::property_tree::ptree& pt);
};

#endif  // CONFIG_H_
