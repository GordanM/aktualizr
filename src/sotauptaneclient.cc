#include "sotauptaneclient.h"

#include <boost/make_shared.hpp>

#include "crypto.h"
#include "json/json.h"
#include "logger.h"
#include "uptane/exceptions.h"
#include "utils.h"

SotaUptaneClient::SotaUptaneClient(const Config &config_in, event::Channel *events_channel_in)
    : config(config_in), events_channel(events_channel_in), uptane_repo(config) {}

void SotaUptaneClient::run(command::Channel *commands_channel) {
  while (true) {
    *commands_channel << boost::make_shared<command::GetUpdateRequests>();
    sleep(static_cast<unsigned int>(config.core.polling_sec));
  }
}

std::vector<OstreePackage> SotaUptaneClient::getAvailableUpdates() {
  std::vector<OstreePackage> result;
  std::vector<Uptane::Target> targets = uptane_repo.getNewTargets();
  for (std::vector<Uptane::Target>::iterator it = targets.begin(); it != targets.end(); ++it) {
    result.push_back(
        OstreePackage((*it).custom_["ecuIdentifier"].asString(), (*it).filename_, (*it).hash_.hash_, "",
                      config.getOstreeRepoServer()));  // should be changed when multiple targets are supported
  }
  return result;
}

void SotaUptaneClient::OstreeInstall(std::vector<OstreePackage> packages) {
  data::PackageManagerCredentials cred;
  cred.ca_file = (config.device.certificates_path / config.tls.ca_file).string();
  cred.pkey_file = (config.device.certificates_path / config.tls.pkey_file).string();
  cred.cert_file = (config.device.certificates_path / config.tls.client_certificate).string();
  for (std::vector<OstreePackage>::iterator it = packages.begin(); it != packages.end(); ++it) {
    data::InstallOutcome outcome = (*it).install(cred, config.ostree);
    data::OperationResult result = data::OperationResult::fromOutcome((*it).ref_name, outcome);
    Json::Value operation_result;
    operation_result["operation_result"] = result.toJson();
    uptane_repo.putManifest(operation_result);
  }
}

void SotaUptaneClient::runForever(command::Channel *commands_channel) {
  if (!boost::filesystem::exists(config.device.certificates_path / config.tls.client_certificate) ||
      !boost::filesystem::exists(config.device.certificates_path / config.tls.ca_file)) {
    if (!uptane_repo.deviceRegister() || !uptane_repo.ecuRegister()) {
      throw std::runtime_error(
          "Fatal error of tls or ecu device registration, please look at previous error log messages to understand "
          "the reason");
    }
  }
  uptane_repo.authenticate();
  uptane_repo.putManifest();
  uptane_repo.updateRoot();
  boost::thread polling_thread(boost::bind(&SotaUptaneClient::run, this, commands_channel));

  boost::shared_ptr<command::BaseCommand> command;
  while (*commands_channel >> command) {
    LOGGER_LOG(LVL_info, "got " + command->variant + " command");

    try {
      if (command->variant == "GetUpdateRequests") {
        std::vector<OstreePackage> updates = getAvailableUpdates();
        if (updates.size()) {
          LOGGER_LOG(LVL_info, "got new updates");
          *events_channel << boost::make_shared<event::UptaneTargetsUpdated>(updates);
        } else {
          LOGGER_LOG(LVL_info, "no new updates, sending UptaneTimestampUpdated event");
          *events_channel << boost::make_shared<event::UptaneTimestampUpdated>();
        }
      } else if (command->variant == "OstreeInstall") {
        command::OstreeInstall *ot_command = command->toChild<command::OstreeInstall>();
        std::vector<OstreePackage> packages = ot_command->packages;
        OstreeInstall(packages);
      } else if (command->variant == "Shutdown") {
        polling_thread.interrupt();
        return;
      }

    } catch (Uptane::SecurityException e) {
      LOGGER_LOG(LVL_error, e.what());
    }
  }
}
