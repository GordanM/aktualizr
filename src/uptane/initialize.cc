#include <string>

#include "uptane/uptanerepository.h"
#include "logger.h"
#include "bootstrap.h"
namespace Uptane {

// Postcondition: device_id is in the storage
bool Repository::initDeviceId (const UptaneConfig& uptane_config) {
	// if device_id is already stored, just return
	std::string device_id;
	if(storage.loadDeviceId(&device_id))
		return true;

	// if device_id is specified in config, just use it, otherwise generate a  random one
	device_id = uptane_config.device_id;
	if(device_id.empty())
		device_id = Utils::genPrettyName();

	storage.storeDeviceId(device_id);
	return true;
}
void Repository::resetDeviceId() {
	storage.clearDeviceId();
}

// Postcondition [(serial, hw_id)] is in the storage
bool Repository::initEcuSerials(const UptaneConfig& uptane_config) {
	if(storage.loadEcuSerials(NULL))
		return true;

	std::vector<std::pair<std::string, std::string> > ecu_serials;
	std::string primary_ecu_serial = uptane_config.primary_ecu_serial;
	if(primary_ecu_serial.empty())
		primary_ecu_serial = Utils::randomUuid();

	std::string primary_ecu_hardware_id = uptane_config.primary_ecu_hardware_id;
	if(primary_ecu_hardware_id.empty()) {
		char hostname[200];
		if(gethostname(hostname, 200) < 0)
			return false;
		primary_ecu_hardware_id = hostname;
	}

	ecu_serials.push_back(std::pair<std::string, std::string>(primary_ecu_serial, primary_ecu_hardware_id));

	std::vector<Uptane::SecondaryConfig>::const_iterator it;
	int index = 0;
	for (it = uptane_config.secondaries.begin(); it != uptane_config.secondaries.end(); ++it) {
		std::string secondary_ecu_serial = it->ecu_serial;
		if (secondary_ecu_serial.empty())
			secondary_ecu_serial = Utils::intToString(index++) + "-" + primary_ecu_serial;
		std::string secondary_ecu_hardware_id = it->ecu_hardware_id;
		if (secondary_ecu_hardware_id.empty()) {
			secondary_ecu_hardware_id = primary_ecu_hardware_id;
		}
		ecu_serials.push_back(std::pair<std::string, std::string>(secondary_ecu_serial, secondary_ecu_hardware_id));
	}

	storage.storeEcuSerials(ecu_serials);
	return true;
}
void Repository::resetEcuSerials() {
	storage.clearEcuSerials();
}

// Postcondition: (public, private) is in the storage. It should not be stored until secondaries are provisioned
bool Repository::initEcuKeys() {
	if(storage.loadPrimaryKeys(NULL, NULL))
		return true;

	std::string primary_public;
	std::string primary_private;
	if(!Crypto::generateRSAKeyPair(&primary_public, &primary_private))
		return false;
	
	std::vector<std::pair<std::string, std::string> > ecu_serials;
	// InitEcuSerials should have been called by this point
	if(!storage.loadEcuSerials(&ecu_serials) || ecu_serials.size() < 1)
		return false;
	
	std::vector<std::pair<std::string, std::string> >::const_iterator it;
	// skip first element, that is primary serial
	for(it = ecu_serials.begin()+1; it != ecu_serials.end(); it++) {
		std::string secondary_public;
		std::string secondary_keytype;
		if(!transport.reqPublicKey(it->first, &secondary_keytype, &secondary_public)) {
			std::string secondary_private;
			if (!Crypto::generateRSAKeyPair(&secondary_public, &secondary_private)) {
				LOGGER_LOG(LVL_error, "Could not generate rsa keys for secondary " << it->second << "@"
						<< it->first);
				return false;
			}
			transport.sendKeys(it->first, secondary_public, secondary_private);
		}
	}
	storage.storePrimaryKeys(primary_public, primary_private);
	return true;
}

void Repository::resetEcuKeys() {
	storage.clearPrimaryKeys();
}

// Postcondition: TLS credentials are in the storage
InitRetCode Repository::initTlsCreds(const ProvisionConfig& provision_config) {
	std::string pkey;
	std::string cert;
	std::string ca;
	if (storage.loadTlsCreds(&ca, &cert, &pkey)) {
		LOGGER_LOG(LVL_trace, "Device already registered, proceeding");
		// set provisioned credentials
		http.setCerts(ca, cert, pkey);
		return INIT_RET_OK;
	}
	// set bootstrap credentials
	Bootstrap boot(provision_config.provision_path, provision_config.p12_password);
	http.setCerts(boot.getCa(), boot.getCert(), boot.getPkey());

	Json::Value data;
	std::string device_id;
	if(!storage.loadDeviceId(&device_id)) {
		LOGGER_LOG(LVL_error, "device_id unknown during autoprovisioning process");
		return INIT_RET_STORAGE_FAILURE;
	}
	data["deviceId"] = device_id;
	data["ttl"] = provision_config.expiry_days;
	HttpResponse response = http.post(provision_config.server + "/devices", data);
	if (!response.isOk()) {
		Json::Value resp_code = response.getJson()["code"];
		if(resp_code.isString() && resp_code.asString() == "device_already_registered") {
			LOGGER_LOG(LVL_error, "Device id" << device_id << "is occupied");
			return INIT_RET_OCCUPIED;
		} else {
			LOGGER_LOG(LVL_error, "Autoprovisioning failed, response: " << response.body);
			return INIT_RET_SERVER_FAILURE;
		}
	}

	FILE *device_p12 = fmemopen(const_cast<char *>(response.body.c_str()), response.body.size(), "rb");
	if (!Crypto::parseP12(device_p12, "", &pkey, &cert, &ca)) {
		return INIT_RET_BAD_P12;
	}
	fclose(device_p12);
	storage.storeTlsCreds(ca, cert, pkey);

	// set provisioned credentials
	http.setCerts(ca, cert, pkey);

	// TODO: acknowledgement to the server
	LOGGER_LOG(LVL_info, "Provisioned successfully on Device Gateway");
	return INIT_RET_OK;
}
void Repository::resetTlsCreds() {
	storage.clearTlsCreds();
}

// Postcondition: "ECUs registered" flag set in the storage
InitRetCode Repository::initEcuRegister() {
	if(storage.loadEcuRegistered())
		return INIT_RET_OK;

	std::string primary_public;
	if(!storage.loadPrimaryKeys(&primary_public, NULL)) {
		LOGGER_LOG(LVL_error, "Unable to read primary public key from the storage");
		return INIT_RET_STORAGE_FAILURE;
	}

	std::vector<std::pair<std::string, std::string> > ecu_serials;
	// InitEcuSerials should have been called by this point
	if(!storage.loadEcuSerials(&ecu_serials) || ecu_serials.size() < 1)
		return INIT_RET_STORAGE_FAILURE;
	
	Json::Value all_ecus;
	all_ecus["primary_ecu_serial"] = ecu_serials[0].first;
	all_ecus["ecus"] = Json::arrayValue;
	{
		Json::Value primary_ecu;
		primary_ecu["hardware_identifier"] = ecu_serials[0].second;
		primary_ecu["ecu_serial"] = ecu_serials[0].first;
		primary_ecu["clientkey"]["keytype"] = "RSA";
		primary_ecu["clientkey"]["keyval"]["public"] = primary_public;
		all_ecus["ecus"].append(primary_ecu);
	}

	std::vector<std::pair<std::string, std::string> >::const_iterator it;
	for(it = ecu_serials.begin()+1; it != ecu_serials.end(); it++) {
		std::string secondary_public;
		std::string secondary_keytype;
		if(!transport.reqPublicKey(it->first, &secondary_keytype, &secondary_public)) {
			LOGGER_LOG(LVL_error, "Unable to read public key from secondary " << it->first);
			return INIT_RET_SECONDARY_FAILURE;
		}
		Json::Value ecu;
		ecu["hardware_identifier"] = it->second;
		ecu["ecu_serial"] = it->first;
		ecu["clientkey"]["keytype"] = secondary_keytype;
		ecu["clientkey"]["keyval"]["public"] = secondary_public;
		all_ecus["ecus"].append(ecu);
	}


	HttpResponse response = http.post(config.tls.server + "/director/ecus", all_ecus);
	if (!response.isOk()) {
		Json::Value resp_code = response.getJson()["code"];
		if (resp_code.isString() && (resp_code.asString() == "ecu_already_registered" || resp_code.asString() == "device_already_registered")) {
			LOGGER_LOG(LVL_error, "Some ECU is already registered");
			return INIT_RET_OCCUPIED;
		} else {
			LOGGER_LOG(LVL_error, "Error registering device on Uptane, response: " << response.body);
			return INIT_RET_SERVER_FAILURE;
		}
	}
	// do not call storage.storeEcuRegistered(), it will be called from the top-level Init function after the acknowledgement
	LOGGER_LOG(LVL_info, "ECUs have been successfully registered to the server");
	return INIT_RET_OK;
}

// Postcondition: "ECUs registered" flag set in the storage
bool Repository::initialize() {
	if(storage.loadEcuRegistered())
		return true;

	// if device has aready been registered, just create new device and reprovision
	//   it should be changed/fixed when the backend supports registration acknowledgement
	for(int i = 0; i < MaxInitializationAttempts; i++) {
		if(!initDeviceId(config.uptane)) {
			LOGGER_LOG(LVL_error, "Device ID generation failed, abort initialization");
			return false;
		}
		if(!initEcuSerials(config.uptane)) {
			LOGGER_LOG(LVL_error, "ECU serial generation failed, abort initialization");
			return false;
		}
		if(!initEcuKeys()) {
			LOGGER_LOG(LVL_error, "ECU key generation failed, abort initialization");
			return false;
		}
		InitRetCode ret_code = initTlsCreds(config.provision);
		if(ret_code == INIT_RET_OCCUPIED)  {
			resetEcuKeys();
			resetEcuSerials();
			resetDeviceId();
			LOGGER_LOG(LVL_info, "Device name is already registered, restart");
			continue;
		} else if(ret_code != INIT_RET_OK) {
			LOGGER_LOG(LVL_error, "Autoprovisioning failed, abort initialization");
			return false;
		}

		ret_code = initEcuRegister();
		if(ret_code == INIT_RET_OCCUPIED) {
			// TODO: proper way to process this case after acknowledgement is implemented on the server
			//   is to download the list of registered ECUs and compare it to the list of ECUs present.
			//   If they coincide, that means that the registration has already been done by this device,
			//   but the registration process has been interrupted between sending the acknowledgement
			//   and setting the flag in the storage. Otherwise we have a name collision and should re-run
			//   initialization process.
			//   Now we will just repeat initialization all the time.
			resetTlsCreds();
			resetEcuKeys();
			resetEcuSerials();
			resetDeviceId();
			LOGGER_LOG(LVL_info, "ECU serial is already registered, restart");
			continue;

		} else if (ret_code != INIT_RET_OK) {
			LOGGER_LOG(LVL_error, "ECU registration failed, abort initialization");
			return false;
		}

		//TODO: acknowledge on server _before_ setting the flag
		storage.storeEcuRegistered();
		return true;
	}
	LOGGER_LOG(LVL_error, "Initialization failed after " << MaxInitializationAttempts << " attempts");
	return false;
}

void Repository::initReset() {
	storage.clearEcuRegistered();
	resetTlsCreds();
	resetEcuKeys();
	resetEcuSerials();
	resetDeviceId();
}

}
