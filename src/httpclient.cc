#include "httpclient.h"

#include <assert.h>
#include <libp11.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <sys/stat.h>
#include <boost/lexical_cast.hpp>
#include <boost/move/make_unique.hpp>
#include <boost/move/utility.hpp>

#include "logger.h"
#include "openssl_compat.h"

/*****************************************************************************/
/**
 * \par Description:
 *    A writeback handler for the curl library. It handles writing response
 *    data from curl into a string.
 *    https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 *
 */
static size_t writeString(void* contents, size_t size, size_t nmemb, void* userp) {
  assert(userp);
  // append the writeback data to the provided string
  (static_cast<std::string*>(userp))->append((char*)contents, size * nmemb);

  // return size of written data
  return size * nmemb;
}

HttpClient::HttpClient() : user_agent(std::string("Aktualizr/") + AKTUALIZR_VERSION) {
  curl = curl_easy_init();
  headers = NULL;
  http_code = 0;

  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 60L);

  // let curl use our write function
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeString);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);

  if (loggerGetSeverity() == LVL_trace) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }

  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Accept: */*");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());
}

HttpClient::HttpClient(const HttpClient& curl_in) {
  curl = curl_easy_duphandle(curl_in.curl);
  token = curl_in.token;

  struct curl_slist* inlist = curl_in.headers;
  headers = NULL;
  struct curl_slist* tmp;

  while (inlist) {
    tmp = curl_slist_append(headers, inlist->data);

    if (!tmp) {
      curl_slist_free_all(headers);
      throw std::runtime_error("curl_slist_append returned null");
    }

    headers = tmp;
    inlist = inlist->next;
  }
}

HttpClient::~HttpClient() {
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
}

HttpResponse HttpClient::get(const std::string& url) {
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  LOGGER_LOG(LVL_debug, "GET " << url);
  return perform(curl, RETRY_TIMES);
}

void HttpClient::setCerts(const std::string& ca, const std::string& cert, const std::string& pkey) {
  boost::movelib::unique_ptr<TemporaryFile> tmp_ca_file = boost::movelib::make_unique<TemporaryFile>("tls-ca");
  boost::movelib::unique_ptr<TemporaryFile> tmp_cert_file = boost::movelib::make_unique<TemporaryFile>("tls-cert");
  boost::movelib::unique_ptr<TemporaryFile> tmp_pkey_file = boost::movelib::make_unique<TemporaryFile>("tls-pkey");

  tmp_ca_file->PutContents(ca);
  tmp_cert_file->PutContents(cert);
  tmp_pkey_file->PutContents(pkey);

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true);
  curl_easy_setopt(curl, CURLOPT_CAINFO, tmp_ca_file->Path().c_str());
  curl_easy_setopt(curl, CURLOPT_SSLCERT, tmp_cert_file->Path().c_str());
  curl_easy_setopt(curl, CURLOPT_SSLKEY, tmp_pkey_file->Path().c_str());

  tls_ca_file = boost::move_if_noexcept(tmp_ca_file);
  tls_cert_file = boost::move_if_noexcept(tmp_cert_file);
  tls_pkey_file = boost::move_if_noexcept(tmp_pkey_file);
}

bool HttpClient::setPkcs11(const std::string& module, const std::string& pass, const std::string& certid,
                           const std::string& ca) {
  std::string certname;

  // Get certificate name
  try {
    P11ContextWrapper ctx(module);
    P11SlotsWrapper slots(ctx.get());
    PKCS11_SLOT* slot = PKCS11_find_token(ctx.get(), slots.get_slots(), slots.get_nslots());
    if (!slot || !slot->token) {
      LOGGER_LOG(LVL_error, "Couldn't find pkcs11 token");
      return false;
    }
    int slot_ind = (((uintptr_t)slot) - ((uintptr_t)slots.get_slots())) / sizeof(slots.get_slots()[0]);
    certname = std::string("slot_") + boost::lexical_cast<std::string>(slot_ind) + "-id_";
    for (int i = 0; i < certid.length(); i++) {
      unsigned char nibble = certid[i] >> 4;
      if (nibble >= 10)
        certname.append(1, (nibble - 10) + 'a');
      else
        certname.append(1, nibble + '0');

      nibble = certid[i] & 0x0F;
      if (nibble >= 10)
        certname.append(1, (nibble - 10) + 'a');
      else
        certname.append(1, nibble + '0');
    }
    // TODO: a) will we store root CA in the token as well?
    //       b) does this set private key?
  } catch (...) {
    return false;
  }

  ENGINE_load_builtin_engines();
#if AKTUALIZR_OPENSSL_AFTER_11
  OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_OPENSSL, NULL);
#else
// TODO: how to initialize SSL engine in 1.0.2?
#endif
  // TODO: support reinitialization
  ssl_engine = ENGINE_by_id("pkcs11");
  if (!ssl_engine) return false;
  if (!ENGINE_ctrl_cmd_string(ssl_engine, "SO_PATH", kPkcs11Path, 0) ||
      !ENGINE_ctrl_cmd_string(ssl_engine, "ID", "pkcs11", 0) ||
      !ENGINE_ctrl_cmd_string(ssl_engine, "LIST_ADD", "1", 0) || !ENGINE_ctrl_cmd_string(ssl_engine, "LOAD", NULL, 0) ||
      !ENGINE_ctrl_cmd_string(ssl_engine, "MODULE_PATH", module.c_str(), 0) ||
      !ENGINE_ctrl_cmd_string(ssl_engine, "PIN", pass.c_str(), 0)) {
    LOGGER_LOG(LVL_error, "Engine command failed");
    return false;
  }

  if (!ENGINE_init(ssl_engine)) {
    LOGGER_LOG(LVL_error, "Engine initialization failed");
    return false;
  }

  curl_easy_setopt(curl, CURLOPT_SSLCERT, certname);
  curl_easy_setopt(curl, CURLOPT_SSLKEY, certname);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
  curl_easy_setopt(curl, CURLOPT_SSLENGINE, "pkcs11");
  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
  curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);

  // Root CA is not stored in the pkcs11 device
  boost::movelib::unique_ptr<TemporaryFile> tmp_ca_file = boost::movelib::make_unique<TemporaryFile>("tls-ca");
  tmp_ca_file->PutContents(ca);
  curl_easy_setopt(curl, CURLOPT_CAINFO, tmp_ca_file->Path().c_str());
  tls_ca_file = boost::move_if_noexcept(tmp_ca_file);
  return true;
}

HttpResponse HttpClient::post(const std::string& url, const Json::Value& data) {
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_POST, 1);
  std::string data_str = Json::FastWriter().write(data);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data_str.c_str());
  LOGGER_LOG(LVL_trace, "post request body:" << data);
  return perform(curl, RETRY_TIMES);
}

HttpResponse HttpClient::put(const std::string& url, const Json::Value& data) {
  CURL* curl_put = curl_easy_duphandle(curl);

  curl_easy_setopt(curl_put, CURLOPT_URL, url.c_str());
  std::string data_str = Json::FastWriter().write(data);
  curl_easy_setopt(curl_put, CURLOPT_POSTFIELDS, data_str.c_str());
  curl_easy_setopt(curl_put, CURLOPT_CUSTOMREQUEST, "PUT");
  LOGGER_LOG(LVL_trace, "put request body:" << data);
  HttpResponse result = perform(curl_put, RETRY_TIMES);
  curl_easy_cleanup(curl_put);
  return result;
}

HttpResponse HttpClient::perform(CURL* curl_handler, int retry_times) {
  std::string response_str;
  curl_easy_setopt(curl_handler, CURLOPT_WRITEDATA, (void*)&response_str);
  CURLcode result = curl_easy_perform(curl_handler);
  curl_easy_getinfo(curl_handler, CURLINFO_RESPONSE_CODE, &http_code);
  HttpResponse response(response_str, http_code, result, (result != CURLE_OK) ? curl_easy_strerror(result) : "");
  if (response.curl_code != CURLE_OK || response.http_status_code >= 500) {
    std::ostringstream error_message;
    error_message << "curl error " << response.http_status_code << ": " << response.error_message;
    LOGGER_LOG(LVL_error, error_message.str());
    if (retry_times) {
      sleep(1);
      response = perform(curl_handler, --retry_times);
    }
  }
  LOGGER_LOG(LVL_trace, "response: " << response.body);
  return response;
}

HttpResponse HttpClient::download(const std::string& url, curl_write_callback callback, void* userp) {
  CURL* curl_download = curl_easy_duphandle(curl);
  curl_easy_setopt(curl_download, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl_download, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl_download, CURLOPT_WRITEFUNCTION, callback);
  curl_easy_setopt(curl_download, CURLOPT_WRITEDATA, userp);

  CURLcode result = curl_easy_perform(curl_download);
  curl_easy_getinfo(curl_download, CURLINFO_RESPONSE_CODE, &http_code);
  HttpResponse response("", http_code, result, (result != CURLE_OK) ? curl_easy_strerror(result) : "");
  curl_easy_cleanup(curl_download);
  return response;
}

// vim: set tabstop=2 shiftwidth=2 expandtab:
