#ifndef HTTPCLIENT_H_
#define HTTPCLIENT_H_

#include <curl/curl.h>
#include <libp11.h>
#include <boost/move/unique_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include "json/json.h"

#include "config.h"
#include "httpinterface.h"
#include "logger.h"
#include "utils.h"

#define kPkcs11Path "/usr/lib/engine/libp11.so"

/**
 * Helper class to manage curl_global_init/curl_global_cleanup calls
 */
class CurlGlobalInitWrapper {
 public:
  CurlGlobalInitWrapper() { curl_global_init(CURL_GLOBAL_DEFAULT); }
  ~CurlGlobalInitWrapper() { curl_global_cleanup(); }
};

class P11ContextWrapper {
 public:
  P11ContextWrapper(const std::string &module) {
    // never returns NULL
    ctx = PKCS11_CTX_new();
    if (PKCS11_CTX_load(ctx, module.c_str())) {
      PKCS11_CTX_free(ctx);
      LOGGER_LOG(LVL_error, "Couldn't load PKCS11 module " << module);
      throw std::runtime_error("PKCS11 error");
    }
  }
  ~P11ContextWrapper() {
    PKCS11_CTX_unload(ctx);
    PKCS11_CTX_free(ctx);
  }
  PKCS11_CTX *get() { return ctx; }

 private:
  PKCS11_CTX *ctx;
};

class P11SlotsWrapper {
 public:
  P11SlotsWrapper(PKCS11_CTX *ctx_in) {
    ctx = ctx_in;
    if (PKCS11_enumerate_slots(ctx, &slots, &nslots)) {
      LOGGER_LOG(LVL_error, "Couldn't enumerate slots");
      throw std::runtime_error("PKCS11 error");
    }
  }
  ~P11SlotsWrapper() { PKCS11_release_all_slots(ctx, slots, nslots); }
  PKCS11_SLOT *get_slots() { return slots; }
  unsigned int get_nslots() { return nslots; }

 private:
  PKCS11_CTX *ctx;
  PKCS11_SLOT *slots;
  unsigned int nslots;
};

class HttpClient : public HttpInterface {
 public:
  HttpClient();
  HttpClient(const HttpClient &);
  virtual ~HttpClient();
  virtual HttpResponse get(const std::string &url);
  virtual HttpResponse post(const std::string &url, const Json::Value &data);
  virtual HttpResponse put(const std::string &url, const Json::Value &data);

  virtual HttpResponse download(const std::string &url, curl_write_callback callback, void *userp);
  virtual void setCerts(const std::string &ca, const std::string &cert, const std::string &pkey);
  virtual bool setPkcs11(const std::string &module, const std::string &pass, const std::string &certid,
                         const std::string &ca);
  unsigned int http_code;
  std::string token; /**< the OAuth2 token stored as string */

 private:
  /**
   * These are here to catch a common programming error where a Json::Value is
   * implicitly constructed from a std::string. By having an private overload
   * that takes string (and with no implementation), this will fail during
   * compilation.
   */
  HttpResponse post(const std::string &url, const std::string data);
  HttpResponse put(const std::string &url, const std::string data);

  CurlGlobalInitWrapper manageCurlGlobalInit_;  // Must be first member to ensure curl init/shutdown happens first/last
  CURL *curl;
  curl_slist *headers;
  HttpResponse perform(CURL *curl_handler, int retry_times);
  std::string user_agent;

  static CURLcode sslCtxFunction(CURL *handle, void *sslctx, void *parm);
  boost::mutex tls_mutex;
  boost::movelib::unique_ptr<TemporaryFile> tls_ca_file;
  boost::movelib::unique_ptr<TemporaryFile> tls_cert_file;
  boost::movelib::unique_ptr<TemporaryFile> tls_pkey_file;
  ENGINE *ssl_engine;
  static const int RETRY_TIMES = 2;
};
#endif
