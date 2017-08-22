#ifndef TEST_UTILS_H_
#define TEST_UTILS_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "utils.h"

std::string getFreePort();

class TestHelperProcess {
 public:
  TestHelperProcess(const std::string& argv0, const std::string& argv1);
  ~TestHelperProcess();

 private:
  pid_t pid_;
};

#endif  // TEST_UTILS_H_