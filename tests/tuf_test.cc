#include <gtest/gtest.h>
#include <json/json.h>
#include <logger.h>
#include <uptane/exceptions.h>

#include "uptane/tuf.h"
#include "utils.h"

Uptane::TimeStamp now("2017-01-01T01:00:00Z");

TEST(Root, RootValidates) {
  Json::Value initial_root = Utils::parseJSONFile("tests/tuf/sample1/root.json");
  LOGGER_LOG(LVL_info, "Root is:" << initial_root);

  Uptane::Root root1(Uptane::Root::kAcceptAll);
  Json::Value i = root1.UnpackSignedObject(now, "director", Uptane::Role::Root(), initial_root);
  Uptane::Root root("director", i);

  Json::Value unpacked = root.UnpackSignedObject(now, "director", Uptane::Role::Root(), initial_root);
  EXPECT_EQ(unpacked, initial_root["signed"]);
}

TEST(Root, RootJsonNoKeys) {
  Uptane::Root root1(Uptane::Root::kAcceptAll);
  Json::Value initial_root = Utils::parseJSONFile("tests/tuf/sample1/root.json");
  LOGGER_LOG(LVL_info, "Root is:" << initial_root);
  Json::Value i = root1.UnpackSignedObject(now, "director", Uptane::Role::Root(), initial_root);
  i.removeMember("keys");
  EXPECT_THROW(Uptane::Root("director", i), Uptane::InvalidMetadata);
}

TEST(Root, RootJsonNoRoles) {
  Uptane::Root root1(Uptane::Root::kAcceptAll);
  Json::Value initial_root = Utils::parseJSONFile("tests/tuf/sample1/root.json");
  LOGGER_LOG(LVL_info, "Root is:" << initial_root);
  Json::Value i = root1.UnpackSignedObject(now, "director", Uptane::Role::Root(), initial_root);
  i.removeMember("roles");
  EXPECT_THROW(Uptane::Root("director", i), Uptane::InvalidMetadata);
}

TEST(TimeStamp, Parsing) {
  Uptane::TimeStamp t_old("2038-01-19T02:00:00Z");
  Uptane::TimeStamp t_new("2038-01-19T03:14:06Z");

  Uptane::TimeStamp t_invalid;

  EXPECT_LT(t_old, t_new);
  EXPECT_GT(t_new, t_old);
  EXPECT_FALSE(t_invalid < t_old);
  EXPECT_FALSE(t_old < t_invalid);
  EXPECT_FALSE(t_invalid < t_invalid);
}

TEST(TimeStamp, ParsingInvalid) { EXPECT_THROW(Uptane::TimeStamp("2038-01-19T0"), Uptane::InvalidMetadata); }

TEST(TimeStamp, Now) {
  Uptane::TimeStamp t_past("1982-12-13T02:00:00Z");
  Uptane::TimeStamp t_future("2038-01-19T03:14:06Z");
  Uptane::TimeStamp t_now(Uptane::TimeStamp::Now());

  EXPECT_LT(t_past, t_now);
  EXPECT_LT(t_now, t_future);
}

#ifndef __NO_MAIN__
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  loggerSetSeverity(LVL_trace);
  return RUN_ALL_TESTS();
}
#endif