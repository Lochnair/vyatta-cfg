#include <stdio.h>
#include <iostream>

#include "lib/vyatta_config.hpp"

using namespace std;

/*
 * check when deleting static-route
 */
static int
check_ip(const string& gw, const string& gw_ip)
{
  if (gw == "0.0.0.0/0") {
    string gateway_ip;
    vyatta::Config config;
    if (config.returnValue("system gateway-address", gateway_ip)) {
      if (gateway_ip == gw_ip) {
        return 1;
      }
    }
  }
  return 0;
}

/*
 * check when deleting static-route
 */
static int
check(const string& gw)
{
  vector<string> nhs;
  vyatta::Config config;

  config.listNodes("protocols static route 0.0.0.0/0 next-hop", nhs);
  for (size_t i = 0; i < nhs.size(); i ++) {
    if (nhs[i] == gw) {
      return 1;
    }
  }
  return 0;
}

static void
warn()
{
  vyatta::Config config;

  if (config.exists("system gateway-address")) {
    if (config.exists("protocols static route 0.0.0.0/0")) {
      cout << "Warning:" << endl;
      cout << "Both a 'system gateway-address' and a protocols static default route"  << endl;
      cout << "(0.0.0.0/0) are configured. This configuration is not recommended."  << endl;
    }
  }
}

/**
 * @brief The main function ubnt-gw-check application.
 * @param[in] argc Arguments count.
 * @param[in] argv Arguments array.
 * @return Exit status of the application.
 */
int main(int argc, char **argv)
{
  int rc = 0;

  if (argc == 2) {
    if (!strncmp(argv[1], "warn", 4)) {
      warn();
    } else {
      rc = check(argv[1]);
    }
  } else if (argc == 3) {
    rc = check_ip(argv[1], argv[2]);
  }
  return rc;
}
