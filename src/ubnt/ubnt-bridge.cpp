#include <stdio.h>
#include <iostream>
#include <errno.h>
#include <getopt.h>

#include "lib/vyatta_interface.hpp"
#include "lib/vyatta_config.hpp"

#include <boost/filesystem.hpp>

using namespace std;
typedef vyatta::Interface InterfaceT;

static int
system_pipe(const string& cmd,
            const string& tool,
            const string& msg)
{
  int ret = EXIT_SUCCESS;

  string pipe_cmd = "sudo " + tool + " -batch - ";
  errno = 0;
  FILE* pipe = popen(pipe_cmd.c_str(), "w");
  if (!pipe) {
    cerr << msg << ": cannot open pipe" << endl;
    return EXIT_FAILURE;
  }
  size_t size = fwrite(cmd.c_str(), cmd.size(), 1, pipe);
  if (size != 1) {
    cerr << msg << ": pipe is broken" << endl;
    ret = EXIT_FAILURE;
  }
  int rc = pclose(pipe);
  if (rc) {
    cerr << cmd << " failed:";
    if (rc == -1) {
      rc = EXIT_FAILURE;
      cerr << errno << "(" << strerror(errno) << ")";
    } else {
      rc = WEXITSTATUS(rc);
      cerr << WEXITSTATUS(rc);
    }
    cerr << endl;
    ret = rc;
  }
  return ret;
}

static int
system_ip(const string& cmd)
{
  return system_pipe(cmd, "/sbin/ip", "IP");
}

static int
system_bridge(const string& cmd)
{
  return system_pipe(cmd, "/sbin/bridge", "Bridge");
}

static int
delete_bridge(const string& ifname)
{
  vector<string> intfs;
  InterfaceT::listSystemInterfaces(intfs);
  for (size_t i = 0; i < intfs.size(); i ++) {
    InterfaceT intf(intfs[i]);
    if (!intf.get()) {
      continue;
    }
    if (intf.bridge_grp() == ifname) {
      cerr << "Interfaces are still assigned to bridge " << ifname << endl;
      return EXIT_FAILURE;
    }
  }

  string cmd = "link set " + ifname + " down\n";
  cmd += "link del dev " + ifname;

  return system_ip(cmd);
}

static int
add_bridge_port(const string& bridge,
                const string& ifname,
                InterfaceT& intf,
                vyatta::Config& config)
{
  string cost, priority, val;

  if (bridge.empty()) {
    return EXIT_SUCCESS;
  }

  config.returnValue("bond-group", val);
  if (!val.empty()) {
    cerr << "Error: can not add interface " + ifname +
            " that is part of bond-group to bridge" << endl;
    return EXIT_FAILURE;
  }

  config.returnValue("address", val);
  if (!val.empty()) {
    cerr << "Error: Can not add interface " + ifname +
            " with addresses to bridge" << endl;
    return EXIT_FAILURE;
  }

  cout << "Adding interface " << ifname <<
          " to bridge " << bridge << endl;

  string cmd = "link set dev " + ifname + " master " + bridge;
  int ret = system_ip(cmd);
  if (ret) {
    return EXIT_FAILURE;
  }

  cmd = "";
  config.returnValue("bridge-group cost", cost);
  if (cost.length()) {
    cmd += "link set dev " + ifname + " cost " + cost + "\n";
  }

  config.returnValue("bridge-group priority", priority);
  if (priority.length()) {
    cmd += "link set dev " + ifname + " priority " + priority + "\n";
  }

  if (!cmd.empty()) {
    return system_bridge(cmd);
  }

  return EXIT_SUCCESS;
}

static int
remove_bridge_port(const string& ifname,
                   InterfaceT& intf,
                   vyatta::Config& config)
{
  cout << "Removing interface " + ifname + " from bridge" << endl;

#if 0
  // this is the case where the bridge that this interface is assigned
  // to is getting deleted in the same commit as the bridge node under
  // this interface - Bug 5064|4734. Since bridge has a higher priority;
  // it gets deleted before the removal of bridge-groups under interfaces
  string bridge;
  config.returnOrigValue("bridge-group bridge", bridge);
  if (bridge.empty()) {
    return EXIT_SUCCESS;
  }
  string dir = "/sys/class/net/" + bridge;
  if (!boost::filesystem::exists(dir)) {
    return EXIT_SUCCESS;
  }
#endif

  string cmd = "link set dev " + ifname + " nomaster";
  int ret = system_ip(cmd.c_str());
  if (ret) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

static int
change_bridge_port(const string& ifname,
                   InterfaceT& intf,
                   vyatta::Config& config)
{
  string newbridge, cost, priority, val;

  config.returnValue("bridge-group bridge", newbridge);

  if (newbridge.empty()) {
    return remove_bridge_port(ifname, intf, config);
  }

  return add_bridge_port(newbridge, ifname, intf, config);
}

/*
 * Specifying the expected options
 * The two options l and b expect numbers as argument
 */
enum {
  DELETE_BRIDGE = 1000,
  BRIDGE_INTERFACE_NAME,
  ACTION
};

static struct option long_options[] = {
  { "name",   required_argument,  0,  BRIDGE_INTERFACE_NAME },
  { "delbr",  no_argument,        0,  DELETE_BRIDGE },
  { "action", required_argument,  0,  ACTION },
  { 0,        0,                  0,  0 }
};

/**
 * @brief The main function ubnt-bridge application.
 * @param[in] argc Arguments count.
 * @param[in] argv Arguments array.
 * @return Exit status of the application.
 */
int main(int argc, char **argv)
{
  int opt = 0, index, rc = EXIT_SUCCESS;
  bool is_del = false;
  string dev, action;

  if (argc < 3) {
    cerr << "Error: missing argument" << endl;
    exit(EXIT_FAILURE);
  }

  while ((opt = getopt_long_only(argc, argv, "",
                                 long_options, &index)) != -1) {
    switch (opt) {
      case BRIDGE_INTERFACE_NAME:
      case ACTION:
        if (!optarg) {
          cerr << "Error: missing argument" << endl;
          exit(EXIT_FAILURE);
        }
        break;
    }

    switch (opt) {
      case DELETE_BRIDGE:
        is_del = true;
        break;
      case BRIDGE_INTERFACE_NAME:
        dev = optarg;
        break;
      case ACTION:
        action = optarg;
        break;
      default:
        rc = 1;
        break;
    }
  }

  if (is_del) {
    rc = delete_bridge(dev);
  } else {
    // Get bridge information from configuration
    InterfaceT intf(dev);
    if (!intf.get()) {
      return EXIT_FAILURE;
    }
    vyatta::Config config(intf.path());

    if (action == "SET") {
      string bridge;
      config.returnValue("bridge-group bridge", bridge);
      rc = add_bridge_port(bridge, dev, intf, config);
    } else if (action == "DELETE") {
      rc = remove_bridge_port(dev, intf, config);
    } else {
      rc = change_bridge_port(dev, intf, config);
    }
  }

  return rc;
}
