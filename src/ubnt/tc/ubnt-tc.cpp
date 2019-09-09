#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <getopt.h>
#include <errno.h>
#include <cmath>
#include <netdb.h>
#include <sys/stat.h>
#include <iomanip>

#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/unordered_map.hpp>
#include <boost/lexical_cast.hpp>

#include "../lib/vyatta_config.hpp"

using namespace std;

typedef struct rate_s
{
  const char* suffix;
  double      scale;
} rate_t;

static rate_t rates[] = {
  { "bit",    1 },
  { "kibit",  1024 },
  { "kbit",   1000 },
  { "Kbit",   1000 },
  { "mibit",  1048576 },
  { "mbit",   1000000 },
  { "Mbit",   1000000 },
  { "gibit",  1073741824 },
  { "gbit",   1000000000 },
  { "Gbit",   1000000000 },
  { "tibit",  1099511627776 },
  { "tbit",   1000000000000 },
  { "Tbit",   1000000000000 },
  { "bps",    8 },
  { "kibps",  8192 },
  { "kbps",   8000 },
  { "mibps",  8388608 },
  { "mbps",   8000000 },
  { "gibps",  8589934592 },
  { "gbps",   8000000000 },
  { "tibps",  8796093022208 },
  { "tbps",   8000000000000 },
  { NULL},
};

// Default time units for tc are usec.
static rate_t timeunits[] = {
  { "s",      1000000 },
  { "sec",    1000000 },
  { "secs",   1000000 },
  { "ms",     1000 },
  { "msec",   1000 },
  { "msecs",  1000 },
  { "us",     1 },
  { "usec",   1 },
  { "usecs",  1 },
};

static rate_t scales[] = {
  { "b",      1 },
  { "k",      1024 },
  { "kb",     1024 },
  { "kbit",   1024 / 8 },
  { "m",      1024 * 1024 },
  { "mb",     1024 * 1024 },
  { "mbit",   1024 * 1024 / 8 },
  { "g",      1024 * 1024 * 1024 },
  { "gb",     1024 * 1024 * 1024 },
};

static rate_t sizes[] = {
  { "b",      8 },
  { "bit",    1 },
  { "k",      1000 * 8 },
  { "kb",     1000 * 8 },
  { "kbit",   1000 },
  { "m",      1000 * 1000 * 8 },
  { "mb",     1000 * 1000 * 8 },
  { "mbit",   1000 * 1000 },
  { "g",      (double)1000 * 1000 * 1000 * 8 },
  { "gb",     (double)1000 * 1000 * 1000 * 8 },
  { "gbit",   (double)1000 * 1000 * 1000 },
};

const string aq_base("traffic-control advanced-queue ");

static double
get_num(string rate, string& suffix)
{
  char *endptr = 0;

  if (rate.empty()) {
    return -1;
  }
  boost::trim(rate);

  errno = 0;
  double num = strtod(rate.c_str(), &endptr);
  /* Check for various possible errors */
  if ((errno == ERANGE && (num == HUGE_VALF || num == HUGE_VALL))
      || (errno != 0 && num == 0)) {
    return -1;
  }
  if (endptr == rate.c_str()) {
    return -1;
  }
  if (endptr && *endptr != '\0') {
    suffix = endptr;
  }
  return num;
}

static double
getRate(const string& rate)
{
  string suffix;

  double num = get_num(rate, suffix);
  if (num == -1) {
    cerr << rate << " is not a valid bandwidth (not a number)" << endl;
    exit(EXIT_FAILURE);
  }
  if (num == 0) {
    cerr << "Bandwidth of zero is not allowed" << endl;
    exit(EXIT_FAILURE);
  }
  if (num < 0) {
    cerr << rate << " is not a valid bandwidth (negative value)" << endl;
    exit(EXIT_FAILURE);
  }
  if (!suffix.empty()) {
    for (size_t i = 0; rates[i].suffix; i ++) {
      if (suffix == rates[i].suffix) {
        return num * rates[i].scale;
      }
    }
    cerr << rate << " is not a valid bandwidth (unknown scale suffix)" << endl;
    exit(EXIT_FAILURE);
  } else {
    // No suffix implies Kbps just as IOS
    return num * 1000;
  }
}

/*
 * Fetch actual rate using ethtool and format to valid tc rate
 */
static double
ethtoolRate(string dev)
{
  double rate = -1;

  // Get rate of real device (ignore vlan)
  size_t pos = dev.find(".");
  dev = dev.substr(0, pos);

  string cmd = "/sbin/ethtool " + dev + " 2>/dev/null";
  errno = 0;
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    return -1;
  }
  try {
    char buf[1024];
    while (!feof(pipe)) {
      if (fgets(buf, sizeof(buf), pipe)) {
        string line = buf;
        boost::trim(line);
        if (line.empty()) {
          continue;
        }
        // ethtool produces:
        //
        // Settings for eth1:
        // Supported ports: [ TP ]
        // ...
        // Speed: 1000Mb/s
        if (!line.compare(0, 7, "Speed: ")) {
          line = line.substr(7);
          pos = line.find("Mb/s");
          double mult = 1;
          if (pos != string::npos) {
            line = line.replace(pos, 4, "");
            mult = 1000000;
          }
          string suffix;
          double num = get_num(line, suffix);
          if (num > 0 && suffix.empty()) {
            rate = num * mult;
          }
          break;
        }
      }
    }
  } catch (...) {
  }
  pclose(pipe);

  return rate;
}

/*
 * return result in bits per second
 */
static double
interfaceRate(const string& interface)
{
  vyatta::Config config;

  string speed, suffix;
  if (config.returnValue("interfaces ethernet " + interface + " speed", speed)) {
    if (speed != "auto") {
      double num = get_num(speed, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << speed << " is not a valid speed" << endl;
        exit(EXIT_FAILURE);
      }
      return num * 1000000;
    }
  }

  // During boot it may take time for auto-negotiation
  for (int retries = 0; retries < 5; retries ++) {
    double num = ethtoolRate(interface);
    if (num > 0) {
      return num;
    }
    sleep(1);
  }
  return -1;
}

/*
 * Rate can be something like "auto" or "10.2mbit"
 */
static double
getAutoRate(const string& srate, const string& dev)
{
  if (srate == "auto") {
    double rate = interfaceRate(dev);
    if (rate <= 0) {
      cerr << "Interface " << dev
           << " speed cannot be determined (assuming 1gbit)" << endl;
      rate = 1000000000;
    }
    return rate;
  } else {
    return getRate(srate);
  }
}

static double
getPercent(const string& percent)
{
  string suffix;

  double num = get_num(percent, suffix);
  if (num == -1) {
    cerr << percent << " is not a valid percent (not a number)" << endl;
    exit(EXIT_FAILURE);
  }
  if (num < 0) {
    cerr << percent << " is not a acceptable percent (negative value)" << endl;
    exit(EXIT_FAILURE);
  }
  if (num > 100) {
    cerr << percent << " is not a acceptable percent (greater than 100%)" << endl;
    exit(EXIT_FAILURE);
  }
  if (!suffix.empty() && suffix != "%") {
    cerr << percent << " incorrect suffix (expect %)" << endl;
    exit(EXIT_FAILURE);
  } else {
    // No suffix
    return num;
  }
}

static double
getPercentOrRate(const string& rate)
{
  if (rate.find("%") != string::npos) {
    return getPercent(rate);
  } else {
    return getRate(rate);
  }
}

static double
getTime(const string& time)
{
  string suffix;

  double num = get_num(time, suffix);
  if (num == -1) {
    cerr << time << " is not a valid time interval (not a number)" << endl;
    exit(EXIT_FAILURE);
  }
  if (num < 0) {
    cerr << time << " is not a valid time interval (negative value)" << endl;
    exit(EXIT_FAILURE);
  }
  if (!suffix.empty()) {
    for (size_t i = 0; timeunits[i].suffix; i ++) {
      if (suffix == timeunits[i].suffix) {
        return num * timeunits[i].scale;
      }
    }
    cerr << time << " is not a valid time interval (unknown suffix)" << endl;
    exit(EXIT_FAILURE);
  } else {
    // No suffix implies ms
    return num * 1000;
  }
}

static double
getBurstSize(const string& size)
{
  string suffix;

  double num = get_num(size, suffix);
  if (num == -1) {
    cerr << size << " is not a valid burst size (not a number)" << endl;
    exit(EXIT_FAILURE);
  }
  if (num < 0) {
    cerr << size << " is not a valid burst size (negative value)" << endl;
    exit(EXIT_FAILURE);
  }
  if (!suffix.empty()) {
    for (size_t i = 0; scales[i].suffix; i ++) {
      if (suffix == scales[i].suffix) {
        return num * scales[i].scale;
      }
    }
    cerr << size << " is not a valid burst size (unknown scale suffix)" << endl;
    exit(EXIT_FAILURE);
  } else {
    // No suffix
    return num;
  }
}

static double
getSize(const string& size)
{
  string suffix;

  double num = get_num(size, suffix);
  if (num == -1) {
    cerr << size << " is not a valid burst size (not a number)" << endl;
    exit(EXIT_FAILURE);
  }
  if (num < 0) {
    cerr << size << " is not a valid burst size (negative value)" << endl;
    exit(EXIT_FAILURE);
  }
  if (!suffix.empty()) {
    for (size_t i = 0; sizes[i].suffix; i ++) {
      if (suffix == sizes[i].suffix) {
        return num * sizes[i].scale;
      }
    }
    cerr << size << " is not a valid burst size (unknown scale suffix)" << endl;
    exit(EXIT_FAILURE);
  } else {
    // No suffix
    return num;
  }
}

static int
getProtocol(const string& str)
{
  string suffix;

  // match number (or hex)
  int num = get_num(str, suffix);
  if (num != -1 && suffix.empty()) {
    if (num <= 0 || num > 255) {
      cerr << str << " is not a valid protocol number" << endl;
      exit(EXIT_FAILURE);
    }
    return num;
  }

  struct protoent *proto = getprotobyname(str.c_str());
  if (proto) {
    return proto->p_proto;
  } else {
    cerr << str << " unknown protocol" << endl;
    exit(EXIT_FAILURE);
  }
}

// Parse /etc/iproute/rt_dsfield
// return a hex string "0x10" or exit
static int
getDsfield(const string& str)
{
  string suffix;

  // match number (or hex)
  int num = get_num(str, suffix);
  if (num != -1 && suffix.empty()) {
    if (num < 0 || num > 63) {
      cerr << str << " is not a valid DSCP value" << endl;
      exit(EXIT_FAILURE);
    }
    // convert DSCP value to header value used by iproute
    return num << 2;
  }

  string line, val, name;
  ifstream fp("/etc/iproute2/rt_dsfield");
  if (!fp.is_open()) {
    cerr << " Can't open /etc/iproute2/rt_dsfield" << endl;
    exit(EXIT_FAILURE);
  }
  try {
    while (getline(fp, line)) {
      boost::trim(line);
      if (line[0] == '#') {
        continue;
      }
      istringstream iss(line);
      iss >> val;
      iss >> name;

      if (str == name) {
        suffix.clear();
        num = get_num(val, suffix);
        if (num == -1 || !suffix.empty()) {
          cerr << str << " is not a valid DSCP value:" << val << endl;
          exit(EXIT_FAILURE);
        }
        break;
      }
    }
  } catch (...) {
    cerr << str << " unknown DSCP value" << endl;
    exit(EXIT_FAILURE);
  }
  fp.close();

  return num;
}

static bool
_intf_tc_unique(const string& if_name)
{
  string val;
  int times = 0;
  vyatta::Config config;

  // check interfaces traffic-policy/mirror/redirect
  if (config.exists("interfaces ethernet " + if_name + " traffic-policy out")) {
    times ++;
  }
  if (config.exists("interfaces ethernet " + if_name + " traffic-policy in")) {
    if (++ times > 1) {
      return false;
    }
  }
  if (config.exists("interfaces ethernet " + if_name + " mirror")) {
    if (++ times > 1) {
      return false;
    }
  }
  if (config.exists("interfaces ethernet " + if_name + " redirect")) {
    if (++ times > 1) {
      return false;
    }
  }

  // check traffic-control smart-queue
  vector<string> names;
  string base("traffic-control smart-queue ");
  config.listNodes(base, names);
  for (size_t i = 0; i < names.size(); i ++) {
    if (config.returnValue(base + names[i] + " wan-interface", val)) {
      if (if_name == val) {
        if (++ times > 1) {
          return false;
        }
      }
    }
  }

  // check traffic-control advanced-queue
  base = aq_base + "root queue ";
  config.listNodes(base, names);
  for (size_t i = 0; i < names.size(); i ++) {
    if (config.returnValue(base + names[i] + " attach-to", val)) {
      if (if_name == val) {
        if (++ times > 1) {
          return false;
        }
      }
    }
  }
  return true;
}

static int
intf_tc_unique(const string& if_name)
{
  if (!_intf_tc_unique(if_name)) {
    cerr << if_name << " should be only used in one QoS policy!" << endl;
    return 1;
  }
  return 0;
}

static void
cfg_upd(const string& type, const string& param)
{
  FILE *f = fopen("/opt/vyatta/config/.tc", "a");
  if (!f) {
    return;
  }
  string out = type + " " + param + "\n";
  fwrite(out.c_str(), out.size(), 1, f);
  fclose(f);
}

static void
cfg_clr(const string& if_name)
{
  string command(
    "/sbin/tc qdisc del dev " + if_name + " root > /dev/null 2>&1;" \
    "/sbin/tc qdisc del dev " + if_name + " ingress > /dev/null 2>&1;" \
    "/sbin/ip link del dev ifb_" + if_name + " > /dev/null 2>&1");
  system(command.c_str());
}

static void
intf_changed(const string& policy, const string& name)
{
  string ori_intf;
  vyatta::Config config;

  if (policy == "smart-queue") {
    if (!config.returnOrigValue(
      "traffic-control smart-queue " + name + " wan-interface", ori_intf)) {
      return;
    }
  } else if (policy == "advanced-queue") {
    if (!config.returnOrigValue( aq_base + "root queue " + name + " attach-to",
      ori_intf)) {
      return;
    }
    if (ori_intf == "global") {
      ori_intf = "imq0";
    }
  }

  cfg_clr(ori_intf);
}

static int
chk_sq_rate(const string& policy, const string& name)
{
  double sum = 0;
  vyatta::Config config;
  string path("traffic-control " + policy + " " + name);

  string rate;
  if (config.returnValue(path + " upload rate", rate)) {
    sum = getRate(rate);
  }
  if (config.returnValue(path + " download rate", rate)) {
    sum += getRate(rate);
  }

  string cmd = "declare -x PATH=\"/usr/sbin\"; /usr/sbin/ubnt-hal getSqPerf";
  FILE* p = popen(cmd.c_str(), "r");
  if (!p) {
    return 1;
  }
  char buf[1024];
  string perf;
  while (!feof(p)) {
    if (fgets(buf, sizeof(buf), p)) {
      perf += buf;
    }
  }
  pclose(p);

  if (perf.size() && sum > getRate(perf + "mbit")) {
    return 1;
  }
  return 0;
}

static int
chk_sq(const string& name)
{
  vyatta::Config config;
  string path("traffic-control smart-queue " + name);

  if (!config.exists(path + " wan-interface")) {
    cerr << "The \"wan-interface\" is required" << endl;
    return 1;
  }

  if (!config.exists(path + " upload") &&
      !config.exists(path + " download")) {
    cerr << "At least one of \"upload\" and \"download\" is required" << endl;
    return 1;
  }
  return 0;
}

static int
rate_gt(const string& rate_1, const string& rate_2)
{
  if (!(getRate(rate_1) > getRate(rate_2))) {
    return 1;
  }
  return 0;
}

static int
rate_lt(const string& rate_1, const string& rate_2)
{
  if (!(getRate(rate_1) < getRate(rate_2))) {
    return 1;
  }
  return 0;
}

static int
time_gt(const string& time_1, const string& time_2)
{
  if (!(getTime(time_1) > getTime(time_2))) {
    return 1;
  }
  return 0;
}

static int
time_lt(const string& time_1, const string& time_2)
{
  if (!(getTime(time_1) < getTime(time_2))) {
    return 1;
  }
  return 0;
}

static int
time_range(const string& time_1, const string& time_2, const string& time_3)
{
  double t1 = getTime(time_1);
  if (!(t1 < getTime(time_2) || t1 > getTime(time_3))) {
    return 1;
  }
  return 0;
}

static int
size_gt(const string& size_1, const string& size_2)
{
  if (!(getBurstSize(size_1) > getBurstSize(size_2))) {
    return 1;
  }
  return 0;
}

static int
size_lt(const string& size_1, const string& size_2)
{
  if (!(getBurstSize(size_1) < getBurstSize(size_2))) {
    return 1;
  }
  return 0;
}

static int
size_range(const string& size_1, const string& size_2, const string& size_3)
{
  double s1 = getBurstSize(size_1);
  if (!(s1 < getBurstSize(size_2) || s1 > getBurstSize(size_3))) {
    return 1;
  }
  return 0;
}

static void
get_rate(const string& rate)
{
  cout << (long long)getRate(rate);
}

static void
list_queues(const string& aq1)
{
  vector<string> nodes;
  vyatta::Config config;

  config.listNodes(aq_base + aq1 + " queue", nodes);
  for (size_t i = 0; i < nodes.size(); i ++) {
    if (i) {
      cout << " ";
    }
    cout << nodes[i];
  }
  cout << endl;
}

static void
list_2_queues(const string& aq1, const string& aq2)
{
  vector<string> nodes;
  vyatta::Config config;

  config.listNodes(aq_base + aq1 + " queue", nodes);
  for (size_t i = 0; i < nodes.size(); i ++) {
    cout << nodes[i] << " ";
  }

  nodes.clear();
  config.listNodes(aq_base + aq2 + " queue", nodes);
  for (size_t i = 0; i < nodes.size(); i ++) {
    cout << nodes[i] << " ";
  }
  cout << endl;
}

static void
list_queue_types()
{
  vector<string> nodes;
  vyatta::Config config;

  config.listNodes(aq_base + "queue-type", nodes);
  for (size_t i = 0; i < nodes.size(); i ++) {
    vector<string> names;
    config.listNodes(aq_base + "queue-type " + nodes[i], names);
    for (size_t j = 0; j < names.size(); j ++) {
      cout << names[j] << " ";
    }
    cout << endl;
  }
}

/* key = id, value = queue type(root,branch,leaf) */
static boost::unordered_map<string, string> aq_map;
/* key = id, value = parent id */
static boost::unordered_map<string, string> aq_parent_map;
/* key = id, value = attach-to value */
static boost::unordered_map<string, string> aq_attach_to_map;

static bool
_advq_find_qtype(const string& qid, string& q_type)
{
  boost::unordered_map<string, string>::iterator it = aq_map.find(qid);
  if (it == aq_map.end()) {
    q_type = "";
    return false;
  }
  q_type = it->second;
  return true;
}

static bool
_advq_find_attach_to(vyatta::Config& config, const string& qid,
                     const string& q_type, string& intf)
{
  boost::unordered_map<string, string>::iterator it =
    aq_attach_to_map.find(qid);
  if (it != aq_attach_to_map.end()) {
    intf = it->second;
    return intf.empty() ? false : true;
  }

  if (!config.returnValue(aq_base + q_type + " queue " + qid + " attach-to", intf)) {
    aq_attach_to_map[qid] = "";
    return false;
  }
  aq_attach_to_map[qid] = intf;
  return true;
}

static bool
_advq_find_parent(vyatta::Config& config, const string& qid,
                  const string& q_type, string& parent)
{
  boost::unordered_map<string, string>::iterator it = aq_parent_map.find(qid);
  if (it != aq_parent_map.end()) {
    parent = it->second;
    return parent.empty() ? false : true;
  }

  if (!config.returnValue(aq_base + q_type + " queue " + qid + " parent", parent)) {
    aq_parent_map[qid] = "";
    return false;
  }
  aq_parent_map[qid] = parent;
  return true;
}

static bool
_advq_find_parent(vyatta::Config& config, const string& qid, string& parent)
{
  boost::unordered_map<string, string>::iterator it = aq_parent_map.find(qid);
  if (it != aq_parent_map.end()) {
    parent = it->second;
    return parent.empty() ? false : true;
  }

  string q_type;
  if (!_advq_find_qtype(qid, q_type)) {
    return false;
  }

  if (!config.returnValue(aq_base + q_type + " queue " + qid + " parent", parent)) {
    aq_parent_map[qid] = "";
    return false;
  }
  aq_parent_map[qid] = parent;
  return true;
}

static bool
advq_find_parent(vyatta::Config& config, const string& qid,
                 string& parent, string& parent_qtype)
{
  if (!_advq_find_parent(config, qid, parent)) {
    return false;
  }
  if (!_advq_find_qtype(parent, parent_qtype)) {
    return false;
  }
  return true;
}

static bool
advq_find_root(vyatta::Config& config, const string& qid, string& parent)
{
  string son(qid), q_type;

  while (advq_find_parent(config, son, parent, q_type)) {
    if (q_type == "root") {
      return true;
    }
    son = parent;
  }
  return false;
}

static bool
advq_find_att_intf(vyatta::Config& config, const string& qid, string& intf)
{
  string root_qid;

  if (advq_find_root(config, qid, root_qid)) {
    if (_advq_find_attach_to(config, root_qid, "root", intf)) {
      return true;
    }
  }
  return false;
}

static bool
advq_is_ancestor(vyatta::Config& config,
                 string son, const string& anc)
{
  string parent;
  while (_advq_find_parent(config, son, parent)) {
    if (parent == anc) {
      return true;
    }
    son = parent;
  }
  return false;
}

static int
chk_hfq_mask(string subnet, string maxMask)
{
  long int prefix = 32, mask;
  char *endptr = 0;

  boost::trim(subnet);
  boost::trim(maxMask);

  size_t pos = subnet.find('/');
  if (pos != string::npos) {
    string prefixstr = subnet.substr(pos + 1);

    errno = 0;
    prefix = strtol(prefixstr.c_str(), &endptr, 10);
    /* Check for various possible errors */
    if ((errno == ERANGE && (prefix == LONG_MAX || prefix == LONG_MIN)) ||
        (errno != 0 && prefix == 0) || prefix < 0 || prefix > 32) {
      return 1;
    }
    if (endptr == prefixstr.c_str()) {
      return 1;
    }

    errno = 0;
    mask = strtol(maxMask.c_str(), &endptr, 10);
    /* Check for various possible errors */
    if ((errno == ERANGE && (mask == LONG_MAX || mask == LONG_MIN)) ||
        (errno != 0 && mask == 0) || mask < 0 || mask > 32) {
      return 1;
    }
    if (endptr == maxMask.c_str()) {
      return 1;
    }

    if (prefix < mask) {
      return 1;
    }
  }
  return 0;
}

/*
 * Integrity check for max-rate/ceiling
 */
static int
chk_rate_ceil_advq_conf(vyatta::Config& config, const string& npath,
                        const string& name)
{
  // check burst
  if (!config.exists(npath + " burst")) {
    return 0;
  }

  string brate;
  if (!config.returnValue(npath + " burst burst-rate", brate)) {
    cerr << "burst-rate should exist" << endl;
    return 1;
  }
  double br = getRate(brate);

  string bsize;
  if (!config.returnValue(npath + " burst burst-size", bsize)) {
    cerr << "burst-size should exist" << endl;
    return 1;
  }
  if (getSize(bsize) > 30 * br) {
    cerr << "The max allowed burst-size can't be over 30 seconds of burst-rate" << endl;
    return 1;
  }

  string ceil;
  if (config.returnValue(npath + " " + name, ceil)) {
    if (!(br > getRate(ceil))) {
      cerr << "burst-rate should > " + name << endl;
      return 1;
    }
  }

  return 0;
}

/*
 * Integrity check for HFQ
 */
static int
chk_hfq_advq_conf(vyatta::Config& config)
{
  vector<string> nodes;
  const string path(aq_base + "queue-type hfq ");

  config.listNodes(path, nodes);
  BOOST_FOREACH(const string& node, nodes) {
    string npath = path + node;

    if (!config.exists(npath + " subnet")) {
      cerr << "subnet is missing in HFQ " + node << endl;
      return 1;
    }

    if (chk_rate_ceil_advq_conf(config, npath, "max-rate")) {
      return 1;
    }
  }
  return 0;
}

/*
 * Integrity check for bandwidth/ceiling
 */
static int
chk_band_ceil_advq_conf(vyatta::Config& config, const string& npath,
                        const string& node)
{
  string rate;
  if (!config.returnValue(npath + " bandwidth", rate)) {
    cerr << "bandwidth is missing in queue " + node << endl;
    return 1;
  }
  string ceil;
  if (config.returnValue(npath + " ceiling", ceil)) {
    if (getRate(rate) > getRate(ceil)) {
      cerr << "ceiling < bandwidth in queue " + node + " ?" << endl;
      return 1;
    }
  }
  return 0;
}

/*
 * Integrity check for root nodes
 */
static int
chk_root_advq_conf(vyatta::Config& config, vector<string>& nodes)
{
  const string path(aq_base + "root queue ");

  BOOST_FOREACH(const string& node, nodes) {
    string npath = path + node;

    // Integrity check for reference of "default" in root queue.
    // The "default" should be the direct child of root queue.
    string def_qid;
    if (config.returnValue(npath + " default", def_qid)) {
      string pid;
      if (!_advq_find_parent(config, def_qid, "leaf", pid) ||
          pid != node) {
        cerr << "\"default\" of root queue " + node +
          " should be its direct leaf queue" << endl;
        return 1;
      }
    }

    // Integrity check for root bandwidth/ceiling
    if (chk_band_ceil_advq_conf(config, npath, node)) {
      return 1;
    }
  }
  return 0;
}

/*
 * Integrity check for reference of "parent"
 */
static int
chk_parent_advq_conf(vyatta::Config& config, const string& node,
                     const string& type)
{
  string pid;
  if (!_advq_find_parent(config, node, type, pid)) {
    cerr << "\"parent\" of " + type +
      " queue " + node + " is missing" << endl;
    return 1;
  }

  string q;
  if (!_advq_find_qtype(pid, q) || q == "leaf") {
    cerr << "\"parent\" queue " + pid + " of " + type +
      " queue " + node + " doesn't exist" << endl;
    return 1;
  }

  return 0;
}

/*
 * Integrity check for branch nodes
 */
static int
chk_branch_advq_conf(vyatta::Config& config, vector<string>& nodes)
{
  const string path(aq_base + "branch queue ");

  BOOST_FOREACH(const string& node, nodes) {
    string npath = path + node;

    // Integrity check for reference of "parent"
    if (chk_parent_advq_conf(config, node, "branch")) {
      return 1;
    }

    // Integrity check for branch bandwidth/ceiling
    if (chk_band_ceil_advq_conf(config, npath, node)) {
      return 1;
    }
  }
  return 0;
}

/*
 * Integrity check for leaf nodes
 */
static int
chk_leaf_advq_conf(vyatta::Config& config, vector<string>& nodes)
{
  const string path(aq_base + "leaf queue ");

  config.listNodes(path, nodes);
  BOOST_FOREACH(const string& node, nodes) {
    string npath = path + node;

    // Integrity check for reference of "parent"
    if (chk_parent_advq_conf(config, node, "leaf")) {
      return 1;
    }

    // Integrity check for root/branch/leaf bandwidth/ceiling
    if (chk_band_ceil_advq_conf(config, npath, node)) {
      return 1;
    }

    if (chk_rate_ceil_advq_conf(config, npath, "ceiling")) {
      return 1;
    }
  }
  return 0;
}

/*
 * Integrity check for filters
 */
static int
chk_filter_advq_conf(vyatta::Config& config)
{
  vector<string> nodes;
  const string path(aq_base + "filters match ");

  config.listNodes(path, nodes);
  BOOST_FOREACH(const string& node, nodes) {
    string npath = path + node;

    string son;
    if (!config.returnValue(npath + " target", son)) {
      cerr << "\"target\" is required" << endl;
      return 1;
    }

    string anc;
    if (!config.returnValue(npath + " attach-to", anc)) {
      cerr << "\"attach-to\" is required" << endl;
      return 1;
    }
    if (!advq_is_ancestor(config, son, anc)) {
      cerr << "\"target\" should be descendant of \"attach-to\"" << endl;
      return 1;
    }

    string intf;
    if (advq_find_att_intf(config, son, intf)) {
      // match on ether dst not applicable for "global"
      if (intf == "global") {
        if (config.exists(npath + " ether destination")) {
          cerr << "match on ether destination is not applicable for \"" + intf + "\"" << endl;
          return 1;
        }
      } else {
        // match on ether src not applicable for eth interfaces
        if (config.exists(npath + " ether source")) {
          cerr << "match on ether source is not applicable for \"" + intf + "\"" << endl;
          return 1;
        }
      }
    }
  }
  return 0;
}

static int
chk_advq_conf()
{
  vyatta::Config config;

  // Integrity check for HFQ
  if (chk_hfq_advq_conf(config)) {
    return 1;
  }

  // Integrity check for root/branch/leaf nodes
  vector<string> root_nodes, branch_nodes, leaf_nodes;
  config.listNodes(aq_base + "root queue", root_nodes);
  BOOST_FOREACH(const string& node, root_nodes) {
    aq_map[node] = "root";
  }
  config.listNodes(aq_base + "branch queue", branch_nodes);
  BOOST_FOREACH(const string& node, branch_nodes) {
    aq_map[node] = "branch";
  }
  config.listNodes(aq_base + "leaf queue", leaf_nodes);
  BOOST_FOREACH(const string& node, leaf_nodes) {
    aq_map[node] = "leaf";
  }

  if (chk_root_advq_conf(config, root_nodes)) {
    return 1;
  }
  if (chk_branch_advq_conf(config, branch_nodes)) {
    return 1;
  }
  if (chk_leaf_advq_conf(config, leaf_nodes)) {
    return 1;
  }

  // Integrity check for filters
  if (chk_filter_advq_conf(config)) {
    return 1;
  }

  return 0;
}

static bool
validate_drop_tail(const string& name)
{
  return true;
}

static bool
configure_drop_tail(const string& name, const string& dev,
                    string& cmd)
{
  vyatta::Config config;
  string path = "traffic-policy drop-tail " + name;

  cmd = "qdisc add dev " + dev + " root pfifo";

  string limit;
  if (config.returnValue(path + " queue-limit", limit)) {
    cmd += " limit " + limit;
  }

  cmd += "\n";
  return true;
}

static bool
validate_fair_queue(const string& name)
{
  return true;
}

static bool
configure_fair_queue(const string& name, const string& dev,
                     string& cmd)
{
  vyatta::Config config;
  string path = "traffic-policy fair-queue " + name;

  cmd = "qdisc add dev " + dev + " root sfq";

  string perturb;
  if (config.returnValue(path + " hash-interval", perturb)) {
    cmd += " perturb " + perturb;
  }
  string limit;
  if (config.returnValue(path + " queue-limit", limit)) {
    cmd += " limit " + limit;
  }

  cmd += "\n";
  return true;
}

static bool
validate_rate_control(const string& name)
{
  vyatta::Config config;
  string path = "traffic-policy rate-control " + name;

  string bw;
  if (!config.returnValue(path + " bandwidth", bw)) {
    cerr << path << " bandwidth not defined" << endl;
    return false;
  }
  string burst;
  if (!config.returnValue(path + " burst", burst)) {
    cerr << path << " burst not defined" << endl;
    return false;
  }
  string latency;
  if (!config.returnValue(path + " latency", latency)) {
    cerr << path << " latency not defined" << endl;
    return false;
  }
  return true;
}

static bool
configure_rate_control(const string& name, const string& dev,
                       string& cmd)
{
  vyatta::Config config;
  string path = "traffic-policy rate-control " + name;

  string bw;
  if (!config.returnValue(path + " bandwidth", bw)) {
    cerr << path << " bandwidth not defined" << endl;
    return false;
  }
  long long rt = (long long)getRate(bw);
  stringstream rate;
  rate << rt;
  string burst;
  if (!config.returnValue(path + " burst", burst)) {
    cerr << path << " burst not defined" << endl;
    return false;
  }
  string val;
  if (!config.returnValue(path + " latency", val)) {
    cerr << path << " latency not defined" << endl;
    return false;
  }
  long long latency = getTime(val);

  stringstream sstream;
  sstream << "qdisc add dev " << dev
    << " root tbf rate " << rate.str()
    << " latency " << latency
    << " burst " << burst
    << "\n";
  cmd = sstream.str();
  return true;
}

static bool
validate_random_detect(const string& name)
{
  vyatta::Config config;
  const string path = "traffic-policy random-detect " + name;

  string bw;
  if (!config.returnValue(path + " bandwidth", bw)) {
    cerr << path << " bandwidth configuration missing" << endl;
    return false;
  }

  for (int i = 0; i <= 7 ; i ++) {
    stringstream ppath(path);
    ppath << " " << i;

    //Compute some sane defaults based on predence and max-threshold
    long long qmax, qmin, qlim;
    string val, suffix;
    if (!config.returnValue(ppath.str() + " maximum-threshold", val)) {
      qmax = 18;
    } else {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid threshold" << endl;
        return false;
      }
      qmax = num;
    }

    if (config.returnValue(ppath.str() + " minimum-threshold", val)) {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid threshold" << endl;
        return false;
      }
      qmin = num;
      if (qmin >= qmax) {
        cerr << "min-threshold: " << qmin
             << " >= max-threshold: " << qmax << endl;
        return false;
      }
    }

    if (config.returnValue(ppath.str() + " queue-limit", val)) {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid threshold" << endl;
        return false;
      }
      qlim = num;
      if (qlim < qmax) {
        cerr << "queue-limit: " << qlim
             << " < max-threshold: " << qmax << endl;
        return false;
      }
    }
  }
  return true;
}

static bool
configure_random_detect(const string& name, const string& dev,
                        string& cmd)
{
  vyatta::Config config;
  const string path = "traffic-policy random-detect " + name;

  string val;
  if (!config.returnValue(path + " bandwidth", val)) {
    cerr << path << " bandwidth configuration missing" << endl;
    return false;
  }
  long long rate = getAutoRate(val, dev);

  // 1. setup DSMARK to convert DSCP to tc_index
  int root = 1;
  stringstream sstream;
  sstream << "qdisc add dev " << dev << " root handle "
          << hex << root << ":0 dsmark indices 8 set_tc_index\n";

  // 2. use tcindex filter to convert tc_index to precedence
  //  Precedence Field: the three leftmost bits in the TOS octet of an IPv4
  //   header.
  sstream << "filter add dev " << dev << " parent "
          << hex << root << ":0 protocol ip prio 1 "
          << "tcindex mask 0xe0 shift 5\n";

  // 3. Define GRED with unmatched traffic going to index 0
  sstream << "qdisc add dev " << dev << " parent "
          << hex << root << ":0 handle "
          << hex << (root + 1) << ":0 gred "
          << "setup DPs 8 default 0 grio\n";

  // set VQ parameters
  for (int i = 0; i <= 7 ; i ++) {
    stringstream ppath;
    ppath << path << " precedence " << i;

    //Compute some sane defaults based on predence and max-threshold
    double prob;
    string suffix;
    long qmax, qmin, qlim, avpkt;
    if (!config.returnValue(ppath.str() + " maximum-threshold", val)) {
      qmax = 18;
    } else {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid threshold" << endl;
        return false;
      }
      qmax = num;
    }

    if (!config.returnValue(ppath.str() + " minimum-threshold", val)) {
      qmin = ((9 + i) * qmax)/ 18;
    } else {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid threshold" << endl;
        return false;
      }
      qmin = num;
      if (qmin >= qmax) {
        cerr << "min-threshold: " << qmin
             << " >= max-threshold: " << qmax << endl;
        return false;
      }
    }

    if (!config.returnValue(ppath.str() + " queue-limit", val)) {
      qlim = 4 * qmax;
    } else {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid limit" << endl;
        return false;
      }
      qlim = num;
      if (qlim < qmax) {
        cerr << "queue-limit: " << qlim
             << " < max-threshold: " << qmax << endl;
        return false;
      }
    }

    if (!config.returnValue(ppath.str() + " mark-probability", val)) {
      prob = (double)1 / (double)10;
    } else {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid probability" << endl;
        return false;
      }
      prob = 1 / num;
    }

    if (!config.returnValue(ppath.str() + " average-packet", val)) {
      avpkt = 1024;
    } else {
      double num = get_num(val, suffix);
      if (num < 0 || !suffix.empty()) {
        cerr << val << " is not a valid probability" << endl;
        return false;
      }
      avpkt = num;
    }
    double burst = (2*qmin + qmax) / 3;
    sstream << "qdisc change dev " << dev << " handle "
            << hex << (root + 1) << ":0 gred", //$i;
    sstream << dec << " limit " << qlim * avpkt
                   << " min " << qmin * avpkt
                   << " max " << qmax * avpkt
                   << " avpkt " << avpkt
                   << " burst " << burst
                   << " bandwidth " << rate
                   << " probability " << prob
                   << " DP " << i
                   << " prio " << (8 - i) << "\n";
  }
  cmd = sstream.str();

  return true;
}

/*
 * find policy for name - also check for duplicates
 */
static bool
find_policy(const string& name, string& policy)
{
  vyatta::Config config;
  vector<string> names, policies, ret;

  config.listNodes("traffic-policy", policies);
  BOOST_FOREACH(const string& qtype, policies) {
    vector<string> names;
    config.listNodes("traffic-policy " + qtype, names);
    BOOST_FOREACH(const string& qname, names) {
      if (name == qname) {
        ret.push_back(qtype);
        if (ret.size() > 1) {
          cerr << "Policy name \"" << name << "\" conflict, used by: "
               << ret[0] << " " << ret[1] << endl;
          exit(EXIT_FAILURE);
        }
      }
    }
  }

  if (ret.size()) {
    policy = ret[0];
    return true;
  }
  return false;
}

static bool
validate_policy(const string& type, const string& name)
{
  bool ret;

  if (type == "drop-tail") {
    ret = validate_drop_tail(name);
  } else if (type == "fair-queue") {
    ret = validate_fair_queue(name);
  } else if (type == "rate-control") {
    ret = validate_rate_control(name);
  } else if (type == "random-detect") {
    ret = validate_random_detect(name);
  } else {
    cerr << "unsupported policy type: " << type << endl;
    ret = false;
  }
  return ret;
}

/*
 * class factory for policies
 */
static bool
make_policy(const string& type, const string& name,
            const string& direction)
{
  string cmd;
  bool ret = true;

  if (type == "shaper" ||
      type == "fair-queue" ||
      type == "rate-control" ||
      type == "drop-tail" ||
      type == "network-emulator" ||
      type == "round-robin" ||
      type == "priority-queue" ||
      type == "random-detect") {
    if (!direction.empty() && direction != "out") {
      cerr << "QoS policy " << name << " is type " << type
           << " and is only valid for out" << endl;
      ret = false;
    }
  } else if (type == "limiter") {
    if (!direction.empty() && direction != "in") {
      cerr << "QoS policy " << name << " is type " << type
           << " and is only valid for in" << endl;
      ret = false;
    }
  } else {
    cerr << "QoS policy " << name << " has not been created" << endl;
    ret = false;
  }
  return ret;
}

static bool
configure_policy(const string& type, const string& name,
                 const string& dev)
{
  bool ret;
  string cmd;

  if (type == "drop-tail") {
    ret = configure_drop_tail(name, dev, cmd);
  } else if (type == "fair-queue") {
    ret = configure_fair_queue(name, dev, cmd);
  } else if (type == "rate-control") {
    ret = configure_rate_control(name, dev, cmd);
  } else if (type == "random-detect") {
    ret = configure_random_detect(name, dev, cmd);
  } else {
    cerr << "QoS policy " << name << " has not been applied" << endl;
    exit(EXIT_FAILURE);
  }

  if (!ret) {
    cerr << "QoS policy " << name << " has not been applied" << endl;
    exit(EXIT_FAILURE);
  }

  errno = 0;
  FILE* pipe = popen("/sbin/tc -batch - ", "w");
  if (!pipe) {
    cerr << "Tc setup failed: cannot open pipe" << endl;
    return false;
  }
  size_t size = fwrite(cmd.c_str(), cmd.size(), 1, pipe);
  if (size != 1) {
    cerr << "Tc setup failed: pipe is broken" << endl;
    ret = false;
  }
  int rc = pclose(pipe);
  if (rc) {
    cerr << "Tc setup failed:";
    if (rc == -1) {
      cerr << errno << "(" << strerror(errno) << ")";
    } else {
      cerr << WEXITSTATUS(rc);
    }
    cerr << endl;
    ret = false;
  }

  return ret;
}

/*
 * list defined qos policy names
 */
static void
list_policy(const string& direction)
{
  vyatta::Config config;
  vector<string> names, policies;

  if (direction == "in") {
    config.listNodes("traffic-policy limiter", names);
  } else {
    config.listNodes("traffic-policy", policies);
    BOOST_FOREACH(const string& qtype, policies) {
      if (qtype == "limiter") {
        continue;
      }
      vector<string> n;
      config.listNodes("traffic-policy " + qtype, n);
      names.insert(names.end(), n.begin(), n.end());
    }
  }
  BOOST_FOREACH(const string& name, names) {
    cout << name << " ";
  }
  cout << endl;
}

/*
 * remove all filters and qdisc's
 */
static void
delete_interface(const string& interface, const string& direction)
{
  string cmd = "/sbin/tc qdisc del dev " + interface;

  if (direction == "in") {
    cmd +=  " parent ffff: 2>/dev/null";
  } else if (direction == "out") {
    cmd +=  " root 2>/dev/null";
  } else {
    cerr << "bad direction " << direction << endl;
    exit(EXIT_FAILURE);
  }

  // ignore errors (may have no qdisc)
  system(cmd.c_str());
}

/*
 * check if interface exists
 * Note: retry to handle chicken-egg problem with ppp devices
 *       ppp devices can take a while to get named correctly
 *       ppp script won't see policy until it is committed
 */
static bool
interface_exists(const string& ifname)
{
  struct stat st = {0};
  string sysfs = "/sys/class/net/" + ifname;

  for (int i = 0; i < 10; i ++) {
    if (!stat(sysfs.c_str(), &st) && (st.st_mode & S_IFDIR)) {
      return true;
    }
    sleep(1);
  }
  return false;
}

/*
 * update policy to interface
 */
static void
update_interface(const string& device, const string& direction,
                 const string& name)
{
  string policy;
  if (!find_policy(name, policy)) {
    cerr << "Unknown traffic-policy " << name << endl;
    exit(EXIT_FAILURE);
  }
  if (!make_policy(policy, name, direction)) {
    cerr << "Failed to make policy: " << policy << " " << name << endl;
    exit(EXIT_FAILURE);
  }

  if (!interface_exists(device)) {
    cout << device
         << " not present yet, traffic-policy will be applied later"
         << endl;
    return;
  }

  // Remove old policy
  delete_interface(device, direction);
  if (!configure_policy(policy, name, device)) {
    // cleanup any partial commands
    delete_interface(device, direction);
    cerr << "TC command failed." << endl;
    exit(EXIT_FAILURE);
  }
}

static bool
interface_using(vyatta::Config& config, const string& criteria,
                const string& path)
{
  string val;
  if (config.returnValue(path, val) && criteria == val) {
    return true;
  }
  return false;
}

/*
 * returns interface (name, direction, policy) if attached
 */
static bool
interfaces_using(const string& policy, vector<string>& intfs,
                 vector<string>& dirs, vector<string>& policies,
                 const bool firstOccur)
{
  vyatta::Config config;
  vector<string> types, names, vifs;

  config.listNodes("interfaces", types);
  BOOST_FOREACH(const string& type, types) {
    config.listNodes("interfaces " + type, names);
    BOOST_FOREACH(const string& name, names) {
      string val;
      string path("interfaces " + type + " " + name);
      if (interface_using(config, policy, path + " traffic-policy in")) {
        intfs.push_back(name);
        dirs.push_back("in");
        policies.push_back(policy);
        if (firstOccur) {
          return true;
        }
      }
      if (interface_using(config, policy, path + " traffic-policy out")) {
        intfs.push_back(name);
        dirs.push_back("out");
        policies.push_back(policy);
        if (firstOccur) {
          return true;
        }
      }
      config.listNodes(path + " vif", vifs);
      BOOST_FOREACH(const string& vif, vifs) {
        string vif_path = path + " vif " + vif;
        if (interface_using(config, policy, vif_path + " traffic-policy in")) {
          intfs.push_back(name + "." + vif);
          dirs.push_back("in");
          policies.push_back(policy);
          if (firstOccur) {
            return true;
          }
        }
        if (interface_using(config, policy, vif_path + " traffic-policy out")) {
          intfs.push_back(name + "." + vif);
          dirs.push_back("out");
          policies.push_back(policy);
          if (firstOccur) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

/*
 * check if policy name(s) are still in use
 */
static void
delete_policy(const string& name)
{
  vector<string> intfs, dirs, policies;

  if (interfaces_using(name, intfs, dirs, policies, true)) {
    cerr << "Can not delete traffic-policy " << name <<
      ", still applied to interface " << intfs[0] << endl;
    exit(EXIT_FAILURE);
  }
}

/*
 * Create policy: just validate it on this phase
 */
static int
create_policy(const string& policy, const string& name)
{
  string tmp;
  bool found = find_policy(name, tmp);

  // Check policy for validity
  if (!found || tmp != policy || !validate_policy(policy, name)) {
    cerr << "Failed to create policy: " << policy << " " << name << endl;
    exit(EXIT_FAILURE);
  }
  return 0;
}

/*
 * Configuration changed, reapply to all interfaces.
 */
static int
apply_policy(const string& name)
{
  string policy;
  vector<string> intfs, dirs, policies;

  if (interfaces_using(name, intfs, dirs, policies, false)) {
    for (size_t i = 0; i < intfs.size(); i ++) {
      update_interface(intfs[i], dirs[i], policies[i]);
    }
  } else if (find_policy(name, policy)) {
    // Recheck the policy, might have new errors.
    if (!make_policy(policy, name, "")) {
      cerr << "Failed to create policy: " << policy << " " << name << endl;
      exit(EXIT_FAILURE);
    }
  }
  return 0;
}

static bool
find_dev_path(vyatta::Config& config, const string& dev, string& dev_path)
{
  vector<string> types, names, vifs;

  config.listNodes("interfaces", types);
  BOOST_FOREACH(const string& type, types) {
    config.listNodes("interfaces " + type, names);
    BOOST_FOREACH(const string& name, names) {
      string path = "interfaces " + type + " " + name;
      if (dev == name) {
        dev_path = path;
        return true;
      }
      config.listNodes(path + " vif", vifs);
      BOOST_FOREACH(const string& vif, vifs) {
        if (dev == name + "." + vif) {
          dev_path = path + " vif " + vif;
          return true;
        }
      }
    }
  }
  return false;
}

/*
 * This is used for actions mirror and redirect
 */
static void
update_action(const string& dev)
{
  vyatta::Config config;
  bool is_ingress = false;
  string path, ingress, cmd;

  if (!find_dev_path(config, dev, path)) {
    cerr << "Unknown interface type: " << dev << endl;
    exit(EXIT_FAILURE);
  }

  is_ingress = config.returnValue(path + " traffic-policy in", ingress);

  vector<string> actions;
  actions.push_back(" mirror");
  actions.push_back(" redirect");
  BOOST_FOREACH(const string& action, actions) {
    string target;
    if (!config.returnValue(path + action, target)) {
      continue;
    }
    // TODO support combination of limiting and redirect/mirror
    if (is_ingress) {
      cerr << "interface " << dev << ": combination of " << action
           << " and traffic-policy " << ingress << " not supported"
           << endl;
      exit(EXIT_FAILURE);
    }
    // Clear existing ingress
    cmd = "/sbin/tc qdisc del dev " + dev + " parent ffff: 2>/dev/null";
    system(cmd.c_str());

    cmd = "/sbin/tc qdisc add dev " + dev + " handle ffff: ingress";
    if (system(cmd.c_str())) {
      cerr << "tc qdisc ingress failed" << endl;
      exit(EXIT_FAILURE);
    }

    cmd = "/sbin/tc filter add dev " + dev +
      " parent ffff: protocol all prio 10 u32 match u32 0 0 flowid 1:1 action mirred egress " +
      action + " dev " + target;
    if (system(cmd.c_str())) {
      cerr << "tc action " + action + " command failed" << endl;
      exit(EXIT_FAILURE);
    }
    return;
  }

  if (!is_ingress) {
    // Drop what ever was there before...
    cmd = "/sbin/tc qdisc del dev " + dev + " parent ffff: 2>/dev/null";
    system(cmd.c_str());
  }
}

/*
 * find any interfaces whose actions refer to this interface
 */
static bool
interfaces_refer(const string& dev, string& intf)
{
  vyatta::Config config;
  vector<string> types, names, vifs;

  config.listNodes("interfaces", types);
  BOOST_FOREACH(const string& type, types) {
    config.listNodes("interfaces " + type, names);
    BOOST_FOREACH(const string& name, names) {
      string val;
      string path("interfaces " + type + " " + name);
      if (interface_using(config, dev, path + " redirect")) {
        intf = name;
        return true;
      }
      if (interface_using(config, dev, path + " mirror")) {
        intf = name;
        return true;
      }
      config.listNodes(path + " vif", vifs);
      BOOST_FOREACH(const string& vif, vifs) {
        string vif_path = path + " vif " + vif;
        if (interface_using(config, dev, vif_path + " redirect")) {
          intf = name + "." + vif;
          return true;
        }
        if (interface_using(config, dev, vif_path + " mirror")) {
          intf = name + "." + vif;
          return true;
        }
      }
    }
  }
  return false;
}

static void
check_target(const string& name)
{
  string intf;
  if (interfaces_refer(name, intf)) {
    cerr << "Can not delete interface " << name
         << ", still being used by: " << intf << endl;
    exit(EXIT_FAILURE);
  }
}

static void
delete_action(const string& dev)
{
  string cmd = "/sbin/tc qdisc del dev " + dev + " parent ffff: 2>/dev/null";
  system(cmd.c_str());
}

static boost::unordered_map<string, string> aq_desc;

static bool
get_queue_desc(const unsigned int qid, string& desc)
{
  vyatta::Config config;
  string node = boost::lexical_cast<string>(qid);

  boost::unordered_map<string, string>::iterator it = aq_desc.find(node);
  if (it != aq_desc.end()) {
    desc = it->second;
    return true;
  }

  if (config.returnEffectiveValue("traffic-control advanced-queue leaf queue "
                                  + node + " description", desc) ||
      config.returnEffectiveValue("traffic-control advanced-queue branch queue "
                                  + node + " description", desc) ||
      config.returnEffectiveValue("traffic-control advanced-queue root queue "
                                  + node + " description", desc)) {
    aq_desc[node] = desc;
    return true;
  }
  return false;
}

static void
tc_class_stat(const string& ifname, const bool show_name, const bool csv)
{
  vector<string> output;
  size_t wnum = 11, wid = 7, cwid = 7, wrate = 12;
  string cmd = "/sbin/tc -s class show dev " + ifname + "|grep -A 2 \"class htb \"";
  /*
   * Output:
   * class htb 7000:21 parent 7000:1f leaf 7015: prio 0 rate 8Mbit ceil 8Mbit burst 1600b cburst 1600b
   *  Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
   *  rate 0bit 0pps backlog 0b 0p requeues 0
   */
  FILE* p = popen(cmd.c_str(), "r");
  if (!p) {
    return;
  }

  char buf[1024];
  while (!feof(p)) {
    if (fgets(buf, sizeof(buf), p)) {
      output.push_back(buf);

      if (show_name) {
        char *p;
        string str;
        vector<string> ws;
        stringstream ss(buf);
        while (ss >> str) {
          ws.push_back(str);
        }

        if (ws.size() > 4 && ws[0] == "class") {
          unsigned int node;
          size_t pos = ws[2].find(":");
          if (pos != string::npos) {
            node = strtoul(ws[2].substr(pos + 1).c_str(), &p, 16);
            if (get_queue_desc(node, str) && wid < str.size() + 1) {
              wid = str.size() + 1;
            }
          }

          if (ws[3] == "parent") {
            pos = ws[4].find(":");
            if (pos != string::npos) {
              node = strtoul(ws[4].substr(pos + 1).c_str(), &p, 16);
              if (get_queue_desc(node, str) && wid < str.size() + 1) {
                wid = str.size() + 1;
              }
            }
          }
        }
      }
    }
  }
  pclose(p);

  if (!csv) {
    cout << setw(wid) << left << "class";
    if (wid > cwid) {
      cout << setw(wid) << left;
    }
    cout << "parent ";
    cout << setw(wnum) << left << "bytes";
    cout << setw(wnum) << left << "packets";
    cout << setw(wnum) << left << "dropped";
    cout << setw(wrate) << left << "rate";
    cout << "pps" << endl;

    cout << setw(wid) << left << "-----";
    if (wid > cwid) {
      cout << setw(wid) << left;
    }
    cout << "------ ";
    cout << setw(wnum) << left << "-----";
    cout << setw(wnum) << left << "-------";
    cout << setw(wnum) << left << "-------";
    cout << setw(wrate) << left << "----";
    cout << "---" << endl;
  }

  BOOST_FOREACH(const string& line, output) {
    char *p;
    string str;
    vector<string> ws;
    stringstream ss(line);
    while (ss >> str) {
      ws.push_back(str);
    }

    if (ws.size() > 4 && ws[0] == "class") {
      size_t pos = ws[2].find(":");
      if (pos != string::npos) {
        unsigned int node = strtoul(ws[2].substr(pos + 1).c_str(), &p, 16);
        if (!csv) {
          cout << setw(wid) << left;
        }
        if (show_name && get_queue_desc(node, str)) {
          cout << str;
        } else {
          cout << node;
        }
        if (csv) {
          cout << ",";
        }

        if (!csv) {
          cout << setw(wid) << left;
        }
        if (ws[3] == "parent") {
          pos = ws[4].find(":");
          if (pos != string::npos) {
            node = strtoul(ws[4].substr(pos + 1).c_str(), &p, 16);
            if (show_name && get_queue_desc(node, str)) {
              cout << str;
            } else {
              cout << node;
            }
          }
        } else if (ws[3] == "root") {
          if (!csv || show_name) {
            cout << "root";
          } else {
            cout << "-1";
          }
        }
        if (csv) {
          cout << ",";
        }

      }
    } else if (ws.size() > 6 && ws[0] == "Sent") {
      if (!csv) {
        cout << setw(wnum) << left << ws[1];
        cout << setw(wnum) << left << ws[3];
        cout << setw(wnum) << left << ws[6].substr(0, ws[6].size() - 1);
      } else {
        cout << ws[1] << ",";
        cout << ws[3] << ",";
        cout << ws[6].substr(0, ws[6].size() - 1) << ",";
      }
    } else if (ws.size() > 2 && ws[0] == "rate") {
      if (!csv) {
        cout << setw(wrate) << left;
      }
      if (ws[1] != "0bit") {
        cout << (unsigned long long)getRate(ws[1]);
      } else {
        cout << "0";
      }
      if (csv) {
        cout << ",";
      }

      if (ws[2].substr(ws[2].size() - 3) == "pps") {
        if (!csv) {
          cout << setw(3) << left;
        }
        cout << ws[2].substr(0, ws[2].size() - 3);
      } else {
        if (!csv) {
          cout << setw(wnum) << left;
        }
        cout << ws[2];
      }
      cout << endl;
    }
  }
}

static void
tc_qdisc_stat(const string& ifname, const bool show_name, const bool csv)
{
  vector<string> output;
  size_t wnum = 11, wid = 7, cwid = 7, wtype = 9;
  string cmd = "/sbin/tc -s qdisc show dev " + ifname;
  /*
   * Output:
   * qdisc htb 7000: root refcnt 2 r2q 10 default 3fd direct_packets_stat 0 direct_qlen 2
   *  Sent 38539 bytes 318 pkt (dropped 0, overlimits 0 requeues 0)
   *  backlog 0b 0p requeues 0
   * qdisc fq_codel 7001: parent 7000:3fc limit 10240p flows 1024 quantum 1514 target 5.0ms interval 100.0ms ecn
   *  Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
   *  backlog 0b 0p requeues 0
   *   maxpacket 256 drop_overlimit 0 new_flow_count 0 ecn_mark 0
   *   new_flows_len 0 old_flows_len 0
   */
  FILE* p = popen(cmd.c_str(), "r");
  if (!p) {
    return;
  }

  char buf[1024];
  while (!feof(p)) {
    if (fgets(buf, sizeof(buf), p)) {
      output.push_back(buf);

      if (show_name) {
        char *p;
        string str;
        vector<string> ws;
        unsigned int node;

        stringstream ss(buf);
        while (ss >> str) {
          ws.push_back(str);
        }

        if (ws.size() > 4 && ws[0] == "qdisc") {
          if (ws[3] == "parent") {
            size_t pos = ws[4].find(":");
            if (pos != string::npos) {
              node = strtoul(ws[4].substr(pos + 1).c_str(), &p, 16);
              if (get_queue_desc(node, str) && wid < str.size() + 1) {
                wid = str.size() + 1;
              }
            }
          }
        }
      }
    }
  }

  pclose(p);

  if (!csv) {
    cout << setw(cwid) << left << "qdisc";
    if (wid > cwid) {
      cout << setw(wid) << left;
    }
    cout << "parent ";
    cout << setw(wtype) << left << "type";
    cout << setw(wnum) << left << "bytes";
    cout << setw(wnum) << left << "packets";
    cout << setw(wnum) << left << "dropped";
    cout << setw(wnum) << left << "overlimits";
    cout << "requeues" << endl;

    cout << setw(cwid) << left << "-----";
    if (wid > cwid) {
      cout << setw(wid) << left;
    }
    cout << "------ ";
    cout << setw(wtype) << left << "----";
    cout << setw(wnum) << left << "-----";
    cout << setw(wnum) << left << "-------";
    cout << setw(wnum) << left << "-------";
    cout << setw(wnum) << left << "----------";
    cout << "--------" << endl;
  }

  BOOST_FOREACH(const string& line, output) {
    char *p;
    string str;
    vector<string> ws;
    stringstream ss(line);
    while (ss >> str) {
      ws.push_back(str);
    }

    if (ws.size() > 4 && ws[0] == "qdisc") {
      size_t pos = ws[2].find(":");
      if (pos != string::npos) {
        unsigned int node = strtoul(ws[2].substr(0, pos).c_str(), &p, 16);
        if (!csv) {
          cout << setw(cwid) << left;
        }
        cout << node;
        if (csv) {
          cout << ",";
        }

        if (!csv) {
          cout << setw(wid) << left;
        }
        if (ws[3] == "parent") {
          pos = ws[4].find(":");
          if (pos != string::npos) {
            node = strtoul(ws[4].substr(pos + 1).c_str(), &p, 16);
            if (show_name && get_queue_desc(node, str)) {
              cout << str;
            } else {
              cout << node;
            }
          }
        } else if (ws[3] == "root") {
          if (!csv || show_name) {
            cout << "root";
          } else {
            cout << "-1";
          }
        }
        if (csv) {
          cout << ",";
        }
      }

      if (!csv) {
        cout << setw(wtype) << left;
      }
      cout << ws[1];
      if (csv) {
        cout << ",";
      }
    } else if (ws.size() > 10 && ws[0] == "Sent") {
      if (!csv) {
        cout << setw(wnum) << left << ws[1];
        cout << setw(wnum) << left << ws[3];
        cout << setw(wnum) << left << ws[6].substr(0, ws[6].size() - 1);
        cout << setw(wnum) << left << ws[8];
        cout << setw(wnum) << left << ws[10].substr(0, ws[10].size() - 1);
      } else {
        cout << ws[1] << ",";
        cout << ws[3] << ",";
        cout << ws[6].substr(0, ws[6].size() - 1) << ",";
        cout << ws[8] << ",";
        cout << ws[10].substr(0, ws[10].size() - 1);
      }
      cout << endl;
    }
  }
}

/*
 * Specifying the expected options
 * The two options l and b expect numbers as argument
 */
enum {
  CFG_UPD = 1000,
  CFG_CLR,
  TC_CHANGED,
  TC_UNIQUE,
  SQ_RATE,
  SQ,
  RATE_GT,
  RATE_LT,
  TIME_GT,
  TIME_LT,
  TIME_RANGE,
  SIZE_GT,
  SIZE_LT,
  SIZE_RANGE,
  GET_RATE,
  LIST_QUEUES,
  LIST_2QUEUES,
  LIST_QUEUE_TYPES,
  HFQ_MASK,
  ADVQ_CONF,
  RATE,
  BURST,
  TIME,
  PERCENT,
  PERCENT_RATE,
  PROTOCOL,
  DSCP,
  LIST_POLICY,
  UPDATE_INTERFACE,
  DELETE_INTERFACE,
  CREATE_POLICY,
  APPLY_POLICY,
  DELETE_POLICY,
  UPDATE_ACTION,
  DELETE_ACTION,
  CHECK_TARGET,
  TC_CLASS_STAT,
  TC_QDISC_STAT,
  TC_DESC,
  CSV,
};

static struct option long_options[] = {
  { "cfg-upd",          required_argument,  0,  CFG_UPD },
  { "cfg-clr",          required_argument,  0,  CFG_CLR },
  { "intf-changed",     required_argument,  0,  TC_CHANGED },
  { "intf-tc-unique",   required_argument,  0,  TC_UNIQUE },
  { "chk-sq-rate",      required_argument,  0,  SQ_RATE },
  { "chk-sq",           required_argument,  0,  SQ },
  { "rate-gt",          required_argument,  0,  RATE_GT },
  { "rate-lt",          required_argument,  0,  RATE_LT },
  { "time-gt",          required_argument,  0,  TIME_GT },
  { "time-lt",          required_argument,  0,  TIME_LT },
  { "time-range",       required_argument,  0,  TIME_RANGE },
  { "size-gt",          required_argument,  0,  SIZE_GT },
  { "size-lt",          required_argument,  0,  SIZE_LT },
  { "size-range",       required_argument,  0,  SIZE_RANGE },
  { "get-rate",         required_argument,  0,  GET_RATE },
  { "list-queues",      required_argument,  0,  LIST_QUEUES },
  { "list-2queues",     required_argument,  0,  LIST_2QUEUES },
  { "list-queue-types", no_argument,        0,  LIST_QUEUE_TYPES },
  { "chk-hfq-mask",     required_argument,  0,  HFQ_MASK },
  { "chk-advq-conf",    no_argument,        0,  ADVQ_CONF },
  { "rate",             required_argument,  0,  RATE },
  { "burst",            required_argument,  0,  BURST },
  { "time",             required_argument,  0,  TIME },
  { "percent",          required_argument,  0,  PERCENT },
  { "percent-or-rate",  required_argument,  0,  PERCENT_RATE },
  { "protocol",         required_argument,  0,  PROTOCOL },
  { "dscp",             required_argument,  0,  DSCP },
  { "update-interface", required_argument,  0,  UPDATE_INTERFACE },
  { "delete-interface", required_argument,  0,  DELETE_INTERFACE },
  { "list-policy",      required_argument,  0,  LIST_POLICY },
  { "delete-policy",    required_argument,  0,  DELETE_POLICY },
  { "create-policy",    required_argument,  0,  CREATE_POLICY },
  { "apply-policy",     required_argument,  0,  APPLY_POLICY },
  { "update-action",    required_argument,  0,  UPDATE_ACTION },
  { "delete-action",    required_argument,  0,  DELETE_ACTION },
  { "check-target",     required_argument,  0,  CHECK_TARGET },
  { "tc-class-stat",    required_argument,  0,  TC_CLASS_STAT },
  { "tc-qdisc-stat",    required_argument,  0,  TC_QDISC_STAT },
  { "tc-desc",          no_argument,        0,  TC_DESC },
  { "csv",              no_argument,        0,  CSV },
  { 0,                  0,                  0,  0 }
};

/**
 * @brief The main function ubnt-tc application.
 * @param[in] argc Arguments count.
 * @param[in] argv Arguments array.
 * @return Exit status of the application.
 */
int main(int argc, char **argv)
{
  int opt = 0, index, rc = 0;
  bool need_desc = false, csv = false, class_stat = false, qdisc_stat = false;
  string dev;

  if (argc < 2) {
    cerr << "Error: missing argument" << endl;
    exit(EXIT_FAILURE);
  }

  while ((opt = getopt_long_only(argc, argv, "",
                                 long_options, &index)) != -1) {
    switch (opt) {
      case CFG_CLR:
      case LIST_QUEUES:
      case TC_UNIQUE:
      case GET_RATE:
      case SQ:
      case RATE:
      case BURST:
      case TIME:
      case PERCENT:
      case PERCENT_RATE:
      case PROTOCOL:
      case DSCP:
      case LIST_POLICY:
      case DELETE_POLICY:
      case APPLY_POLICY:
      case UPDATE_ACTION:
      case DELETE_ACTION:
      case CHECK_TARGET:
      case TC_CLASS_STAT:
      case TC_QDISC_STAT:
        if (!optarg) {
          cerr << "Error: missing argument" << endl;
          exit(EXIT_FAILURE);
        }
        break;
      case CFG_UPD:
      case LIST_2QUEUES:
      case RATE_GT:
      case RATE_LT:
      case TIME_GT:
      case TIME_LT:
      case SIZE_GT:
      case SIZE_LT:
      case TC_CHANGED:
      case HFQ_MASK:
      case SQ_RATE:
      case DELETE_INTERFACE:
      case CREATE_POLICY:
        if (!optarg || argc < optind + 1 || *argv[optind] == '-') {
          cerr << "Error: missing argument" << endl;
          exit(EXIT_FAILURE);
        }
        break;
      case TIME_RANGE:
      case SIZE_RANGE:
      case UPDATE_INTERFACE:
        if (!optarg || argc < optind + 2 ||
            *argv[optind] == '-' || *argv[optind + 1] == '-') {
          cerr << "Error: missing argument" << endl;
          exit(EXIT_FAILURE);
        }
        break;
    }

    switch (opt) {
      case CFG_UPD:
        cfg_upd(optarg, argv[optind ++]);
        break;
      case CFG_CLR:
        cfg_clr(optarg);
        break;
      case TC_CHANGED:
        intf_changed(optarg, argv[optind ++]);
        break;
      case TC_UNIQUE:
        rc = intf_tc_unique(optarg);
        break;
      case SQ_RATE:
        rc = chk_sq_rate(optarg, argv[optind ++]);
        break;
      case SQ:
        rc = chk_sq(optarg);
        break;
      case LIST_QUEUES:
        list_queues(optarg);
        break;
      case LIST_2QUEUES:
        list_2_queues(optarg, argv[optind ++]);
        break;
      case LIST_QUEUE_TYPES:
        list_queue_types();
        break;
      case RATE_GT:
        rc = rate_gt(optarg, argv[optind ++]);
        break;
      case RATE_LT:
        rc = rate_lt(optarg, argv[optind ++]);
        break;
      case GET_RATE:
        get_rate(optarg);
        break;
      case TIME_GT:
        rc = time_gt(optarg, argv[optind ++]);
        break;
      case TIME_LT:
        rc = time_lt(optarg, argv[optind ++]);
        break;
      case TIME_RANGE:
        {
          string time1(optarg);
          string time2(argv[optind ++]);
          string time3(argv[optind ++]);
          rc = time_range(time1, time2, time3);
        }
        break;
      case SIZE_GT:
        rc = size_gt(optarg, argv[optind ++]);
        break;
      case SIZE_LT:
        rc = size_lt(optarg, argv[optind ++]);
        break;
      case SIZE_RANGE:
        {
          string size1(optarg);
          string size2(argv[optind ++]);
          string size3(argv[optind ++]);
          rc = size_range(size1, size2, size3);
        }
        break;
      case HFQ_MASK:
        rc = chk_hfq_mask(optarg, argv[optind ++]);
        break;
      case ADVQ_CONF:
        rc = chk_advq_conf();
        break;
      case RATE:
        getRate(optarg);
        break;
      case BURST:
        getBurstSize(optarg);
        break;
      case TIME:
        getTime(optarg);
        break;
      case PERCENT:
        getPercent(optarg);
        break;
      case PERCENT_RATE:
        getPercentOrRate(optarg);
        break;
      case PROTOCOL:
        getProtocol(optarg);
        break;
      case DSCP:
        getDsfield(optarg);
        break;
      case LIST_POLICY:
        list_policy(optarg);
        break;
      case UPDATE_INTERFACE:
        {
          string dev(optarg);
          string dir(argv[optind ++]);
          string name(argv[optind ++]);
          update_interface(dev, dir, name);
        }
        break;
      case DELETE_INTERFACE:
        delete_interface(optarg, argv[optind ++]);
        break;
      case CREATE_POLICY:
        rc = create_policy(optarg, argv[optind ++]);
        break;
      case DELETE_POLICY:
        delete_policy(optarg);
        break;
      case APPLY_POLICY:
        apply_policy(optarg);
        break;
      case UPDATE_ACTION:
        update_action(optarg);
        break;
      case DELETE_ACTION:
        delete_action(optarg);
        break;
      case CHECK_TARGET:
        check_target(optarg);
        break;
      case TC_CLASS_STAT:
        if (optarg) {
          class_stat = true;
          dev = optarg;
        }
        break;
      case TC_QDISC_STAT:
        if (optarg) {
          qdisc_stat = true;
          dev = optarg;
        }
        break;
      case TC_DESC:
        need_desc = true;
        break;
      case CSV:
        csv = true;
        break;
      default:
        rc = 1;
        break;
    }
  }

  if (class_stat) {
    tc_class_stat(dev, need_desc, csv);
  }
  if (qdisc_stat) {
    tc_qdisc_stat(dev, need_desc, csv);
  }

  return rc;
}
