#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>

#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <boost/foreach.hpp>
#include <boost/unordered_map.hpp>
#include <boost/filesystem.hpp>

#include "vyatta_config.hpp"
#include "vyatta_interface.hpp"

using namespace std;

typedef struct vyatta_intf_s_ {
    const char *dev;
    const char *type;
    const char *vifpath;
} vyatta_intf_t;

static vyatta_intf_t _intfs[] = {
//  dev         type                vifpath
  { "adsl",     "adsl",             "vif" },
  { "bond",     "bonding",          "vif" },
  { "br",       "bridge",           "vif" },
  { "eth",      "ethernet",         "vif" },
  { "ml",       "multilink",        "vif" },
  { "vtun",     "openvpn",          0     },
  { "v6tun",    "ipv6-tunnel",      0     },
  { "pptpc",    "pptp-client",      0     },
  { "tun",      "tunnel",           0     },
  { "vti",      "vti",              0     },
  { "wlm",      "wireless-modem",   0     },
  { "peth",     "pseudo-ethernet",  "vif" },
  { "wlan",     "wireless",         "vif" },
  { "ifb",      "input",            0     },
  { "switch",   "switch",           "vif" },
  { "l2tpeth",  "l2tpv3",           0     },
  { "wan",      "serial",           "cisco-hdlc vif" },
  { "wan",      "serial",           "ppp vif" },   
  { "wan",      "serial",           "frame-relay vif" },   
  { "lo",       "loopback",         0},
  { 0 }
};

const string vyatta::Interface::_dummy;

static int
check_address(vyatta::Config& cfg, const string& path, const string& ip)
{
  vector<string> addrs;

  if (path.find("openvpn") != std::string::npos) {
    cfg.listNodes(path + " local-address", addrs); 
  } else {
    cfg.returnValues(path + " address", addrs);
  }

  int count = 0;
  for (size_t i = 0; i < addrs.size(); i ++) {
    if (addrs[i] == ip) {
      count ++;
    }
  }
  return count;
}

static bool
check_addresses(vyatta::Config& cfg, const string& path,
                boost::unordered_map<string, int>& amap,
                const bool exit = true)
{
  bool is_uniq = true;
  vector<string> addrs;

  if (path.find("openvpn") != std::string::npos) {
    cfg.listNodes(path + " local-address", addrs); 
  } else {
    cfg.returnValues(path + " address", addrs);
  }

  for (size_t i = 0; i < addrs.size(); i ++) {
    boost::unordered_map<string, int>::iterator it = amap.find(addrs[i]);
    if (it == amap.end()) {
      continue;
    }
    it->second += 1;
    if (it->second > 1) {
      is_uniq = false;
      if (exit) {
        break;
      }
    }
  }
  return is_uniq;
}

vyatta::Interface::Interface(const string& name)
{
  // need argument to constructor
  if (name.empty()) {
    return;
  }

  string vif, dev, dev_type, dev_id;
  parse_if_name(name, dev, dev_type, dev_id, vif);

  // Special case for ppp devices
  if (check_if_ppp(dev_type, dev_id)) {
    _name = name;
    _type = dev_type;
    _dev_type = dev_type;
    _dev_id = dev_id;
    _dev_vif = vif;
    return;
  }

  string path;
  if (!fill_interface(dev_type, dev_id, vif, path, _type)) {
    return;
  }

  _name = name;
  _path = path;
  _dev_vif  = vif;
  _dev_type = dev_type;
  _dev_id = dev_id;
}

bool
vyatta::Interface::fill_interface(const string& dev, const string& dev_id,
                                  const string& vif,
                                  string& path, string& type) const
{
  string vifpath;

  vyatta_intf_t* intf = _intfs;
  while (intf->dev) {
    if (dev == intf->dev) {
      type = intf->type;
      if (intf->vifpath) {
        vifpath = intf->vifpath;
      }
      break;
    }
    intf ++;
  }

  if (type.empty()) {
    // not found
    return false;
  }

  // Interface name has vif, but this type doesn't support vif!
  if (!vif.empty() && vifpath.empty()) {
    return false;
  }

  // Check path if given
  //return if ( $#_ >= 0 && join( ' ', @_ ) ne $type );

  path = "interfaces " + type + " " + dev + dev_id;
  if (!vif.empty() && !vifpath.empty()) {
    path += " "  + vifpath + " "  + vif;
  }

  return true;
}


string
vyatta::Interface::fill_path(const string& type, const string& name,
                             const string& vifpath, const string& vif)
{
  string path = "interfaces " + type;
  if (!name.empty()) {
   path += " " + name;
    if (!vifpath.empty()) {
      path += " " + vifpath;
      if (!vif.empty()) {
        path += " " + vif;
      }
    }
  }
  return path;
}

/*
 * check to see if an address is unique in the working configuration
 */
bool
vyatta::Interface::is_uniq_address(const string& ip)
{
  int count = 0;
  string path;
  vyatta::Config cfg;
  vector<string> eths;

  cfg.listNodes("interfaces ethernet", eths);

  vyatta_intf_t* intf = _intfs;
  while (intf->dev) {
    vector<string> tifs;
    if (!strcmp(intf->type, "ethernet")) {
      tifs = eths;
    } else {
      path = fill_path(intf->type);
      cfg.listNodes(path, tifs);
    }
    BOOST_FOREACH (const string& tif, tifs) {
      //'path' => "interfaces $type $tif"
      path = fill_path(intf->type, tif);
      count += check_address(cfg, path, ip);
      if (count > 1) {
        return false;
      }

      if (intf->vifpath) {
        vector<string> vnums;
        path = fill_path(intf->type, tif, intf->vifpath);
        cfg.listNodes(path, vnums);
        BOOST_FOREACH (const string& vnum, vnums) {
          // 'path' => "interfaces $type $tif $vpath $vnum"
          path = fill_path(intf->type, tif, intf->vifpath, vnum);
          count += check_address(cfg, path, ip);
          if (count > 1) {
            return false;
          }
        }
      }
    }
    intf ++;
  }

  // now special case for pppo*
  BOOST_FOREACH (const string& eth, eths) {
    vector<string> eps;
    path = "interfaces ethernet " + eth + " pppoe";
    cfg.listNodes(path, eps);
    BOOST_FOREACH (const string& ep, eps) {
      // 'path' => "interfaces ethernet $eth pppoe $ep"
      string p = path + " " + ep;
      count += check_address(cfg, p, ip);
      if (count > 1) {
        return false;
      }
    }
  }

  // now special case for adsl
  vector<string> as;
  cfg.listNodes("interfaces adsl", as);
  BOOST_FOREACH (const string& a, as) {
    vector<string> ps;
    cfg.listNodes("interfaces adsl " + a + " pvc", ps);
    BOOST_FOREACH (const string& p, ps) {
      vector<string> ts;
      cfg.listNodes("interfaces adsl " + a + " pvc " + p, ts);
      BOOST_FOREACH (const string& t, ts) {
        if (t == "classical-ipoa" or t == "bridged-ethernet") {
          // classical-ipoa or bridged-ethernet
          // 'path' => "interfaces adsl $a pvc $p $t"
          count += check_address(cfg,
                                 "interfaces adsl " + a + " pvc " + p + " " + t,
                                 ip);
          if (count > 1) {
            return false;
          }
          continue;
        }
        // pppo[ea]
        // 'path' => "interfaces adsl $a pvc $p $t $i"
        vector<string> iss;
        cfg.listNodes("interfaces adsl " + a + " pvc " + p + " " + t, iss);
        BOOST_FOREACH (const string& i, iss) {
          count += check_address(cfg,
                                 "interfaces adsl " + a + " pvc " + p + " " + t + " " + i,
                                 ip);
          if (count > 1) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

bool
vyatta::Interface::is_uniq_address(const vector<string>& ips)
{
  string path;
  vyatta::Config cfg;
  vector<string> eths;
  boost::unordered_map<string, int> amap;

  for (size_t i = 0; i < ips.size(); i ++) {
    amap[ips[i]] = 0;
  }

  cfg.listNodes("interfaces ethernet", eths);

  vyatta_intf_t* intf = _intfs;
  while (intf->dev) {
    vector<string> tifs;
    if (!strcmp(intf->type, "ethernet")) {
      tifs = eths;
    } else {
      path = fill_path(intf->type);
      cfg.listNodes(path, tifs);
    }
    BOOST_FOREACH (const string& tif, tifs) {
      path = fill_path(intf->type, tif);
      //'path' => "interfaces $type $tif"
      if (!check_addresses(cfg, path, amap)) {
        return false;
      }

      if (intf->vifpath) {
        vector<string> vnums;
        path = fill_path(intf->type, tif, intf->vifpath);
        cfg.listNodes(path, vnums);
        BOOST_FOREACH (const string& vnum, vnums) {
          // 'path' => "interfaces $type $tif $vpath $vnum"
          path = fill_path(intf->type, tif, intf->vifpath, vnum);
          if (!check_addresses(cfg, path, amap)) {
            return false;
          }
        }
      }
    }
    intf ++;
  }

  // now special case for pppo*
  BOOST_FOREACH (const string& eth, eths) {
    vector<string> eps;
    path = "interfaces ethernet " + eth + " pppoe";
    cfg.listNodes(path, eps);
    BOOST_FOREACH (const string& ep, eps) {
      // 'path' => "interfaces ethernet $eth pppoe $ep"
      string p = path + " " + ep;
      if (!check_addresses(cfg, p, amap)) {
        return false;
      }
    }
  }

  // now special case for adsl
  vector<string> as;
  cfg.listNodes("interfaces adsl", as);
  BOOST_FOREACH (const string& a, as) {
    vector<string> ps;
    cfg.listNodes("interfaces adsl " + a + " pvc", ps);
    BOOST_FOREACH (const string& p, ps) {
      vector<string> ts;
      cfg.listNodes("interfaces adsl " + a + " pvc " + p, ts);
      BOOST_FOREACH (const string& t, ts) {
        if (t == "classical-ipoa" or t == "bridged-ethernet") {
          // classical-ipoa or bridged-ethernet
          // 'path' => "interfaces adsl $a pvc $p $t"
          if (!check_addresses(cfg,
                               "interfaces adsl " + a + " pvc " + p + " " + t,
                               amap)) {
            return false;
          }
          continue;
        }
        // pppo[ea]
        vector<string> iss;
        cfg.listNodes("interfaces adsl " + a + " pvc " + p + " " + t, iss);
        // 'path' => "interfaces adsl $a pvc $p $t $i"
        BOOST_FOREACH (const string& i, iss) {
          if (!check_addresses(cfg,
                               "interfaces adsl " + a + " pvc " + p + " " + t + " " + i,
                               amap)) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

void
vyatta::Interface::parse_if_name(const string& name,
                                 string& dev, string& dev_type,
                                 string& dev_id, string& vif) const
{
  // Strip off vif from name
  string::size_type pos = name.find('.');
  if (pos != name.npos) {
    dev = name.substr(0, pos);
    vif = name.substr(pos + 1, name.npos);
  } else {
    dev = name;
  }

  // Get size of device-type substring by iterating chars from end to beginning
  // until we hit a non-digit char
  //
  // Example: dev         = l2tpeth42
  //                        ---------
  //                        012345678 -> 9 chars
  //
  //          type_size   = 7
  //          dev_type    = l2tpeth (0..6)
  //          dev_id      = 42 (7..8)
  size_t type_size = dev.size() - 1;
  for(; type_size >= 0 && isdigit(dev[type_size]); type_size--) { }

  // Device type is left part
  type_size++;
  dev_type = dev.substr(0, type_size);

  // Device id is right part
  dev_id = dev.substr(type_size);
}

string
vyatta::Interface::path() const
{
  if (!_path.empty()) {
    return _path;
  }
  // Go path hunting to find ppp device
  return ppp_path();
}

bool
vyatta::Interface::check_if_ppp(const string& dev, const string& dev_id) const
{
  return (!dev_id.empty() &&
          (dev == "pppoas" || dev == "pppoa" ||
           dev == "pppoes" || dev == "pppoe" ||
           dev == "pptp"   || dev == "l2tp"));
}

/*
 * Go path hunting to find ppp device
 */
string
vyatta::Interface::ppp_path() const
{
  string path, intf;

  if (!check_if_ppp(_dev_type, _dev_id)) {
    return path;
  }

  if (_dev_type == "pppoe" && ppp_intf(_name, intf)) {
    string vif, dev, dev_type, dev_id;
    parse_if_name(intf, dev, dev_type, dev_id, vif);

    if (dev_type == "eth") {
      path = "interfaces ethernet ";
    } else if (dev_type == "peth") {
      path = "interfaces pseudo-ethernet ";
    } else if (dev_type == "switch") {
      path = "interfaces switch ";
    } else if (dev_type == "bridge") {
      path = "interfaces bridge ";
    }
    path += dev;
    if (!vif.empty()) {
      path += " vif " + vif;
    }
    path += " pppoe " + _dev_id;
  }
  return path;
}

/*
 * Read ppp config to fine associated interface for ppp device
 */
bool
vyatta::Interface::ppp_intf(const string& dev, string& intf) const
{
  intf = "";

  string path, line;
  path = "/etc/ppp/peers/" + dev;

  ifstream ifs;
  ifs.open(path.c_str());
  if (!ifs.is_open()) {
    return false;
  }

  string param("#interface ");
  while (!ifs.eof()) {
    getline(ifs, line);

    string::size_type off = line.find(param, 0);
    if (off == string::npos || off != 0) {
      continue;
    }
    intf = line.substr(param.size());
    break;
  }
  ifs.close();
  return !intf.empty();
}

string
vyatta::Interface::mtu()
{
  vyatta::Config config(path());
  string mtu;
  config.returnValue("mtu", mtu);
  return mtu;
}

string
vyatta::Interface::bridge_grp()
{
  vyatta::Config config(path());
  string grp;
  config.returnValue("bridge-group bridge", grp);
  return grp;
}

bool
vyatta::Interface::up()
{
  return flags() & IFF_UP;
}

long
vyatta::Interface::flags()
{
  string str, file_path("/sys/class/net/");
  file_path += _name + "/flags";
  ifstream ifs(file_path.c_str());
  if (getline(ifs, str)) {
    char *endptr;
    long flags = strtol(str.c_str(), &endptr, 16); //in hex with 0x
    if ((errno == ERANGE && (flags == LONG_MAX || flags == LONG_MIN)) ||
        (errno != 0 && flags == 0)) {
      return 0;
    }
    if (endptr == str.c_str()) {
      return 0;
    }
    return flags;
  }
  return 0;
}

void
vyatta::Interface::listSystemInterfaces(vector<string>& intfs)
{
  try {
    boost::filesystem::directory_iterator di("/sys/class/net");
    for (; di != boost::filesystem::directory_iterator(); ++ di) {
      string cname = di->path().filename().string();
      if (cname.length() < 1 || cname[0] == '.') {
        continue;
      }
      string filter = "bonding_masters";
      if (cname == filter) {
        continue;
      }
      filter = "mon.wlan";
      if (!cname.compare(0, filter.size(), filter)) {
        continue;
      }
      filter = "wmaster";
      if (!cname.compare(0, filter.size(), filter)) {
        continue;
      }
      intfs.push_back(cname);
    }
  } catch (...) {
    // skip the rest
  }
}

