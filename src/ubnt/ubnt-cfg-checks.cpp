#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <regex.h>

#include <boost/unordered_map.hpp>
#include <boost/foreach.hpp>

#include <cstore/cstore.hpp>

using namespace std;
using namespace cstore;

static char _line[256];

static bool
_read_line()
{
    if (!fgets(_line, 256, stdin)) {
        return false;
    }
    char *c = strchr(_line, '\n');
    if (c) {
        *c = 0;
    }
    return true;
}

static regex_t _regex_eth_intf_name;
static regex_t _regex_br_intf_name;
static regex_t _regex_bond_intf_name;
static regex_t _regex_switch_intf_name;
static regex_t _regex_vif_intf_name;
static regex_t _regex_all_intf_name;
static boost::unordered_map<string, regex_t *> _intf_name_regex_map;
static Cstore *_cstore;

static void
err_exit(const char *fmt, ...)
{
    va_list alist;
    va_start(alist, fmt);
    vprintf(fmt, alist);
    va_end(alist);
    exit(1);
}

static void
_do_list_sys_intfs()
{
    if (!_read_line()) {
        exit(1);
    }

    bool all = (strcmp(_line, "all") == 0);
    if (!all && _intf_name_regex_map.find(_line)
                == _intf_name_regex_map.end()) {
        exit(1);
    }
    regex_t *re = (all ? NULL : _intf_name_regex_map[_line]);

    while (_read_line()) {
        if (all || regexec(re, _line, 0, NULL, 0) == 0) {
            printf("%s ", _line);
        }
    }
}

static void
_do_valid_intf()
{
    if (!_read_line()) {
        exit(1);
    }

    if (_intf_name_regex_map.find(_line) == _intf_name_regex_map.end()) {
        printf("Invalid interface type %s\n", _line);
        exit(1);
    }

    string type(_line);
    regex_t *re = _intf_name_regex_map[type];

    if (!_read_line()) {
        exit(1);
    }

    if (regexec(re, _line, 0, NULL, 0) != 0) {
        printf("Type of interface %s is not %s\n", _line, type.c_str());
        exit(1);
    }
    exit(0);
}

static void
_do_eth_commit()
{
    Cpath cpath;
    while (_read_line() && strcmp(_line, "'''") != 0) {
        cpath.push(_line);
    }

    if (!_read_line()) exit(1); string speed(_line);
    if (!_read_line()) exit(1); string duplex(_line);
    if (speed != "none" && duplex != "none") {
        string os, od;
        cpath.push("speed");
        _cstore->cfgPathGetValue(cpath, os, true);
        cpath.pop();
        cpath.push("duplex");
        _cstore->cfgPathGetValue(cpath, od, true);
        cpath.pop();

        if (speed != os || duplex != od) {
            if (speed == "auto") {
                if (duplex != "auto") {
                    err_exit("If duplex is hardcoded, speed must also "
                             "be hardcoded\n");
                }
            } else if (duplex == "auto") {
                err_exit("If speed is hardcoded, duplex must also "
                         "be hardcoded\n");
            }
        }
    }

    vector<string> addrs;
    vector<bool> multi;
    vector<bool> v4;
    while (_read_line()) {
        addrs.push_back(_line);
        if (!_read_line()) exit(1); multi.push_back(_line[0] == '1');
        if (!_read_line()) exit(1); v4.push_back(_line[0] == '1');
    }

    vector<string> oaddrs;
    cpath.push("address");
    _cstore->cfgPathGetValues(cpath, oaddrs, true);
    cpath.pop();
    if (oaddrs.size() == addrs.size()) {
        bool unchanged = true;
        for (size_t i = 0; i < addrs.size(); i++) {
            if (oaddrs[i] != addrs[i]) {
                unchanged = false;
                break;
            }
        }
        if (unchanged) {
            exit(0);
        }
    }

    cpath.push("bridge-group"); cpath.push("bridge");
    if (_cstore->cfgPathExists(cpath, false)) {
        err_exit("Cannot configure address on bridged interface\n");
    }
    cpath.pop(); cpath.pop();

    cpath.push("bond-group");
    if (_cstore->cfgPathExists(cpath, false)) {
        err_exit("Cannot configure address on bonded interface\n");
    }
    cpath.pop();

    bool a_dhcp4 = false, a_v4 = false;
    for (size_t i = 0; i < addrs.size(); i++) {
        if (addrs[i] == "dhcp") {
            a_dhcp4 = true;
        } else if (addrs[i] == "dhcp6") {
        } else if (multi[i]) {
            err_exit("Address %s is present on multiple interfaces\n",
                     addrs[i].c_str());
        } else if (v4[i]) {
            a_v4 = true;
        }
    }
    if (a_dhcp4 && a_v4) {
        err_exit("Cannot configure static IPv4 address and DHCP "
                 "on the same interface.\n");
    }
    exit(2);
}

typedef void (*handler_t)(void);
static boost::unordered_map<string, handler_t> _handler_map;

int
main(int argc, const char *argv[])
{
    _handler_map["list-sys-intfs"] = _do_list_sys_intfs;
    _handler_map["valid-intf"] = _do_valid_intf;
    _handler_map["eth-commit"] = _do_eth_commit;

    regcomp(&_regex_eth_intf_name, "^eth[0-9]+$", REG_EXTENDED);
    regcomp(&_regex_br_intf_name, "^br[0-9]+$", REG_EXTENDED);
    regcomp(&_regex_bond_intf_name, "^bond[0-9]+$", REG_EXTENDED);
    regcomp(&_regex_switch_intf_name, "^switch[0-9]+$", REG_EXTENDED);
    regcomp(&_regex_vif_intf_name, "^[a-z]+[0-9]\\.[0-9]+$", REG_EXTENDED);
    regcomp(&_regex_all_intf_name, "^.*$", REG_EXTENDED);

    _intf_name_regex_map["ethernet"] = &_regex_eth_intf_name;
    _intf_name_regex_map["bridge"] = &_regex_br_intf_name;
    _intf_name_regex_map["bonding"] = &_regex_bond_intf_name;
    _intf_name_regex_map["switch"] = &_regex_switch_intf_name;
    _intf_name_regex_map["vif"] = &_regex_vif_intf_name;
    _intf_name_regex_map["all"] = &_regex_all_intf_name;

    if (!_read_line()) {
        exit(1);
    }
    if (_handler_map.find(_line) == _handler_map.end()) {
        exit(1);
    }

    string dummy;
    char *sid = getenv("COMMIT_SESSION_ID");
    _cstore = (sid ? Cstore::createCstore(sid, dummy)
                     : Cstore::createCstore(true));
    if (!_cstore) {
        exit(1);
    }

    (_handler_map[_line])();

    return 0;
}
