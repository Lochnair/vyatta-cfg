#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <arpa/inet.h>
#include <regex.h>

#include <boost/algorithm/string.hpp>

#include "fw.hpp"
#include "address.hpp"
#include "util.hpp"

using namespace std;
using namespace cstore;

Address::Address()
{
    _setup = false;
}

void
Address::setup(Cpath& cpath, bool active)
{
    vector<string> children;
    vector<string>::iterator it;

    _ip_version = "ipv4";
    _srcdst     = cpath[5];

    cpath.pop();
    cpath.push("protocol");
    g_cstore->_cfgPathGetValue(cpath, _protocol, active);
    cpath.pop();
    cpath.push(_srcdst);

    g_cstore->_cfgPathGetChildNodes(cpath, children, active);
    for (it = children.begin(); it < children.end(); it++) {
        if (*it == "address") {
            size_t pos;
            cpath.push(*it);
            g_cstore->_cfgPathGetValue(cpath, _address, active);
            if (_address.find('/') != string::npos) {
                _network = _address;
                _address.clear();
            } else if ((pos = _address.find('-')) != string::npos) {
                _range_start = _address.substr(0, pos);
                _range_stop  = _address.substr(pos+1);
                _address.clear();
            }
            cpath.pop();
            continue;
        }
        if (*it == "port") {
            cpath.push(*it);
            g_cstore->_cfgPathGetValue(cpath, _port, active);
            cpath.pop();
            continue;
        }
        if (*it == "mac-address") {
            cpath.push(*it);
            g_cstore->_cfgPathGetValue(cpath, _src_mac, active);
            cpath.pop();
            continue;
        }
        if (*it == "group") {
            vector<string> g_children;
            vector<string>::iterator g_it;
            cpath.push(*it);
            g_cstore->_cfgPathGetChildNodes(cpath, g_children, active);
            for (g_it = g_children.begin(); g_it < g_children.end(); g_it++) {
                if (*g_it == "address-group") {
                    cpath.push(*g_it);
                    g_cstore->_cfgPathGetValue(cpath, _address_group, active);
                    cpath.pop();
                    continue;
                }
                if (*g_it == "network-group") {
                    cpath.push(*g_it);
                    g_cstore->_cfgPathGetValue(cpath, _network_group, active);
                    cpath.pop();
                    continue;
                }
                if (*g_it == "ipv6-address-group") {
                    cpath.push(*g_it);
                    g_cstore->_cfgPathGetValue(cpath, _address_group, active);
                    cpath.pop();
                    continue;
                }
                if (*g_it == "ipv6-network-group") {
                    cpath.push(*g_it);
                    g_cstore->_cfgPathGetValue(cpath, _network_group, active);
                    cpath.pop();
                    continue;
                }

                if (*g_it == "port-group") {
                    cpath.push(*g_it);
                    g_cstore->_cfgPathGetValue(cpath, _port_group, active);
                    cpath.pop();
                    continue;
                }
            } // end of for g_children
            cpath.pop();
        } // end of "group"
    }
    _setup = true;
}

bool
Address::get_port_rule_string(bool can_use_port, string& port_rule,
                              string& err) const
{
    string port_str(_port), negate, new_port_str;
    vector<string> v;
    vector<string>::iterator it;

    if (port_str.find('!', 0) != string::npos) {
        port_str = port_str.substr(1);
        negate = "! ";
    }

    int num_ports = 0;
    split(port_str, ',', v);
    for (it = v.begin(); it < v.end(); it++) {
        if (it->empty())
            continue;
        string range_s, range_e;
        if (is_port_range(*it, range_s, range_e)) {
            if  (!is_valid_port_range(range_s, range_e, err))
                return false;
            new_port_str += range_s + ":" + range_e + ",";
            num_ports += 2;
            continue;
        }
        if (is_digit(*it)) {
            if (!is_valid_port_number(*it, err))
                return false;
            else {
                new_port_str += *it + ",";
                num_ports++;
                continue;
            }
        }
        if (_protocol == "tcp_udp") {
            if ((!is_valid_port_name(*it, "tcp", err))
                || (!is_valid_port_name(*it, "udp", err)))
                return false;
            else {
                new_port_str += *it + ",";
                num_ports++;
                continue;
            }
        } else {
            if (!is_valid_port_name(*it, _protocol.c_str(), err))
                return false;
            else {
                new_port_str += *it + ",";
                num_ports++;
                continue;
            }
        }
        err  = "unexpected error [";
        err += *it + "]\n";
        return false;
    }

    if (num_ports > 0 && !can_use_port) {
        err  = "ports can only be specified when protocol is 'tcp'";
        err += "or 'udp' (currently '";
        err += _protocol + "')";
        return false;
    }

    if (num_ports > 15) {
        err  = "source/destination port specification only supports ";
        err += "up to 15 ports (port range counts as 2)";
        return false;
    }

    char prefix;
    if (_srcdst == "source")
        prefix = 's';
    else
        prefix = 'd';

    size_t last = new_port_str.length();
    if (last > 0 && new_port_str.at(last - 1) == ',') {
        new_port_str = new_port_str.substr(0, last - 1);
    }

    port_rule = " ";
    if (num_ports > 1) {
        port_rule += " -m multiport ";
        port_rule += negate + " --" + prefix + "ports " + new_port_str + " ";
    } else if (num_ports > 0) {
        port_rule += negate + " --" + prefix + "port " + new_port_str + " ";
    }

    return true;
}

bool
Address::rule(string& rule_string, string& err) const
{
    bool can_use_port = false;
    string ip;

    if (!_protocol.empty()) {
        if (_protocol == "tcp_udp" || _protocol == "tcp"
            || _protocol == "udp"  || _protocol == "6"
            || _protocol == "17") {
            can_use_port = true;
        }
    }

    if (_srcdst == "source" && !_src_mac.empty()) {
        string str(_src_mac), negate;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        rule_string = "-m mac ";
        rule_string += negate + " --mac-source " + str + " ";
    }

    bool group_ok[FW_GROUP_LAST];
    bool group_used[FW_GROUP_LAST];
    int i;
    for (i = 0; i < FW_GROUP_LAST; i++) {
        group_ok[i] = true;
        group_used[i] = false;
    }

    if (!_network.empty()) {
        string str(_network), negate;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        if (!validate_network(_ip_version, str)) {
            err  = "'";
            err += str + "' is not a valid " + _ip_version + " subnet";
            return false;
        }
        rule_string += negate + " --" + _srcdst + " " + str + " ";
        group_ok[NETWORK] = false;
    } else if (!_address.empty()) {
        string str(_address), negate;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        if (!validate_address(_ip_version, str)) {
            err  = "'";
            err += str + "' is not a valid " + _ip_version + " address";
            return false;
        }
        rule_string += negate + " --" + _srcdst + " " + str + " ";
        group_ok[NETWORK] = false;
    } else if (!_range_start.empty() && !_range_stop.empty()) {
        string str(_range_start), negate, tmp;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        if (!validate_address(_ip_version, str)
            || !validate_address(_ip_version, _range_stop)) {
            err  = "'";
            err += str + "-" + _range_stop + "' "
                + "is not a valid " + _ip_version + " range";
            return false;
        }
        tmp = "-m iprange ";
        if (_srcdst == "source") {
            rule_string += tmp + negate + " --src-range " + str
                + "-" + _range_stop + " ";
        } else {
            rule_string += tmp + negate + " --dst-range " + str
                + "-" + _range_stop + " ";
        }
        group_ok[ADDRESS] = false;
        group_ok[NETWORK] = false;
    }

    if (!_port.empty())
        group_ok[PORT] = false;

    string port_rule;
    if (!get_port_rule_string(can_use_port, port_rule, err)) {
        return false;
    }
    rule_string += port_rule;

    string ipset_srcdst;
    if (_srcdst == "source")
        ipset_srcdst = "src";
    else
        ipset_srcdst = "dst";

    // TODO: validate group exists

    if (!_address_group.empty()){
        if (!group_ok[ADDRESS]) {
            err = "Can't mix " + _srcdst + " address group "
                + "[" + _address_group + "] and address";
            return false;
        }

        group_used[ADDRESS] = true;
        string str(_address_group), negate, tmp;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        tmp = "-m set ";
        rule_string += tmp + negate + " --match-set "
            + str + " " + ipset_srcdst + " ";
    }

    if (!_network_group.empty()){
        if (!group_ok[NETWORK]) {
            err = "Can't mix " + _srcdst + " network group "
                + "[" + _address_group + "] and address";
            return false;
        }

        group_used[NETWORK] = true;
        string str(_network_group), negate, tmp;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        tmp = "-m set ";
        rule_string += tmp + negate + " --match-set "
            + str + " " + ipset_srcdst + " ";
    }

    if (!_port_group.empty()){
        if (!group_ok[PORT]) {
            err = "Can't mix " + _srcdst + " port group "
                + "[" + _port_group + "] and port";
            return false;
        }

        group_used[PORT] = true;
        string str(_port_group), negate, tmp;
        if (str.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        tmp = "-m set ";
        rule_string += tmp + negate + " --match-set "
            + str + " " + ipset_srcdst + " ";
    }

    if (group_used[NETWORK] && group_used[ADDRESS]) {
        err = "Can't combine network and address group for "
            + _srcdst;
        return false;
    }

    return true;
}

void
Address::set_ip_version(const string& ip_version)
{
    _ip_version = ip_version;
}

bool
Address::validate_address(const string& version, const string& address)
{
    unsigned char buf[sizeof(struct in6_addr)];
    int rc;

    if (version == "ipv4") {
        rc = inet_pton(AF_INET, address.c_str(), buf);
        return rc ? true : false;
    } else {
        rc = inet_pton(AF_INET6, address.c_str(), buf);
        return rc ? true : false;
    }
}

bool
Address::validate_network(const string& version, const string& network)
{
    size_t pos;
    string address, prefix;
    int i_prefix;

    if (version == "ipv4") {
        pos = network.find('/');
        if (pos == string::npos)
            return false;
        address = network.substr(0, pos);
        prefix  = network.substr(pos+1);
        i_prefix = my_atoi(prefix);
        if (i_prefix < 0 || i_prefix > 32)
            return false;
        return validate_address(version, address);
    } else {
        pos = network.find('/');
        if (pos == string::npos)
            return false;
        address = network.substr(0, pos);
        prefix  = network.substr(pos+1);
        i_prefix = my_atoi(prefix);
        if (i_prefix < 0 || i_prefix > 128)
            return false;
        return validate_address(version, address);
    }
}

void
Address::print() const
{
    if (!_ip_version.empty()) {
        cout << "ip_version: [" << _ip_version << "]" << endl;
    }
    if (!_srcdst.empty()) {
        cout << "srcdst: [" << _srcdst << "]" << endl;
    }
    if (!_range_start.empty()) {
        cout << "range_start: [" << _range_start << "]" << endl;
    }
    if (!_range_stop.empty()) {
        cout << "range_stop: [" << _range_stop << "]" << endl;
    }
    if (!_network.empty()) {
        cout << "network: [" << _network << "]" << endl;
    }
    if (!_address.empty()) {
        cout << "address: [" << _address << "]" << endl;
    }
    if (!_port.empty()) {
        cout << "port: [" << _port << "]" << endl;
    }
    if (!_protocol.empty()) {
        cout << "protocol: [" << _protocol << "]" << endl;
    }
    if (!_src_mac.empty()) {
        cout << "src_mac: [" << _src_mac << "]" << endl;
    }
    if (!_address_group.empty()) {
        cout << "address_group: [" << _address_group << "]" << endl;
    }
    if (!_network_group.empty()) {
        cout << "network_group: [" << _network_group << "]" << endl;
    }
    if (!_port_group.empty()) {
        cout << "port_group: [" << _port_group << "]" << endl;
    }
}
