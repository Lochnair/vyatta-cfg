#include <stdio.h>
#include <iostream>
#include <string>
#include <sstream>
#include <pcre.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "fw.hpp"
#include "rule.hpp"
#include "util.hpp"
#include "fw_dpi.hpp"

using namespace std;
using namespace cstore;

Rule::Rule()
{
    _debug   = false;
    _setup   = false;
    _p2p_set = false;

    _disable    = false;
    _p2p[ALL]   = false;
    _p2p[APPLE] = false;
    _p2p[BIT]   = false;
    _p2p[DC]    = false;
    _p2p[EDK]   = false;
    _p2p[GNU]   = false;
    _p2p[KAZAA] = false;
    _time_utc   = false;
    _ipsec      = false;
    _non_ipsec  = false;
    _frag       = false;
    _non_frag   = false;

    _selfdestruct = false;
}

void
Rule::setup_base(Cpath& cpath, bool active)
{
    // firewall name <chain> rule <n>
    _tree        = cpath[1];
    _name        = cpath[2];
    _rule_number = cpath[4];
    _comment     = _name + "-" + _rule_number;

    vector<string> children;
    vector<string>::iterator it;
    g_cstore->_cfgPathGetChildNodes(cpath, children, active);
    for (it = children.begin(); it < children.end(); it++) {
        if (*it == "action") {
            cpath.push("action");
            g_cstore->_cfgPathGetValue(cpath, _action, active);
            cpath.pop();
            continue;
        }
        if (*it == "protocol") {
            cpath.push("protocol");
            g_cstore->_cfgPathGetValue(cpath, _protocol, active);
            cpath.pop();
            continue;
        }
        if (*it == "state") {
            cpath.push("state");
            cpath.push("established");
            g_cstore->_cfgPathGetValue(cpath, _state[ESTABLISHED], active);
            cpath.pop();
            cpath.push("new");
            g_cstore->_cfgPathGetValue(cpath, _state[NEW], active);
            cpath.pop();
            cpath.push("related");
            g_cstore->_cfgPathGetValue(cpath, _state[RELATED], active);
            cpath.pop();
            cpath.push("invalid");
            g_cstore->_cfgPathGetValue(cpath, _state[INVALID], active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "log") {
            cpath.push("log");
            g_cstore->_cfgPathGetValue(cpath, _log, active);
            cpath.pop();
            continue;
        }
        if (*it == "tcp") {
            cpath.push("tcp");
            cpath.push("flags");
            g_cstore->_cfgPathGetValue(cpath, _tcp_flags, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "icmp") {
            cpath.push("icmp");
            cpath.push("code");
            g_cstore->_cfgPathGetValue(cpath, _icmp_code, active);
            cpath.pop();
            cpath.push("type");
            g_cstore->_cfgPathGetValue(cpath, _icmp_type, active);
            cpath.pop();
            cpath.push("type-name");
            g_cstore->_cfgPathGetValue(cpath, _icmp_name, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "icmpv6") {
            cpath.push("icmpv6");
            cpath.push("type");
            g_cstore->_cfgPathGetValue(cpath, _icmpv6_type, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "ipsec") {
            cpath.push("ipsec");
            cpath.push("match-ipsec");
            _ipsec = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("match-none");
            _non_ipsec = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "fragment") {
            cpath.push("fragment");
            cpath.push("match-frag");
            _frag = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("match-non-frag");
            _non_frag = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "recent") {
            cpath.push("recent");
            cpath.push("time");
            g_cstore->_cfgPathGetValue(cpath, _recent_time, active);
            cpath.pop();
            cpath.push("count");
            g_cstore->_cfgPathGetValue(cpath, _recent_cnt, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "p2p") {
            _p2p_set = true;
            cpath.push("p2p");
            cpath.push("all");
            _p2p[ALL] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("applejuice");
            _p2p[APPLE] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("bittorrent");
            _p2p[BIT] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("directconnect");
            _p2p[DC] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("edonkey");
            _p2p[EDK] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("gnutella");
            _p2p[GNU] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.push("kazaa");
            _p2p[KAZAA] = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "time") {
            cpath.push("time");
            cpath.push("startdate");
            g_cstore->_cfgPathGetValue(cpath, _time[STARTDATE], active);
            cpath.pop();
            cpath.push("stopdate");
            g_cstore->_cfgPathGetValue(cpath, _time[STOPDATE], active);
            cpath.pop();
            cpath.push("starttime");
            g_cstore->_cfgPathGetValue(cpath, _time[STARTTIME], active);
            cpath.pop();
            cpath.push("stoptime");
            g_cstore->_cfgPathGetValue(cpath, _time[STOPTIME], active);
            cpath.pop();
            cpath.push("monthdays");
            g_cstore->_cfgPathGetValue(cpath, _time[MONTHDAYS], active);
            cpath.pop();
            cpath.push("weekdays");
            g_cstore->_cfgPathGetValue(cpath, _time[WEEKDAYS], active);
            cpath.pop();
            cpath.push("utc");
            _time_utc = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "limit") {
            cpath.push("limit");
            cpath.push("rate");
            g_cstore->_cfgPathGetValue(cpath, _limit[RATE], active);
            cpath.pop();
            cpath.push("burst");
            g_cstore->_cfgPathGetValue(cpath, _limit[BURST], active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "disable") {
            cpath.push("disable");
            _disable = g_cstore->_cfgPathExists(cpath, active);
            cpath.pop();
            continue;
        }
        if (*it == "modify") {
            cpath.push("modify");
            cpath.push("dscp");
            g_cstore->_cfgPathGetValue(cpath, _mod_dscp, active);
            cpath.pop();
            cpath.push("mark");
            g_cstore->_cfgPathGetValue(cpath, _mod_mark, active);
            cpath.pop();
            cpath.push("tcp-mss");
            g_cstore->_cfgPathGetValue(cpath, _mod_tcpmss, active);
            cpath.pop();
            cpath.push("table");
            g_cstore->_cfgPathGetValue(cpath, _mod_table, active);
            if (_mod_table == "main")
                _mod_table = "254";
            cpath.pop();

            cpath.push("connmark");
            cpath.push("set-mark");
            g_cstore->_cfgPathGetValue(cpath, _mod_connmark_set, active);
            cpath.pop();
            cpath.push("save-mark");
            if (g_cstore->_cfgPathExists(cpath, active))
                _mod_connmark_save = "save";
            cpath.pop();
            cpath.push("restore-mark");
            if (g_cstore->_cfgPathExists(cpath, active))
                _mod_connmark_restore = "restore";
            cpath.pop();
            cpath.pop();
            cpath.push("lb-group");
            g_cstore->_cfgPathGetValue(cpath, _mod_lb_group, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "description") {
            string description;
            cpath.push("description");
            g_cstore->_cfgPathGetValue(cpath, description, active);
            cpath.pop();
            if (description == "XXXSELFDESTRUCTXXX")
                _selfdestruct = true;
            continue;
        }
        if (*it == "statistic") {
            cpath.push("statistic");
            cpath.push("probability");
            g_cstore->_cfgPathGetValue(cpath, _probability, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "connmark") {
            cpath.push("connmark");
            g_cstore->_cfgPathGetValue(cpath, _connmark, active);
            cpath.pop();
            continue;
        }
        if (*it == "mark") {
            cpath.push("mark");
            g_cstore->_cfgPathGetValue(cpath, _mark, active);
            cpath.pop();
            continue;
        }
        if (*it == "application") {
            cpath.push("application");
            cpath.push("category");
            g_cstore->_cfgPathGetValue(cpath, _dpi_cat, active);
            if (!_dpi_cat.empty()) {
                /*
                 * fixed categories are stored lower case and '_'
                 * instead of space.  Custom categories are store as
                 * the user entered them.
                 */
                transform(_dpi_cat.begin(), _dpi_cat.end(), _dpi_cat.begin(),
                          ::tolower);
                replace(_dpi_cat.begin(), _dpi_cat.end(), ' ', '-');
            }
            cpath.pop();
            cpath.push("custom-category");
            g_cstore->_cfgPathGetValue(cpath, _dpi_cust_cat, active);
            cpath.pop();
            cpath.pop();
            continue;
        }
        if (*it == "dscp") {
            cpath.push("dscp");
            g_cstore->_cfgPathGetValue(cpath, _dscp, active);
            cpath.pop();
            continue;
        }

    } // for all rule children

    cpath.push("source");
    _src.setup(cpath, active);
    cpath.pop();
    cpath.push("destination");
    _dst.setup(cpath, active);
    cpath.pop();

    _setup = true;
}

void
Rule::setup(Cpath& cpath)
{
    setup_base(cpath, false);
}

void
Rule::setupOrig(Cpath& cpath)
{
    setup_base(cpath, true);
}

bool
Rule::is_route_table() const
{
    if (_mod_table.empty())
        return false;
    return true;
}

const string&
Rule::get_route_table() const
{
    return _mod_table;
}

bool
Rule::is_wlb_group() const
{
    if (_mod_lb_group.empty())
        return false;
    return true;
}

const string&
Rule::get_wlb_group() const
{
    return _mod_lb_group;
}

bool
Rule::is_dpi_cat() const
{
    if (_dpi_cat.empty())
        return false;
    return true;
}

bool
Rule::is_dpi_cust_cat() const
{
    if (_dpi_cust_cat.empty())
        return false;
    return true;
}

const string&
Rule::get_dpi_cat() const
{
    return _dpi_cat;
}

const string&
Rule::get_dpi_cust_cat() const
{
    return _dpi_cust_cat;
}

static bool
split_on_match_set(const string& line, vector<string>& m)
{
    const char *error;
    int erroffset;
    int ovector[186];
    int rc;
    char match[1024];
    int i;
    static pcre *re = NULL;

    if (!re) {
        string pattern2;
        const char *regex = "(.+?)(-m\\s+set\\s+--match-set)(.+)";
        re = pcre_compile(regex, PCRE_CASELESS|PCRE_DOTALL,
                          &error, &erroffset, NULL);
        if (!re) {
            cerr << "pcre_compile failed\n";
            exit(1);
        }
    }

    rc = pcre_exec(re, NULL, line.c_str(), line.length(), 0, 0, ovector, 186);
    if (rc != 4)
        return false;

    m.clear();
    for (i = 1 ; i < rc; i++) {
        pcre_copy_substring(line.c_str(), ovector, rc, i, match, 1024);
        m.push_back(match);
    }
    return true;
}

bool
Rule::rule(vector<string>& rules, string& err)
{
    string rule_string;
    bool tcp_udp = false;

    rule_string  = "-m comment --comment ";
    rule_string += _comment + " ";

    if (_disable) {
        return true;
    }

    if (_tree == "modify" || _tree == "ipv6-modify") {
        if (_action != "modify") {
            if (!_mod_mark.empty() || !_mod_tcpmss.empty() ||
                !_mod_mark.empty() || ! _mod_table.empty()) {
                err = "modify field can only be use with action modify";
                return false;
            }
        }
    }

    if (!_protocol.empty()) {
        string str(_protocol), negate;
        if (_protocol.find('!', 0) != string::npos) {
            str = str.substr(1);
            negate = "! ";
        }
        if (str == "tcp_udp") {
            tcp_udp = true;
            rule_string += negate + "-p tcp ";
            // we'll ad the udp to 2nd rule later
        } else {
            rule_string += negate + "-p " + str + " ";
        }
    }

    if (is_stateful()) {
        rule_string += get_state_string();
    }

    if (!_tcp_flags.empty()) {
        if  ((_protocol == "tcp") || (_protocol == "6")) {
            rule_string += get_tcp_flags_string();
        } else {
            err = "TCP flags can only be set if protocol is set to TCP";
            return false;
        }
    }

    if (_protocol == "icmp" || _protocol == "1") {
        string tmp("--icmp-type ");
        if (!_icmp_name.empty()) {
            if (!_icmp_type.empty() || !_icmp_code.empty()) {
                err = "Cannot use ICMP type/code with ICMP type-name";
                return false;
            }
            rule_string += tmp + _icmp_name;
        } else if (!_icmp_type.empty()) {
            rule_string += tmp + _icmp_type;
            if (!_icmp_code.empty()) {
                rule_string += "/" + _icmp_code;
            }
            rule_string += " ";
        } else if (!_icmp_code.empty()) {
            err = "ICMP code can only be defined if ICMP type is defined";
            return false;
        }
    } else if (!_icmp_type.empty() || !_icmp_code.empty()
               || !_icmp_name.empty()) {
        err =
        "ICMP type/code or type-name can only be defined if protocol is ICMP";
        return false;
    }

    if (_protocol == "icmpv6" || _protocol == "ipv6-icmp"
        || _protocol == "58") {
        string tmp("-m icmpv6 --icmpv6-type ");
        if (!_icmpv6_type.empty()) {
            rule_string += tmp + _icmpv6_type + " ";
        }
    }

    string src_rule, dst_rule, tmp;
    if (!_src.rule(src_rule, err)) {
        return false;
    }
    if (!_dst.rule(dst_rule, err)) {
        return false;
    }

    // Q: is this check really needed anymore?
    if ((src_rule.find("multiport") != string::npos) ^
        (dst_rule.find("multiport") != string::npos)) {
        if ((src_rule.find("sport") != string::npos) &&
            (dst_rule.find("dport") != string::npos)) {
            err  = "Cannot specify multiple ports when both ";
            err += "source and destination ports are specified";
            return false;
        }
    }
    tmp = " ";
    rule_string += tmp + src_rule + tmp + dst_rule;

    if (_frag && _non_frag) {
        err = "Cannot specify both 'match-frag' and 'match-non-frag'";
        return false;
    }
    if (_frag) {
        string tmp = " -f ";
        rule_string += tmp;
    } else if (_non_frag) {
        string tmp = " ! -f ";
        rule_string += tmp;
    }

    if (_ipsec && _non_ipsec) {
        err = "Cannot specify both 'match-ipsec' and 'match-none'";
        return false;
    }
    if (_ipsec) {
        string tmp = " -m policy --pol ipsec --dir in ";
        rule_string += tmp;
    } else if (_non_ipsec) {
        string tmp = " -m policy --pol none --dir in ";
        rule_string += tmp;
    }

    if (_p2p_set) {
        rule_string += get_p2p_string();
    }

    string time_string;
    if (_time_utc) {
        time_string = "--utc ";
    }
    if (!_time[STARTDATE].empty()) {
        string tmp;
        tmp = "startdate";
        if (!validate_date(_time[STARTDATE], tmp, err)) {
            return false;
        }
        tmp = " --datestart ";
        time_string += tmp + _time[STARTDATE] + " ";
    }
    if (!_time[STOPDATE].empty()) {
        string tmp;
        tmp = "stopdate";
        if (!validate_date(_time[STOPDATE], tmp, err)) {
            return false;
        }
        tmp = " --datestop ";
        time_string += tmp + _time[STOPDATE] + " ";
    }
    if (!_time[STARTTIME].empty()) {
        string tmp;
        if (!validate_timevalues(_time[STARTTIME], TIME)) {
            tmp = "Invalid starttime ";
            err = tmp + _time[STARTTIME] + ".\n" + " Time should use"
                + "24 hour notation hh:mm:ss and lie in between "
                + "00:00:00 and 23:59:59";
            return false;
        }
        tmp = " --timestart ";
        time_string += tmp + _time[STARTTIME] + " ";
    }
    if (!_time[STOPTIME].empty()) {
        string tmp;
        if (!validate_timevalues(_time[STOPTIME], TIME)) {
            tmp = "Invalid stoptime ";
            err = tmp + _time[STOPTIME] + ".\n" + " Time should use"
                + "24 hour notation hh:mm:ss and lie in between "
                + "00:00:00 and 23:59:59";
            return false;
        }
        tmp = " --timestop ";
        time_string += tmp + _time[STOPTIME] + " ";
    }
    if (!_time[MONTHDAYS].empty()) {
       string negate, tmp;
       if (_time[MONTHDAYS].find('!',0) != string::npos) {
           negate = "! ";
           _time[MONTHDAYS] = _time[MONTHDAYS].substr(1);
       }
       if (!validate_timevalues(_time[MONTHDAYS], MONTHDAY)) {
           tmp = "Invalid monthdays value ";
           err = tmp + _time[MONTHDAYS] + ".\n" + "Monthdays should "
               + "have values between 1 and 31 with multiple days "
               + "separated by commas\n"
               + "eg. 2,12,21 For negation, add ! in front eg. !2,12,21";
           return false;
       }
       time_string += negate + " --monthdays " + _time[MONTHDAYS] + " ";
    }
    if (!_time[WEEKDAYS].empty()) {
        string negate, tmp;
        if (_time[WEEKDAYS].find('!',0) != string::npos) {
            negate = "! ";
            _time[WEEKDAYS] = _time[WEEKDAYS].substr(1);
        }
        if (!validate_timevalues(_time[WEEKDAYS], WEEKDAY)) {
            tmp = "Invalid weekdays value ";
            err = tmp + _time[WEEKDAYS] + ".\n" + "Weekdays should "
                + "be specified using the first three characters of "
                + "the day with the first character capitalized\n"
                + "eg. Mon,Thu,Sat For negation, add ! in front "
                + "eg. !Mon,Thu,Sat";
            return false;
        }
        time_string += negate + " --weekdays " + _time[WEEKDAYS] + " ";
    }
    if (!time_string.empty()) {
        string tmp = " -m time ";
        rule_string += tmp + time_string + " ";
    }

    string limit_string;
    if (!_limit[RATE].empty()) {
        size_t pos = _limit[RATE].find('/');
        if (pos == string::npos) {
            err  = "Invalid rate string [";
            err += _limit[RATE] + "]\n";
            return false;
        }
        string rate = _limit[RATE].substr(0, pos);
        int i_rate = my_atoi(rate);
        if (i_rate < 1) {
            err = "rate integer value in rate cannot be less than 1";
            return false;
        }
        string tmp = "--limit ";
        limit_string = tmp + _limit[RATE] + " --limit-burst " + _limit[BURST];
    }
    if (!limit_string.empty()) {
        string tmp = " -m limit ";
        rule_string += tmp + limit_string + " ";
    }

    if (!_connmark.empty()) {
        string negate;
        if (_connmark.find('!', 0) != string::npos) {
            _connmark = _connmark.substr(1);
            negate = "! ";
        }
        rule_string += " -m connmark " + negate + " --mark " + _connmark + " ";
    }
    if (!_mark.empty()) {
        string negate;
        if (_mark.find('!', 0) != string::npos) {
            _mark = _mark.substr(1);
            negate = "! ";
        }
        if (_mark.find('/') == string::npos) {
            int i_mark = my_atoi(_mark);
            if (i_mark <= 255) {
                _mark += "/0xff";
            }
        }
        rule_string += " -m mark " + negate + " --mark " + _mark + " ";
    }
    if (!_probability.empty()) {
        int i_percent;
        float f_percent;
        string percent;
        // percentage has been validated
        i_percent = strtoul(_probability.c_str(), NULL, 10);
        f_percent = (float)i_percent / 100.0;
        percent = boost::lexical_cast<string>(f_percent);
        rule_string += " -m statistic --mode random --probability "
            + percent + " ";
    }
    if (!_dpi_cat.empty()) {
        string mark;
        if (!dpi_get_cat_mark(_dpi_cat, _name, _rule_number, mark, err)) {
            return false;
        }
        rule_string += " -m mark --mark " + mark + " ";
    }
    if (!_dpi_cust_cat.empty()) {
        string mark;
        if (!dpi_get_cust_cat_mark(_dpi_cust_cat, _name, _rule_number, mark,
                                   err)) {
            return false;
        }
        rule_string += " -m mark --mark " + mark + " ";
    }
    if (!_dscp.empty()) {
        rule_string += " -m dscp --dscp " + _dscp + " ";
    }

    // recent match condition SHOULD BE DONE IN THE LAST so
    // all options in rule_string are copied to recent_rule below
    string recent_rule;
    if (!_recent_time.empty() || !_recent_cnt.empty()) {
        string recent_rule1, recent_rule2, tmp;

        recent_rule1 = " -m recent --update ";
        recent_rule2 = " -m recent --set ";
        if (!_recent_time.empty()) {
            tmp  = " --seconds ";
            tmp += _recent_time + " ";
            recent_rule1 += tmp;
        }
        if (!_recent_cnt.empty()) {
            tmp  = " --hitcount ";
            tmp += _recent_cnt + "  ";
            recent_rule1 += tmp;
        }

        recent_rule = rule_string;

        // check for a fw group, if so it needs to be after the recent
        // rule (due to a iptables bug with "set" being used by both
        // "recent" and "ipset".
        vector<string> m(3);
        if (split_on_match_set(rule_string, m)) {
            rule_string = m[0] + recent_rule1 + m[1] + m[2];
            if (split_on_match_set(recent_rule, m)) {
                recent_rule = m[0] + recent_rule2 + m[1] + m[2];
            } else {
                cerr << "Warning: unexpected bug\n";
            }
        } else {
            rule_string += recent_rule1;
            recent_rule += recent_rule2;
        }
    }

    string chain, rule_num, rule2;

    chain    = _name;
    rule_num = _rule_number;

    if (_log == "enable") {
        rule2  = rule_string;
        rule2 += get_log_prefix();
    }

    if (_action == "drop")
        rule_string += "-j DROP ";
    else if (_action == "accept")
        rule_string += "-j RETURN ";
    else if (_action == "reject")
        rule_string += "-j REJECT ";
    else if (_action == "reject-tcp") {
        if (_protocol == "tcp" || _protocol == "6") {
            rule_string += "-j REJECT --reject-with tcp-reset";
        } else {
            err = "reject-tcp can only be used if protocol is set to TCP";
            return false;
        }
    } else if (_action == "inspect") {
        // currently no snort in EdgeOS
    } else if (_action == "modify") {
        int count = 0;
        int connmark_count = 0;
        string tmp;
        if (!_mod_mark.empty()) {
            tmp = "-j MARK --set-mark ";
            if (_mod_mark.find('/') == string::npos) {
                int i_mod_mark = my_atoi(_mod_mark);
                if (i_mod_mark <= 255) {
                    _mod_mark += "/0xff";
                }
            }
            rule_string += tmp + _mod_mark + " ";
            count++;
        }
        if (!_mod_dscp.empty()) {
            tmp = "-j DSCP --set-dscp  ";
            rule_string += tmp + _mod_dscp + " ";
            count++;
        }
        if (!_mod_tcpmss.empty()) {
            if (_tcp_flags.empty()
                || _tcp_flags.find("SYN") == string::npos) {
                err = "need to set TCP SYN flag to modify TCP MSS";
                return false;
            }
            if (_mod_tcpmss == "pmtu") {
                tmp = "-j TCPMSS --clamp-mss-to-pmtu ";
            } else {
                tmp  = "-j TCPMSS --set-mss ";
                tmp += _mod_tcpmss + " ";
            }
            count++;
            rule_string += tmp;
        }
        if (!_mod_table.empty()) {
            rule_string += "-j UBNT_PBR_" + _mod_table + " ";
            count++;
        }
        if (!_mod_connmark_set.empty()) {
            rule_string += "-j CONNMARK --set-mark " + _mod_connmark_set + " ";
            count++;
            connmark_count++;
        }
        if (!_mod_connmark_save.empty()) {
            rule_string += "-j CONNMARK --save-mark ";
            count++;
            connmark_count++;
        }
        if (!_mod_connmark_restore.empty()) {
            rule_string += "-j CONNMARK --restore-mark ";
            count++;
            connmark_count++;
        }
        if (!_mod_lb_group.empty()) {
            rule_string += "-j UBNT_WLB_" + _mod_lb_group + " ";
            count++;

        }
        if (connmark_count > 1) {
            err  = "Cannot define more than one connmark action ";
            return false;
        }

        if (count == 0) {
            err  = "Action 'modify' requires more specific configuration ";
            err += "under the 'modify' node";
            return false;
        } else if (count > 1) {
            err  = "Cannot define more than one modification under ";
            err += "the 'modify' node";
            return false;
        }
    } else {
        err = "'action' must be defined";
        return false;
    }

    if (!rule2.empty()) {
        string tmp;
        tmp = rule2;
        rule2 = rule_string;
        rule_string = tmp;
    } else if (!recent_rule.empty()) {
        rule2 = recent_rule;
        recent_rule.clear();
    }

    string udp_rule, udp_rule2, udp_recent_rule;
    if (tcp_udp) {
        udp_rule = rule_string;
        boost::replace_all(udp_rule, " -p tcp ", " -p udp ");
        if (!rule2.empty()) {
            udp_rule2 = rule2;
            boost::replace_all(udp_rule2, " -p tcp ", " -p udp ");
        }
        if (!recent_rule.empty()) {
            udp_recent_rule = recent_rule;
            boost::replace_all(udp_recent_rule, " -p tcp ", " -p udp ");
        }
    }

    if (_debug) {
        if (!rule_string.empty())
            cout << "rule : \n[" << rule_string << "]\n";
        if (!rule2.empty())
            cout << "rule2 : \n[" << rule2 << "]\n";
        if (!recent_rule.empty())
            cout << "recent_rule : \n[" << recent_rule << "]\n";
        if (!udp_rule.empty())
            cout << "udp_rule : \n[" << udp_rule << "]\n";
        if (!udp_rule2.empty())
            cout << "udp_rule2 : \n[" << udp_rule2 << "]\n";
        if (!udp_recent_rule.empty())
            cout << "udp_recent_rule : \n[" << udp_recent_rule << "]\n";
    }

    if (!rule_string.empty())
        rules.push_back(rule_string);
    if (!rule2.empty())
        rules.push_back(rule2);
    if (!recent_rule.empty())
        rules.push_back(recent_rule);
    if (!udp_rule.empty())
        rules.push_back(udp_rule);
    if (!udp_rule2.empty())
        rules.push_back(udp_rule2);
    if (!udp_recent_rule.empty())
        rules.push_back(udp_recent_rule);

    if (_selfdestruct) {
        cout << "self destruct triggered" << endl;
        rules.push_back(" -m SOMEFAKEMATCHTARGETTHATWILLCAUSEIPTABLESTOBARF");
    }

    return true;
}

bool
Rule::is_stateful() const
{
    if (!_setup) {
        cerr << "Unexpected error: is_stateful() called without setup\n";
        exit(1);
    }

    if (_disable)
        return false;

    if (_state[ESTABLISHED] == "enable")
        return true;
    if (_state[NEW] == "enable")
        return true;
    if (_state[RELATED] == "enable")
        return true;
    if (_state[INVALID] == "enable")
        return true;
    return false;
}

bool
Rule::is_disabled() const
{
    if (!_setup) {
        cerr << "Unexpected error: is_stateful() called without setup\n";
        exit(1);
    }

    return _disable;
}

string
Rule::get_state_string() const
{
    string state;
    vector<string> s;

    if (! is_stateful())
        return state;

    if (_state[ESTABLISHED] == "enable")
        s.push_back("established");
    if (_state[NEW] == "enable")
        s.push_back("new");
    if (_state[RELATED] == "enable")
        s.push_back("related");
    if (_state[INVALID] == "enable")
        s.push_back("invalid");

    vector<string>::iterator it;
    size_t vcount, count;
    vcount = s.size();
    count = 0;
    for (it = s.begin(); it < s.end(); it++) {
        count++;
        state.append(*it);
        if (count != vcount)
            state.append(",");
    }

    string prefix = "-m state --state ";
    state = prefix + state + " ";

    return state;
}

string
Rule::get_p2p_string() const
{
    string p2p_string;

    if (_p2p[ALL]) {
        p2p_string = "--apple --bit --dc --edk --gnu --kazaa ";
    } else {
        string tmp;
        if (_p2p[APPLE]) {
            tmp = "--apple";
            p2p_string += tmp + " ";
        }
        if (_p2p[BIT]) {
            tmp = "--bit";
            p2p_string += tmp + " ";
        }
        if (_p2p[DC]) {
            tmp = "--dc";
            p2p_string += tmp + " ";
        }
        if (_p2p[EDK]) {
            tmp = "--edk";
            p2p_string += tmp + " ";
        }
        if (_p2p[GNU]) {
            tmp = "--gnu";
            p2p_string += tmp + " ";
        }
        if (_p2p[KAZAA]) {
            tmp = "--kazaa";
            p2p_string += tmp + " ";
        }
    }

    string prefix("-m ipp2p ");
    p2p_string = prefix + p2p_string;

    return p2p_string;
}

string
Rule::get_log_prefix() const
{
    string chain, action, log_prefix, tmp;

    // In iptables it allows a 29 character log_prefix, but we ideally
    // want to include "[$chain-$rule_num-$action] " but that would require
    //                  1   29 1   4     1  1    11 = 39
    // so truncate the chain name so that it'll all fit.
    chain = _name.substr(0, 19);
    action = boost::to_upper_copy(_action.substr(0,1));
    log_prefix = "[";
    log_prefix += chain + "-" + _rule_number + "-" + action + "] ";
    tmp = "-j LOG --log-prefix ";
    log_prefix = tmp + log_prefix;

    return log_prefix;
}

void
Rule::set_ip_version(const string& ip_version)
{
    _ip_version = ip_version;
    _src.set_ip_version(ip_version);
    _dst.set_ip_version(ip_version);
}

int
Rule::get_num_ipt_rules() const
{
    int ipt_rules = 1;
    bool protocol_tcpudp = false;

    if (_disable)
        return 0;

    if (_protocol == "tcp_udp") {
        ipt_rules++;
        protocol_tcpudp = true;
    }

    if (_log == "enable") {
        ipt_rules++;
        if (protocol_tcpudp)
            ipt_rules++;
    }

    if (!_recent_time.empty() || !_recent_cnt.empty()) {
        ipt_rules++;
        if (protocol_tcpudp)
            ipt_rules++;
    }

    return ipt_rules;
}

string
Rule::get_tcp_flags_string() const
{
    string s, flags_string;
    vector<string> v, flags, flags_set;

    if (_tcp_flags.empty())
        return flags_string;

    split(_tcp_flags, ',', v);
    vector<string>::iterator it;
    for (it = v.begin(); it < v.end(); it++) {
        if (it->find('!',0) != string::npos) {
            flags.push_back(it->substr(1));
        } else {
            flags.push_back(*it);
            flags_set.push_back(*it);
        }
    }

    size_t vcount, count;
    vcount = flags.size();
    count = 0;
    for (it = flags.begin(); it < flags.end(); it++) {
        count++;
        flags_string.append(*it);
        if (count != vcount)
            flags_string.append(",");
    }
    flags_string.append(" ");
    count = 0;
    for (it = flags_set.begin(); it < flags_set.end(); it++) {
        count++;
        flags_string.append(*it);
        if (count != vcount)
            flags_string.append(",");
    }
    if (flags_set.empty())
        flags_string.append("NONE");

    string prefix = "-m tcp --tcp-flags ";
    flags_string = prefix + flags_string + " ";

    return flags_string;
}

bool
Rule::validate_timevalues(const string& s, TIME_TYPE etype) const
{
    vector<string> v;
    vector<string>::iterator it;
    string year, month, day, hour, min, sec;
    int i_year, i_month, i_day, i_hour, i_min, i_sec;

    switch (etype) {
        case DATE:
            split(s, '-', v);
            if (v.size() != 3)
                return false;
            year  = v[0];
            month = v[1];
            day   = v[2];
            i_year  = my_atoi(year);
            i_month = my_atoi(month);
            i_day   = my_atoi(day);
            if (i_year < 2011)
                return false;
            if (i_month < 1 || i_month > 12)
                return false;
            if (i_day < 1 || i_day > 31)
                return false;
            return true;
        case TIME:
            split(s, ':', v);
            if (v.size() != 3)
                return false;
            hour = v[0];
            min  = v[1];
            sec  = v[2];
            i_hour = my_atoi(hour);
            i_min  = my_atoi(min);
            i_sec  = my_atoi(sec);
            if (i_hour < 0 || i_hour > 23)
                return false;
            if (i_min < 0 || i_min > 59)
                return false;
            if (i_sec < 0 || i_sec > 59)
                return false;
            return true;
        case MONTHDAY:
        {
            string sm(s);
            if (sm.find('!',0) != string::npos)
                sm = sm.substr(1);
            split(sm, ',', v);
            for (it = v.begin(); it < v.end(); it++) {
                int value = my_atoi(*it);
                if (value < 1 || value > 31)
                    return false;
            }
            return true;
        }
        case WEEKDAY:
        {
            string sw(s);
            if (sw.find('!',0) != string::npos)
                sw = sw.substr(1);
            split(sw, ',', v);
            for (it = v.begin(); it < v.end(); it++) {
                if (*it == "Mon")
                    continue;
                if (*it == "Tue")
                    continue;
                if (*it == "Wed")
                    continue;
                if (*it == "Thu")
                    continue;
                if (*it == "Fri")
                    continue;
                if (*it == "Sat")
                    continue;
                if (*it == "Sun")
                    continue;
                return false;
            }
            return true;
        }
    }

    return false;
}

bool
Rule::validate_date(const string& date, const string& type, string& err) const
{
    string msg;

    if (date.find('T') != string::npos) {
        string actualdate = date.substr(0, 10);
        string datetime   = date.substr(11);
        if (!validate_timevalues(actualdate, DATE)) {
            err  = "Invalid";
            err += type + " " + actualdate + ".\n"
                +  "Date should use yyyy-mm-dd format and lie "
                +  "in between 2011-01-01 and 2038-01-19";
            return false;
        }
        if (!validate_timevalues(datetime, TIME)) {
            err  = "Invalid time ";
            err += datetime + " for " + type + " " + actualdate + ".\n"
                +  "Time should use 24 hour notation hh:mm:ss and lie "
                +  "in between 00:00:00 and 23:59:59";
            return false;
        }
    } else {
        if (!validate_timevalues(date, DATE)) {
            err  = "Invalid ";
            err += type + " " + date + ".\n"
                +  "Date should use yyyy-mm-dd format and lie "
                +  "in between 2011-01-01 and 2038-01-19";
            return false;
        }
    }
    return true;
}

void
Rule::print() const
{
    cout << "firewall " << _tree << " " << _name << " " << _rule_number
              << " " << _action << endl;

    cout << "comment [" << _comment << "]" << endl;
    cout << "State established " << _state[ESTABLISHED] << endl;
    cout << "State new         " << _state[NEW] << endl;
    cout << "State related     " << _state[RELATED] << endl;
    cout << "State invalid     " << _state[INVALID] << endl;

    cout << "disable = " << _disable << endl;
    int ipt_num = get_num_ipt_rules();
    cout << "ipt_num = " << ipt_num << endl;
    string flags = get_tcp_flags_string();
    cout << "flags = [" << flags << "]\n";
    cout << "\nsrc address " << endl;
    _src.print();
    cout << "\ndst address " << endl;
    _dst.print();
}
