#ifndef _FW_RULE_HPP_
#define _FW_RULE_HPP_

#include <string>
#include <vector>

#include <cstore/cstore.hpp>

#include "address.hpp"

class Rule
{
public:
    enum STATES {
        ESTABLISHED = 0,
        NEW,
        RELATED,
        INVALID,
        STATES_LAST
    };
    enum P2P {
        ALL = 0,
        APPLE,
        BIT,
        DC,
        EDK,
        GNU,
        KAZAA,
        P2P_LAST
    };
    enum TIME {
        STARTDATE = 0,
        STOPDATE,
        STARTTIME,
        STOPTIME,
        MONTHDAYS,
        WEEKDAYS,
        TIME_LAST
    };
    enum LIMIT {
        RATE = 0,
        BURST,
        LIMIT_LAST
    };

    enum TIME_TYPE {
        DATE = 0,
        TIME,
        MONTHDAY,
        WEEKDAY,
    };

    Rule();
    void setup(cstore::Cpath& cpath);
    void setupOrig(cstore::Cpath& cpath);
    bool rule(std::vector<std::string>& rules, std::string& err);
    void set_ip_version(const std::string& ip_version);
    bool is_stateful() const;
    bool is_disabled() const;
    int get_num_ipt_rules() const;
    void print() const;
    bool is_route_table() const;
    const std::string& get_route_table() const;
    bool is_wlb_group() const;
    const std::string& get_wlb_group() const;
    bool is_dpi_cat() const;
    bool is_dpi_cust_cat() const;
    const std::string& get_dpi_cat() const;
    const std::string& get_dpi_cust_cat() const;

private:
    void setup_base(cstore::Cpath& cpath, bool active);
    std::string get_log_prefix() const;
    std::string get_tcp_flags_string() const;
    std::string get_state_string() const;
    std::string get_p2p_string() const;
    bool validate_timevalues(const std::string& s, TIME_TYPE etype) const;
    bool validate_date(const std::string& date, const std::string& type,
                       std::string& err) const;

    std::string    _tree;
    std::string    _name;
    std::string    _rule_number;
    std::string    _action;
    std::string    _protocol;
    std::string    _state[STATES_LAST];
    std::string    _log;
    std::string    _tcp_flags;
    std::string    _icmp_code;
    std::string    _icmp_type;
    std::string    _icmp_name;
    std::string    _icmpv6_type;
    std::string    _mod_mark;
    std::string    _mod_dscp;
    std::string    _mod_tcpmss;
    std::string    _mod_table;
    std::string    _mod_connmark_save;
    std::string    _mod_connmark_restore;
    std::string    _mod_connmark_set;
    std::string    _mod_lb_group;
    bool           _ipsec;
    bool           _non_ipsec;
    bool           _frag;
    bool           _non_frag;
    std::string    _recent_time;
    std::string    _recent_cnt;
    bool           _p2p[P2P_LAST];
    bool           _time_utc;
    std::string    _time[TIME_LAST];
    std::string    _limit[LIMIT_LAST];
    std::string    _connmark;
    std::string    _mark;
    std::string    _probability;
    bool           _disable;
    std::string    _comment;

    std::string    _ip_version;
    bool           _debug;
    bool           _setup;
    bool           _p2p_set;
    Address        _src;
    Address        _dst;
    std::string    _dpi_cat;
    std::string    _dpi_cust_cat;
    std::string    _dscp;

    bool           _selfdestruct;   // for testing purposes
};

#endif /* _FW_RULE_HPP_ */
