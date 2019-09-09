#include <string.h>
#include <cstdio>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <netdb.h>

#include "util.hpp"

using namespace std;

static bool
check_member_address(const string& member, string& err)
{
    if (!validate_ipv4(member)) {
        err  = "[";
        err += member + "] isn't a valid IPv4 address";
        return false;
    }
    if (member == "0.0.0.0") {
        err = "zero IP address not valid in address group";
        return false;
    }
    return true;
}

static bool
check_member_ipv6_address(const string& member, string& err)
{
    if (member == "0::/0") {
        err = "zero IP address not valid in ipv6-address group";
        return false;
    }
    return true;
}

static void
split_last_octet(const string& ip, string& a, string& b)
{
    size_t pos;

    pos = ip.find_last_of('.');
    if (pos == string::npos) {
        cerr << "unexpected IP string [" << ip << "]" << endl;
        exit(1);
    }
    a = ip.substr(0, pos);
    b = ip.substr(pos+1);
}

static bool
ipset_check_member(const string& set_name, const string& set_type,
                   const string& member, string& err)
{
    size_t pos;
    bool   rc;

    if (set_type == "address") {
        pos = member.find('-');
        if (pos != string::npos) {
            string start_ip = member.substr(0, pos);
            string stop_ip  = member.substr(pos + 1);
            rc = check_member_address(start_ip, err);
            if (!rc)
                return false;
            rc = check_member_address(stop_ip, err);
            if (!rc)
                return false;
            string startA, startB, stopA, stopB;
            split_last_octet(start_ip, startA, startB);
            split_last_octet(stop_ip, stopA, stopB);
            if (startA != stopA) {
                err = "address range must be within /24";
                return false;
            }
            int i_startB = my_atoi(startB);
            int i_stopB  = my_atoi(stopB);
            if (i_stopB <= i_startB) {
                err += stop_ip + " must be less than " + start_ip;
                return false;
            }
        } else {
            rc = check_member_address(member, err);
            if (!rc)
                return false;
        }
        return true;
    } else if (set_type == "network") {
        pos = member.find('/');
        if (pos != string::npos) {
            string net  = member.substr(0, pos);
            string mask = member.substr(pos+1);
            int i_mask = my_atoi(mask);
            if (i_mask < 1 || i_mask > 31) {
                err  = "invalid mask [";
                err += mask + "] - must be between 1-31";
                return false;
            }
        } else {
            err  = "invalid network group [";
            err += member + "]";
            return false;
        }
        return true;
    } else if (set_type == "port") {
        string start, stop;
        if (is_port_range(member, start, stop)) {
            rc = is_valid_port_range(start, stop, err);
        } else if (is_digit(member)) {
            rc = is_valid_port_number(member, err);
        } else {
            rc = is_valid_port_name(member, NULL, err);
        }
        if (!rc)
            return false;
        return true;
    } else {
        err  = "invalid set type [";
        err += set_type + "]";
        return false;
    }

    return false;
}

static bool
ipset_check_ipv6_member(const string& set_name, const string& set_type,
                        const string& member, string& err)
{
    size_t pos;
    bool   rc;

    if (set_type == "ipv6-address") {
        rc = check_member_ipv6_address(member, err);
        if (!rc)
            return false;
        return true;
    } else if (set_type == "ipv6-network") {
        pos = member.find('/');
        if (pos != string::npos) {
            string net  = member.substr(0, pos);
            string mask = member.substr(pos+1);
            int i_mask = my_atoi(mask);
            if (i_mask < 1 || i_mask > 127) {
                err  = "invalid mask [";
                err += mask + "] - must be between 1-127";
                return false;
            }
        } else {
            err  = "invalid ipv6-network group [";
            err += member + "]";
            return false;
        }
        return true;
    } else {
        err  = "invalid set type [";
        err += set_type + "]";
        return false;
    }

    return false;
}

static bool
check_mark_valid(const string& mark, string& err, bool warn)
{
    unsigned long int i_mark;
    const char *startp;
    char *endp;
    size_t pos;
    int base = 10;

    pos = mark.find("0x");
    if (pos != string::npos) {
        base = 16;
    }
    startp = mark.c_str();
    i_mark = strtoul(mark.c_str(), &endp, base);
    if (endp != startp + mark.length()) {
        err = "invalid mark. Only digits are allow or start with '!' to negate.";
        return false;
    }
    if (i_mark > 2147483647) {
        err = "mark must be between 0 and 2147483647";
        return false;
    }
    if (i_mark > 255 && warn) {
        printf("Warning: marks > 255 may conflict with system marks\n");
    }
    return true;
}

static bool
check_mark(string mark, string& err)
{
    size_t pos;
    bool warn(true);

    pos = mark.find('!');
    if (pos != string::npos) {
        mark = mark.substr(pos + 1);
    }
    pos = mark.find('-'); // strtoul allow -0
    if (pos != string::npos) {
        err = "invalid mark. Only digits are allow or start with '!' to negate.";
        return false;
    }
    pos = mark.find('/'); // using mask
    if (pos != string::npos) {
        string tmp_mark = mark.substr(0, pos);
        if (!check_mark_valid(tmp_mark, err, warn)) {
            return false;
        }
        mark = mark.substr(pos + 1);
        warn = false;
    }
    return check_mark_valid(mark, err, warn);
}

static bool
check_percent(string percent, string& err)
{
    size_t pos;
    int i_percent;
    const char *startp;
    char *endp;

    startp = percent.c_str();
    pos = percent.find('%');
    if (pos != string::npos) {
        if (startp + percent.length() != startp + pos + 1) {
            err = "invalid percent. Percent must be between 0% - 100%.";
            return false;
        }
        percent = percent.substr(0, pos);
    }
    pos = percent.find('-'); // strtoul allow -0
    if (pos != string::npos) {
        err = "invalid percent. Percent must be between 0% - 100%.";
        return false;
    }
    i_percent = strtoul(startp, &endp,10);
    if (endp != startp + percent.length()) {
        err = "invalid percent. Percent must be between 0% - 100%.";
        return false;
    }
    if (i_percent > 100) {
        err = "invalid percent. Percent must be between 0% - 100%.";
        return false;
    }
    return true;
}

int
main(int argc, const char *argv[])
{
    if (argc < 2) {
        cerr << "Error: Invalid operation" << endl;
        exit(1);
    }

    string op(argv[1]);
    string err;
    bool rc;
    if (op == "valid-mark" && argc == 3) {
        rc = check_mark(argv[2], err);
    } else if (op == "valid-group-member" && argc == 5) {
        string set_name(argv[2]), set_type(argv[3]), member(argv[4]);
        rc = ipset_check_member(set_name, set_type, member, err);
    } else if (op == "valid-group-ipv6-member" && argc == 5) {
        string set_name(argv[2]), set_type(argv[3]), member(argv[4]);
        rc = ipset_check_ipv6_member(set_name, set_type, member, err);
    } else if (op == "valid-percent" && argc == 3) {
        rc = check_percent(argv[2], err);
    } else {
        cerr << "Error: Invalid operation" << endl;
        exit(1);
    }

    if (rc == false) {
        cerr << "Error: " << err << endl;
        exit(1);
    }
    exit(0);
}