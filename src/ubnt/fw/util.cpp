#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <iterator>


#include "util.hpp"

bool debug_flag = false;

using namespace std;

void
log_msg(const char *format, ...)
{
    va_list ap;

    if (debug_flag) {
         va_start(ap, format);
         vprintf(format, ap);
         va_end(ap);
         printf("\n");
    }
}

void
read_refcnt_file(const char *file_name, vector<string>& v)
{
    string line;
    ifstream fs(file_name);

    if (fs.is_open()) {
        while (fs.good()) {
            getline(fs, line);
            if (line.empty()) {
                continue;
            }
            v.push_back(line);
        }
        fs.close();
    }
}

void
write_refcnt_file(const char *file_name, vector<string>& lines)
{
    if (lines.size() > 0) {
        vector<string>::iterator it;
        ofstream os;

        os.open(file_name, ios::out|ios::trunc);
        if (os.fail()) {
            cout << "Error opening [" << file_name << "]"
                 << strerror(errno) << endl;
            exit(1);
        }

        for (it = lines.begin(); it < lines.end(); it++)  {
            if (it->empty()) {
                continue;
            }
            it->append("\n");
            os << *it;
        }
        os.close();
    } else {
        unlink(file_name);
    }
}

void
line_to_tokens(const string& line, vector<string>& v)
{
    istringstream iss(line);

    copy(istream_iterator<string>(iss),
         istream_iterator<string>(),
         back_inserter<vector<string> >(v));
}

void
tokens_to_line(const vector<string>& v, string& line)
{
    ostringstream oss;

    copy(v.begin(), v.end(), ostream_iterator<string>(oss, " "));
    line = oss.str();
}

bool
chain_exists(const string& ipt_cmd, const string& table, const string& chain)
{
    string cmd;
    int rc;

    log_msg("chain_exists(%s, %s)", table.c_str(), chain.c_str());

    cmd = ipt_cmd + " -t " + table + " -nL " + chain + " >& /dev/null";
    rc = system(cmd.c_str());
    if (rc == 0) {
        log_msg("exists");
        return true;
    } else {
        log_msg("does not exists");
        return false;
    }
}

#define MAXBUF 256
char buf[MAXBUF];

bool
chain_referenced(const string& table, const string& chain,
                 const string& ipt_cmd)
{
    FILE *stream;
    string cmd;
    int rc;
    regex_t preg;
    const char *pattern = "\\(([0-9]+)[[:space:]]references";
    regmatch_t pmatch[2];
    bool match_found = false;
    int  refs = -1;

    if (0 != (rc = regcomp(&preg, pattern,REG_EXTENDED))) {
         std::cerr << "regcomp() failed (" << rc << ")" << std::endl;
         exit(1);
    }

    cmd = ipt_cmd + " -t " + table + " -nL " + chain;
    stream = popen(cmd.c_str(), "r");
    while (fgets(buf, MAXBUF, stream) != NULL) {
        if (match_found)
            break;
        rc = regexec(&preg, buf, 2, pmatch, 0);
        if (rc == 0) {
            match_found = true;
            string s(buf);
            string sub = s.substr(pmatch[1].rm_so,
                                  pmatch[1].rm_eo - pmatch[1].rm_so);
            refs = my_atoi(sub);
        }
    }
    regfree(&preg);
    rc = pclose(stream);
    if (!match_found && rc != 0) {
        cerr << "chain_referenced(" << cmd << ") failed." << rc << endl;
        exit(1);
    }
    if (refs > 0)
        return true;
    else
        return false;
}

string
fw_get_hook(const string& dir)
{
    if (dir == "in")
        return "VYATTA_FW_IN_HOOK ";
    else if (dir == "out")
        return "VYATTA_FW_OUT_HOOK ";
    else if (dir == "local")
        return "VYATTA_FW_LOCAL_HOOK ";
    else
        return NULL;
}

int
fw_find_intf_rule(const string& ipt_cmd, const string& ipt_table,
                  const string& dir, const string& intf)
{
    string cmd, hook;
    FILE *stream;
    int rc, count = 0;
    bool match_found;

    log_msg("fw_find_intf_rule(%s, %s, %s)", ipt_table.c_str(),
            dir.c_str(), intf.c_str());

    cmd  = ipt_cmd + "-save -t " + ipt_table;
    hook = fw_get_hook(dir);
    match_found = false;
    stream = popen(cmd.c_str(), "r");
    while (fgets(buf, MAXBUF, stream) != NULL) {
        string s(buf);
        string match = "-A " + hook;
        if (s.find(match) != s.npos) {
            count++;
            istringstream iss(s);
            string junk, ipt_intf;
            // -A <hook> -i <intf> -j <chain>
            // eat the first 3 parameters
            ipt_intf.clear();
            iss >> junk;
            iss >> junk;
            iss >> junk;
            iss >> ipt_intf;
            if (ipt_intf == intf) {
                match_found = true;
                // pclose will fail if we don't finish reading
                // the ouput, but we got what we wanted and
                // are bailing.
                break;
            }
        }
    }

    rc = pclose(stream);
    if (!match_found && rc != 0) {
        cerr << "Firewall config error: pclose failed [" << cmd
             << "] = " << rc << endl;
        exit(1);
    }

    if (match_found) {
        log_msg("found");
        return count;
    } else {
        log_msg("NOT found");
        return -1;
    }

}

bool
validate_ipv4(const std::string& address)
{
    std::string oct1, oct2, oct3, oct4, tmp;
    size_t pos1, pos2, pos3;
    int oct[4], i;

    pos1 = address.find('.');
    if (pos1 == std::string::npos)
        return false;
    oct1 = address.substr(0, pos1);
    tmp  = address.substr(pos1 + 1);
    pos2 = tmp.find('.');
    if (pos2 == std::string::npos)
        return false;
    oct2 = tmp.substr(0, pos2);
    tmp  = tmp.substr(pos2 + 1);
    pos3 = tmp.find('.');
    if (pos3 == std::string::npos)
        return false;
    oct3 = tmp.substr(0, pos3);
    oct4 = tmp.substr(pos3 + 1);
    if (oct4.find('.') != std::string::npos)
        return false;

    oct[0] = my_atoi(oct1);
    oct[1] = my_atoi(oct2);
    oct[2] = my_atoi(oct3);
    oct[3] = my_atoi(oct4);
    for (i = 0; i < 4; i++) {
        if (oct[i] < 0 || oct[i] > 255)
            return false;
    }
    return true;
}

bool
is_valid_port_number(const std::string& number, std::string& err)
{
    int i_number;

    if (!is_digit(number)) {
        err  = "invalid port '";
        err += number + "' (must be between 1 and 65535)";
        return false;
    }

    i_number = my_atoi(number);
    if (i_number < 1 || i_number > 65535) {
        err  = "invalid port '";
        err += number + "' (must be between 1 and 65535)";
        return false;
    }
    return true;
}

bool
is_valid_port_name(const std::string& name, const char *proto,
                   std::string& err)
{
    struct servent *se = getservbyname((const char *)name.c_str(),
                                       proto);
    if (!se) {
        err  = "'";
        if (proto == NULL)
            err += name + "' is not a valid port name";
        else
            err += name + "' is not a valid port name for protocol '"
                + proto + "'";
        return false;
    }

    return true;
}

bool
is_valid_port_range(const std::string& start, const std::string& stop,
                    std::string& err)
{
    int i_start, i_stop;

    if (!is_valid_port_number(start, err))
        return false;
    if (!is_valid_port_number(stop, err))
        return false;

    i_start = my_atoi(start);
    i_stop  = my_atoi(stop);
    if (i_stop <= i_start) {
        err  = "invalid port range (";
        err += stop + " is not greater than " + start;
        return false;
    }
    return true;
}

int
my_atoi(const std::string& s)
{
    int value = -1;
    std::stringstream ss;

    ss << s;
    ss >> value;
    return value;
}

std::string
my_itoa(int i)
{
    std::stringstream ss;
    ss << i;
    return ss.str();
}


void
split(const std::string& s, char c, std::vector<std::string>& v)
{
    size_t i = 0;
    size_t j = s.find(c);

    while (j != std::string::npos) {
        v.push_back(s.substr(i, j-i));
        i = ++j;
        j = s.find(c, j);
        if (j == std::string::npos)
            v.push_back(s.substr(i, s.length( )));
    }
    if (v.size() == 0)
        v.push_back(s);
}

bool
is_digit(const std::string& s)
{
    static regex_t  digit_regex;
    static bool compiled = 0;
    int rc;

    if (!compiled) {
        const char *pattern = "^[0-9]+$";
        if (0 != (rc = regcomp(&digit_regex, pattern,
                               REG_EXTENDED|REG_NOSUB))) {
            std::cerr << "regcomp() failed (" << rc << ")" << std::endl;
            exit(1);
        }
        compiled = true;
    }

    rc = regexec(&digit_regex, s.c_str(), 0, NULL, 0);
    return rc ? false : true;
}

bool
is_port_range(const std::string& s, std::string& start, std::string& stop)
{
    static regex_t range_reg;
    static bool compiled=false;
    string range_pattern = "^([0-9]+)-([0-9]+)$";
    regmatch_t pmatch[3];
    int rc;

    if (!compiled) {
        rc = regcomp(&range_reg, range_pattern.c_str(), REG_EXTENDED);
        if (rc != 0) {
            std::cerr << "pattern regcomp() failed (" << rc << ")" << std::endl;
            exit(1);
        }
        compiled = true;
    }

    rc = regexec(&range_reg, s.c_str(), 3, pmatch, 0);
    if (rc == 0) {
        start = s.substr(pmatch[1].rm_so,
                         pmatch[1].rm_eo - pmatch[1].rm_so);
        stop  = s.substr(pmatch[2].rm_so,
                         pmatch[2].rm_eo - pmatch[2].rm_so);
        return true;
    }
    return false;
}