#include <cstdio>
#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>

#include "util.hpp"

const char *pbr_rule_file = "/var/run/vyatta/vyatta_pbr_rule";
const char *ipv6_pbr_rule_file = "/var/run/vyatta/vyatta_ipv6_pbr_rule";

using namespace std;

vector<string> ip_commands;

static const char *
get_refcnt_file(const string& ip_version)
{
    if (ip_version == "ipv6")
        return ipv6_pbr_rule_file;
    return pbr_rule_file;
}

static int
run_regex(const string& s, string& a, string& b)
{
    static bool compiled = false;
    static regex_t reg;
    regmatch_t pmatch[3];
    int rc;

    if (!compiled) {
        string pattern = "(.*):([0-9]+)";

        if (0 != (rc = regcomp(&reg, pattern.c_str(), REG_EXTENDED))) {
            std::cerr << "pattern regcomp() failed (" << rc << ")" << std::endl;
            exit(1);
        }
        compiled = true;
    }

    rc = regexec(&reg, s.c_str(), 3, pmatch, 0);
    if (rc == 0) {
        a = s.substr(pmatch[1].rm_so,
                     pmatch[1].rm_eo - pmatch[1].rm_so);
        b = s.substr(pmatch[2].rm_so,
                     pmatch[2].rm_eo - pmatch[2].rm_so);
    }
    return rc;
}

static int table_shift = 23;
static string table_mask = "/0x7F800000";

static void
iptables_add_rule(vector<string>& restore_vector, int table_num)
{
    unsigned int mark = table_num << table_shift;
    string table = boost::lexical_cast<std::string>(table_num);
    string cmd;

    log_msg("iptables_add_rule(%d)", table_num);
    cmd = "sudo /sbin/ip rule add pref " + table + " fwmark ";
    cmd += boost::lexical_cast<std::string>(mark);
    cmd += table_mask + " table " + table;
    ip_commands.push_back(cmd);

    string chain_name = "UBNT_PBR_" + table;
    cmd = ":" + chain_name + " - [0:0]\n";
    restore_vector.push_back(cmd);

    cmd = "-I " + chain_name + " 1 -j MARK --set-mark ";
    cmd += boost::lexical_cast<std::string>(mark);
    cmd += table_mask + "\n";
    restore_vector.push_back(cmd);

    cmd = "-I " + chain_name + " 2 -j ACCEPT\n";
    restore_vector.push_back(cmd);
}

static void
iptables_remove_rule(vector<string>& restore_vector, int table_num)
{
    unsigned int mark = table_num << table_shift;
    string table = boost::lexical_cast<std::string>(table_num);
    string cmd;

    log_msg("iptables_remove_rule(%d)", table_num);
    cmd = "sudo /sbin/ip rule del pref " + table + " fwmark ";
    cmd += boost::lexical_cast<std::string>(mark);
    cmd += table_mask + " table " + table;
    ip_commands.push_back(cmd);

    string chain_name = "UBNT_PBR_" + table;
    cmd = "-F " + chain_name + "\n";
    restore_vector.push_back(cmd);

    cmd = "-X " + chain_name + "\n";
    restore_vector.push_back(cmd);
}

void
add_route_table(const string& ip_version, vector<string>& restore_vector,
                const string& table, const string& rule)
{
    bool rule_found = false;
    vector<string> lines, new_lines, tokens;
    int rc, table_num, table_ref_cnt = -1, table_count = -1;
    int new_table = boost::lexical_cast<int>(table);
    const char *file = get_refcnt_file(ip_version);

    log_msg("add_route_table(%s, %s)", table.c_str(), rule.c_str());
    read_refcnt_file(file, lines);
    BOOST_FOREACH(string line, lines) {
        line_to_tokens(line, tokens);
        string a, b;
        rc = run_regex(tokens[0], a, b);
        if (rc == 0) {
            int tmp_table_num = boost::lexical_cast<int>(a);
            int tmp_table_count = boost::lexical_cast<int>(b);
            if (tmp_table_num == new_table) {
                table_num = tmp_table_num;
                table_count = tmp_table_count;
                table_ref_cnt = table_count + 1;
                a += ":";
                a += boost::lexical_cast<std::string>(table_ref_cnt);
                tokens[0] = a;
                for (unsigned int i = 1; i < tokens.size(); i++) {
                    string token = tokens[i];
                    string tmp_rule, tmp_count;
                    rc = run_regex(token, tmp_rule, tmp_count);
                    if (rc == 0) {
                        if (tmp_rule == rule) {
                            int i_count = boost::lexical_cast<int>(tmp_count);
                            rule_found = true;
                            i_count++;
                            token = tmp_rule + ":";
                            token += boost::lexical_cast<std::string>(i_count);
                        }
                        tokens[i] = token;
                    }
                } // end foreach token
                if (!rule_found) {
                    string tmp = rule + ":1";
                    tokens.push_back(tmp);
                }
            } // end table_num == new_table
        } // end regex match
        tokens_to_line(tokens, line);
        new_lines.push_back(line);
        tokens.clear();
    } // end foreach line
    if (table_count < 0) {
        string tmp = table + ":1 " + rule + ":1";
        new_lines.push_back(tmp);
    }
    if (table_count < 1) {
        table_num = boost::lexical_cast<int>(table);
        iptables_add_rule(restore_vector, table_num);
    }
    write_refcnt_file(file, new_lines);
}

void
remove_route_table(const string& ip_version, vector<string>& restore_vector,
                   const string& table, const string& rule)
{
    bool rule_found = false;
    std::vector<std::string> lines, new_lines, tokens;
    int rc, table_num, table_ref_cnt = -1, table_count = -1;
    int new_table = boost::lexical_cast<int>(table);
    const char *file = get_refcnt_file(ip_version);

    log_msg("remove_route_table(%s, %s)", table.c_str(), rule.c_str());
    read_refcnt_file(file, lines);
    BOOST_FOREACH(string line, lines) {
        line_to_tokens(line, tokens);
        string a, b;
        rc = run_regex(tokens[0], a, b);
        if (rc == 0) {
            int tmp_table_num = boost::lexical_cast<int>(a);
            int tmp_table_count = boost::lexical_cast<int>(b);
            if (tmp_table_num == new_table) {
                if (table_count == 0) {
                    cerr << "Error: table count already 0\n";
                    exit(1);
                }
                table_num = tmp_table_num;
                table_count = tmp_table_count;
                table_ref_cnt = table_count - 1;
                a += ":";
                a += boost::lexical_cast<std::string>(table_ref_cnt);
                tokens[0] = a;
                for (unsigned int i = 1; i < tokens.size(); i++) {
                    string token = tokens[i];
                    string tmp_rule, tmp_count;
                    rc = run_regex(token, tmp_rule, tmp_count);
                    if (rc == 0) {
                        if (tmp_rule == rule) {
                            int i_count = boost::lexical_cast<int>(tmp_count);
                            if (i_count == 0) {
                                cerr << "Error: rule count already 0\n";
                                exit(1);
                            }
                            rule_found = true;
                            i_count--;
                            token = tmp_rule + ":";
                            token += boost::lexical_cast<std::string>(i_count);
                        }
                        tokens[i] = token;
                    }
                } // end of foreach token
                if (!rule_found) {
                    cerr << "Error: rule not found\n";
                    exit(1);
                }
                if (table_ref_cnt < 1) {
                    iptables_remove_rule(restore_vector, table_num);
                }
            } // end of table_num == new_table
        } // end of regex match
        tokens_to_line(tokens, line);
        new_lines.push_back(line);
        tokens.clear();
    } // end of foreach line
    if (table_ref_cnt < 0) {
        cerr << "Error: table not found\n";
        exit(1);
    }
    write_refcnt_file(file, new_lines);
}

void
flush_route_table(const string& ip_version, vector<string>& restore_vector,
                  const string& rule)
{
    vector<string> lines, new_lines, tokens;
    int rc, table_num, table_count = -1;
    const char *file = get_refcnt_file(ip_version);

    log_msg("flush_route_table(%s)", rule.c_str());
    read_refcnt_file(file, lines);
    BOOST_FOREACH(string line, lines) {
        line_to_tokens(line, tokens);
        string a, b;
        rc = run_regex(tokens[0], a, b);
        table_num = 0;
        table_count = 0;
        if (rc == 0) {
            table_num = boost::lexical_cast<int>(a);
            table_count = boost::lexical_cast<int>(b);
            for (unsigned int i = 1; i < tokens.size(); i++) {
                string token = tokens[i];
                string tmp_rule, tmp_count;
                rc = run_regex(token, tmp_rule, tmp_count);
                if (rc == 0) {
                    if (tmp_rule == rule) {
                        int i_count = boost::lexical_cast<int>(tmp_count);
                        if (i_count != 0) {
                            token = tmp_rule + ":0";
                            table_count -= i_count;
                        }
                    }
                    tokens[i] = token;
                }
            } // end foreach token
            a += ":";
            a += boost::lexical_cast<std::string>(table_count);
            tokens[0] = a;
        } // end regex match
        if (table_count > 0) {
            tokens_to_line(tokens, line);
            new_lines.push_back(line);
        }
        if (table_count < 1) {
            iptables_remove_rule(restore_vector, table_num);
        }
        tokens.clear();
    } // end of foreach line
    write_refcnt_file(file, new_lines);
}

int
run_ip_commands(void)
{
    int rc;

    log_msg("run_ip_commands: %d", ip_commands.size());

    if (ip_commands.empty())
        return 0;

    BOOST_FOREACH(const string& cmd, ip_commands) {
        rc = system(cmd.c_str());
        log_msg("[%s] = %d", cmd.c_str(), rc);
    }
    return 0;
}