#include <cstdio>
#include <iostream>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <regex.h>
#include <stdarg.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>

#include "fw.hpp"
#include "fw_pbr.hpp"
#include "fw_wlb.hpp"
#include "fw_dpi.hpp"
#include "rule.hpp"
#include "util.hpp"

using namespace std;
using namespace cstore;

Cstore *g_cstore = NULL;

map<string, string> table_map;
map<string, string> cmd_map;
vector<string> tree_vector;
vector<string> restore_vector;

string max_rule = "10000";
bool fail = false;
const char *fw_tree_file     = "/var/run/vyatta/vyatta_fw_trees";
const char *fw_stateful_file = "/var/run/vyatta/vyatta_fw_stateful";
const char *iptables_out     = "/tmp/iptables.out";


static string
fw_get_policy_target(const string& policy)
{
    if (policy == "drop")
        return "DROP";
    if (policy == "reject")
        return "REJECT";
    if (policy == "accept")
        return "RETURN";
    cerr << "Unexpected policy [" << policy << "]\n";
    exit(1);
}

static void
set_default_policy(const string& chain, string& policy, bool log)
{
    string target, comment, cmd;

    if (policy.empty())
        policy = "drop";

    log_msg("set_default_policy(%s, %s, %d)", chain.c_str(),
            policy.c_str(), log);

    target   = fw_get_policy_target(policy);
    comment  = " -m comment --comment \"";
    comment += chain + "-" + max_rule + " default-action " + policy + "\"";
    if (log) {
        string chain2, action, ltarget, cmd;

        chain2   = chain.substr(0, 16);
        action   = boost::to_upper_copy(policy.substr(0,1));
        ltarget  = "LOG --log-prefix \"[";
        ltarget += chain2 + "-default-" + action + "]\" ";
        cmd  = "-A ";
        cmd += chain + comment + " -j " + ltarget + "\n";
        restore_vector.push_back(cmd);
    }
    cmd  = "-A ";
    cmd += chain + comment + " -j " + target + "\n";
    restore_vector.push_back(cmd);
}

static void
change_default_policy(const string& chain, string& policy, bool old_policy_log,
                      bool policy_log, int default_rule)
{
    string cmd;

    if (policy.empty())
        policy = "drop";

    log_msg("change_default_policy(%s, %s, %d, %d)", chain.c_str(),
            policy.c_str(), policy_log, default_rule);

    // add new policy after existing policy
    set_default_policy(chain, policy, policy_log);

    // remove old policy
    if (old_policy_log) {
        if (default_rule < 2) {
            string tmp;
            log_msg("unexpected rule number %d", default_rule);
        }
        string tmp = my_itoa(default_rule);
        cmd  = "-D ";
        cmd += chain + " " + tmp + "\n";
        restore_vector.push_back(cmd);
    }
    string tmp2 = my_itoa(default_rule);
    cmd  = "-D ";
    cmd += chain + " " + tmp2 + "\n";
    restore_vector.push_back(cmd);
}

static bool
setup_chain(const string& table, const string& chain, const string& ipt_cmd,
            string& policy, bool policy_log)
{
    string cmd;

    log_msg("setup_chain(%s, %s, %s, %d)", table.c_str(), chain.c_str(),
            policy.c_str(), policy_log);

    if (chain_exists(ipt_cmd, table, chain)) {
        cout << "cmd [" << cmd << "]" << endl;
        cerr << "Firewall config error: Chain '" << chain << "' is "
             << "already used in the system.  Cannot use it as a "
             << "ruleset name";
        exit(1);
    }
    cmd  = ":";
    cmd += chain + " - [0:0]\n";
    restore_vector.push_back(cmd);
    set_default_policy(chain, policy, policy_log);
    return true;
}

/*
 * mode: 0: check if the chain is configured in any tree.
 *       1: check if it is configured in the specified tree.
 *       2: check if it is configured in any "other" tree.
 */
static bool
chain_configured(int mode, const string& chain,
                 const string& tree, string& err)
{
    Cpath cpath;
    MapT<string, string> nodes;
    MapT<string, string>::const_iterator i;
    vector<string>::iterator it;

    log_msg("chain_configured(%d, %s, %s)", mode, chain.c_str(),
            tree.c_str());

    cpath.push("firewall");
    for (it = tree_vector.begin(); it < tree_vector.end(); it++) {
        if (mode == 1 && *it != tree)
            continue;
        if (mode == 2 && *it == tree)
            continue;
        cpath.push(*it);
        g_cstore->cfgPathGetChildNodesStatus(cpath, nodes);
        i = nodes.find(chain);
        if (i != nodes.end()) {
            if (i->second != "deleted") {
                err = *it;
                log_msg("found");
                return true;
            }
        }
        cpath.pop();
    }
    log_msg("not found");
    return false;
}

static bool
delete_chain(const string& table, const string& chain, const string& ipt_cmd)
{
    string cmd;

    cmd  = "-F ";
    cmd += chain + "\n";
    restore_vector.push_back(cmd);
    cmd  = "-X ";
    cmd += chain + "\n";
    restore_vector.push_back(cmd);
    return true;
}

static void
fw_get_zones(vector<string>& zones)
{
     Cpath cpath;

     cpath.push("zone-policy");
     cpath.push("zone");
     g_cstore->_cfgPathGetChildNodes(cpath, zones, false);
}

static string
fw_get_ip_version(const string& tree)
{
    if (tree == "name" || tree == "modify")
        return "ipv4";
    if (tree == "ipv6-name" || tree == "ipv6-modify")
        return "ipv6";
    cerr << "Error: unexpected tree [" << tree << "]" << endl;
    exit(1);
}

static string
fw_get_table_name(const string& tree)
{
    map<string, string>::const_iterator i;

    i = table_map.find(tree);
    if (i == table_map.end()) {
        cerr << "Error: invalid tree " << tree << endl;
        exit(1);
    }
    return i->second;
}

static string
fw_get_ipt_cmd(const string& tree)
{
    map<string, string>::const_iterator i;

    i= cmd_map.find(tree);
    if (i == cmd_map.end()) {
        cerr << "Error: invalid tree " << tree << endl;
        exit(1);
    }
    return i->second;
}

static void
add_refcnt(const char *file, const string& value)
{
    vector<string> lines;
    vector<string>::iterator it;

    log_msg("add_refcnt: %s %s", file, value.c_str());
    read_refcnt_file(file, lines);
    for (it = lines.begin(); it < lines.end(); it++)  {
        if (*it == value) {
            return;
        }
    }
    lines.push_back(value);
    write_refcnt_file(file, lines);
}

static void
remove_refcnt(const char *file, const string& value)
{
    vector<string> lines, new_lines;
    vector<string>::iterator it;

    log_msg("remove_refcnt: %s %s", file, value.c_str());
    read_refcnt_file(file, lines);
    for (it = lines.begin(); it < lines.end(); it++)  {
        if (*it == value) {
            continue;
        } else {
            new_lines.push_back(*it);
        }
    }
    if (new_lines.size() != lines.size())
        write_refcnt_file(file, new_lines);
}

static bool
is_conntrack_enabled(const string& ipt_cmd)
{
    vector<string> lines;
    vector<string>::iterator it;

    read_refcnt_file(fw_stateful_file, lines);
    if (lines.empty())
        return false;

    for (it = lines.begin(); it < lines.end(); it++)  {
        size_t pos;
        string tree, cmd;

        if (it->empty())
            continue;

        pos = it->find(' ');
        if (pos == string::npos) {
            cerr << "invalid refcnt format" << endl;
            exit(1);
        }
        tree = it->substr(0, pos);
        cmd = fw_get_ipt_cmd(tree);
        if (cmd == ipt_cmd)
            return true;
    }
    return false;
}

static void
enable_fw_conntrack(const string& ipt_cmd)
{
    restore_vector.push_back("*raw\n");
    restore_vector.push_back("-R FW_CONNTRACK 1 -j ACCEPT\n");
    restore_vector.push_back("COMMIT\n");
}

static void
disable_fw_conntrack(const string& ipt_cmd)
{
    restore_vector.push_back("*raw\n");
    restore_vector.push_back("-R FW_CONNTRACK 1 -j RETURN\n");
    restore_vector.push_back("COMMIT\n");
}

static bool
is_switchport(const string& intf)
{
     Cpath cpath;
     vector<string> ports;
     vector<string>::iterator it;

     cpath.push("interfaces");
     cpath.push("switch");
     cpath.push("switch0");
     cpath.push("switch-port");
     if (!g_cstore->_cfgPathExists(cpath, false))
         return false;

     cpath.push("interface");
     g_cstore->_cfgPathGetValues(cpath, ports, false);
     for (it = ports.begin(); it != ports.end(); it++) {
         if (*it == intf)
             return true;
     }
     return false;
}

static int
fw_update_interface(string& action, const string& intf,
                    const string& dir, const string& chain,
                    const string& tree)
{
    string err, ipt_table, ipt_cmd;

    ipt_table = fw_get_table_name(tree);
    ipt_cmd   = fw_get_ipt_cmd(tree);

    if (action == "update") {
        if (tree == "name" || tree == "ipv6-name") {
            vector<string> zones;
            vector<string>::iterator it;

            fw_get_zones(zones);
            if (!zones.empty()) {
                for (it = zones.begin(); it < zones.end(); it++) {
                    if (*it == intf) {
                        cerr << "Firewall config error: interface " << intf
                             << " is defined under zone " << *it << endl;
                        exit(1);
                    }
                }
            }
        }
        // check if configured
        if (!chain_configured(1, chain, tree, err)) {
            cerr << "Firewall config error: Rule set " << chain
                 << " is not configured" << endl;
            exit(1);
        }
        // check if exists
        if (!chain_exists(ipt_cmd, ipt_table, chain)) {
            cerr << "Firewall config error: Rule set " << chain
                 << " is not configured" << endl;
            exit(1);
        }
        if (is_switchport(intf)) {
            cerr << "Firewall config error: Can not an firewall"
                 << " to a switch-port interface" << endl;
            exit(1);
        }

    }

    if (action != "delete" && ipt_table == "mangle" && dir == "local") {
        cerr << "Firewall config error: Modify rule set " << chain
             << " cannot be used for local" << endl;
        exit(1);
    }

    string intf_param;
    if (dir == "in") {
        intf_param = "--in-interface " + intf;
    } else if (dir == "out") {
        intf_param = "--out-interface " + intf;
    } else if (dir == "local") {
        intf_param = "--in-interface " + intf;
    } else {
        cerr << "Firewall config error: invalid direction ["
             << dir << "]\n";
        exit(1);
    }

    int count   = fw_find_intf_rule(ipt_cmd, ipt_table, dir, intf);
    string hook = fw_get_hook(dir);

    string cmd;
    if (count > 0) {
        string count_string = my_itoa(count);
        if (debug_flag)
            cout << "Match found at " << count << endl;
        if (action == "update") {
            action = "replace";
            cmd = "--replace ";
            cmd += hook + " " + count_string + " " + intf_param
                + " --jump " + chain;
        } else {
            cmd = "--delete ";
            cmd += hook + " " + count_string;
        }
    }

    if (cmd.empty()) {
        if (debug_flag)
            cout << "No match" << endl;
        if (action == "update") {
            cmd = "--insert ";
            cmd += hook + " 1 " + intf_param + " --jump " + chain;
        }
    }

    if (cmd.empty()) {
        cout << "Nothing to do" << endl;
        return 0;
    }

    string prefix = ipt_cmd + " -t " + ipt_table + " ";
    cmd = prefix + cmd;
    if (debug_flag)
        cout << "cmd = [" << cmd << "]\n";
    int rc = system(cmd.c_str());
    if (rc != 0) {
        cerr << "Error: iptables failed on [" << cmd << "]\n";
        exit(1);
    }

    return 0;
}

struct strint
{
    bool operator()(const string& s1, const string& s2) const
    {
        int a, b;
        a = my_atoi(s1);
        b = my_atoi(s2);
        return a < b;
    }
};

static bool
do_commit(const string& name, const string& ipt_cmd)
{
    FILE *stream;
    string cmd;
    int rc;
    size_t size;

    if (debug_flag)
        cout << "chain commit() " << name << endl;

    if (restore_vector.empty()) {
        if (debug_flag)
            cout << "no cmds to commit" << endl;
        return true;
    }

    cmd = ipt_cmd + "-restore -n -v 2> " + iptables_out;

    stream = popen(cmd.c_str(), "w");
    BOOST_FOREACH(const string& line, restore_vector) {
        if (debug_flag) {
            cout << "[" << line << "]" << endl;
        }
        size = fwrite(line.c_str(), line.size(), 1, stream);
        if (size != 1) {
            cerr << "Error writing to pipe 1 [" << size
                 << "][" << line.size() << "]" << endl;
            exit(1);
        }
    }
    rc = pclose(stream);
    if (rc != 0) {
        cerr << "Error: [" << cmd << "] = " << rc << endl;
        write_refcnt_file("/tmp/fw_commit_fail", restore_vector);
        return false;
    }

    restore_vector.clear();
    return true;
}

string restore_cmd;
string restore_iptables_file;
string restore_tree_file;
string restore_stateful_file;

static void
copy_tmp_file(const char *src, string& dst, const string& pid)
{
    string cmd;
    int rc;

    if (access(src, F_OK) != 0) {
        dst.clear();
        return;
    }

    dst  = src;
    dst += pid;

    cmd  = "/bin/cp ";
    cmd += src;
    cmd += " ";
    cmd += dst;

    rc = system(cmd.c_str());
    if (rc != 0) {
        cerr << "Error: unable to create filefile [" << dst << "]" << endl;
        exit(1);
    }
}

static void
save_state(const string& ipt_cmd)
{
    string cmd, a_pid;
    pid_t pid;
    int rc;

    log_msg("save_state: %s", ipt_cmd.c_str());
    pid = getpid();
    a_pid = my_itoa(pid);
    restore_iptables_file = "/tmp/fw_restore.";
    restore_iptables_file += a_pid;
    restore_cmd = ipt_cmd + "-restore < " + restore_iptables_file;

    cmd = ipt_cmd + "-save > " + restore_iptables_file;
    rc = system(cmd.c_str());
    if (rc != 0) {
        cerr << "Error: unable to save current iptables state " << rc << endl;
        exit(1);
    }

    copy_tmp_file(fw_tree_file, restore_tree_file, a_pid);
    copy_tmp_file(fw_stateful_file, restore_stateful_file, a_pid);
}

static void
restore_state()
{
    int rc;

    log_msg("restore_state()");
    fail = true;

    if (!restore_tree_file.empty())
        rename(restore_tree_file.c_str(), fw_tree_file);
    if (!restore_stateful_file.empty())
        rename(restore_stateful_file.c_str(), fw_stateful_file);

    rc = system(restore_cmd.c_str());
    if (rc != 0) {
        cerr << "Iptables restore failed" << endl;
        exit(1);
    } else {
        cout << "Iptables restore OK" << endl;
        exit(1);
    }
}

static void
exit_cleanup()
{
    log_msg("exit_cleanup()");
    if (!restore_iptables_file.empty())
        unlink(restore_iptables_file.c_str());
    if (!restore_tree_file.empty())
        unlink(restore_tree_file.c_str());
    if (!restore_stateful_file.empty())
        unlink(restore_stateful_file.c_str());
    if (!fail)
        unlink(iptables_out);
}

static int
fw_update_rules(const string& tree, const string& chain)
{
     set<string, strint> rules;
     set<string, strint>::iterator rules_it;
     Cpath cpath;
     bool chain_stateful(false), policy_set(false);
     bool policy_log(false), old_policy_log(false);
     string policy, old_policy;
     string ip_version, ipt_table, ipt_cmd;
     string chain_status, cmd;
     MapT<string, string> rules_status;
     MapT<string, string>::iterator m_it;
     int ipt_rule = 1;

     ip_version = fw_get_ip_version(tree);
     ipt_table  = fw_get_table_name(tree);
     ipt_cmd    = fw_get_ipt_cmd(tree);

     save_state(ipt_cmd);

     log_msg("update_rules: %s %s %s %s", tree.c_str(), chain.c_str(),
             ipt_table.c_str(), ip_version.c_str());

     cpath.push("firewall");
     cpath.push(tree);
     cpath.push(chain);

     cpath.push("default-action");
     g_cstore->_cfgPathGetValue(cpath, policy, false);
     g_cstore->_cfgPathGetValue(cpath, old_policy, true);
     if (ipt_table == "mangle") {
         old_policy = "accept";
         policy = "accept";
     }
     if (policy.empty())
         policy = "drop";
     if (old_policy.empty())
         old_policy = "drop";
     if (debug_flag)
         cout << "\tpolicy(" << policy << "), old_policy("
              << old_policy << ")\n";
     cpath.pop();

     cpath.push("enable-default-log");
     if (g_cstore->_cfgPathExists(cpath, false))
         policy_log = true;
     if (g_cstore->_cfgPathExists(cpath, true))
         old_policy_log = true;
     if (debug_flag)
         cout << "\tpolicy_log(" << policy_log << "), old_policy_log("
              << old_policy_log << ")\n";
     cpath.pop();

     cmd  = "*";
     cmd += ipt_table + "\n";
     restore_vector.push_back(cmd);

     if (g_cstore->_cfgPathDeleted(cpath)) {
         log_msg("%s %s = deleted", tree.c_str(), chain.c_str());

         chain_status = "deleted";
         if (chain_referenced(ipt_table, chain, ipt_cmd)) {
             cerr << "Firewall config error: Cannot delete rule set \""
                  << chain << "\" (still in use)" << endl;
             exit(1);
         }
         delete_chain(ipt_table, chain, ipt_cmd);
         string tmp = tree + " " + chain;
         remove_refcnt(fw_tree_file, tmp);

         if (ipt_table == "mangle")
             flush_route_table(ip_version, restore_vector, chain);

         dpi_flush_chain(chain);

         goto end_of_rules;
     } else if (g_cstore->_cfgPathAdded(cpath)) {
         log_msg("%s %s = added", tree.c_str(), chain.c_str());

         chain_status = "added";
         string err;
         if (chain_configured(2, chain, tree, err)) {
             cerr << "Firewall config error: Rule set '" << chain
                  << "' already used in '" << err << "'" << endl;
             exit(1);
         }
         setup_chain(ipt_table, chain, ipt_cmd, policy, policy_log);
         string tmp = tree + " " + chain;
         add_refcnt(fw_tree_file, tmp);
         policy_set = true;
     } else if (g_cstore->_cfgPathChanged(cpath)) {
         log_msg("%s %s = changed", tree.c_str(), chain.c_str());

         chain_status = "changed";
     } else {
         cout << "Unexpected static status [" << tree << "][" << chain
              << "]" << endl;
         // must be "static"
         // check if stateful
         log_msg("%s %s = static", tree.c_str(), chain.c_str());

         chain_status = "static";
         cpath.push("rule");
         vector<string> rules;
         vector<string>::iterator it;
         g_cstore->_cfgPathGetChildNodes(cpath, rules, true);
         for (it = rules.begin(); it < rules.end(); it++) {
             Rule node;
             cpath.push(*it);
             node.setupOrig(cpath);
             node.set_ip_version(ip_version);
             if (node.is_stateful())
                 chain_stateful = true;
             cpath.pop();
         }
         cpath.pop();
         // Q: if it hasn't changed, do we need to go through the rules?
     }

     cpath.push("rule");
     g_cstore->cfgPathGetChildNodesStatus(cpath, rules_status);

     if (rules_status.empty()) {
         // no rules. flush the user rules.
         // note that this clears the counters on the default DROP rule.
         // we could delete rule one by one if those are important.
         cmd  = "-F ";
         cmd += chain + "\n";
         restore_vector.push_back(cmd);
         set_default_policy(chain, policy, policy_log);
         goto end_of_rules;
     }

     for (m_it = rules_status.begin(); m_it != rules_status.end(); m_it++) {
         rules.insert(m_it->first);
     }

     for (rules_it = rules.begin(); rules_it != rules.end(); rules_it++) {
         string rule_number = *rules_it;
         string rule_status;
         Rule node, oldnode;
         vector<string> rule_cmds;
         vector<string>::iterator r_it;
         string err;
         int num_rules;

         m_it = rules_status.find(rule_number);
         if (m_it == rules_status.end()) {
             cerr << "Unexpected fatal error: " << rule_number << " not found";
             exit(1);
         }
         rule_status = m_it->second;

         if (debug_flag) {
             cout << "rule [" << rule_number << "] status [" << rule_status
                  << "]" << endl;
         }

         if (rule_status == "static") {
             cpath.push(rule_number);
             node.setupOrig(cpath);
             cpath.pop();
             node.set_ip_version(ip_version);
             if (node.is_stateful())
                 chain_stateful = true;
             num_rules = node.get_num_ipt_rules();
             ipt_rule += num_rules;
         } else if (rule_status == "added") {
             cpath.push(rule_number);
             node.setup(cpath);
             cpath.pop();
             node.set_ip_version(ip_version);
             if (node.is_stateful())
                 chain_stateful = true;

             if (node.is_route_table()) {
                 const string& table = node.get_route_table();
                 add_route_table(ip_version, restore_vector, table, chain);
             } else if (node.is_wlb_group()) {
                 const string& wlb = node.get_wlb_group();
                 add_wlb_group(ipt_cmd, restore_vector, wlb, chain);
             }

             if (node.is_dpi_cat()) {
                 string cat = node.get_dpi_cat();
                 dpi_set_cat_mark(cat, chain, rule_number, err);
                 chain_stateful = true;
             }

             if (!node.rule(rule_cmds, err)) {
                 if (chain_status == "added") {
                     delete_chain(ipt_table, chain, ipt_cmd);
                     string tmp = tree + " " + chain;
                     remove_refcnt(fw_tree_file, tmp);
                     if (node.is_route_table()) {
                         const string& table = node.get_route_table();
                         remove_route_table(ip_version, restore_vector,
                                            table, chain);
                     } else if (node.is_wlb_group()) {
                         const string& wlb = node.get_wlb_group();
                         remove_wlb_group(ipt_cmd, restore_vector,
                                          wlb, chain);
                     }
                     if (node.is_dpi_cat()) {
                         string cat = node.get_dpi_cat();
                         string zero("0");
                         dpi_del_cat_mark(cat, zero, chain, rule_number, err);
                     }
                 }
                 cerr << "Firewall config error: " << err << endl;
                 exit(1);
             }

             for (r_it = rule_cmds.begin(); r_it < rule_cmds.end(); r_it++) {
                 if (r_it->empty())
                     continue;

                 string num = my_itoa(ipt_rule);
                 cmd  = "-I ";
                 cmd += chain + " " + num + " " + *r_it + "\n";
                 restore_vector.push_back(cmd);
                 ipt_rule++;
             }
         } else if (rule_status == "changed") {
             // create a new iptables object of the current rule
             cpath.push(rule_number);
             oldnode.setupOrig(cpath);
             node.setup(cpath);
             cpath.pop();
             oldnode.set_ip_version(ip_version);
             node.set_ip_version(ip_version);
             if (node.is_stateful())
                 chain_stateful = true;

             if (!node.rule(rule_cmds, err)) {
                 cerr << "Firewall config error: " << err << endl;
                 exit(1);
             }
             num_rules = oldnode.get_num_ipt_rules();
             int i;
             for (i = 1; i<= num_rules; i++) {
                 string num = my_itoa(ipt_rule);
                 cmd  = "-D ";
                 cmd += chain + " " + num + "\n";
                 restore_vector.push_back(cmd);
             }

             if (oldnode.is_route_table() || node.is_route_table()) {
                 const string& otable = oldnode.get_route_table();
                 const string& table = node.get_route_table();
                 if (!otable.empty())
                     remove_route_table(ip_version, restore_vector,
                                        otable, chain);
                 if (!table.empty())
                     add_route_table(ip_version, restore_vector, table, chain);
             }
             if (oldnode.is_wlb_group() || node.is_wlb_group()) {
                 const string& owlb = oldnode.get_wlb_group();
                 const string& wlb = node.get_wlb_group();
                 if (owlb != wlb) {
                     if (!owlb.empty())
                         remove_wlb_group(ipt_cmd, restore_vector,
                                          owlb, chain);
                     if (!wlb.empty())
                         add_wlb_group(ipt_cmd, restore_vector, wlb, chain);
                 }
             }

             if (oldnode.is_dpi_cat() || node.is_dpi_cat()) {
                 string ocat = oldnode.get_dpi_cat();
                 string cat = node.get_dpi_cat();
                 if (ocat != cat) {
                     string zero("0");
                     if (!ocat.empty())
                         dpi_del_cat_mark(ocat, zero, chain, rule_number, err);
                     if (!cat.empty()) {
                         dpi_set_cat_mark(cat, chain, rule_number, err);
                         chain_stateful = true;
                     }
                 }
             }
             if (oldnode.is_dpi_cust_cat() || node.is_dpi_cust_cat()) {
                 const string& occat = oldnode.get_dpi_cust_cat();
                 const string& ccat = node.get_dpi_cust_cat();
                 if (occat != ccat) {
                     if (!occat.empty()) {
                         string custom("custom");
                         string cust_cat_num;
                         dpi_get_cust_cat_num(occat, cust_cat_num, err);
                         dpi_del_cat_mark(custom, cust_cat_num, chain,
                                          rule_number, err);
                     }
                 }
             }

             for (r_it = rule_cmds.begin(); r_it < rule_cmds.end(); r_it++) {
                 if (r_it->empty())
                     continue;

                 string num = my_itoa(ipt_rule);
                 cmd  = "-I ";
                 cmd += chain + " " + num + " " + *r_it + "\n";
                 restore_vector.push_back(cmd);
                 ipt_rule++;
             }
         } else if (rule_status == "deleted") {
             cpath.push(rule_number);
             oldnode.setupOrig(cpath);
             cpath.pop();
             oldnode.set_ip_version(ip_version);

             num_rules = oldnode.get_num_ipt_rules();
             int i;
             for (i = 1; i<= num_rules; i++) {
                 string num = my_itoa(ipt_rule);
                 cmd  = "-D ";
                 cmd += chain + " " + num + "\n";
                 restore_vector.push_back(cmd);
             }

             if (oldnode.is_route_table()) {
                 const string& table = oldnode.get_route_table();
                 remove_route_table(ip_version, restore_vector, table, chain);
             } else if (oldnode.is_wlb_group()) {
                 const string& wlb = oldnode.get_wlb_group();
                 remove_wlb_group(ipt_cmd, restore_vector, wlb, chain);
             }

             if (oldnode.is_dpi_cat()) {
                 string cat = oldnode.get_dpi_cat();
                 string zero("0");
                 dpi_del_cat_mark(cat, zero, chain, rule_number, err);
             }
             if (oldnode.is_dpi_cust_cat()) {
                 const string& occat = oldnode.get_dpi_cust_cat();
                 string custom("custom");
                 string cust_cat_num;
                 if (!dpi_get_cust_cat_num(occat, cust_cat_num, err)) {
                     cerr << err;
                     exit(1);
                 }
                 if (!dpi_del_cat_mark(custom, cust_cat_num, chain, rule_number,
                                       err)) {
                     cerr << err;
                     exit(1);
                 }
             }
         } else {
             cerr << "Unexpected error - shouldn't get here" << endl;
             exit(1);
         }
     } // end for all rules

     if (policy_set)
         goto end_of_rules;

     if (debug_flag)
         cout << "ipt_rule " << ipt_rule << endl;

     if ((policy != old_policy) || (old_policy_log != policy_log)) {
         change_default_policy(chain, policy, old_policy_log,
                               policy_log, ipt_rule);
     }

  end_of_rules:

     restore_vector.push_back("COMMIT\n");

     bool global_stateful = is_conntrack_enabled(ipt_cmd);
     if (chain_stateful) {
         string tmp = tree + " " + chain;
         add_refcnt(fw_stateful_file, tmp);
         if (! global_stateful) {
             enable_fw_conntrack(ipt_cmd);
         }
     } else {
         string tmp = tree + " " + chain;
         remove_refcnt(fw_stateful_file, tmp);
         if (! is_conntrack_enabled(ipt_cmd)) {
             disable_fw_conntrack(ipt_cmd);
         }
     }

     if (!do_commit(chain, ipt_cmd)) {
         // Oh crap, it's generally a programming error if
         // iptables fails.  Better restore & bail.
         restore_state();
         return 1;
     }

     if (ipt_table == "mangle")
         run_ip_commands();

    return 0;
}

static void
map_init()
{
    table_map["name"]        = "filter";
    table_map["ipv6-name"]   = "filter";
    table_map["modify"]      = "mangle";
    table_map["ipv6-modify"] = "mangle";

    cmd_map["name"]        = "sudo /sbin/iptables";
    cmd_map["ipv6-name"]   = "sudo /sbin/ip6tables";
    cmd_map["modify"]      = "sudo /sbin/iptables";
    cmd_map["ipv6-modify"] = "sudo /sbin/ip6tables";

    tree_vector.push_back("name");
    tree_vector.push_back("modify");
    tree_vector.push_back("ipv6-name");
    tree_vector.push_back("ipv6-modify");
}

static int
fw_validate_protocol(string& protocol)
{
    size_t pos;
    bool negate = false;

    pos = protocol.find('!', 0);
    if (pos != std::string::npos) {
        negate = true;
        protocol = protocol.substr(pos+1);
    }

    if (protocol == "all" || protocol == "0" || protocol == "ip") {
        if (negate)
            return 1;
        return 0;
    }

    if (protocol == "tcp_udp")
        return 0;

    if (is_digit(protocol)) {
        int proto = my_atoi(protocol);
        if (proto >= 1 && proto <= 255)
            return 0;
        else
            return 1;
    }

    protocol = boost::to_lower_copy(protocol);
    if (!getprotobyname(protocol.c_str()))
        return 1;

    return 0;
}

static int
fw_validate_name(const char *name)
{
    size_t len = strlen(name);

    if (len < 1 || len > 28) {
        printf("Firewall rule set name must be between 1 and 28 "
               "characters long\n");
        return 1;
    }
    if (name[0] == '-') {
        printf("Firewall rule set name cannot start with \"-\"\n");
        return 1;
    }
    if (strcspn(name, "!|;&$<>()*") != len) {
        printf("Firewall rule set name cannot contain shell punctuation\n");
        return 1;
    }
    if (!isupper(name[0])) {
        return 0;
    }

    bool reserved = false;
    static const char *pfx[] = {"xt", "ipt", "ip6t", NULL};
    char buf[64]; // > 16 + 4 + 1 + 28 + 3 + 1
    struct stat sb;
    for (size_t i = 0; pfx[i]; i++) {
        snprintf(buf, sizeof(buf), "/lib/xtables/lib%s_%s.so", pfx[i], name);
        if (stat(buf, &sb) == 0) {
            reserved = true;
            break;
        }
    }

    if (reserved || strncmp(name, "VZONE", 5) == 0
            || strcmp(name, "ACCEPT") == 0 || strcmp(name, "DROP") == 0
            || strcmp(name, "RETURN") == 0 || strcmp(name, "QUEUE") == 0) {
        printf("Cannot use reserved name \"%s\" for firewall rule set\n",
               name);
        return 1;
    }

    return 0;
}

static bool
is_cust_cat_used(const string& cust_cat)
{
    Cpath cpath;
    vector<string> chains, rules;
    string val;

    if (debug_flag)
        printf("is_cust_cat_used(%s)\n", cust_cat.c_str());

    cpath.push("firewall");
    cpath.push("name");

    chains.clear();
    g_cstore->_cfgPathGetChildNodes(cpath, chains, false);
    BOOST_FOREACH(const string& chain, chains) {
        cpath.push(chain);
        cpath.push("rule");
        rules.clear();
        g_cstore->_cfgPathGetChildNodes(cpath, rules, false);
        BOOST_FOREACH(const string& rule, rules) {
            cpath.push(rule);
            cpath.push("application");
            cpath.push("custom-category");
            if (g_cstore->_cfgPathExists(cpath, false)) {
                g_cstore->_cfgPathGetValue(cpath, val, false);
                if (val == cust_cat) {
                    return true;
                }
            }
            cpath.pop();
            cpath.pop();
            cpath.pop();
        }
        cpath.pop();
        cpath.pop();
    }
    return false;
}

static int
dpi_update_custom_category(const string& cust_cat)
{
    Cpath cpath;
    vector<string> apps, ccs;
    string cust_cat_num, err;
    map<string, string> app_map;

    if (debug_flag)
        printf("dpi_update_custom_category(%s)\n", cust_cat.c_str());

    if (!dpi_get_cust_cat_num(cust_cat, cust_cat_num, err)) {
        cerr << "Error: " << err;
        return 1;
    }

    if (debug_flag)
        printf("cust_cat_num = [%s]\n", cust_cat_num.c_str());

    cpath.push("system");
    cpath.push("traffic-analysis");
    cpath.push("custom-category");
    cpath.push(cust_cat);
    if (g_cstore->_cfgPathDeleted(cpath)) {
        if (debug_flag)
            printf("custom category deleted\n");
        if (is_cust_cat_used(cust_cat)) {
            cerr << "Error: custom category [" << cust_cat
                 << "] still in use\n";
            return 1;
        }
        apps.clear();
        dpi_cust_cat_add_apps(cust_cat_num, apps);
        dpi_del_cust_cat_num(cust_cat, cust_cat_num, err);
        return 0;
    }

    cpath.pop();
    g_cstore->_cfgPathGetChildNodes(cpath, ccs, false);
    BOOST_FOREACH(const string& cc, ccs) {
        if (cc == cust_cat) {
            continue;
        }
        cpath.push(cc);
        cpath.push("name");
        apps.clear();
        g_cstore->_cfgPathGetValues(cpath, apps, false);
        cpath.pop();
        cpath.pop();
        BOOST_FOREACH(string app, apps) {
            transform(app.begin(), app.end(), app.begin(), ::tolower);
            replace(app.begin(), app.end(), ' ', '-');
            app_map[app] = cc;
        }
    }

    cpath.push(cust_cat);
    cpath.push("name");
    apps.clear();
    g_cstore->_cfgPathGetValues(cpath, apps, false);
    BOOST_FOREACH(string app, apps) {
        transform(app.begin(), app.end(), app.begin(), ::tolower);
        replace(app.begin(), app.end(), ' ', '-');
        if (app_map.find(app) != app_map.end()) {
            printf("Error: [%s] already in use by custom category [%s]\n",
                   app.c_str(), app_map[app].c_str());
            return 1;
        }
    }
    dpi_cust_cat_add_apps(cust_cat_num, apps);
    return 0;
}

int
main(int argc, const char *argv[])
{
    string dummy;
    char *sid = getenv("COMMIT_SESSION_ID");

    if (!sid) {
        sid = getenv("UBNT_CFGD_PROC_REQ_SID");
    }
    g_cstore = (sid ? Cstore::createCstore(sid, dummy, false)
                      : Cstore::createCstore(true));
    if (!g_cstore) {
        exit(1);
    }

    if (argc < 2) {
        cerr << "Error: missing command" << endl;
        exit(1);
    }

    map_init();
    string op(argv[1]);

    switch (argc) {
    case 7:
        if (op == "update-interface") {
            string action(argv[2]);
            string intf(argv[3]);
            string dir(argv[4]);
            string chain(argv[5]);
            string tree(argv[6]);
            return fw_update_interface(action, intf, dir, chain, tree);
        }
        break;

    case 4:
        if (op == "update-rules") {
            string tree(argv[2]);
            string chain(argv[3]);

            atexit(exit_cleanup);

            return fw_update_rules(tree, chain);
        } else if (op == "add-qos-cat") {
            string cat(argv[2]);
            string match(argv[3]);

            dpi_add_qos_cat(cat, match);
        } else if (op == "add-qos-cust-cat") {
            string cust_cat(argv[2]);
            string match(argv[3]);

            dpi_add_qos_cust_cat(cust_cat, match);
        } else if (op == "del-qos-cat") {
            string cat(argv[2]);
            string match(argv[3]);

            dpi_del_qos_cat(cat, match);
        } else if (op == "del-qos-cust-cat") {
            string cust_cat(argv[2]);
            string match(argv[3]);

            dpi_del_qos_cust_cat(cust_cat, match);
        }
        break;

    case 3:
        if (op == "validate-protocol") {
            string proto(argv[2]);
            return fw_validate_protocol(proto);
        } else if (op == "validate-fw-name") {
            return fw_validate_name(argv[2]);
        } else if (op == "update-custom-category") {
            string cust_cat(argv[2]);
            return dpi_update_custom_category(cust_cat);
        }
        break;
    }

    cerr << "Error: Invalid command/param(s) [" << op << "]\n";
    return 1;
}
