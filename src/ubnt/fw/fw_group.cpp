#include <cstdio>
#include <vector>
#include <map>
#include <string>
#include <regex.h>

#include <boost/algorithm/string.hpp>

#include <cstore/cstore.hpp>

#include "group.hpp"
#include "util.hpp"

using namespace std;
using namespace cstore;

Cstore *g_cstore = NULL;

std::string ipset("sudo /sbin/ipset");
bool debug = false;

regex_t type_regex;
regex_t refs_regex;
regex_t memb_regex;
regex_t rang_regex;
regex_t p_rang_regex;
regex_t loct_regex;
regex_t addm_regex;
regex_t p_name_regex;
regex_t family_regex;

#define MAXBUF 256
static char buf[MAXBUF];
#define MAXNAMELEN 31

static int
prune_deleted_sets()
{
    Cpath cpath;
    vector<string> set_type;
    vector<string>::iterator it;
    string err;

    if (debug)
        cout << "prune_delete_sets()" << endl;

    set_type.push_back("address-group");
    set_type.push_back("network-group");
    set_type.push_back("port-group");

    cpath.push("firewall");
    cpath.push("group");

    for (it = set_type.begin(); it < set_type.end(); it++) {
        MapT<string, string> group_status;
        MapT<string, string>::iterator g_it;

        cpath.push(*it);
        if (debug)
            cout << "checking " << *it << endl;

        g_cstore->cfgPathGetChildNodesStatus(cpath, group_status);

        if (group_status.empty()) {
            if (debug)
                cout << "\tgroup empty\n";
            cpath.pop();
            continue;
        }

        for (g_it = group_status.begin(); g_it != group_status.end(); g_it++) {
            if (debug) {
                cout << "checking " << g_it->first << endl;
                cout << g_it->first << " status [" << g_it->second << "]\n";
            }

            if (g_it->second != "deleted") {
                continue;
            }

            cpath.push(g_it->first);
            if (g_cstore->cfgPathEffective(cpath)) {
                // don't prune if delete failed
                if (debug)
                    cout << "effective, skipping" << endl;
                cpath.pop();
                continue;
            }
            cpath.pop();
            Group group(g_it->first);

            if (debug)
               cout << "deleting set" << endl;

            if (!group.set_delete(err)) {
                cout << err << endl;
                return 1;
            }
        }
        cpath.pop();
    }
    return 0;
}

static int
ipset_check_set_type(const string& name, const string& type)
{
    if (name.empty()) {
        cerr << "Error: undefined set name" << endl;
        return 1;
    }
    if (type.empty()) {
        cerr << "Error: undefined set type" << endl;
        return 1;
    }

    const char *pfx = "ADDRv4_";
    if (type == "address" && name.length() > 7
            && memcmp(name.c_str(), pfx, 7) == 0 && name.length() < 31) {
        char cmd[80];
        snprintf(cmd, 80, "sudo /sbin/ipset -N '%s' hash:net >/dev/null 2>&1",
                 name.c_str());
        system(cmd);
    }
    pfx = "NETv4_";
    if (type == "address" && name.length() > 6
            && memcmp(name.c_str(), pfx, 6) == 0 && name.length() < 31) {
        char cmd[80];
        snprintf(cmd, 80, "sudo /sbin/ipset -N '%s' hash:net >/dev/null 2>&1",
                 name.c_str());
        system(cmd);
    }

    Group g(name);
    string g_type;

    if (!g.set_exists()) {
        cerr << "Group [" << name << "] has not been defined" << endl;
        return 1;
    }

    g_type = g.get_type_string();
    if (type != g_type) {
        // don't use "name" since it may be negated
        cerr << "Error: group [" << g.get_name() << "] is of type [" << g_type
             << "] not [" << type << "]" << endl;
        return 1;
    }
    return 0;
}

static bool
ipset_copy_set(Group& group, Group& copy, string& err)
{
    FILE *stream;
    string cmd;
    const string& group_name = group.get_name();
    const string& copy_name  = copy.get_name();

    if (debug)
        cout << "ipset_copy_set(" << group.get_name() << ", "
             << copy.get_name() << ")" << endl;

    if (copy.set_exists()) {
        err  = "Error: copy already exists [";
        err += copy_name + "]";
        return false;
    }

    if (group.set_exists()) {
         // copy members to new group
        if (debug)
            cout << "group exists, start copy" << endl;

        cmd = ipset + " save \"" + group_name + "\"";
        stream = popen(cmd.c_str(), "r");
        while (fgets(buf, MAXBUF, stream) != NULL) {
            string s;
            int len = strlen(buf);

            if (debug)
                cout << "buf [" << buf << "]\n";

            if (buf[0] == '#')
                continue;
            if (len == 1)
                continue;
            if (buf[len -1] == '\n')
                buf[len -1] = 0;
            s = buf;
            string group_name2 = " ";
            group_name2 += group_name + " ";
            string copy_name2 = " ";
            copy_name2 += copy_name + " ";
            boost::replace_all(s, group_name2, copy_name2);
            if (strncmp(buf, "create ", 7) == 0) {
                string tmp = "\n";
                s += tmp;
                copy.add_cmd(s);
                continue;
            }
            regmatch_t pmatch[2];
            int rc;
            rc = regexec(&addm_regex, s.c_str(), 2, pmatch, 0);
            if (rc == 0) {
                string sub =  s.substr(pmatch[1].rm_so,
                                       pmatch[1].rm_eo - pmatch[1].rm_so);
                if (!copy.add_member(sub, group_name, err))
                    return false;
            } else {
                std::cerr << "failed to find member [" << s << "]\n";
                exit(1);
            }
        }
        return true;
    } else {
        if (debug)
            cout << "new group" << endl;

        if (!group.set_create(err))
            return false;
        if (!group.commit(err))
            return false;
        if (!copy.set_create(err))
            return false;
        return true;
    }
}

static void
vector_to_map(const vector<string>& v, map<string, int>& m)
{
    vector<string>::const_iterator v_it;

    for (v_it = v.begin(); v_it < v.end(); v_it++)
        m[*v_it] = 1;
}

static void
compare_value_lists(const vector<string>& ovals, const vector<string>& nvals,
                    vector<string>& deleted, vector<string>& added)
{
    map<string, int> omap, nmap;
    map<string, int>::iterator m_it;
    vector<string>::const_iterator v_it;

    if (debug)
        cout << "compare_value_lists()" << endl;

    vector_to_map(ovals, omap);
    vector_to_map(nvals, nmap);

    for (v_it = ovals.begin(); v_it < ovals.end(); v_it++) {
        m_it = nmap.find(*v_it);
        if (m_it == nmap.end()) {
            if (debug)
                cout << "adding [" << *v_it << "] to deleted" << endl;

            deleted.push_back(*v_it);
        }

    }

    for (v_it = nvals.begin(); v_it < nvals.end(); v_it++) {
        m_it = omap.find(*v_it);
        if (m_it == omap.end()) {
            if (debug)
                cout << "adding [" << *v_it << "] to added" << endl;
            added.push_back(*v_it);
        }
    }
}

static int
update_set(const string& name, const string& type)
{

    Cpath cpath;
    string group_type, family, cmd, err;
    bool newset(false);
    int rc;

    if (debug)
        cout << "update_set(" << name << ", " << type << ")" << endl;

    if (type == "address" || type == "network") {
        family = "inet";
    } else if (type == "ipv6-address" || type == "ipv6-network") {
        family = "inet6";
    } else if (type != "port") {
        cerr << "Error: unknown group type [" << type << "]\n";
    }
    if (debug)
        cout << "group of family [" << family << "]\n";

    Group g(name, type, family);

    cpath.push("firewall");
    cpath.push("group");
    group_type = type + "-group";
    cpath.push(group_type);
    cpath.push(name);
    if (g_cstore->_cfgPathExists(cpath, true)) {
        if (!g_cstore->_cfgPathExists(cpath, false)) {
            if (debug)
                cout << "set deleted" << endl;

            // deleted
            if (!g.set_delete(err)) {
                cerr << err << endl;
                return 1;
            }
            return 0;
        }
    } else {
        if (g_cstore->_cfgPathExists(cpath, false)) {
            if (debug)
                cout << "set added" << endl;
            // added
            if (!g.set_create(err)) {
                cerr << err << endl;
                return 1;
            }
            if (!g.commit(err)) {
                cerr << err << endl;
                return 1;
            }
            newset = true;
        } else {
            // doesn't exist! should not happen
            cerr << "Updating non-exsistent group [" << name << "]\n";
            return 1;
        }
    }

    // added or potentially changed => iterate members
    // to ensure that vyatta config and ipset stay in-sync, do the following:
    // 1. copy orig set to tmp set
    int pid = getpid();
    string s_pid = my_itoa(pid);
    string tmpset = name + "-" + s_pid;
    if (tmpset.length() > MAXNAMELEN) {
        tmpset = tmpset.substr(s_pid.length() + 1);
        tmpset[0] = 'A'; // make sure it doesn't start with '-'
    }
    Group copy(tmpset, type, family);

    if (!ipset_copy_set(g, copy, err)) {
        if (debug)
            cout << "ipset_copy_set failed [" << err << "]" << endl;

        if (newset) {
            cmd = ipset + " destroy \"" + name + "\"";
            system(cmd.c_str());
        }
        return false;
    }

    // 2. add/delete members to/from tmp set according to changes
    cpath.push(type);
    vector<string> ovals, nvals, deleted, added;
    g_cstore->_cfgPathGetValues(cpath, ovals, true);
    g_cstore->_cfgPathGetValues(cpath, nvals, false);
    compare_value_lists(ovals, nvals, deleted, added);
    err.clear();
    vector<string>::iterator it;

    for (it = deleted.begin(); it < deleted.end(); it++) {
        if (debug)
            cout << "deleting [" << *it << "]" << endl;
        if (!copy.delete_member(*it, err))
            goto done;
    }
    for (it = added.begin(); it < added.end(); it++) {
        if (debug)
            cout << "adding [" << *it << "]" << endl;
        if (!copy.add_member(*it, name, err))
            goto done;
    }
  done:
    if (!err.empty()) {
        cerr << err << endl;
        if (newset) {
            cmd = ipset + " destroy \"" + name + "\"";
            system(cmd.c_str());
        }
        return 1;
    }

    if (debug)
        cout << "starting commit" << endl;

    // 3. "commit" changes and/or clean up
    if (debug)
        cout << "commit" << endl;

    if (!copy.commit(err)) {
        cerr << err << endl;
        if (newset) {
            cmd = ipset + " destroy \"" + name + "\"";
            system(cmd.c_str());
        }
        return 1;
    }

    if (debug)
        cout << "swap " << tmpset << " " << name << endl;

    cmd = ipset + " swap " + tmpset + " \"" + name + "\"";
    rc = system(cmd.c_str());

    if (debug)
        cout << "destroy " << tmpset << endl;

    cmd = ipset + " destroy \"" + tmpset + "\"";
    system(cmd.c_str());

    return rc;
}

static void
init_regex()
{
    int rc;
    const char *type_pattern = "^Type:[[:space:]]+([[:alpha:]]+:[[:alpha:]]+)";
    const char *refs_pattern = "^References:[[:space:]]+([[:digit:]]+)";
    const char *memb_pattern = "^Members:[[:space:]]*";
    const char *rang_pattern = "^([^-]+)-([^-]+)$";
    const char *port_rang_pattern = "^([0-9]+)-([0-9]+)$";
    const char *loct_pattern = "^([0-9]+\\.[0-9]+\\.[0-9]+\\.)([0-9]+)$";
    const char *addm_pattern
        = "^add[[:space:]].*[[:space:]]([0-9a-fA-F\\.\\/\\:]+)$";
    const char *port_name_pattern = "[a-zA-Z]+";
    const char *family_pattern
        = "^Header:[[:space:]]+family[[:space:]](inet[6]?)";

    if (0 != (rc = regcomp(&type_regex, type_pattern, REG_EXTENDED))) {
        std::cerr << "type regcomp() failed (" << rc << ")" << std::endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&refs_regex, refs_pattern, REG_EXTENDED))) {
        std::cerr << "refs regcomp() failed (" << rc << ")" << std::endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&memb_regex, memb_pattern,
                           REG_EXTENDED|REG_NOSUB))) {
        std::cerr << "memb regcomp() failed (" << rc << ")" << std::endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&rang_regex, rang_pattern, REG_EXTENDED))) {
        std::cerr << "rang regcomp() failed (" << rc << ")" << std::endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&p_rang_regex, port_rang_pattern, REG_EXTENDED))) {
        std::cerr << "rang regcomp() failed (" << rc << ")" << std::endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&loct_regex, loct_pattern, REG_EXTENDED))) {
        std::cerr << "loct regcomp() failed (" << rc << ")" << std::endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&addm_regex, addm_pattern, REG_EXTENDED))) {
        cerr << "addm regcomp() failed (" << rc << ")" << endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&p_name_regex, port_name_pattern, REG_EXTENDED))) {
        cerr << "portname regcomp() failed (" << rc << ")" << endl;
        exit(1);
    }
    if (0 != (rc = regcomp(&family_regex, family_pattern, REG_EXTENDED))) {
        cerr << "family regcomp() failed (" << rc << ")" << endl;
        exit(1);
    }
}

static void
cleanup_regex()
{
    regfree(&type_regex);
    regfree(&refs_regex);
    regfree(&memb_regex);
    regfree(&rang_regex);
    regfree(&p_rang_regex);
    regfree(&loct_regex);
    regfree(&addm_regex);
    regfree(&p_name_regex);
    regfree(&family_regex);
}


int
main(int argc, const char *argv[])
{
    string dummy;
    char *sid = getenv("COMMIT_SESSION_ID");
    g_cstore = (sid ?  Cstore::createCstore(sid, dummy, false)
                       : Cstore::createCstore(true));
    if (!g_cstore) {
        exit(1);
    }

    string op(argv[1]);
    int rc = 42;

    if (argc < 2) {
        cerr << "Error: missing command" << endl;
        exit(1);
    }

    init_regex();

    if (op == "prune-deleted-sets" && argc == 2) {
        rc = prune_deleted_sets();
    }

    if (op == "check-set-type" && argc == 4) {
        string name(argv[2]), type(argv[3]);
        rc = ipset_check_set_type(name, type);
    }

    if (op == "update-set" && argc == 4) {
        string name(argv[2]), type(argv[3]);
        rc = update_set(name, type);
    }

    cleanup_regex();
    if (rc != 42)
        return rc;

    cerr << "Error: unknown command [" << op << "]\n";
    return 1;
}
