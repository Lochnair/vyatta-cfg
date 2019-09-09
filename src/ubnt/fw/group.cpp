#include <cstdio>
#include <arpa/inet.h>

#include <boost/foreach.hpp>

#include "fw_group.hpp"
#include "group.hpp"
#include "util.hpp"

using namespace std;
using namespace cstore;

#define MAXBUF  256
static char buf[MAXBUF];

static string
map_type_group(enum Group::FW_GROUP type)
{
    switch (type) {
        case Group::ADDRESS:
            return "address-group";
        case Group::NETWORK:
            return "network-group";
        case Group::PORT:
            return "port-group";
        case Group::IPV6_ADDRESS:
            return "ipv6-address-group";
        case Group::IPV6_NETWORK:
            return "ipv6-network-group";
        default:
            return "invalid";
    }
}

static string
map_type_settype(enum Group::FW_GROUP type)
{
    switch (type) {
        case Group::ADDRESS:
            return "hash:net";
        case Group::NETWORK:
            return "hash:net";
        case Group::PORT:
            return "bitmap:port";
        case Group::IPV6_ADDRESS:
            return "hash:net";
        case Group::IPV6_NETWORK:
            return "hash:net";
        default:
            return "invalid";
    }
}

static enum Group::FW_GROUP
map_group_type(const string& type)
{
    if (type == "address")
        return Group::ADDRESS;
    else if (type == "network")
        return Group::NETWORK;
    else if (type == "port")
        return Group::PORT;
    else if (type == "ipv6-address")
        return Group::IPV6_ADDRESS;
    else if (type == "ipv6-network")
        return Group::IPV6_NETWORK;
    else
        return Group::FW_GROUP_INVALID;
}

static enum Group::FW_GROUP
find_group_type(const string& name, const string& family, bool& found)
{
    enum Group::FW_GROUP type = Group::FW_GROUP_INVALID;
    Cpath cpath;
    vector<string> g_types;

    found = false;
    g_types.push_back("port-group");
    if (family == "inet6") {
        g_types.push_back("ipv6-address-group");
        g_types.push_back("ipv6-network-group");
    } else {
        g_types.push_back("address-group");
        g_types.push_back("network-group");
    }

    // get type from config
    cpath.push("firewall");
    cpath.push("group");
    BOOST_FOREACH(const string& g, g_types) {
        cpath.push(g);
        cpath.push(name);
        if (g_cstore->_cfgPathExists(cpath, false)) {
            size_t pos = g.find("-group");
            if (pos == string::npos)
                return type;
            string tmp_g = g.substr(0, pos);
            type = map_group_type(tmp_g);
            if (type == Group::FW_GROUP_INVALID)
                return type;
            found = true;
            return type;
        }
        cpath.pop();
        cpath.pop();
    }

    if (strncmp(name.c_str(), "ADDRv4_", 7) == 0) {
        found = true;
        return Group::ADDRESS;
    }
    if (strncmp(name.c_str(), "NETv4_", 6) == 0) {
        found = true;
        return Group::ADDRESS;
    }

    return type;
}

static void
is_group_type(const char *line, bool& found)
{
    regmatch_t pmatch[2];
    int rc;

    found = false;
    rc = regexec(&type_regex, line, 2, pmatch, 0);
    if (rc == 0) {
        string s(line);
        string sub = s.substr(pmatch[1].rm_so,
                              pmatch[1].rm_eo - pmatch[1].rm_so);
        if (sub == "hash:net")
            found = true;
        else if (sub == "bitmap:port")
            found = true;
        else {
            cerr << "Unexpected type [" << sub << "]" << endl;
            exit(1);
        }
    }
}

static void
is_group_family(char *line, bool& found, string& family)
{
    regmatch_t pmatch[2];
    int rc;

    found = false;
    int len = strlen(line);
    if (line[len - 1] == '\n')
        line[len - 1] = 0;
    rc = regexec(&family_regex, line, 2, pmatch, 0);
    if (rc == 0) {
        string s(line);
        family = s.substr(pmatch[1].rm_so,
                          pmatch[1].rm_eo - pmatch[1].rm_so);
        found = true;
    }
}

static int
is_group_ref(char *line, bool& found)
{
    regmatch_t pmatch[2];
    int rc;
    int refs = -1;

    found = false;
    int len = strlen(line);
    if (line[len - 1] == '\n')
        line[len - 1] = 0;
    rc = regexec(&refs_regex, line, 2, pmatch, 0);
    if (rc == 0) {
        string s(line);
        string sub = s.substr(pmatch[1].rm_so,
                              pmatch[1].rm_eo - pmatch[1].rm_so);
        refs = my_atoi(sub);
        found = true;
    }
    return refs;
}

static void
is_group_member(const char *line, bool& found)
{
    int rc;

    found = false;
    rc = regexec(&memb_regex, line, 0, NULL, 0);
    if (rc == 0) {
        found = true;
    }
}

static int
parse_ipset_name(const string& name, enum Group::FW_GROUP& type,
                 bool& exists, int& refs, string& family,
                 map<string, bool>& members)
{
    FILE *stream;
    string cmd;
    int rc;
    bool type_found(false), ref_found(false), member_found(false),
        family_found(false);

    cmd = ipset + " list " + name + " 2> /dev/null";

    stream = popen(cmd.c_str(), "r");
    while (fgets(buf, MAXBUF, stream) != NULL) {
        if (!type_found) {
            // type is just an existance check
            // find real type from config
            is_group_type(buf, type_found);
            if (type_found) {
                exists = true;
                continue;
            }
        }
        if (!ref_found) {
            int tmp_refs = is_group_ref(buf, ref_found);
            if (ref_found) {
                refs = tmp_refs;
                continue;
            }
        }
        if (!family_found) {
            string tmp_family;
            is_group_family(buf, family_found, tmp_family);
            if (family_found) {
                if (family.empty()) {
                    family = tmp_family;
                } else {
                    if (tmp_family != family) {
                        cerr << "family mismatch: [" << tmp_family
                             << "] [" << family << "]\n";
                        family = tmp_family;
                    }
                }
                continue;
            }
        }
        if (!member_found) {
            is_group_member(buf, member_found);
            if (!member_found)
                continue;
            while (fgets(buf, MAXBUF, stream) != NULL) {
                int len = strlen(buf);
                if (buf[len - 1] == '\n') {
                    buf[len - 1] = 0;
                    len--;
                }
                if (len > 0) {
                    string s(buf);
                    members[s] = true;
                }
            }
        }
    }
    rc = pclose(stream);
    // the ipset command will fail if the group doesn't exist yet

    type_found = false;
    enum Group::FW_GROUP set_type = find_group_type(name, family, type_found);
    if (type_found) {
        if (set_type != Group::FW_GROUP_INVALID) {
            type = set_type;
        }
    }

    return rc;
}

void
Group::Group_common(const string& name, enum Group::FW_GROUP type,
                    string& family)
{
    size_t pos;

    _debug  = false;
    _exists = false;
    _refs   = -1;
    _type   = type;
    _family = family;

    pos = name.find('!', 0);
    if (pos != string::npos) {
        _negate = true;
        _name = name.substr(pos+1);
    } else {
        _negate = false;
        _name = name;
    }

    // return not checked?
    parse_ipset_name(_name, _type, _exists, _refs, family, _members);

    if (_exists && _type != type) {
        _valid = false;
    } else {
        _valid = true;
    }

    if (_debug) {
        cout << "Group " << _name << " type " << _type
                  << " exists " << _exists << " refs " << _refs
                  << endl;
        map<string, bool>::iterator it;
        cout << "members = " << _members.size() << endl;
        for (it = _members.begin(); it != _members.end(); it++) {
            cout << it->first << endl;
        }
    }
}

Group::Group(const string& name)
{
    string family;
    Group_common(name, Group::FW_GROUP_INVALID, family);
}

Group::Group(const string& name, const string& type, string family)
{
    enum Group::FW_GROUP gtype = map_group_type(type);
    Group_common(name, gtype, family);
}

Group::~Group()
{
}

bool
Group::set_exists() const
{
    if (_exists)
        return true;
    else
        return false;
}

bool
Group::set_create(string& err)
{
    string ipset_param, cmd;

    if (!_valid) {
        err = "Error: group already exists with different type";
        return false;
    }

    if (_name.empty()) {
        err  = "Error: undefined group name";
        return false;
    }
    if (_type == Group::FW_GROUP_INVALID) {
        err  = "Error: undefined group type for [";
        err += _name + "]";
        return false;
    }
    enum Group::FW_GROUP new_type = Group::FW_GROUP_INVALID;
    bool new_exists(false);
    int new_refs = -1;
    string family;
    map<string, bool> new_members;

    parse_ipset_name(_name, new_type, new_exists, new_refs, family, new_members);
    if (new_exists) {
        if (new_type != _type) {
            cerr << "Error: group [" << _name << "] already exist and is "
                      << "a different type [" << new_type << "] != ["
                      << _type << "]" << endl;
            exit(1);
        }
        if (new_refs > 0) {
            cerr << "Error: group [" << _name << "] already exist and has "
                      << new_refs << " references to it" << endl;
            exit(1);
        }
        if (new_members.empty()) {
            // since the group exist, is the same type and is
            // empty we'll not consider it an error
            return true;
        } else {
            cerr << "Error: group [" << _name << "] already exist"
                      << endl;
            exit(1);
        }
    }

    ipset_param = map_type_settype(_type);
    if (_type == PORT) {
        string param = " range 1-65535";
        ipset_param += param;
    }
    if (!_family.empty()) {
        ipset_param += " family " + _family + " ";
    }

    cmd  = "create ";
    cmd += _name + " " + ipset_param + "\n";
    add_cmd(cmd);
    return true;
}

bool
Group::set_delete(string& err)
{
    string cmd;
    int rc;

    if (_debug)
        cout << "set_delete " << _name << " refs " << _refs << endl;

    if (_name.empty()) {
        err = "Error: undefined group name";
        return false;
    }
    if (!_exists) {
        err  = "Error: group [";
        err += _name + "] doesn't exist";
        return false;
    }

    if (_refs > 0) {
        // still in use
        vector<string> refs;

        get_firewall_references(refs, false);
        get_nat_references(refs, false);
        if (refs.size() > 0) {
            // still referenced by config
            if (_debug) {
                vector<string>::iterator it;
                for (it = refs.begin(); it < refs.end(); it++) {
                    cout << "ref [" << *it << "]\n";
                }
            }
            err  = "Error: group [";
            err += _name + "] still in use.";
            return false;
        }
        if (_debug)
            cout << "no refs, calling flush" << endl;
        // not referenced by config => simultaneous deletes. just do flush.
        return set_flush(err);
    }

    cmd = ipset + " destroy " + _name;
    rc = system(cmd.c_str());
    if (rc) {
        err  = "Error: call to ipset failed [";
        err += my_itoa(rc) + "]";
        return false;
    }

    return true;
}

void
Group::debug(bool onoff)
{
    _debug = onoff;
}

int
Group::references() const
{
    if (!_exists)
        return 0;
    return _refs;
}

bool
Group::member_exists(const string& member) const
{
    map<string, bool>::const_iterator it;

    if (_debug)
        cout << "member_exists() set [" << _name << "] member ["
                  << member << "] = ";

    it = _members.find(member);
    if (it != _members.end()) {
        if (_debug)
            cout << "found" << endl;
        return true;
    }
    if (_debug)
        cout << "NOT found" << endl;

    return false;
}

bool
Group::add_member_range(const string& start, const string& stop,
                        const string& alias, string& err)
{
    bool rc;
    int i, i_start, i_stop;

    if (_type == PORT) {
        i_start = my_atoi(start);
        i_stop  = my_atoi(stop);
        for (i = i_start; i <= i_stop; i++) {
            string member = my_itoa(i);
            rc = add_member(member, alias, err);
            if (!rc)
                return false;
        }
        return true;
    }

    if (_type == ADDRESS) {
        regmatch_t pmatch[3];
        string s1, s2, loct_start, loct_stop;

        rc = regexec(&loct_regex, start.c_str(), 3, pmatch, 0);
        if (rc == 0) {
            string s(start);
            s1 = s.substr(pmatch[1].rm_so,
                          pmatch[1].rm_eo - pmatch[1].rm_so);
            loct_start = s.substr(pmatch[2].rm_so,
                                  pmatch[2].rm_eo - pmatch[2].rm_so);
        } else {
            err  = "unexpected start regex failure [";
            err += start + "]\n";
            return false;
        }

        rc = regexec(&loct_regex, stop.c_str(), 3, pmatch, 0);
        if (rc == 0) {
            string s(stop);
            s2 = s.substr(pmatch[1].rm_so,
                          pmatch[1].rm_eo - pmatch[1].rm_so);
            loct_stop = s.substr(pmatch[2].rm_so,
                                  pmatch[2].rm_eo - pmatch[2].rm_so);
        } else {
            err  = "unexpected stop regex failure [";
            err += stop + "]\n";
            return false;
        }

        if (s1 != s2) {
            err  = "unexpected IP range [";
            err += s1 + "][" + s2 + "]\n";
            return false;
        }
        i_start = my_atoi(loct_start);
        i_stop  = my_atoi(loct_stop);
        if (i_stop <= i_start) {
            err  = "unexpected last octet [";
            err += loct_start + "][" + loct_stop + "]\n";
            return false;
        }

        for (i = i_start; i <= i_stop; i++) {
            string s = s1 + my_itoa(i);
            rc = add_member(s, alias, err);
            if (!rc)
                return false;
        }
        return true;
    }

    err  = "Unexpected type = ";
    err += _type;
    return false;
}

bool
Group::add_member(string member, const string& alias, string& err)
{
    regmatch_t pmatch[3];
    int rc;

    if (_debug)
        cout << "add_member(" << member << ", " << _name << ")\n";

    if (_type == PORT) {
        rc = regexec(&p_rang_regex, member.c_str(), 3, pmatch, 0);
        if (rc != 0) {
            rc = regexec(&p_name_regex, member.c_str(), 0, NULL, 0);
            if (rc == 0) {
                rc = -1;
                member = "[" + member + "]";
            }
        }
    } else {
        rc = regexec(&rang_regex, member.c_str(), 3, pmatch, 0);
    }
    if (rc == 0) {
        string s(member);
        string start = s.substr(pmatch[1].rm_so,
                              pmatch[1].rm_eo - pmatch[1].rm_so);
        string stop  = s.substr(pmatch[2].rm_so,
                              pmatch[2].rm_eo - pmatch[2].rm_so);
        if (_debug)
            cout << "range [" << start << "][" << stop << "]\n";
        return add_member_range(start, stop, alias, err);
    }

    if (member_exists(member)) {
        err  = "Error: member [";
        err += member + "] already exists in [" + alias + "]\n";
        return false;
    }

    _members[member] = true;

    if (_debug)
        cout << "add member done" << endl;

    return true;
}

bool
Group::delete_member_range(const string& start, const string& stop,
                           string& err)
{
    bool rc;
    int i, i_start, i_stop;

    if (_type == PORT) {
        i_start = my_atoi(start);
        i_stop  = my_atoi(stop);
        for (i = i_start; i <= i_stop; i++) {
            string member = my_itoa(i);
            rc = delete_member(member, err);
            if (!rc)
                return false;
        }
        return true;
    }

    if (_type == ADDRESS) {
        regmatch_t pmatch[3];
        string s1, s2, loct_start, loct_stop;

        rc = regexec(&loct_regex, start.c_str(), 3, pmatch, 0);
        if (rc == 0) {
            string s(start);
            s1 = s.substr(pmatch[1].rm_so,
                          pmatch[1].rm_eo - pmatch[1].rm_so);
            loct_start = s.substr(pmatch[2].rm_so,
                                  pmatch[2].rm_eo - pmatch[2].rm_so);
        } else {
            err  = "unexpected start regex failure [";
            err += start + "]\n";
            return false;
        }

        rc = regexec(&loct_regex, stop.c_str(), 3, pmatch, 0);
        if (rc == 0) {
            string s(stop);
            s2 = s.substr(pmatch[1].rm_so,
                          pmatch[1].rm_eo - pmatch[1].rm_so);
            loct_stop = s.substr(pmatch[2].rm_so,
                                  pmatch[2].rm_eo - pmatch[2].rm_so);
        } else {
            err  = "unexpected stop regex failure [";
            err += stop + "]\n";
            return false;
        }

        if (s1 != s2) {
            err  = "unexpected IP range [";
            err += s1 + "][" + s2 + "]\n";
            return false;
        }
        i_start = my_atoi(loct_start);
        i_stop  = my_atoi(loct_stop);
        if (i_stop <= i_start) {
            err  = "unexpected last octet [";
            err += loct_start + "][" + loct_stop + "]\n";
            return false;
        }

        for (i = i_start; i <= i_stop; i++) {
            string s = s1 + my_itoa(i);
            rc = delete_member(s, err);
            if (!rc)
                return false;
        }
        return true;
    }

    err  = "Unexpected type = ";
    err += _type;
    return false;
}

bool
Group::delete_member(string member, string& err)
{
    map<string, bool>::iterator it;
    regmatch_t pmatch[3];
    int rc = -1;

    if (_type == PORT) {
        rc = regexec(&p_name_regex, member.c_str(), 0, NULL, 0);
        struct servent *se = getservbyname((const char *)member.c_str(), NULL);
        if (se) {
            // int (?!) but manpage example uses ntohs
            member = my_itoa(ntohs(se->s_port));
            rc = -1;
        }
    }
    if (rc != 0)
        rc = regexec(&rang_regex, member.c_str(), 3, pmatch, 0);
    if (rc == 0) {
        string s(member);
        string start = s.substr(pmatch[1].rm_so,
                                pmatch[1].rm_eo - pmatch[1].rm_so);
        string stop  = s.substr(pmatch[2].rm_so,
                                pmatch[2].rm_eo - pmatch[2].rm_so);
        if (_debug)
            cout << "range [" << start << "][" << stop << "]\n";
        return delete_member_range(start, stop, err);
    }

    // for IPv6 ipset will strip out suprious zeros, so we
    // need to also in order to find a match
    if (_family == "inet6") {
        string nmember, prefix;
        size_t pos = member.find('/',0);
        if (pos != string::npos) {
            nmember = member.substr(0, pos);
            prefix = member.substr(pos);
        } else {
            nmember = member;
        }

        unsigned char buf[sizeof(struct in6_addr)];
        char str[INET6_ADDRSTRLEN];
        if (inet_pton(AF_INET6, nmember.c_str(), buf) == -1) {
            perror("inet_pton failed ");
        } else {
            inet_ntop(AF_INET6, buf, str, INET6_ADDRSTRLEN);
            member = str;
            if (!prefix.empty())
                member += prefix;
        }
    }
    it = _members.find(member);
    if (it == _members.end()) {
        cerr << "unexpected member not found [" << member << "]\n";
        exit(1);
    }
    _members.erase(it);
    return true;
}

string
Group::get_type_string() const
{
    switch (_type) {
        case ADDRESS:
            return "address";
        case NETWORK:
            return "network";
        case IPV6_ADDRESS:
            return "ipv6-address";
        case IPV6_NETWORK:
            return "ipv6-network";
        case PORT:
            return "port";
        default:
            return "Invalid";
    }
}

void
Group::add_cmd(const string& cmd)
{
    _cmds.push_back(cmd);
}

bool
Group::commit(string& err)
{
    FILE *stream;
    string cmd;
    vector<string>::iterator v_it;
    map<string, bool>:: iterator m_it;
    int rc;
    size_t size;

    if (_debug)
        cout << "group commit() " << _name << endl;

    if (_cmds.empty() && _members.empty()) {
        if (_debug)
            cout << "no cmds or members to commit" << endl;
        return true;
    }

    cmd = ipset + " restore ";
    stream = popen(cmd.c_str(), "w");
    for (v_it = _cmds.begin(); v_it < _cmds.end(); v_it++) {
        if (_debug)
            cout << "commit cmds [" << *v_it << "]\n";
        size = fwrite(v_it->c_str(), v_it->size(), 1, stream);
        if (size != 1) {
            cerr << "Error writing to pipe 1 [" << size
                      << "][" << v_it->size() << "]" << endl;
            exit(1);
        }
    }
    for (m_it = _members.begin(); m_it != _members.end(); m_it++) {
        cmd = "add ";
        cmd += _name + " " + m_it->first + "\n";
        if (_debug)
            cout << "commit members [" << cmd << "]\n";
        size = fwrite(cmd.c_str(), cmd.size(), 1, stream);
        if (size != 1) {
            cerr << "Error writing to pipe 2 [" << size
                      << "][" << cmd.size() << "]" << endl;
            exit(1);
        }
    }
    cmd = "COMMIT\n";
    size = fwrite(cmd.c_str(), cmd.size(), 1, stream);
    if (size != 1) {
        cerr << "Error writing to pipe 3 [" << size
                  << "][" << cmd.size() << "]" << endl;
        exit(1);
    }
    rc = pclose(stream);
    if (rc != 0) {
        cerr << "unexpected pclose fail = " << rc << endl;
        exit(1);
    }

    _cmds.clear();
    _exists = true;

    return true;
}

const string&
Group::get_name() const
{
    return _name;
}

bool
Group::set_flush(string& err)
{
    string cmd;
    int rc;

    cmd = ipset + " -F " + _name;
    rc = system(cmd.c_str());
    if (rc) {
        err  = "Error: call to ipset failed [";
        err += my_itoa(rc) + "]";
        return false;
    }
    return true;
}

void
Group::print_cpath(const Cpath& cpath) const
{
    cout << "cpath = [";
    for (size_t i = 0; i < cpath.size(); i++) {
        cout << cpath[i] << " ";
    }
    cout << "]" << endl;
}

void
Group::get_firewall_references(vector<string>& refs, bool active) const
{
    string group_type;
    Cpath cpath;
    vector<string> trees;
    vector<string>::iterator t_it;
    vector<string> dir;
    vector<string>::iterator d_it;

    if (!_exists)
        return;

    group_type = map_type_group(_type);
    trees.push_back("name");
    trees.push_back("modify");
    trees.push_back("ipv6-name");
    trees.push_back("ipv6-modify");
    dir.push_back("source");
    dir.push_back("destination");

    cpath.push("firewall");
    for (t_it = trees.begin(); t_it < trees.end(); t_it++) {
        MapT<string, string> chains;
        MapT<string, string>::iterator c_it;

        cpath.push(*t_it);
        g_cstore->cfgPathGetChildNodesStatus(cpath, chains);
        for (c_it = chains.begin(); c_it != chains.end(); c_it++) {
            MapT<string, string> rules;
            MapT<string, string>::const_iterator r_it;

            cpath.push(c_it->first);
            cpath.push("rule");
            g_cstore->cfgPathGetChildNodesStatus(cpath, rules);
            for (r_it = rules.begin(); r_it != rules.end(); r_it++) {
                cpath.push(r_it->first);
                for (d_it = dir.begin(); d_it < dir.end(); d_it++) {
                    map<string, string> group;
                    map<string, string>::iterator g_it;

                    cpath.push(*d_it);
                    cpath.push("group");
                    cpath.push(group_type);
                    cpath.push(_name);
                    bool exists = g_cstore->_cfgPathExists(cpath, false);
                    if (_debug) {
                        print_cpath(cpath);
                        bool deleted = g_cstore->_cfgPathDeleted(cpath);
                        bool effective = g_cstore->cfgPathEffective(cpath);
                        cout << _name << " found. deleted : "
                                  << deleted << " exists : " << exists
                                  << " effective : " << effective
                                  << "\n";
                    }

                    if (exists) {
                        string ref;
                        ref = c_it->first + "-" + r_it->first + "-" + *d_it;
                        refs.push_back(ref);
                    }
                    cpath.pop();
                    cpath.pop();
                    cpath.pop();
                    cpath.pop();
                } // for dir
                cpath.pop();
            } // for rules
            cpath.pop();
            cpath.pop();
        } // for chains
        cpath.pop();
    } // for trees
    cpath.push("");
}

void
Group::get_nat_references(vector<string>& refs, bool active) const
{
    string group_type;
    Cpath cpath;
    vector<string> dir;
    vector<string>::iterator d_it;
    MapT<string, string> rules;
    MapT<string, string>::const_iterator r_it;

    if (!_exists)
        return;

    group_type = map_type_group(_type);
    dir.push_back("source");
    dir.push_back("destination");

    cpath.push("service");
    cpath.push("nat");
    cpath.push("rule");
    g_cstore->cfgPathGetChildNodesStatus(cpath, rules);
    for (r_it = rules.begin(); r_it != rules.end(); r_it++) {
        cpath.push(r_it->first);
        for (d_it = dir.begin(); d_it < dir.end(); d_it++) {
            map<string, string> group;
            map<string, string>::iterator g_it;

            cpath.push(*d_it);
            cpath.push("group");
            cpath.push(group_type);
            cpath.push(_name);
            bool exists = g_cstore->_cfgPathExists(cpath, false);
            if (_debug) {
                print_cpath(cpath);
                bool deleted = g_cstore->_cfgPathDeleted(cpath);
                bool effective = g_cstore->cfgPathEffective(cpath);
                cout << _name << " found. deleted : "
                     << deleted << " exists : " << exists
                     << " effective : " << effective
                     << "\n";
            }

            if (exists) {
                string ref;
                ref = "NAT-" + r_it->first + "-" + *d_it;
                refs.push_back(ref);
            }
            cpath.pop();
            cpath.pop();
            cpath.pop();
            cpath.pop();
        } // for dir
        cpath.pop();
    } // for rules
}