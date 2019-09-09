#include <sys/types.h>
#include <regex.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>

#include <cstdio>
#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <map>
#include <algorithm>

#include <boost/foreach.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/lexical_cast.hpp>

#include "fw_dpi.hpp"
#include "util.hpp"

using namespace std;
using namespace boost::property_tree;


static const char *cats_file = "/etc/ubnt/tdts/cats.xml";
static const char *apps_file = "/etc/ubnt/tdts/rule.xml";
static const char *marks_file = "/var/run/vyatta/fw_marks";
static const char *cust_cat_file = "/var/run/vyatta/dpi_cust_cat";
static const char *nf_dpi_proc = "/proc/nf_dpi/app_int";

static string categories("data.app_categories");
static string applications("data.applications");

static map <string, uint32_t> app_name_map;
static map<string, uint8_t> cat_name_map;
static map<string, string> cat_map;

enum MARKS {
    DPI_MARK = 0,
    DPI_CAT,
    DPI_APP,
    DPI_CHAIN,
    DPI_RULE,
    DPI_MAX,
};

enum CUST_CAT {
    CC_NUM = 0,
    CC_NAME,
    CC_MAX,
};

enum PROC_CMD {
    PROC_FLUSH = 0,
    PROC_ADD,
    PROC_DEL,
};

static int cat_mark_start = 1;
static int cat_mark_max = 31;
static int cat_mark_shift = 18;
static string cat_mark_mask = "/0x7c0000";

static int cust_cat_num_start = 1;
static int cust_cat_num_max = 31;
static int cust_cat_mark_shift = 13;
static string cust_cat_mark_mask = "/0x3e000";


static uint8_t convert_cat_int(const string& cat)
{
    int val;
    uint8_t val2;

    stringstream ss(cat);
    ss >> val;
    val2 = (uint8_t) (val & 0x7f);  // Trend Micro strips the high bit
    return val2;
}

static bool convert_cat_int(const string& cat, string& cat_id)
{
    int val;

    stringstream ss(cat);
    ss >> val;
    val = (uint8_t) (val & 0x7f);   // Trend Micro strips the high bit
    cat_id = boost::lexical_cast<std::string>(val);
    return true;
}

static uint32_t convert_app_int(const string& app, uint8_t cat_id)
{
    int val;
    uint32_t val2;

    stringstream ss(app);
    ss >> val;
    val2 = (uint32_t)val;
    val2 = ((cat_id << 16) | val2);
    return val2;
}

static int read_xml_file(const char *file, ptree& pt)
{
    ifstream input(file);
    if (!input.is_open()) {
        cerr << "Failed to open file" << endl;
        return -1;
    }
    try {
        read_xml(file, pt);
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    input.close();
    return 0;
}

static int parse_xml_cats(const char *file, map<string, uint8_t>& m)
{
    string name, id;
    ptree pt;
    uint8_t cat_id;

    read_xml_file(file, pt);

    m.clear();
    try {
        BOOST_FOREACH(const ptree::value_type& val, pt.get_child(categories)) {
            const ptree& sub = val.second.get_child("<xmlattr>");
            id = sub.get_child("id").get_value("");
            name = sub.get_child("name").get_value("");
            replace(name.begin(), name.end(), ' ', '-');
            cat_id = convert_cat_int(id);
            transform(name.begin(), name.end(), name.begin(), ::tolower);
            replace(name.begin(), name.end(), ' ', '-');
            m[name] = cat_id;
        }
    } catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    m["custom"] = 254;

    return 0;
}

static int parse_xml_cats_id(const char *file, map<string, string>& m)
{
    string name, id, cat_id, cust_cat_id("254");
    ptree pt;

    read_xml_file(file, pt);

    m.clear();
    try {
        BOOST_FOREACH(const ptree::value_type& val, pt.get_child(categories)) {
            const ptree& sub = val.second.get_child("<xmlattr>");
            id = sub.get_child("id").get_value("");
            name = sub.get_child("name").get_value("");
            replace(name.begin(), name.end(), ' ', '-');
            convert_cat_int(id, cat_id);
            m[cat_id] = name;
        }
    } catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    m[cust_cat_id] = "custom";

    return 0;
}

static int parse_xml_apps(const char *file, map<string, uint32_t>& m)
{
    string name, cat, app;
    uint8_t cat_id, old_cat_id;
    uint32_t app_id;
    ptree pt;

    read_xml_file(file, pt);

    m.clear();
    try {
        BOOST_FOREACH(const ptree::value_type& v, pt.get_child(applications)) {
            const ptree& sub = v.second.get_child("<xmlattr>");
            cat = sub.get_child("cat_id").get_value("");
            app = sub.get_child("app_id").get_value("");
            name = sub.get_child("name").get_value("");
            cat_id = convert_cat_int(cat);
            app_id = convert_app_int(app, cat_id);
            transform(name.begin(), name.end(), name.begin(), ::tolower);
            replace(name.begin(), name.end(), ' ', '-');
            if (app_name_map.find(name) != app_name_map.end()) {
                /*
                 * When there are duplicates, it's the TopSites that are
                 * the old category.  TopSites go from category id 28 to 43.
                 */
                if (debug_flag)
                    printf("Duplicate app found [%s] [%d] [%d] [%d]\n",
                           name.c_str(), app_name_map[name], cat_id, app_id);
                old_cat_id = app_name_map[name] >> 16;
                if (old_cat_id >= 28 && old_cat_id <= 43) {
                    app_name_map[name] = app_id;
                } else if (cat_id >= 28 && cat_id <= 43) {
                    // keep the old one
                } else {
                    cerr << "Unexpected duplicate application\n";
                }
            } else {
                app_name_map[name] = app_id;
            }
        }
    } catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    return 0;
}

static int lookup_cat(string& cat)
{
    map<string, uint8_t>::iterator it;
    int cat_id;

    if (cat_name_map.empty())
        parse_xml_cats(cats_file, cat_name_map);

    transform(cat.begin(), cat.end(), cat.begin(), ::tolower);
    replace(cat.begin(), cat.end(), ' ', '-');

    it = cat_name_map.find(cat);
    if (it != cat_name_map.end()) {
        cat_id = it->second;
        return cat_id;
    }
    return -1;
}

static int lookup_cat_id(const string& cat_id, string& cat)
{
    map<string, string>::iterator it;

    if (cat_map.empty())
        parse_xml_cats_id(cats_file, cat_map);

    it = cat_map.find(cat_id);
    if (it != cat_map.end()) {
        cat = it->second;
        return 0;
    }
    return -1;
}

static uint32_t lookup_app(string& app_name)
{
    map<string, uint32_t>::iterator it;

    if (debug_flag)
        printf("lookup_app(%s)\n", app_name.c_str());

    if (app_name_map.empty())
        parse_xml_apps(apps_file, app_name_map);

    transform(app_name.begin(), app_name.end(), app_name.begin(), ::tolower);
    replace(app_name.begin(), app_name.end(), ' ', '-');
    it = app_name_map.find(app_name);
    if (it == app_name_map.end()) {
        if (debug_flag)
            printf("app not found\n");
        return 0;
    }
    if (debug_flag)
        printf("app found\n");

    return it->second;
}

static bool find_mark(string& mark, int cat, int app,
                      const string& chain, const string& rule)
{
    string s_mark;
    string s_cat, s_app;
    vector<string> marks, tokens;
    bool found(false);

    if (debug_flag)
        printf("find_mark cat [%d] app [%d] chain [%s] rule [%s]\n",
               cat, app, chain.c_str(), rule.c_str());

    s_cat = my_itoa(cat);
    s_app = my_itoa(app);
    mark.clear();
    read_refcnt_file(marks_file, marks);
    BOOST_FOREACH(const string& line, marks) {
        tokens.clear();
        line_to_tokens(line, tokens);
        if (tokens.size() != DPI_MAX) {
            cerr << "Fail find_mark [" << mark << "][" << line << "]\n";
            cerr << "token.size " << tokens.size() << endl;
            BOOST_FOREACH(const string& t, tokens) {
                cerr << "[" << t << "]" << endl;
            }
            goto done;
        }
        if (tokens[DPI_CAT] == s_cat && tokens[DPI_APP] == s_app
            && tokens[DPI_CHAIN] == chain && tokens[DPI_RULE] == rule) {
            if (debug_flag)
                printf("found [%s] [%s]\n", line.c_str(), mark.c_str());

            mark = tokens[DPI_MARK];
            found = true;
            goto done;
        }
    }
done:
    if (debug_flag)
        printf("found = %d, mark = [%s]\n", found ? 1 : 0, mark.c_str());
    return found;
}

static bool write_proc_file(int cmd, int mark, int cat, int app)
{
    FILE *f = fopen(nf_dpi_proc, "w");

    if (debug_flag)
        printf("write_proc_file(%d, %d, %d, %d)\n", cmd, mark, cat, app);

    if (!f) {
        cerr << "open " << nf_dpi_proc << " failed\n";
        return false;
    }
    if (cmd == PROC_ADD) {
        if (fprintf(f, "%d %d %d %d\n", cmd, mark, cat, app) < 1) {
            perror("Error writing for PROC_ADD\n");
            fclose(f);
            return false;
        }
    } else if (cmd == PROC_DEL) {
        if (fprintf(f, "%d %d\n", cmd, mark) < 1) {
            perror("Error writing for PROC_DEL\n");
            fclose(f);
            return false;
        }
    }
    fclose(f);
    return true;
}

static bool del_mark(const string& mark, int cat, int app,
                     const string& chain, const string& rule)
{
    string s_mark;
    string s_cat, s_app;
    vector<string> marks, tokens, new_lines;
    bool found(false);

    if (debug_flag)
        printf("del_mark [%s] cat %d chain [%s] rule [%s]\n", mark.c_str(), cat,
               chain.c_str(), rule.c_str());

    s_cat = my_itoa(cat);
    s_app = my_itoa(app);
    read_refcnt_file(marks_file, marks);
    BOOST_FOREACH(const string& line, marks) {
        tokens.clear();
        line_to_tokens(line, tokens);
        if (tokens.size() != DPI_MAX) {
            cerr << "Fail del_mark [" << mark << "][" << line << "]\n";
            cerr << "token.size %d\n" << tokens.size() << endl;
            goto done;
        }
        if (tokens[DPI_MARK] == mark && tokens[DPI_CAT] == s_cat &&
            tokens[DPI_APP] == s_app && tokens[DPI_CHAIN] == chain
            && tokens[DPI_RULE] == rule) {
            found = true;
        } else {
            new_lines.push_back(line);
        }
    }

    if (found) {
        write_refcnt_file(marks_file, new_lines);
    }
done:
    if (debug_flag)
        printf("found %d\n", found ? 1 : 0);

    return found;
}

static bool find_next_mark(string& mark, int cat, int app,
                           const string& chain, const string& rule)
{
    vector<string> lines, item;
    map<int, string> marks;
    string s_cat, s_app, cat_mark_match;
    int next = cat_mark_start;
    bool found = false;

    if (debug_flag)
        printf("find_next_mark cat %d chain [%s] rule [%s]\n", cat,
               chain.c_str(), rule.c_str());

    s_cat = my_itoa(cat);
    s_app = my_itoa(app);
    read_refcnt_file(marks_file, lines);
    BOOST_FOREACH(const string& l, lines) {
        item.clear();
        line_to_tokens(l, item);
        if (item.size() != DPI_MAX) {
            cerr << "Fail find_next_mark [" << l << "]\n";
            cerr << "item.size %d\n" << item.size() << endl;
            return false;
        }
        string omark(item[DPI_MARK]);
        int i_mark = (int)strtoul(omark.c_str(), NULL, 0);
        marks[i_mark] = l;
        if (item[DPI_CAT] == s_cat && app == 0) {
            mark = omark;
            found = true;
        }
    }

    map<int, string>::iterator it;
    while (!found && next <= cat_mark_max) {
        it = marks.find(next);
        if (it == marks.end()) {
            mark = boost::lexical_cast<std::string>(next);
            found = true;
        } else {
            next++;
        }
    }

    if (debug_flag)
        printf("found = %d mark [%s]\n", found ? 1 : 0, mark.c_str());

    if (found) {
        string new_line = mark + " " + s_cat + " " + s_app + " "
            + chain + " " + rule;
        lines.push_back(new_line);
        write_refcnt_file(marks_file, lines);
    }
    return found;
}

static bool add_cust_cat_mark(const string& mark, int cat, int app,
                              const string& chain, const string& rule)
{
    vector<string> lines, item;
    string s_cat, s_app;

    if (debug_flag)
        printf("add_cust_cat_mark mark [%s] cat %d chain [%s] rule [%s]\n",
               mark.c_str(), cat, chain.c_str(), rule.c_str());

    s_cat = my_itoa(cat);
    s_app = my_itoa(app);
    read_refcnt_file(marks_file, lines);
    BOOST_FOREACH(const string& l, lines) {
        item.clear();
        line_to_tokens(l, item);
        if (item.size() != DPI_MAX) {
            cerr << "Fail find_next_mark [" << l << "]\n";
            cerr << "item.size %d\n" << item.size() << endl;
            return false;
        }
        if (item[DPI_MARK] == mark && item[DPI_CAT] == s_cat
            && s_app == item[DPI_APP] && chain == item[DPI_CHAIN]
            && rule == item[DPI_RULE]) {
            return true;
        }
    }

    string new_line = mark + " " + s_cat + " " + s_app + " " + chain
        + " " + rule;

    if (debug_flag)
        printf("adding line [%s]\n", new_line.c_str());

    lines.push_back(new_line);
    write_refcnt_file(marks_file, lines);

    return true;
}

static bool find_cust_cat_num(string& cust_cat_num, const string& cust_cat)
{
    vector<string> cats, tokens;
    string s_name, s_num;
    bool found(false);

    if (debug_flag)
        printf("find_cust_cat_num cust_cat [%s]\n", cust_cat.c_str());

    read_refcnt_file(cust_cat_file, cats);
    BOOST_FOREACH(const string& line, cats) {
        tokens.clear();
        line_to_tokens(line, tokens);
        if (tokens.size() != CC_MAX) {
            cerr << "Fail find_cust_cat_num [" << cust_cat << "]["
                 << line << "]\n";
            cerr << "token.size " << tokens.size() << endl;
            BOOST_FOREACH(const string& t, tokens) {
                cerr << "[" << t << "]" << endl;
            }
            goto done;
        }
        if (tokens[CC_NAME] == cust_cat) {
            if (debug_flag)
                printf("found [%s] [%s]\n", line.c_str(), cust_cat.c_str());

            cust_cat_num = tokens[CC_NUM];
            found = true;
            goto done;
        }
    }
done:
    if (debug_flag)
        printf("found = %d, num = [%s]\n", found ? 1 : 0, cust_cat_num.c_str());
    return found;
}

static bool find_next_cust_cat_num(string& cust_cat_num,
                                   const string& cust_cat)
{
    vector<string> lines, item;
    map<int, string> cats;
    int next = cust_cat_num_start;
    bool found = false;

    if (debug_flag)
        printf("find_next_cust_cat_num cust_cat [%s]\n", cust_cat.c_str());

    read_refcnt_file(cust_cat_file, lines);
    BOOST_FOREACH(const string& l, lines) {
        item.clear();
        line_to_tokens(l, item);
        if (item.size() != CC_MAX) {
            cerr << "Fail find_next_cust_cat_num [" << l << "]\n";
            cerr << "item.size %d\n" << item.size() << endl;
            return false;
        }
        string num(item[CC_NUM]);
        string name(item[CC_NAME]);
        int i_num = (int)strtoul(num.c_str(), NULL, 0);
        cats[i_num] = name;
    }

    map<int, string>::iterator it;
    while (!found) {
        it = cats.find(next);
        if (it == cats.end()) {
            cust_cat_num = boost::lexical_cast<std::string>(next);
            found = true;
        } else {
            next++;
        }
    }
    if (next >= cust_cat_num_max) {
        cerr << "Error: max custom categories used\n";
        return false;
    }

    if (debug_flag)
        printf("found = %d num [%s]\n", found ? 1 : 0, cust_cat_num.c_str());

    if (found) {
        string new_line = cust_cat_num + " " + cust_cat;
        lines.push_back(new_line);
        write_refcnt_file(cust_cat_file, lines);
    } else {
        cerr << "Error: couldn't find next custom category\n";
    }
    return found;
}

static bool del_cust_cat_num(const string& cust_cat_num, const string& cust_cat)
{
    vector<string> cats, tokens, new_lines;
    bool found(false);

    if (debug_flag)
        printf("del_cust_cat_num [%s] cust_cat [%s]\n", cust_cat_num.c_str(),
               cust_cat.c_str());

    read_refcnt_file(cust_cat_file, cats);
    BOOST_FOREACH(const string& line, cats) {
        tokens.clear();
        line_to_tokens(line, tokens);
        if (tokens.size() != CC_MAX) {
            cerr << "Fail del_cust_cat_num [" << cust_cat_num << "]["
                 << line << "]\n";
            cerr << "token.size %d\n" << tokens.size() << endl;
            goto done;
        }
        if (tokens[CC_NUM] == cust_cat_num && tokens[CC_NAME] == cust_cat) {
            found = true;
        } else {
            new_lines.push_back(line);
        }
    }

    if (found) {
        write_refcnt_file(cust_cat_file, new_lines);
    }
done:
    if (debug_flag)
        printf("found %d\n", found ? 1 : 0);

    return found;
}

/****** external ******/

bool dpi_get_cat_mark(string& cat, const string& chain,
                      const string& rule, string& mark, string& err)
{
    int cat_id;
    int i_mark;

    cat_id = lookup_cat(cat);
    if (cat_id < 0) {
        err = "Error: get_cat_mark Invalid category\n";
        return false;
    }
    if (!find_mark(mark, cat_id, 0, chain, rule)) {
        if (!find_next_mark(mark, cat_id, 0, chain, rule)) {
            err = "Error: Unable to allocate new dpi mark\n";
            return false;
        }
    }
    i_mark = my_atoi(mark);
    if (i_mark > cat_mark_max) {
        err = "Error: Maximum number of categories exceeded\n";
        return false;
    }
    i_mark <<= cat_mark_shift;
    mark = my_itoa(i_mark);
    mark += cat_mark_mask;

    return true;
}

bool dpi_get_cust_cat_mark(const string& cust_cat, const string& chain,
                           const string& rule, string& mark, string& err)
{
    int i_cust_cat_num;
    string cust_cat_num;
    int i_mark;

    if (debug_flag)
        printf("dpi_get_cust_cat_mark cust_cat [%s] chain [%s] rule [%s]\n",
               cust_cat.c_str(), chain.c_str(), rule.c_str());

    if (!find_cust_cat_num(cust_cat_num, cust_cat)) {
        err = "Error: Custom category does not exist\n";
        return false;
    }
    if (debug_flag)
        printf("found cust_cat_num [%s]\n", cust_cat_num.c_str());

    i_cust_cat_num = my_atoi(cust_cat_num);
    i_mark = i_cust_cat_num;
    i_mark <<= 16;
    mark = my_itoa(i_mark);
    add_cust_cat_mark(mark, 254, i_cust_cat_num, chain, rule);

    i_mark = i_cust_cat_num;
    i_mark <<= cust_cat_mark_shift;
    mark = my_itoa(i_mark);

    mark += cust_cat_mark_mask;

    return true;
}

bool dpi_set_cat_mark(string& cat, const string& chain,
                      const string& rule, string& err)
{
    int cat_id;
    int i_mark;
    string no_app("0");
    string mark;

    cat_id = lookup_cat(cat);
    if (cat_id < 0) {
        err = "Error: set_cat_mark Invalid category\n";
        return false;
    }
    if (!find_mark(mark, cat_id, 0, chain, rule)) {
        if (!find_next_mark(mark, cat_id, 0, chain, rule)) {
            err = "Error: Unable to allocate new dpi mark\n";
            return false;
        }
    }
    i_mark = my_atoi(mark);
    return write_proc_file(PROC_ADD, i_mark, cat_id, 0);
}

bool dpi_del_cat_mark(string& cat, const string& app,
                      const string& chain, const string& rule,
                      string& err)
{
    int cat_id;
    int i_mark, i_app;
    string mark;

    if (debug_flag)
        printf("dpi_del_cat_mark cat [%s] app [%s] chain [%s] rule [%s]\n",
               cat.c_str(), app.c_str(), chain.c_str(), rule.c_str());

    cat_id = lookup_cat(cat);
    if (cat_id < 0) {
        err = "Error: del_cat_mark Invalid category\n";
        return false;
    }
    i_app  = my_atoi(app);
    if (!find_mark(mark, cat_id, i_app, chain, rule)) {
        err = "Error: Unable to allocate new dpi mark\n";
        return false;
    }
    del_mark(mark, cat_id, i_app, chain, rule);
    if (cat_id != 254) {
        i_mark = my_atoi(mark);
        write_proc_file(PROC_DEL, i_mark, cat_id, 0);
    }
    return true;
}

bool dpi_flush_chain(const string& chain)
{
    vector<string> marks, tokens, new_lines;
    bool found(false);

    if (debug_flag)
        printf("dpi_flush_chain [%s]\n", chain.c_str());

    read_refcnt_file(marks_file, marks);
    BOOST_FOREACH(const string& line, marks) {
        tokens.clear();
        line_to_tokens(line, tokens);
        if (tokens.size() != DPI_MAX) {
            cerr << "Fail dpi_flush_chain [" << chain << "][" << line << "]\n";
            cerr << "token.size %d\n" << tokens.size() << endl;
            goto done;
        }
        if (tokens[DPI_CHAIN] == chain) {
            string err;
            string cat_id;
            found = true;
            lookup_cat_id(tokens[DPI_CAT], cat_id);
            if (!dpi_del_cat_mark(cat_id, tokens[DPI_APP], tokens[DPI_CHAIN],
                                  tokens[DPI_RULE], err)) {
                cout << err;
            }
        }
    }

done:
    if (debug_flag)
        printf("found %d\n", found ? 1 : 0);

    return found;
}

bool dpi_get_cust_cat_num(const string& cust_cat, string& cust_cat_num,
                          string& err)
{
    if (!find_cust_cat_num(cust_cat_num, cust_cat)) {
        if (!find_next_cust_cat_num(cust_cat_num, cust_cat)) {
            err = "Error: Unable to allocate new cust cat num\n";
            return false;
        }
    }

    return true;
}

bool dpi_del_cust_cat_num(const string& cust_cat, string& cust_cat_num,
                          string& err)
{
    if (!find_cust_cat_num(cust_cat_num, cust_cat)) {
        err = "Error: Unable to find cust cat num to delete\n";
        return false;
    }

    del_cust_cat_num(cust_cat_num, cust_cat);

    return true;
}

bool dpi_cust_cat_add_apps(const string& cust_cat_num,
                           const vector<string>& apps)
{
    uint32_t i_mark = my_atoi(cust_cat_num);
    uint32_t cat_app, cat_id, app_id;

    if (debug_flag)
        printf("dpi_cust_cat_add_apps [%s] mark %d\n", cust_cat_num.c_str(),
               i_mark);

    i_mark <<= 16;

    if (debug_flag)
        printf("shifted mark %d %x\n", i_mark, i_mark);

    write_proc_file(PROC_DEL, i_mark, 0, 0);
    BOOST_FOREACH(string app, apps) {
        cat_app = lookup_app(app);
        if (cat_app > 0) {
            app_id = cat_app & 0xffff;
            cat_id = cat_app >> 16;
            if (!write_proc_file(PROC_ADD, i_mark, cat_id, app_id)) {
                printf("Error: writing proc_add %d %d %d\n", i_mark, cat_id,
                       app_id);
                return false;
            }
        } else {
            printf("Error: looking up app_id [%s]\n", app.c_str());
            exit(1);
        }
    }
    return true;
}

void dpi_add_qos_cat(string& cat, const string& match_no)
{
    int cat_id;
    string orig_cat(cat), chain("UBNT_TC"), mark, err;

    cat_id = lookup_cat(cat);
    if (cat_id < 0) {
        cout << "Error: category [" << orig_cat << "] not found\n";
        exit(1);
    }
    if (!dpi_get_cat_mark(cat, chain, match_no, mark, err)) {
        cout << err << endl;
        exit(1);
    }
    if (!dpi_set_cat_mark(cat, chain, match_no, err)) {
        cout << err << endl;
        exit(1);
    }
    cout << mark << endl;
    exit(0);
}

void dpi_add_qos_cust_cat(const string& cust_cat, const string& match_no)
{
    string cust_cat_num, chain("UBNT_TC"), mark, err;

    if (!find_cust_cat_num(cust_cat_num, cust_cat)) {
        cout << "Error: custom category [" << cust_cat << "] not defined\n";
        exit(1);
    }
    if (!dpi_get_cust_cat_mark(cust_cat, chain, match_no, mark, err)) {
        cout << err << endl;
        exit(1);
    }
    cout << mark << endl;
    exit(0);
}

void dpi_del_qos_cat(string& cat, const string& match_no)
{
    int cat_id;
    string chain("UBNT_TC"), zero("0"), err;

    cat_id = lookup_cat(cat);
    if (cat_id < 0) {
        cout << "Error: category [" << cat << "] not found\n";
        exit(1);
    }
    if (!dpi_del_cat_mark(cat, zero, chain, match_no, err)) {
        cout << err << endl;
        exit(1);
    }
    exit(0);
}

void dpi_del_qos_cust_cat(const string& cust_cat, const string& match_no)
{
    string cust_cat_num, custom("CUSTOM"), chain("UBNT_TC"), err;

    if (!find_cust_cat_num(cust_cat_num, cust_cat)) {
        cout << "Error: custom category [" << cust_cat << "] not defined\n";
        exit(1);
    }
    if (!dpi_get_cust_cat_num(cust_cat, cust_cat_num, err)) {
        cout << err << endl;
        exit(1);
    }
    if (!dpi_del_cat_mark(custom, cust_cat_num, chain, match_no, err)) {
        cout << err << endl;
        exit(1);
    }
    exit(0);
}