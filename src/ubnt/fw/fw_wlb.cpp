#include <cstdio>
#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <iterator>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>

#include "util.hpp"

using namespace std;

void
add_wlb_group(const string& ipt_cmd, vector<string>& restore_vector,
              const string& wlb, const string& rule)
{
    log_msg("add_wlb_group(%s, %s)", wlb.c_str(), rule.c_str());

    string table("mangle");
    string chain = "UBNT_WLB_" + wlb;

    // The chain may have already have been created by wlb
    if (!chain_exists(ipt_cmd, table, chain)) {
        string cmd = ":" + chain + " - [0:0]\n";
        restore_vector.push_back(cmd);
    }
}

void
remove_wlb_group(const string& ipt_cmd, vector<string>& restore_vector,
                 const string& wlb, const string& rule)
{
    log_msg("remove_wlb_group(%s, %s)", wlb.c_str(), rule.c_str());

    string table("mangle");
    string chain = "UBNT_WLB_" + wlb;

    if (chain_exists(ipt_cmd, table, chain)) {
        if (!chain_referenced(table, chain, ipt_cmd)) {
            string cmd = "-F " + chain + "\n";
            restore_vector.push_back(cmd);
            cmd = "-X " + chain + "\n";
            restore_vector.push_back(cmd);
        }
    }
}