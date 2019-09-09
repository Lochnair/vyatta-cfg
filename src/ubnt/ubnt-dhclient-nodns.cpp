#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <cstore/cstore.hpp>
#include <cparse/cparse.hpp>

#include <boost/foreach.hpp>

using namespace std;
using namespace cstore;
using namespace cparse;

Cstore *g_cstore = NULL;

static bool
nodns(vector<string>& cpath)
{
    string val;
    bool yesno(false);

    cpath.push_back("dhcp-options");
    cpath.push_back("name-server");
    if (g_cstore->cfgPathExists(cpath, true)) {
        g_cstore->cfgPathGetValue(cpath, val, true);
        if (!val.empty() && val == "no-update") {
            yesno = true;
        }
    }
    cpath.pop_back();
    cpath.pop_back();

    return yesno;
}

static void
make_turd(const string& intf)
{
    string turd, turd_path = "/var/run/vyatta/dhclient-nodns-";
    fstream f;

    turd = turd_path + intf;
    f.open(turd.c_str(), ios::out);
    f << flush;
    f.close();
}

static void
check_nodns(vector<string>& cpath)
{
    vector<string> intfs;

    g_cstore->cfgPathGetChildNodes(cpath, intfs, true);
    BOOST_FOREACH(const string& intf, intfs) {
        cpath.push_back(intf);
        if (nodns(cpath)) {
            make_turd(intf);
        }
        cpath.push_back("vif");
        if (g_cstore->cfgPathExists(cpath, true)) {
            vector<string> vifs;
            g_cstore->cfgPathGetChildNodes(cpath, vifs, true);
            BOOST_FOREACH(const string& vif, vifs) {
                cpath.push_back(vif);
                if (nodns(cpath)) {
                    string intf_vif = intf + "." + vif;
                    make_turd(intf_vif);
                }
                cpath.pop_back();
            }
        }
        cpath.pop_back();
        cpath.pop_back();
    } 
}

int
main(int argc, const char *argv[])
{
    const char *fname = "/config/config.boot";
    vector<string> cpath;

    g_cstore = Cstore::createCstore(true);
    if (!g_cstore) {
        cerr << "Error: failed to create g_cstore" << endl;
        exit(1);
    }

    cnode::CfgNode *root = cparse::parse_file(fname, *g_cstore);
    if (!root) {
        cerr << "Error: failed to parse config" << endl;
        exit(1);
    }

    cpath.push_back("interfaces");

    cpath.push_back("ethernet");
    check_nodns(cpath);
    cpath.pop_back();

    cpath.push_back("pseudo-ethernet");
    check_nodns(cpath);
    cpath.pop_back();

    cpath.push_back("bridge");
    check_nodns(cpath);
    cpath.pop_back();

    cpath.push_back("bonding");
    check_nodns(cpath);
    cpath.pop_back();

    cpath.push_back("switch");
    check_nodns(cpath);
    cpath.pop_back();

    cpath.pop_back();
}
