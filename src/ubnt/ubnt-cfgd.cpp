#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <memory>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <grp.h>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/unordered_set.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/thread/locks.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/thread/mutex.hpp>

#include <cli_cstore.h>
#include <cstore/cstore.hpp>
#include <cnode/cnode.hpp>
#include <cnode/cnode-algorithm.hpp>
#include <commit/commit-algorithm.hpp>

#define CFGD_SOCKET_PATH "/tmp/ubnt.socket.cfgd"
#define ACTIVE_ONLY_SID "ACTIVE_ONLY"

enum {
    CFGD_GET_TMPL = 0,
    CFGD_GET_CHILDREN,
    CFGD_GET_VALUES,
    CFGD_GET_VALUE,
    CFGD_GET_CHILDREN_W,
    CFGD_GET_VALUES_W,
    CFGD_GET_VALUE_W,
    CFGD_SET_PATHS,
    CFGD_DELETE_PATHS,
    CFGD_MOVE_PATHS,
    CFGD_CLONE_PATHS,
    CFGD_COMMIT,
    CFGD_DISCARD,
    CFGD_SAVE,
    CFGD_EXISTS,
    CFGD_EXISTS_W,
    CFGD_GET_CHILDREN_STATUS_W,
    CFGD_PATH_DELETED,
    CFGD_PATH_ADDED,
    CFGD_PATH_CHANGED,
    CFGD_PATH_EFFECTIVE,
    CFGD_TEARDOWN,
    CFGD_GET_CHILDREN_E,
    CFGD_GET_VALUES_E,
    CFGD_GET_VALUE_E,
    CFGD_LOAD_DEFCFG,
    CFGD_GET_TMPL_CHILDREN,
    CFGD_INVALID
};

using namespace std;
using namespace cstore;
using boost::asio::local::stream_protocol;
typedef boost::shared_ptr<stream_protocol::socket> sock_ptr_t;
typedef boost::shared_ptr<Cstore> cstore_ptr_t;
typedef boost::archive::binary_iarchive iarchive_t;
typedef boost::archive::binary_oarchive oarchive_t;
static MapT<string, cstore_ptr_t> cs_cache;

static const size_t _max_req_size = 2097152;

class ProcReqEnv {
public:
    ProcReqEnv(const string& sid) {
        char *e = getenv(SID_ENV_STR.c_str());
        if (e) {
            _old = e;
        }
        setenv(SID_ENV_STR.c_str(), sid.c_str(), 1);
    }
    ~ProcReqEnv() {
        if (_old.empty()) {
            unsetenv(SID_ENV_STR.c_str());
        } else {
            setenv(SID_ENV_STR.c_str(), _old.c_str(), 1);
        }
    }

private:
    string _old;
    static const string SID_ENV_STR;
};

const string ProcReqEnv::SID_ENV_STR = "UBNT_CFGD_PROC_REQ_SID";

static void
process_req(const string& rsid, unsigned int rop,
            iarchive_t& req, iostream& resp_stream)
{
    ProcReqEnv pre(rsid);

    vector<string> args;
    vector<vector<string> > vargs;
    Cpath p;
    vector<Cpath> paths;

    switch (rop) {
    case CFGD_GET_TMPL:
    case CFGD_GET_CHILDREN:
    case CFGD_GET_CHILDREN_STATUS_W:
    case CFGD_GET_VALUES:
    case CFGD_GET_VALUE:
    case CFGD_GET_CHILDREN_W:
    case CFGD_GET_CHILDREN_E:
    case CFGD_GET_VALUES_W:
    case CFGD_GET_VALUES_E:
    case CFGD_GET_VALUE_W:
    case CFGD_GET_VALUE_E:
    case CFGD_EXISTS:
    case CFGD_EXISTS_W:
    case CFGD_PATH_DELETED:
    case CFGD_PATH_ADDED:
    case CFGD_PATH_CHANGED:
    case CFGD_PATH_EFFECTIVE:
    case CFGD_GET_TMPL_CHILDREN:
        req >> args;
        p = args;
        break;
    case CFGD_SET_PATHS:
    case CFGD_DELETE_PATHS:
    case CFGD_MOVE_PATHS:
    case CFGD_CLONE_PATHS:
        req >> vargs;
        for (size_t i = 0; i < vargs.size(); i++) {
            paths.push_back(vargs[i]);
        }
        break;
    case CFGD_COMMIT:
    case CFGD_DISCARD:
    case CFGD_SAVE:
    case CFGD_TEARDOWN:
    case CFGD_LOAD_DEFCFG:
        {
            int dummy;
            req >> dummy;
        }
        break;
    default:
        break;
    }

    oarchive_t oa(resp_stream);
    cstore_ptr_t cs;
    MapT<string, cstore_ptr_t>::iterator csit = cs_cache.find(rsid);
    if (csit != cs_cache.end()) {
        cs = csit->second;
    } else {
        string dummy;
        cs.reset(Cstore::createCstore(rsid, dummy));
        cs_cache[rsid] = cs;
    }
    if (rsid == ACTIVE_ONLY_SID) {
        switch (rop) {
        case CFGD_GET_CHILDREN_W:
        case CFGD_GET_CHILDREN_STATUS_W:
        case CFGD_GET_VALUES_W:
        case CFGD_GET_VALUE_W:
        case CFGD_EXISTS_W:
        case CFGD_PATH_DELETED:
        case CFGD_PATH_ADDED:
        case CFGD_PATH_CHANGED:
        case CFGD_PATH_EFFECTIVE:
        case CFGD_SET_PATHS:
        case CFGD_DELETE_PATHS:
        case CFGD_MOVE_PATHS:
        case CFGD_CLONE_PATHS:
        case CFGD_COMMIT:
        case CFGD_DISCARD:
        case CFGD_SAVE:
        case CFGD_TEARDOWN:
        case CFGD_LOAD_DEFCFG:
            throw boost::system::system_error(
                    boost::asio::error::operation_aborted);
            break;
        default:
            break;
        }
    } else if (rop != CFGD_TEARDOWN && !cs->inSession()
               && !cs->setupSession()) {
        throw boost::system::system_error(
                boost::asio::error::operation_aborted);
    }

    switch (rop) {
    case CFGD_GET_TMPL:
        {
            MapT<string, string> tmap;
            if (!cs->getParsedTmpl(p, tmap)) {
                tmap.clear();
                tmap["invalid"] = "";
            } else {
                if (cs->cfgPathExists(p, true)) {
                    tmap["in_active"] = "";
                }
                if (rsid != ACTIVE_ONLY_SID) {
                    if (cs->cfgPathExists(p, false)) {
                        tmap["in_work"] = "";
                    }
                }
            }
            map<string, string> m(tmap.begin(), tmap.end());
            oa << m;
        }
        break;
    case CFGD_GET_CHILDREN:
    case CFGD_GET_CHILDREN_W:
        {
            vector<string> cnodes;
            cs->cfgPathGetChildNodes(p, cnodes,
                                     (rop == CFGD_GET_CHILDREN));
            oa << cnodes;
        }
        break;
    case CFGD_GET_CHILDREN_E:
        {
            vector<string> cnodes;
            cs->cfgPathGetEffectiveChildNodes(p, cnodes);
            oa << cnodes;
        }
        break;
    case CFGD_GET_VALUES:
    case CFGD_GET_VALUES_W:
        {
            vector<string> vals;
            cs->cfgPathGetValues(p, vals, (rop == CFGD_GET_VALUES));
            oa << vals;
        }
        break;
    case CFGD_GET_VALUE_E:
        {
            string val;
            cs->cfgPathGetEffectiveValue(p, val);
            oa << val;
        }
    case CFGD_GET_VALUES_E:
        {
            vector<string> vals;
            cs->cfgPathGetEffectiveValues(p, vals);
            oa << vals;
        }
        break;
    case CFGD_GET_VALUE:
    case CFGD_GET_VALUE_W:
        {
            string val;
            cs->cfgPathGetValue(p, val, (rop == CFGD_GET_VALUE));
            oa << val;
        }
        break;
    case CFGD_GET_CHILDREN_STATUS_W:
        {
            MapT<string, string> cmap;
            vector<string> skeys;
            cs->cfgPathGetChildNodesStatus(p, cmap, skeys);
            map<string, string> m(cmap.begin(), cmap.end());
            oa << m;
        }
        break;
    case CFGD_SET_PATHS:
    case CFGD_DELETE_PATHS:
    case CFGD_MOVE_PATHS:
    case CFGD_CLONE_PATHS:
        {
            bool failure = false, success = false;
            map<string, string> ret;
            for (size_t i = 0; i < paths.size(); i++) {
                bool fail1 = false;
                FILE *oout = out_stream;
                FILE *tf = tmpfile();
                const char *def_msg;

                out_stream = tf;
                switch (rop) {
                case CFGD_SET_PATHS:
                    def_msg = "Set failed";
                    fail1 = (!cs->validateSetPath(paths[i])
                             || !cs->setCfgPath(paths[i]));
                    break;
                case CFGD_DELETE_PATHS:
                    def_msg = "Delete failed";
                    fail1 = (!cs->deleteCfgPath(paths[i]));
                    break;
                case CFGD_MOVE_PATHS:
                    def_msg = "Move failed";
                    fail1 = (!cs->validateMoveArgs(paths[i])
                             || !cs->moveCfgPath(paths[i]));
                    break;
                case CFGD_CLONE_PATHS:
                    def_msg = "Clone failed";
                    fail1 = (!cs->validateCloneArgs(paths[i])
                             || !cs->cloneCfgPath(paths[i]));
                    break;
                }

                if (fail1) {
                    char mbuf[512];
                    const char *msg = def_msg;
                    if (ftell(tf) > 0) {
                        memset(mbuf, 0, 512);
                        fseek(tf, 0, SEEK_SET);
                        fread(mbuf, 511, 1, tf);
                        msg = mbuf;
                    }
                    failure = true;
                    ret[paths[i].to_string()] = msg;
                } else {
                    success = true;
                }

                out_stream = oout;
                fclose(tf);
            }
            ret["success"] = (success ? "1" : "0");
            ret["failure"] = (failure ? "1" : "0");
            oa << ret;
        }
        break;
    case CFGD_COMMIT:
        {
            bool success = false, failure = false;
            map<string, string> ret;
            Cpath dummy;
            cnode::CfgNode aroot(*cs, dummy, true, true);
            cnode::CfgNode wroot(*cs, dummy, false, true);

            FILE *oout = out_stream;
            FILE *tf = tmpfile();
            out_stream = tf;
            if (commit::doCommit(*cs, aroot, wroot)) {
                success = true;
            } else {
                failure = true;
                char *e = getenv("COMMIT_STATUS");
                if (e && strcmp(e, "PARTIAL") == 0) {
                    success = true;
                }

                char msg[2048];
                memset(msg, 0, 2048);
                fseek(tf, 0, SEEK_SET);
                fread(msg, 2047, 1, tf);
                ret["error"] = msg;
            }
            out_stream = oout;
            fclose(tf);

            ret["success"] = (success ? "1" : "0");
            ret["failure"] = (failure ? "1" : "0");
            oa << ret;
        }
        break;
    case CFGD_DISCARD:
        {
            map<string, string> ret;
            ret["success"]  = (cs->discardChanges() ? "1" : "0");
            oa << ret;
        }
        break;
    case CFGD_SAVE:
        {
            bool success = false;
            string tfile("/config/config.boot.");
            tfile += rsid;
            FILE *s = fopen(tfile.c_str(), "w");
            if (s) {
                Cpath dummy;
                cnode::showConfig(cnode::ACTIVE_CFG, cnode::ACTIVE_CFG, dummy,
                                  true, false, false, false, true, s);
                fclose(s);

                string cmd = "/opt/vyatta/sbin/vyatta_current_conf_ver.pl >>";
                cmd += tfile;
                system(cmd.c_str());

                if (rename(tfile.c_str(), "/config/config.boot") == 0) {
                    success = true;
                }
                sync();
            }
            map<string, string> ret;
            ret["success"] = (success ? "1" : "0");
            oa << ret;
        }
        break;
    case CFGD_EXISTS:
    case CFGD_EXISTS_W:
        {
            bool val = cs->cfgPathExists(p, (rop == CFGD_EXISTS));
            oa << val;
        }
        break;
    case CFGD_PATH_DELETED:
        {
            bool val = cs->cfgPathDeleted(p);
            oa << val;
        }
        break;
    case CFGD_PATH_ADDED:
        {
            bool val = cs->cfgPathAdded(p);
            oa << val;
        }
        break;
    case CFGD_PATH_CHANGED:
        {
            bool val = cs->cfgPathChanged(p);
            oa << val;
        }
        break;
    case CFGD_PATH_EFFECTIVE:
        {
            bool val = cs->cfgPathEffective(p);
            oa << val;
        }
        break;
    case CFGD_TEARDOWN:
        {
            map<string, string> ret;
            bool success = (cs->inSession() && cs->teardownSession());
            ret["success"]  = (success ? "1" : "0");
            oa << ret;
        }
        break;
    case CFGD_LOAD_DEFCFG:
        {
            map<string, string> ret;
            bool success = false, failure = false;

            if (!cs->loadFile("/opt/vyatta/etc/config.boot.default")) {
                ret["error"] = "Failed to load default config";
                failure = true;
            } else {
                Cpath dummy;
                cnode::CfgNode aroot(*cs, dummy, true, true);
                cnode::CfgNode wroot(*cs, dummy, false, true);

                FILE *oout = out_stream;
                FILE *tf = tmpfile();
                out_stream = tf;
                if (commit::doCommit(*cs, aroot, wroot)) {
                    success = true;
                } else {
                    failure = true;
                    char *e = getenv("COMMIT_STATUS");
                    if (e && strcmp(e, "PARTIAL") == 0) {
                        success = true;
                    }

                    string es = "Failed to commit default config: ";
                    char msg[2048];
                    memset(msg, 0, 2048);
                    fseek(tf, 0, SEEK_SET);
                    fread(msg, 2047, 1, tf);
                    ret["error"] = es + msg;
                }
                out_stream = oout;
                fclose(tf);
            }

            ret["success"] = (success ? "1" : "0");
            ret["failure"] = (failure ? "1" : "0");
            oa << ret;
        }
        break;
    case CFGD_GET_TMPL_CHILDREN:
        {
            vector<string> cnodes;
            cs->tmplGetChildNodes(p, cnodes);
            oa << cnodes;
        }
        break;
        break;
    default:
        break;
    }
}

static void
handle_session(sock_ptr_t sock)
{
    try {
        try {
            boost::asio::streambuf in_buf(1024);
            istream in_stream(&in_buf);

            while (true) {
                string rsid, rop_str, rlen_str;
                boost::asio::read_until(*sock, in_buf, '\n');
                getline(in_stream, rsid);
                boost::asio::read_until(*sock, in_buf, '\n');
                getline(in_stream, rop_str);
                boost::asio::read_until(*sock, in_buf, '\n');
                getline(in_stream, rlen_str);

                unsigned int rop = strtoul(rop_str.c_str(), NULL, 10);
                if (rop >= CFGD_INVALID) {
                    return;
                }
                size_t rlen = strtoul(rlen_str.c_str(), NULL, 10);
                if (rlen > _max_req_size) {
                    return;
                }
                size_t rem_len = in_buf.size();
                boost::asio::streambuf req_buf(rlen);
                iostream req_stream(&req_buf);
                if (rem_len > 0) {
                    req_stream << &in_buf;
                }
                if (req_buf.size() < rlen) {
                    boost::asio::read(*sock, req_buf);
                }
                iarchive_t ia(req_stream);
                boost::asio::streambuf resp_buf;
                iostream resp_stream(&resp_buf);
                process_req(rsid, rop, ia, resp_stream);

                boost::asio::streambuf head_buf;
                iostream head_stream(&head_buf);
                head_stream << resp_buf.size() << "\n";
                boost::asio::write(*sock, head_buf);
                boost::asio::write(*sock, resp_buf);
            }
        } catch (boost::system::system_error& e) {
            if (e.code() == boost::asio::error::eof) {
                return;
            }
            throw;
        }
    } catch (exception& e) {
        cerr << "Exception: " << e.what() << "\n";
        return;
    } catch (...) {
        cerr << "Unknown exception\n";
        return;
    }
}

class WaitTimer {
public:
    WaitTimer(boost::asio::io_service& io) : _timer(io) {
        rearm();
    }

    ~WaitTimer() {
        _timer.cancel();
    }

    void addPid(pid_t pid) {
        {
            lock_t lock(_plock);
            _pids.insert(pid);
        }
        boost::posix_time::time_duration td = _timer.expires_from_now();
        if (td > _intvl || (td + _intvl).total_seconds() < 0) {
            rearm();
        }
    }

    void handler(const boost::system::error_code& e) {
        vector<pid_t> del_pids;
        {
            lock_t lock(_plock);
            BOOST_FOREACH(const pid_t pid, _pids) {
                int status;
                if (waitpid(pid, &status, WNOHANG) == pid) {
                    del_pids.push_back(pid);
                }
            }
            BOOST_FOREACH(const pid_t pid, del_pids) {
                _pids.erase(pid);
            }
        }
        if (e != boost::asio::error::operation_aborted) {
            rearm();
        }
    }

private:
    typedef boost::lock_guard<boost::mutex> lock_t;

    static boost::posix_time::seconds _intvl;

    boost::asio::deadline_timer _timer;
    boost::unordered_set<pid_t> _pids;
    boost::mutex _plock;

    void rearm() {
        _timer.cancel();
        _timer.expires_from_now(_intvl);
        _timer.async_wait(boost::bind(&WaitTimer::handler, this, _1));
    }
};

boost::posix_time::seconds WaitTimer::_intvl(3);

static boost::asio::io_service wio;
static WaitTimer wtimer(wio);

static void
startWaitTimer()
{
    wio.run();
}

int
main(int argc, char* argv[])
{
    {
        struct group *g = getgrnam("vyattacfg");
        if (!g || setgid(g->gr_gid) != 0) {
            exit(1);
        }
        umask(S_IWOTH);
    }

    initialize_output_streams();

    {
        boost::thread t(startWaitTimer);
    }

    while (true) {
        boost::asio::io_service io_serv;
        try {
            remove(CFGD_SOCKET_PATH);
            stream_protocol::endpoint ep(CFGD_SOCKET_PATH);
            stream_protocol::acceptor a(io_serv, ep);

            if (chmod(CFGD_SOCKET_PATH, 0770) != 0) {
                perror("chmod");
                exit(1);
            }

            while (true) {
                sock_ptr_t sock(new stream_protocol::socket(io_serv));
                a.accept(*sock);

                pid_t pid = fork();
                if (pid == -1) {
                    throw boost::system::system_error(
                            boost::asio::error::operation_aborted);
                }
                if (pid == 0) {
                    // child
                    handle_session(sock);
                    exit(0);
                }
                // parent
                wtimer.addPid(pid);
            }
        } catch (exception& e) {
            cerr << "Exception: " << e.what() << "\n";
        } catch (...) {
            cerr << "Unknown exception\n";
        }
    }

    return 0;
}
