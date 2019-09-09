/*
 * Copyright (C) 2010 Vyatta, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/time.h>

#include <cli_cstore.h>
#include <cstore/unionfs/cstore-unionfs.hpp>
#include <cnode/cnode.hpp>
#include <commit/commit-algorithm.hpp>

namespace cstore { // begin namespace cstore
namespace unionfs { // begin namespace unionfs

////// constants
// environment vars defining root dirs
const string UnionfsCstore::C_ENV_TMPL_ROOT = "VYATTA_CONFIG_TEMPLATE";
const string UnionfsCstore::C_ENV_WORK_ROOT = "VYATTA_TEMP_CONFIG_DIR";
const string UnionfsCstore::C_ENV_ACTIVE_ROOT
  = "VYATTA_ACTIVE_CONFIGURATION_DIR";
const string UnionfsCstore::C_ENV_CHANGE_ROOT = "VYATTA_CHANGES_ONLY_DIR";
const string UnionfsCstore::C_ENV_TMP_ROOT = "VYATTA_CONFIG_TMP";

// default root dirs/paths
const string UnionfsCstore::C_DEF_TMPL_ROOT
  = "/opt/vyatta/share/vyatta-cfg/templates";
const string UnionfsCstore::C_DEF_CFG_ROOT
  = "/opt/vyatta/config";
const string UnionfsCstore::C_DEF_ACTIVE_ROOT
  = UnionfsCstore::C_DEF_CFG_ROOT + "/active";
const string UnionfsCstore::C_DEF_CHANGE_PREFIX = "/tmp/changes_only_";
const string UnionfsCstore::C_DEF_WORK_PREFIX
  = UnionfsCstore::C_DEF_CFG_ROOT + "/tmp/new_config_";
const string UnionfsCstore::C_DEF_TMP_PREFIX
  = UnionfsCstore::C_DEF_CFG_ROOT + "/tmp/tmp_";

// markers
const string UnionfsCstore::C_MARKER_DEF_VALUE  = "def";
const string UnionfsCstore::C_MARKER_DEACTIVATE = ".disable";
const string UnionfsCstore::C_MARKER_CHANGED = ".modified";
const string UnionfsCstore::C_MARKER_UNSAVED = ".unsaved";
const string UnionfsCstore::C_COMMITTED_MARKER_FILE = ".changes";
const string UnionfsCstore::C_COMMENT_FILE = ".comment";
const string UnionfsCstore::C_TAG_NAME = "node.tag";
const string UnionfsCstore::C_VAL_NAME = "node.val";
const string UnionfsCstore::C_DEF_NAME = "node.def";
const string UnionfsCstore::C_COMMIT_LOCK_FILE
    = UnionfsCstore::C_DEF_CFG_ROOT + "/.lock";
const string UnionfsCstore::C_COMMIT_SID_FILE
    = UnionfsCstore::C_DEF_CFG_ROOT + "/.sid";
const string UnionfsCstore::C_COMMIT_END_FILE
    = UnionfsCstore::C_DEF_CFG_ROOT + "/.end";
const string UnionfsCstore::C_WHITEOUT_PREFIX
    = ".wh.";
const string UnionfsCstore::C_WHITEOUT_OPAQUE
    = ".wh.__dir_opaque";

////// static
static MapT<char, string> _fs_escape_chars;
static MapT<string, char> _fs_unescape_chars;
static void
_init_fs_escape_chars()
{
  _fs_escape_chars[-1] = "\%\%\%";
  _fs_escape_chars['%'] = "\%25";
  _fs_escape_chars['/'] = "\%2F";

  _fs_unescape_chars["\%\%\%"] = -1;
  _fs_unescape_chars["\%25"] = '%';
  _fs_unescape_chars["\%2F"] = '/';
}

static string
_escape_char(char c)
{
  MapT<char, string>::iterator p = _fs_escape_chars.find(c);
  if (p != _fs_escape_chars.end()) {
    return p->second;
  } else {
    return string(1, c);
  }
}

static MapT<string, string> _escape_path_name_cache;

static string
_escape_path_name(const string& path)
{
  MapT<string, string>::iterator p
    = _escape_path_name_cache.find(path);
  if (p != _escape_path_name_cache.end()) {
    // found escaped string in cache. just return it.
    return p->second;
  }

  // special case for empty string
  string npath = (path.size() == 0) ? _fs_escape_chars[-1] : "";
  for (size_t i = 0; i < path.size(); i++) {
    npath += _escape_char(path[i]);
  }

  // cache it before return
  _escape_path_name_cache[path] = npath;
  return npath;
}

static MapT<string, string> _unescape_path_name_cache;

static string
_unescape_path_name(const string& path)
{
  MapT<string, string>::iterator p
    = _unescape_path_name_cache.find(path);
  if (p != _unescape_path_name_cache.end()) {
    // found unescaped string in cache. just return it.
    return p->second;
  }

  // assume all escape patterns are 3-char
  string npath = "";
  for (size_t i = 0; i < path.size(); i++) {
    if ((path.size() - i) < 3) {
      npath += path.substr(i);
      break;
    }
    string s = path.substr(i, 3);
    MapT<string, char>::iterator p = _fs_unescape_chars.find(s);
    if (p != _fs_unescape_chars.end()) {
      char c = p->second;
      if (path.size() == 3 && c == -1) {
        // special case for empty string
        npath = "";
        break;
      }
      npath += string(1, _fs_unescape_chars[s]);
      // skip the escape sequence
      i += 2;
    } else {
      npath += path.substr(i, 1);
    }
  }
  // cache it before return
  _unescape_path_name_cache[path] = npath;
  return npath;
}

////// constructor/destructor
/* "current session" constructor.
 * this constructor sets up the object from environment.
 * used when environment is already set up, i.e., when operating on the
 * "current" config session. e.g., in the following scenarios
 *   configure commands
 *   perl module
 *   shell "current session" api
 *
 * note: this also applies when using the cstore in operational mode,
 *       in which case only the template root and the active root will be
 *       valid.
 */
UnionfsCstore::UnionfsCstore(bool use_edit_level)
{
  // set up root dir strings
  char *val;
  if ((val = getenv(C_ENV_TMPL_ROOT.c_str()))) {
    tmpl_path = val;
  } else {
    tmpl_path = C_DEF_TMPL_ROOT;
  }
  tmpl_root = tmpl_path; // save a copy of tmpl root
  if ((val = getenv(C_ENV_WORK_ROOT.c_str()))) {
    work_root = val;
  }
  if ((val = getenv(C_ENV_TMP_ROOT.c_str()))) {
    tmp_root = val;
    init_commit_data();
  }
  if ((val = getenv(C_ENV_ACTIVE_ROOT.c_str()))) {
    active_root = val;
  } else {
    active_root = C_DEF_ACTIVE_ROOT;
  }
  if ((val = getenv(C_ENV_CHANGE_ROOT.c_str()))) {
    change_root = val;
  }

  /* note: the original perl API module does not use the edit levels
   *       from environment. only the actual CLI operations use them.
   *       so here make it an option.
   */
  mutable_cfg_path = "/";
  if (use_edit_level) {
    // set up path strings
    if ((val = getenv(C_ENV_EDIT_LEVEL.c_str()))) {
      mutable_cfg_path = val;
    }
    if ((val = getenv(C_ENV_TMPL_LEVEL.c_str())) && val[0] && val[1]) {
      /* no need to append root (i.e., "/"). level (if exists) always
       * starts with '/', so only append it if it is at least two chars
       * (i.e., it is not "/").
       */
      FsPath tlvl(val);
      tmpl_path /= tlvl;
    }
  }
  orig_mutable_cfg_path = mutable_cfg_path;
  orig_tmpl_path = tmpl_path;
  _init_fs_escape_chars();
  path_present_cache_enabled = false;
}

/* "specific session" constructor.
 * this constructor sets up the object for the specified session ID and
 * returns an environment string that can be "evaled" to set up the
 * shell environment.
 *
 * used when the session environment needs to be established. this is
 * mainly for the shell functions that set up configuration sessions.
 * i.e., the "vyatta-cfg-cmd-wrapper" (on boot or for GUI etc.) and
 * the cfg completion script (when entering configure mode).
 *
 *   sid: session ID.
 *   env: (output) environment string.
 *
 * note: this does NOT set up the session. caller needs to use the
 *       explicit session setup/teardown functions as needed.
 */
UnionfsCstore::UnionfsCstore(const string& sid, string& env, bool use_edit_lvl)
  : Cstore(env)
{
  tmpl_root = C_DEF_TMPL_ROOT;
  tmpl_path = tmpl_root;
  active_root = C_DEF_ACTIVE_ROOT;
  work_root = (C_DEF_WORK_PREFIX + sid);
  change_root = (C_DEF_CHANGE_PREFIX + sid);
  tmp_root = (C_DEF_TMP_PREFIX + sid);
  init_commit_data();

  string declr = " declare -x -r "; // readonly vars
  env += " umask 002; {";
  env += (declr + C_ENV_ACTIVE_ROOT + "=" + active_root.path_cstr());
  env += (declr + C_ENV_CHANGE_ROOT + "=" + change_root.path_cstr() + ";");
  env += (declr + C_ENV_WORK_ROOT + "=" + work_root.path_cstr() + ";");
  env += (declr + C_ENV_TMP_ROOT + "=" + tmp_root.path_cstr() + ";");
  env += (declr + C_ENV_TMPL_ROOT + "=" + tmpl_root.path_cstr() + ";");
  env += " } >&/dev/null || true";

  // set up path strings using level vars
  char *val;
  mutable_cfg_path = "/";
  if (use_edit_lvl) {
    if ((val = getenv(C_ENV_EDIT_LEVEL.c_str()))) {
      mutable_cfg_path = val;
    }
    if ((val = getenv(C_ENV_TMPL_LEVEL.c_str())) && val[0] && val[1]) {
      // see comment in the other constructor
      FsPath tlvl(val);
      tmpl_path /= tlvl;
    }
  }
  orig_mutable_cfg_path = mutable_cfg_path;
  orig_tmpl_path = tmpl_path;
  _init_fs_escape_chars();
  path_present_cache_enabled = false;
}

UnionfsCstore::~UnionfsCstore()
{
}


////// public virtual functions declared in base class
void
UnionfsCstore::enableCacheMode()
{
  path_present_cache.clear();
  path_present_cache_enabled = true;
}

void
UnionfsCstore::disableCacheMode()
{
  path_present_cache.clear();
  path_present_cache_enabled = false;
}

bool
UnionfsCstore::markSessionUnsaved()
{
  FsPath marker = work_root;
  marker.push(C_MARKER_UNSAVED);
  if (!_create_file(marker.path_cstr())) {
    output_internal("failed to mark unsaved [%s]\n", marker.path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::unmarkSessionUnsaved()
{
  FsPath marker = work_root;
  marker.push(C_MARKER_UNSAVED);
  // if not marked then treat as success.
  if (unlink(marker.path_cstr()) == -1 && errno != ENOENT) {
    output_internal("failed to unmark unsaved [%s]\n", marker.path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::sessionUnsaved()
{
  FsPath marker = work_root;
  marker.push(C_MARKER_UNSAVED);
  return path_exists(marker);
}

bool
UnionfsCstore::sessionChanged()
{
  FsPath marker = work_root;
  marker.push(C_MARKER_CHANGED);
  return path_exists(marker);
}

/* set up the session associated with this object.
 * the session comes from either the environment or the session ID
 * (see the two different constructors).
 */
bool
UnionfsCstore::setupSession()
{
  struct stat status;
  if (!path_exists(work_root, &status)) {
    // session doesn't exist. create dirs.
    try {
      b_fs::create_directories(work_root.path_cstr());
      b_fs::create_directories(change_root.path_cstr());
      b_fs::create_directories(tmp_root.path_cstr());
      if (!path_exists(active_root)) {
        // this should only be needed on boot
        b_fs::create_directories(active_root.path_cstr());
      }
    } catch (...) {
      output_internal("setup session failed to create session directories\n");
      return false;
    }

    // union mount
    if (!do_mount(change_root, active_root, work_root)) {
      return false;
    }
  } else if (!path_is_directory(&status)) {
    output_internal("setup session not dir [%s]\n",
                    work_root.path_cstr());
    return false;
  }
  return true;
}

/* tear down the session associated with this object.
 * the session comes from either the environment or the session ID
 * (see the two different constructors).
 */
bool
UnionfsCstore::teardownSession()
{
  // check if session exists
  string wstr = work_root.path_cstr();
  if (!inSession()) {
    // no session
    output_internal("teardown invalid session [%s]\n", wstr.c_str());
    return false;
  }

  // unmount the work root (union)
  if (!do_umount(work_root)) {
    return false;
  }

  // remove session directories
  bool ret = false;
  try {
    if (b_fs::remove_all(work_root.path_cstr()) != 0
        && b_fs::remove_all(change_root.path_cstr()) != 0
        && b_fs::remove_all(tmp_root.path_cstr()) != 0) {
      ret = true;
    }
  } catch (const b_fs::filesystem_error& e) {
    output_internal("failed %s\n", e.what());
  } catch (...) {
  }
  if (!ret) {
    output_internal("failed to remove session directories\n");
  }
  return ret;
}

/* whether an actual config session is associated with this object.
 * the session comes from either the environment or the session ID
 * (see the two different constructors).
 */
bool
UnionfsCstore::inSession()
{
  string wstr = work_root.path_cstr();
  return (!wstr.empty() && wstr.find(C_DEF_WORK_PREFIX) == 0
          && path_is_directory(work_root));
}

bool
UnionfsCstore::clearCommittedMarkers()
{
  if (unlink(commit_marker_file.path_cstr()) == -1) {
    output_internal("failed to clear committed markers\n");
    return false;
  }
  return true;
}

bool
UnionfsCstore::construct_commit_active(commit::PrioNode& node)
{
  auto_ptr<SavePaths> save(create_save_paths());
  reset_paths();
  append_cfg_path(node.getCommitPath());

  FsPath ap(get_active_path());
  FsPath wp(get_work_path());
  FsPath tap(tmp_active_root);
  tap /= mutable_cfg_path;

  if (path_exists(tap)) {
    output_internal("rm[%s]\n", tap.path_cstr());
    if (b_fs::remove_all(tap.path_cstr()) < 1) {
      output_internal("rm ta failed\n");
      return false;
    }
    cnode::CfgNode *c = node.getCfgNode();
    if (c && c->isTag()) {
      FsPath p(tap);
      p.pop();
      if (isEmptyDir(p.path_cstr())) {
        output_internal("rm[%s]\n", p.path_cstr());
        if (b_fs::remove_all(p.path_cstr()) < 1) {
          output_internal("rm tag failed\n");
          return false;
        }
      }
    }
  } else {
    output_internal("no tap[%s]\n", tap.path_cstr());
  }
  if (node.succeeded()) {
    // prio subtree succeeded
    if (path_exists(wp)) {
      output_internal("cp[%s]->[%s]\n", wp.path_cstr(), tap.path_cstr());
      try {
        recursive_copy_dir(wp, tap, true);
      } catch (const b_fs::filesystem_error& e) {
        output_internal("cp w->ta failed[%s]\n", e.what());
        return false;
      } catch (...) {
        output_internal("cp w->ta failed[unknown exception]\n");
        return false;
      }
    } else {
      output_internal("no wp[%s]\n", wp.path_cstr());
    }
    if (!node.hasSubtreeFailure()) {
      // whole subtree succeeded => stop recursion
      return true;
    }
    // failure present in subtree
  } else {
    // prio subtree failed
    if (path_exists(ap)) {
      output_internal("cp[%s]->[%s]\n", ap.path_cstr(), tap.path_cstr());
      try {
        recursive_copy_dir(ap, tap, false);
      } catch (const b_fs::filesystem_error& e) {
        output_internal("cp a->ta failed[%s]\n", e.what());
        return false;
      } catch (...) {
        output_internal("cp a->ta failed[unknown exception]\n");
        return false;
      }
    } else {
      output_internal("no ap[%s]\n", ap.path_cstr());
    }
    if (!node.hasSubtreeSuccess()) {
      // whole subtree failed => stop recursion
      return true;
    }
    // success present in subtree
  }
  for (size_t i = 0; i < node.numChildNodes(); i++) {
    if (!construct_commit_active(*(node.childAt(i)))) {
      return false;
    }
  }
  return true;
}

bool
UnionfsCstore::mark_dir_changed(const FsPath& d, const FsPath& root)
{
  FsPath marker(d);
  while (marker.size() >= root.size()) {
    marker.push(C_MARKER_CHANGED);
    if (path_exists(marker)) {
      // reached a node already marked => done
      break;
    }
    if (!_create_file(marker.path_cstr())) {
      output_internal("failed to mark changed [%s]\n", marker.path_cstr());
      return false;
    }
    marker.pop();
    marker.pop();
  }
  return true;
}

bool
UnionfsCstore::sync_dir(const FsPath& src, const FsPath& dst,
                        const FsPath& root)
{
  bool parent_marked = false;
  MapT<string, bool> smap;
  MapT<string, bool> dmap;
  vector<string> sentries;
  vector<string> dentries;
  check_dir_entries(src, sentries, false);
  check_dir_entries(dst, dentries, false);
  for (size_t i = 0; i < sentries.size(); i++) {
    smap[sentries[i]] = true;
  }
  for (size_t i = 0; i < dentries.size(); i++) {
    dmap[dentries[i]] = true;
    if (smap.find(dentries[i]) == smap.end()) {
      // entry in dst but not in src => delete
      if (!parent_marked && !mark_dir_changed(dst, root)) {
        return false;
      }
      parent_marked = true;
      FsPath d(dst);
      push_path(d, dentries[i]);
      if (b_fs::remove_all(d.path_cstr()) < 1) {
        return false;
      }
    } else {
      // entry in both src and dst
      FsPath s(src);
      FsPath d(dst);
      push_path(s, dentries[i]);
      push_path(d, dentries[i]);

      struct stat sts, std;
      if (!path_status(s, &sts) || !path_status(d, &std)) {
        // something is wrong
        output_user("inconsistent config entry [%s][%s]\n",
                    s.path_cstr(), d.path_cstr());
        return false;
      } else if (path_is_regular(&sts) && path_is_regular(&std)) {
        // it's file => compare and replace if necessary
        bool different = false;
        if (!compare_files(s, d, different, &sts, &std)) {
          // error
          output_user("failed to replace file [%s][%s]\n",
                      s.path_cstr(), d.path_cstr());
          return false;
        }
        if (different) {
          // need to replace
          try {
            b_fs::copy_file(s.path_cstr(), d.path_cstr(),
                            b_fs::copy_option::overwrite_if_exists);
          } catch (...) {
            output_user("copy failed [%s][%s]\n", s.path_cstr(), d.path_cstr());
            return false;
          }
          if (!parent_marked && !mark_dir_changed(dst, root)) {
            return false;
          }
          parent_marked = true;
        }
      } else if (path_is_directory(&sts) && path_is_directory(&std)) {
        // it's dir => recurse
        if (!sync_dir(s, d, root)) {
          return false;
        }
      } else {
        // something is wrong
        output_user("inconsistent config entry [%s][%s]\n",
                    s.path_cstr(), d.path_cstr());
        return false;
      }
    }
  }
  for (size_t i = 0; i < sentries.size(); i++) {
    if (dmap.find(sentries[i]) == dmap.end()) {
      // entry in src but not in dst => copy
      FsPath s(src);
      FsPath d(dst);
      push_path(s, sentries[i]);
      push_path(d, sentries[i]);
      try {
        if (path_is_regular(s)) {
          // it's file
          b_fs::copy_file(s.path_cstr(), d.path_cstr());
        } else {
          // dir
          recursive_copy_dir(s, d, true);
        }
        if (!parent_marked && !mark_dir_changed(dst, root)) {
          return false;
        }
        parent_marked = true;
      } catch (...) {
        output_user("copy failed [%s][%s]\n", s.path_cstr(), d.path_cstr());
        return false;
      }
    }
  }

  return true;
}

bool
UnionfsCstore::commit_full_config()
{
  if (!do_umount(work_root)) {
    return false;
  }
  try {
    output_internal("mv[%s]->[%s]\n", change_root.path_cstr(),
                    active_root.path_cstr());
    recursive_move_unionfs_dir(change_root, active_root);
  } catch (const b_fs::filesystem_error& e) {
    output_internal("cp work->new active failed[%s]\n", e.what());
    return false;
  } catch (...) {
    output_internal("cp work->new active failed[unknown exception]\n");
    return false;
  }
  if (!remove_dir_content(change_root.path_cstr())) {
    output_internal("failed to remove [%s] content\n",
                    change_root.path_cstr());
    return false;
  }
  if (!do_mount(change_root, active_root, work_root)) {
    return false;
  }
  // all done
  return true;
}

bool
UnionfsCstore::commit_node_config(commit::PrioNode& node)
{
  // make a copy of current "work" dir
  try {
    if (path_exists(tmp_work_root)) {
      output_internal("rm[%s]\n", tmp_work_root.path_cstr());
      if (b_fs::remove_all(tmp_work_root.path_cstr()) < 1) {
        output_internal("rm tw failed\n");
        return false;
      }
    }
    output_internal("cp[%s]->[%s]\n", work_root.path_cstr(),
                    tmp_work_root.path_cstr());
    recursive_copy_dir(work_root, tmp_work_root, true);
  } catch (const b_fs::filesystem_error& e) {
    output_internal("cp w->tw failed[%s]\n", e.what());
    return false;
  } catch (...) {
    output_internal("cp w->tw failed[unknown exception]\n");
    return false;
  }

  if (!construct_commit_active(node)) {
    return false;
  }

  if (!do_umount(work_root)) {
    return false;
  }
  try {
    if (b_fs::remove_all(change_root.path_cstr()) < 1) {
      output_internal("failed to remove [%s]\n", change_root.path_cstr());
      return false;
    }
  } catch (const b_fs::filesystem_error& e) {
    output_internal("failed to remove [%s]: %s\n", change_root.path_cstr(), e.what());
    return false;
  } catch (...) {
    output_internal("failed to remove [%s]\n", change_root.path_cstr());
    return false;
  }
  /* note: unionfs can't cope with whole directory being removed, so just
   * remove the content.
   */
  if (!remove_dir_content(active_root.path_cstr())) {
    output_internal("failed to remove [%s] content\n",
                    active_root.path_cstr());
    return false;
  }
  try {
    b_fs::create_directories(change_root.path_cstr());
    recursive_copy_dir(tmp_active_root, active_root, true);
  } catch (const b_fs::filesystem_error& e) {
    output_internal("cp ta->a failed[%s]\n", e.what());
    return false;
  } catch (...) {
    output_internal("cp ta->a failed[unknown exception]\n");
    return false;
  }
  if (!do_mount(change_root, active_root, work_root)) {
    return false;
  }
  try {
    if (!sync_dir(tmp_work_root, work_root, work_root)) {
      return false;
    }
    if (b_fs::remove_all(tmp_work_root.path_cstr()) < 1
       || b_fs::remove_all(tmp_active_root.path_cstr()) < 1) {
      output_user("failed to remove temp directories\n");
      return false;
    }
  } catch (const std::exception& e) {
    output_internal("cp tw->w: %s\n", e.what());
    return false;
  } catch (...) {
    output_internal("cp tw->w: failed\n");
    return false;
  }
  // all done
  return true;
}

bool
UnionfsCstore::commitConfig(commit::PrioNode& node)
{
  if (node.getCfgNode()->getName().empty()) {
    if (node.succeeded() && !node.hasSubtreeFailure()) {
      return commit_full_config();
    }
  }
  return commit_node_config(node);
}

UnionfsCstore::UnionfsCommitLock::UnionfsCommitLock()
    : _locked(false), _lfd(-1)
{
  _lfd = creat(C_COMMIT_LOCK_FILE.c_str(), 0777);
  if (_lfd < 0) {
    // should not happen (all commit processes should have write access)
    output_internal("CommitLock failed to open lock file\n");
    return;
  }
  if (lockf(_lfd, F_TLOCK, 0) < 0) {
    // locked by someone else
    output_internal("CommitLock failed to get lock\n");
    return;
  }

  const char *sid = getenv("COMMIT_SESSION_ID");
  if (!sid) {
    output_internal("CommitLock failed to get session ID\n");
    return;
  }

  int fd = creat(C_COMMIT_SID_FILE.c_str(), 0777);
  if (fd < 0) {
    output_internal("CommitLock failed to open sid file\n");
    return;
  }

  write(fd, sid, strlen(sid));
  fsync(fd);
  close(fd);
  _locked = true;
}

UnionfsCstore::UnionfsCommitLock::~UnionfsCommitLock()
{
  if (_locked) {
    int fd = creat(C_COMMIT_END_FILE.c_str(), 0777);
    if (fd < 0) {
      output_internal("CommitLock failed to open end file\n");
    } else {
      close(fd);
    }
  }
  if (_lfd >= 0) {
    lockf(_lfd, F_ULOCK, 0);
    close(_lfd);
  }
}

bool
UnionfsCstore::UnionfsCommitLock::locked()
{
  return _locked;
}

tr1::shared_ptr<Cstore::CommitLock>
UnionfsCstore::getCommitLock()
{
  return tr1::shared_ptr<CommitLock>(new UnionfsCommitLock());
}


////// virtual functions defined in base class
/* check if current tmpl_path is a valid tmpl dir.
 * return true if valid. otherwise return false.
 */
typedef struct {
  mode_t                    mode;
  tr1::shared_ptr<vtw_def>  def;
} TmplCacheT;

typedef MapT<FsPath, tr1::shared_ptr<TmplCacheT>, FsPathHash> ParsedTmplCacheT;
static ParsedTmplCacheT _parsed_tmpl_cache;

mode_t
UnionfsCstore::_tmpl_path(const FsPath& path)
{
  ParsedTmplCacheT::iterator p = _parsed_tmpl_cache.find(path);
  if (p != _parsed_tmpl_cache.end()) {
    // found in cache
    return p->second->mode;
  } else {
    struct stat st;
    tr1::shared_ptr<TmplCacheT> tmpl_item(new TmplCacheT);
    TmplCacheT *item = tmpl_item.get();
    if (item) {
      if (path_status(path, &st)) {
        item->mode = st.st_mode;
      } else {
        item->mode = 0;
      }
      _parsed_tmpl_cache[path] = tmpl_item;
      return item->mode;
    }
  }
  return 0;
}

bool
UnionfsCstore::_tmpl_file_exists(const FsPath& path)
{
  return S_ISREG(_tmpl_path(path));
}

bool
UnionfsCstore::_tmpl_node_exists(const FsPath& path)
{
  return S_ISDIR(_tmpl_path(path));
}

bool
UnionfsCstore::tmpl_node_exists(void)
{
  return S_ISDIR(_tmpl_path(tmpl_path));
}

/* parse template at current tmpl_path and return an allocated Ctemplate
 * pointer if successful. otherwise return 0.
 */
Ctemplate *
UnionfsCstore::tmpl_parse()
{
  FsPath tp = tmpl_path;
  tp.push(C_DEF_NAME);

  ParsedTmplCacheT::iterator p = _parsed_tmpl_cache.find(tp);
  if (p != _parsed_tmpl_cache.end()) {
    // found in cache
    if (!p->second->mode || S_ISDIR(p->second->mode)) {
      // does not exists or node
      return 0;
    }
    if (p->second->def) {
      // has been parsed earlier
      return (new Ctemplate(p->second->def));
    }
    // new template => parse
    tr1::shared_ptr<vtw_def> def(new vtw_def);
    vtw_def *_def = def.get();
    if (_def && parse_def(_def, tp.path_cstr(), 0) == 0) {
      p->second->def = def;
      return (new Ctemplate(def));
    }
    return 0;
  }

  Ctemplate* ctmpl = 0;
  tr1::shared_ptr<TmplCacheT> tmpl_item(new TmplCacheT);
  TmplCacheT *item = tmpl_item.get();
  if (item) {
    struct stat st;
    if (!path_status(tp, &st)) {
      item->mode = 0;
    } else {
      item->mode = st.st_mode;
      // new template => parse
      tr1::shared_ptr<vtw_def> def(new vtw_def);
      vtw_def *_def = def.get();
      if (_def && parse_def(_def, tp.path_cstr(), 0) == 0) {
        item->def = def;
        ctmpl = new Ctemplate(def);
      }
    }
    _parsed_tmpl_cache[tp] = tmpl_item;
  }
  return ctmpl;
}

bool
UnionfsCstore::check_cached_path(const FsPath& path, mode_t& mode)
{
  mode = 0;
  if (path_present_cache_enabled) {
    PathPresentCacheT::iterator p = path_present_cache.find(path);
    if (p != path_present_cache.end()) {
      // found in cache
      mode = p->second;
    } else {
      struct stat st;
      if (path_status(path, &st)) {
        mode = st.st_mode;
      }
      path_present_cache[path] = mode;
    }
    return true;
  }
  return false;
}

bool
UnionfsCstore::cfg_node_exists(bool active_cfg)
{
  FsPath p = (active_cfg ? get_active_path() : get_work_path());
  mode_t mode;
  if (check_cached_path(p, mode)) {
    return S_ISDIR(mode);
  }
  return path_is_directory(p);
}

bool
UnionfsCstore::add_node()
{
  bool ret = true;
  try {
    if (!b_fs::create_directory(get_work_path().path_cstr())) {
      // already exists. shouldn't call this function.
      ret = false;
    }
  } catch (...) {
    ret = false;
  }
  if (!ret) {
    output_internal("failed to add node [%s]\n",
                    get_work_path().path_cstr());
  }
  return ret;
}

bool
UnionfsCstore::remove_node()
{
  if (!path_is_directory(get_work_path())) {
    output_internal("remove non-existent node [%s]\n",
                    get_work_path().path_cstr());
    return false;
  }
  bool ret = false;
  try {
    if (b_fs::remove_all(get_work_path().path_cstr()) != 0) {
      ret = true;
    }
  } catch (...) {
    ret = false;
  }
  if (!ret) {
    output_internal("failed to remove node [%s]\n",
                    get_work_path().path_cstr());
  }
  return ret;
}

bool
UnionfsCstore::markCfgPathCommitted(const CstoreCPathListT& clist)
{
  string buf;
  for (size_t i = 0; i < clist.size(); i ++) {
    Cpath path_comps(*(clist[i].second.get()));
    auto_ptr<SavePaths> save(create_save_paths());
    append_cfg_path(path_comps);

    string marker;
    get_committed_marker(clist[i].first, marker);

    buf.append(marker);
    buf.append("\n");
  }
  return _write_file(commit_marker_file.path_cstr(), buf, true);
}

void
UnionfsCstore::get_all_child_node_names_impl(vector<string>& cnodes,
                                             bool active_cfg)
{
  FsPath p = (active_cfg ? get_active_path() : get_work_path());
  get_all_child_dir_names(p, cnodes);

  /* XXX special cases to emulate original perl API behavior.
   *     original perl listNodes() and listOrigNodes() return everything
   *     under a node (except for ".*"), including "node.val" and "def".
   *
   *     perl API should operate at abstract level and should not access
   *     such implementation-specific details. however, currently
   *     things like config output depend on this behavior, so this
   *     function needs to return them for now.
   *
   *     use a whilelist-approach, i.e., only add the following:
   *       node.val
   *       def
   *
   * FIXED: perl scripts have been changed to eliminate the use of "def"
   * and "node.val", so they no longer need to be returned.
   */
}

void
UnionfsCstore::get_all_child_item_names_impl(vector<string>& cnodes,
                                             vector<string>& cmarkers,
                                             const bool active_cfg)
{
  FsPath root = (active_cfg ? get_active_path() : get_work_path());

  struct stat st;
  try {
    b_fs::directory_iterator di(root.path_cstr());
    for (; di != b_fs::directory_iterator(); ++ di) {
      string cname = di->path().filename().string();
      if (cname == C_MARKER_CHANGED) {
        continue;
      }
      if (!path_status(di->path().string(), &st)) {
        continue;
      }
      if (path_is_directory(&st)) {
        if (cname.length() < 1 || cname[0] == '.') {
          continue;
        }
        cnodes.push_back(_unescape_path_name(cname));
      } else if (path_is_regular(&st)) {
        cmarkers.push_back(_unescape_path_name(cname));
      }
    }
  } catch (...) {
    // skip the rest
  }
}

/*
 * mnodes - list of modified items
 * dnodes - list of deleted items
 * content_changed - true if files in directory have been modified/added/deleted
 * content_opaque - true if list of modified items contains all
 *                  currently existing items
 */
void
UnionfsCstore::get_changed_items(vector<string>& mnodes,
                                 vector<string>& dnodes,
                                 bool& content_changed,
                                 bool& content_opaque)
{
  FsPath root = get_change_path();
  content_changed = false;

  struct stat st;
  try {
    b_fs::directory_iterator di(root.path_cstr());
    for (; di != b_fs::directory_iterator(); ++ di) {
      string cname = di->path().filename().string();
      if (cname == C_MARKER_CHANGED ||
          cname == C_MARKER_UNSAVED) {
        continue;
      }
      if (cname == C_WHITEOUT_OPAQUE) {
        content_opaque = true;
        content_changed = true;
        continue;
      }
      if (!path_status(di->path().string(), &st)) {
        continue;
      }
      if (path_is_directory(&st)) {
        if (cname.length() < 1 || cname[0] == '.') {
          continue;
        }
        mnodes.push_back(_unescape_path_name(cname));
      } else if (path_is_regular(&st)) {
        if (cname.substr(0, C_WHITEOUT_PREFIX.length()) == C_WHITEOUT_PREFIX) {
          string nname =
            cname.substr(C_WHITEOUT_PREFIX.length(), cname.length());
          dnodes.push_back(_unescape_path_name(nname));
          // this code is a bit wrong as it does not distinguish between
          // deleted directories and files
        }
        content_changed = true;
      }
    }
  } catch (...) {
    // skip the rest
  }
}

bool
UnionfsCstore::read_value_vec(vector<string>& vvec, bool active_cfg)
{
  FsPath vpath = (active_cfg ? get_active_path() : get_work_path());
  vpath.push(C_VAL_NAME);

  string ostr;
  if (!read_whole_file(vpath, ostr)) {
    return false;
  }

  /* XXX original implementation used to remove a trailing '\n' after
   *     a read. it was only necessary because it was adding a '\n' when
   *     writing the file. don't remove anything now since we shouldn't
   *     be writing it any more.
   */
  // separate values using newline as delimiter
  size_t start_idx = 0, idx = 0;
  for (; idx < ostr.size(); idx++) {
    if (ostr[idx] == '\n') {
      // got a value
      vvec.push_back(ostr.substr(start_idx, (idx - start_idx)));
      start_idx = idx + 1;
    }
  }
  if (start_idx < ostr.size()) {
    vvec.push_back(ostr.substr(start_idx, (idx - start_idx)));
  } else {
    // last char is a newline => another empty value
    vvec.push_back("");
  }
  return true;
}

bool
UnionfsCstore::write_value_vec(const vector<string>& vvec, bool active_cfg)
{
  FsPath wp = (active_cfg ? get_active_path() : get_work_path());
  wp.push(C_VAL_NAME);

  string ostr = "";
  for (size_t i = 0; i < vvec.size(); i++) {
    if (i > 0) {
      // subsequent values require delimiter
      ostr += '\n';
    }
    ostr += vvec[i];
  }

  if (!write_file(wp, ostr)) {
    output_internal("failed to write node value (write) [%s]\n",
                    wp.path_cstr());
    return false;
  }

  return true;
}

bool
UnionfsCstore::update_value_vec()
{
  FsPath wp = get_work_path();
  wp.push(C_VAL_NAME);
  if (utimes(wp.path_cstr(), NULL)) {
    int err = errno;
    output_internal("update_value_vec [%s]: %s\n",
                    wp.path_cstr(), strerror(err));
    return false;
  }
  return true;
}

bool
UnionfsCstore::val_exists(const vector<string>& cmarkers)
{
  if (find(cmarkers.begin(), cmarkers.end(), C_VAL_NAME) !=
    cmarkers.end()) {
    return true;
  }
  return false;
}

bool
UnionfsCstore::rename_child_node(const char *oname, const char *nname)
{
  FsPath opath = get_work_path();
  opath.push(oname);
  FsPath npath = get_work_path();
  npath.push(nname);
  if (!path_is_directory(opath)
      || path_exists(npath)) {
    output_internal("cannot rename node [%s,%s,%s]\n",
                    get_work_path().path_cstr(), oname, nname);
    return false;
  }
  bool ret = true;
  try {
    /* somehow b_fs::rename() can't be used here as it considers the operation
     * "Invalid cross-device link" and fails with an exception, probably due
     * to unionfs in some way.
     * do it the hard way.
     */
    recursive_copy_dir(opath, npath);
    if (b_fs::remove_all(opath.path_cstr()) == 0) {
      ret = false;
    }
  } catch (...) {
    ret = false;
  }
  if (!ret) {
    output_internal("failed to rename node [%s,%s]\n", opath.path_cstr(),
                    npath.path_cstr());
  }
  return ret;
}

bool
UnionfsCstore::copy_child_node(const char *oname, const char *nname)
{
  FsPath opath = get_work_path();
  opath.push(oname);
  FsPath npath = get_work_path();
  npath.push(nname);
  if (!path_is_directory(opath)
      || path_exists(npath)) {
    output_internal("cannot copy node [%s,%s,%s]\n",
                    get_work_path().path_cstr(), oname, nname);
    return false;
  }
  try {
    recursive_copy_dir(opath, npath);
  } catch (...) {
    output_internal("failed to copy node [%s,%s,%s]\n",
                    get_work_path().path_cstr(), oname, nname);
    return false;
  }
  return true;
}

bool
UnionfsCstore::mark_display_default()
{
  FsPath marker = get_work_path();
  marker.push(C_MARKER_DEF_VALUE);
  if (!_create_file(marker.path_cstr())) {
    output_internal("failed to mark default [%s]\n",
                    get_work_path().path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::unmark_display_default(bool& exists)
{
  exists = false;
  FsPath marker = get_work_path();
  marker.push(C_MARKER_DEF_VALUE);
  // if not marked then treat as success.
  if (unlink(marker.path_cstr())) {
    int err = errno;
    if (err != ENOENT) {
      output_internal("unmark default [%s]: %s\n",
                      marker.path_cstr(), strerror(err));
      exists = true;
      return false;
    }
  }
  exists = true;
  return true;
}

bool
UnionfsCstore::marked_display_default(bool active_cfg)
{
  FsPath marker = (active_cfg ? get_active_path() : get_work_path());
  marker.push(C_MARKER_DEF_VALUE);
  return path_exists(marker);
}

bool
UnionfsCstore::marked_display_default(const vector<string>& cmarkers)
{
  if (find(cmarkers.begin(), cmarkers.end(), C_MARKER_DEF_VALUE) !=
      cmarkers.end()) {
    return true;
  }
  return false;
}

bool
UnionfsCstore::marked_deactivated(bool active_cfg)
{
  FsPath marker = (active_cfg ? get_active_path() : get_work_path());
  marker.push(C_MARKER_DEACTIVATE);
  mode_t mode;
  if (check_cached_path(marker, mode)) {
    return S_ISREG(mode);
  }
  return path_exists(marker);
}

bool
UnionfsCstore::marked_deactivated(const vector<string>& cmarkers)
{
  if (find(cmarkers.begin(), cmarkers.end(), C_MARKER_DEACTIVATE) !=
      cmarkers.end()) {
    return true;
  }
  return false;
}

bool
UnionfsCstore::mark_deactivated()
{
  FsPath marker = get_work_path();
  marker.push(C_MARKER_DEACTIVATE);
  if (!_create_file(marker.path_cstr())) {
    output_internal("failed to mark deactivated [%s]\n",
                    get_work_path().path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::unmark_deactivated()
{
  FsPath marker = get_work_path();
  marker.push(C_MARKER_DEACTIVATE);
  // if not deactivated then treat as success.
  if (unlink(marker.path_cstr()) == -1 && errno != ENOENT) {
    output_internal("failed to unmark deactivated [%s]\n",
                    get_work_path().path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::unmark_deactivated_descendants()
{
  bool ret = false;
  do {
    // sanity check
    if (!path_is_directory(get_work_path())) {
      break;
    }

    try {
      vector<string> markers;
      b_fs::recursive_directory_iterator di(get_work_path().path_cstr());
      for (; di != b_fs::recursive_directory_iterator(); ++di) {
        if (di->path().filename() != C_MARKER_DEACTIVATE
            || !path_is_regular(di->path().string())) {
          // not marker
          continue;
        }
        const char *ppath = di->path().parent_path().string().c_str();
        if (strcmp(ppath, get_work_path().path_cstr()) == 0) {
          // don't unmark the node itself
          continue;
        }
        markers.push_back(di->path().string());
      }
      for (size_t i = 0; i < markers.size(); i++) {
        unlink(markers[i].c_str());
      }
    } catch (...) {
      break;
    }
    ret = true;
  } while (0);
  if (!ret) {
    output_internal("failed to unmark deactivated descendants [%s]\n",
                    get_work_path().path_cstr());
  }
  return ret;
}

// mark current work path as "changed"
bool
UnionfsCstore::mark_changed(const bool node_exists)
{
  FsPath marker = work_root;
  if (mutable_cfg_path.has_parent_path()) {
    marker /= mutable_cfg_path;
  }
  marker.push(C_MARKER_CHANGED);

  // creates parent dir if it is not clear whether node exists
  if (!node_exists) {
    if (!create_file(marker)) {
      output_internal("failed to mark changed [%s]\n", marker.path_cstr());
      return false;
    }
  } else {
    if (!_create_file(marker.path_cstr())) {
      output_internal("failed to mark changed [%s]\n", marker.path_cstr());
      return false;
    }
  }
  return true;
}

// mark current work path and all ancestors as "changed"
bool
UnionfsCstore::mark_changed_with_ancestors(const bool node_exists)
{
  bool first = !node_exists;
  FsPath opath = mutable_cfg_path; // use a copy
  bool done = false;
  while (!done) {
    FsPath marker = work_root;
    if (opath.has_parent_path()) {
      marker /= opath;
      pop_path(opath);
    } else {
      done = true;
    }
    // check only the last directory, all other exist if the last one present
    if (first && !path_is_directory(marker)) {
      // don't do anything if the node is not there
      continue;
    }
    first = false;
    marker.push(C_MARKER_CHANGED);
    if (!_create_excl_file(marker)) {
      // reached a node already marked => done
      break;
    }
  }
  return true;
}

/* remove all "changed" markers under the current work path. this is used,
 * e.g., at the end of "commit" to reset a subtree.
 */
bool
UnionfsCstore::unmark_changed_with_descendants()
{
  try {
    vector<string> markers;
    b_fs::recursive_directory_iterator di(get_work_path().path_cstr());
    for (; di != b_fs::recursive_directory_iterator(); ++di) {
      if (di->path().filename() != C_MARKER_CHANGED
          || !path_is_regular(di->path().string())) {
        // not marker
        continue;
      }
      markers.push_back(di->path().string());
    }
    for (size_t i = 0; i < markers.size(); i++) {
      unlink(markers[i].c_str());
    }
  } catch (...) {
    output_internal("failed to unmark changed with descendants [%s]\n",
                    get_work_path().path_cstr());
    return false;
  }
  return true;
}

// remove the comment at the current work path
bool
UnionfsCstore::remove_comment()
{
  FsPath cfile = get_work_path();
  cfile.push(C_COMMENT_FILE);
  if (unlink(cfile.path_cstr()) == -1) {
    output_internal("failed to remove comment [%s]\n", cfile.path_cstr());
    return false;
  }
  return true;
}

// set comment at the current work path
bool
UnionfsCstore::set_comment(const string& comment)
{
  FsPath cfile = get_work_path();
  cfile.push(C_COMMENT_FILE);
  return write_file(cfile, comment);
}

// discard all changes in working config
bool
UnionfsCstore::discard_changes(unsigned long long& num_removed)
{
  // need to keep unsaved marker
  bool unsaved = sessionUnsaved();
  bool ret = true;

  vector<string> files;
  vector<b_fs::path> directories;

  if (!do_umount(work_root)) {
    return false;
  }
  try {
    // iterate through all entries in change root
    b_fs::directory_iterator di(change_root.path_cstr());
    for (; di != b_fs::directory_iterator(); ++di) {
      if (path_is_directory(di->path().string())) {
        directories.push_back(di->path());
      } else {
        files.push_back(di->path().string());
      }
    }

    // remove and count
    num_removed = 0;
    for (size_t i = 0; i < files.size(); i++) {
      b_fs::remove(files[i]);
      num_removed ++;
    }
    for (size_t i = 0; i < directories.size(); i++) {
      num_removed += b_fs::remove_all(directories[i]);
    }
  } catch (...) {
    output_internal("discard failed [%s]\n", change_root.path_cstr());
    ret = false;
  }

  if (!do_mount(change_root, active_root, work_root)) {
    return false;
  }
  if (unsaved) {
    // restore unsaved marker
    num_removed--;
    markSessionUnsaved();
  }
  return ret;
}

// get comment at the current work or active path
bool
UnionfsCstore::get_comment(string& comment, bool active_cfg)
{
  FsPath cfile = (active_cfg ? get_active_path() : get_work_path());
  cfile.push(C_COMMENT_FILE);
  return read_whole_file(cfile, comment);
}

bool
UnionfsCstore::comment_exists(const vector<string>& cmarkers)
{
  if (find(cmarkers.begin(), cmarkers.end(), C_COMMENT_FILE) !=
    cmarkers.end()) {
    return true;
  }
  return false;
}

// whether current work path is "changed"
bool
UnionfsCstore::cfg_node_changed()
{
  FsPath marker = get_work_path();
  marker.push(C_MARKER_CHANGED);
  return path_exists(marker);
}

void
UnionfsCstore::get_edit_level(Cpath& pcomps) {
  FsPath opath = mutable_cfg_path; // use a copy
  vector<string> tmp;
  while (opath.has_parent_path()) {
    string last;
    pop_path(opath, last);
    tmp.push_back(last);
  }
  while (tmp.size() > 0) {
    pcomps.push(tmp.back());
    tmp.pop_back();
  }
}

bool
UnionfsCstore::marked_committed(bool is_delete)
{
  string marker;
  get_committed_marker(is_delete, marker);
  return find_line_in_file(commit_marker_file, marker);
}

bool
UnionfsCstore::mark_committed(bool is_delete)
{
  string marker;
  get_committed_marker(is_delete, marker);
  // write one marker per line
  return write_file(commit_marker_file, marker + "\n", true);
}

string
UnionfsCstore::cfg_path_to_str() {
  string cpath = mutable_cfg_path.path_cstr();
  if (cpath.length() == 0) {
    cpath = "/";
  }
  return cpath;
}

string
UnionfsCstore::tmpl_path_to_str() {
  // return only the mutable part
  string tpath = tmpl_path.path_cstr();
  tpath.erase(0, tmpl_root.length());
  if (tpath.length() == 0) {
    tpath = "/";
  }
  return tpath;
}


////// private functions
void
UnionfsCstore::push_path(FsPath& old_path, const char *new_comp)
{
  string comp = _escape_path_name(new_comp);
  old_path.push(comp);
}

void
UnionfsCstore::push_path(FsPath& old_path, const string& new_comp)
{
  string comp = _escape_path_name(new_comp);
  old_path.push(comp);
}

void
UnionfsCstore::pop_path(FsPath& path)
{
  path.pop();
}

void
UnionfsCstore::pop_path(FsPath& path, string& last)
{
  path.pop(last);
  last = _unescape_path_name(last);
}

void
UnionfsCstore::get_all_tmpl_child_node_names(vector<string>& cnodes)
{
  bool exists;
  FsPath node = tmpl_path;

  try {
    b_fs::directory_iterator di(tmpl_path.path_cstr());
    for (; di != b_fs::directory_iterator(); ++ di) {
      string cname = di->path().filename().string();
      // name cannot start with "." or be node.def name
      if (cname.length() < 1 || cname[0] == '.' || cname == C_DEF_NAME) {
        continue;
      }
      // must be directory
      node.push(cname);
      exists = _tmpl_node_exists(node);
      node.pop();
      if (!exists) {
        continue;
      }
      // found one
      cnodes.push_back(_unescape_path_name(cname));
    }
  } catch (...) {
    // skip the rest
  }
}

bool
UnionfsCstore::check_dir_entries(const FsPath& root, vector<string>& cnodes,
                                 bool filter_nodes)
{
  try {
    b_fs::directory_iterator di(root.path_cstr());
    for (; di != b_fs::directory_iterator(); ++di) {
      string cname = di->path().filename().string();
      if (filter_nodes) {
        // dir name cannot start with "." or be node.val
        if (cname.length() < 1 || cname[0] == '.' || cname == C_VAL_NAME) {
          continue;
        }
        // must be directory
        if (!path_is_directory(di->path().string())) {
          continue;
        }
      }
      // found one
      cnodes.push_back(_unescape_path_name(cname));
    }
  } catch (...) {
    // skip the rest
  }
  return (cnodes.size() > 0);
}

bool
UnionfsCstore::isEmptyDir(const char *const dir)
{
  try {
    b_fs::directory_iterator di(dir);
    if (di == b_fs::directory_iterator())
      return true;
  } catch (...) {
  }
  return false;
}

bool
UnionfsCstore::getNumberSession(int& sessions)
{
  sessions = 0;
  FsPath path = work_root;
  path.pop();
  try {
    b_fs::directory_iterator di(path.path_cstr());
    for (; di != b_fs::directory_iterator(); ++di) {
      string prefix = "tmp_";
      string cname = di->path().filename().string();
      if (cname.substr(0, prefix.length()) == prefix) {
        sessions ++;
      }
    }
    return true;
  } catch (...) {
  }
  return false;
}

bool
UnionfsCstore::_write_file(const char *const file, const string& data,
                           const bool append)
{
  FILE *fp;
  bool result = false;

  if (append) {
    fp = fopen(file, "ab");
  } else {
    fp = fopen(file, "wb");
  }
  if (!fp) {
    output_internal("write_file failed [%s]\n", file);
    return false;
  }
  size_t size = data.size();
  if (fwrite(data.data(), 1, size, fp) != size) {
    output_internal("write_file failed [%s]\n", file);
  } else {
    result = true;
  }
  fclose(fp);
  return result;
}

bool
UnionfsCstore::write_file(const FsPath& file, const string& data,
                          const bool append)
{
  size_t size = data.size();
  if (size > C_UNIONFS_MAX_FILE_SIZE) {
    output_internal("write_file too large [%s]\n", file.path_cstr());
    return false;
  }
  FsPath ppath(file);
  ppath.pop();
  try {
    // make sure the path exists
    b_fs::create_directories(ppath.path_cstr());
  } catch (...) {
    return false;
  }
  return _write_file(file.path_cstr(), data, append);
}

bool
UnionfsCstore::_create_file(const char *const file)
{
  FILE *fp = fopen(file, "wb");
  if (!fp) {
    output_internal("create_file failed [%s]\n", file);
    return false;
  }
  fclose(fp);
  return true;
}

bool
UnionfsCstore::_create_excl_file(const FsPath& file)
{
  int fd = open(file.path_cstr(), O_WRONLY|O_CREAT|O_EXCL,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
  if (fd == -1) {
    if (EEXIST != errno) {
      output_internal("create_file failed [%s]\n", file.path_cstr());
    }
    return false;
  }
  close(fd);
  return true;
}

bool
UnionfsCstore::create_file(const FsPath& file)
{
  FsPath ppath(file);
  ppath.pop();

  try {
    // make sure the path exists
    b_fs::create_directories(ppath.path_cstr());
  } catch (...) {
    return false;
  }
  return _create_file(file.path_cstr());
}

bool
UnionfsCstore::read_whole_file(const FsPath& fpath, string& data, size_t size)
{
  /* must exist, be a regular file, and smaller than limit (we're going
   * to read the whole thing).
   */
  size_t i;
  bool ret = false;
  char buf[1025];
  FILE *fp = fopen(fpath.path_cstr(), "rb");
  if (fp) {
    //data.clear();
    while ((i = fread(buf, 1, 1024, fp)) > 0) {
      buf[i] = 0;
      data.append(buf);
    }
    if (data.size() > C_UNIONFS_MAX_FILE_SIZE) {
      output_internal("read_whole_file too large %s\n", fpath.path_cstr());
    } else if (feof(fp)) {
      ret = true;
    }
    fclose(fp);
  }
  return ret;
}

/* recursively copy source directory to destination.
 * will throw exception (from b_fs) if fail.
 */
void
UnionfsCstore::recursive_copy_dir(const FsPath& src, const FsPath& dst,
                                  bool filter_dot_entries)
{
  string src_str = src.path_cstr();
  string dst_str = dst.path_cstr();
  b_fs::create_directories(dst.path_cstr());

  b_fs::recursive_directory_iterator di(src_str);
  for (; di != b_fs::recursive_directory_iterator(); ++di) {
    const char *oname = di->path().string().c_str();
    string nname = oname;
    nname.replace(0, src_str.length(), dst_str);
    if (filter_dot_entries) {
      string of = di->path().filename().string();
      if (of.empty()) {
        continue;
      }
      if (of.at(0) == '.') {
        // filter dot files (with exceptions)
        if (of == C_COMMENT_FILE) {
          b_fs::copy_file(di->path(), nname);
        }
        continue;
      }
    }
    if (path_is_directory(oname)) {
      b_fs::create_directory(nname);
    } else {
      b_fs::copy_file(di->path(), nname);
    }
  }
}

void
UnionfsCstore::recursive_move_unionfs_dir(FsPath& src, FsPath& dst)
{
  string ocomm, ncomm;
  bool is_opaque = false;
  vector<string> sentries;
  MapT<string, bool> smap;

  try {
    b_fs::directory_iterator di(src.path_cstr());
    for (; di != b_fs::directory_iterator(); ++ di) {
      string of = di->path().filename().string();
      if (of.empty()) {
        continue;
      }

      if (of.at(0) == '.') {
        // filter dot files (with exceptions)
        push_path(dst, _unescape_path_name(of));
        string nname = dst.path_cstr();

        if (of == C_COMMENT_FILE) {
          ocomm = di->path().string().c_str();
          ncomm = nname;
          smap[of] = true;
        } else if (of.substr(0, C_WHITEOUT_PREFIX.length()) == C_WHITEOUT_PREFIX) {
          if (of == C_WHITEOUT_OPAQUE) {
            is_opaque = true;
          } else {
            nname.replace(nname.length() - of.length(), of.length(),
                          of.substr(C_WHITEOUT_PREFIX.length(), of.length()));
            output_internal("rm(dir) [%s] %s\n", of.c_str(), nname.c_str());
            b_fs::remove_all(nname);
          }
        }

        pop_path(dst);
      } else {
        of = _unescape_path_name(of);
        sentries.push_back(of);
        smap[of] = true;
      }
    }

    if (is_opaque) {
      // test for a hidden deletion
      b_fs::directory_iterator di(dst.path_cstr());
      for (; di != b_fs::directory_iterator(); ++ di) {
        string of = di->path().filename().string();
        if (smap.find(_unescape_path_name(of)) == smap.end()) {
          // entry in dst but not in src => delete
          output_internal("rm(dir) [%s] %s\n", of.c_str(), dst.path_cstr());
          b_fs::remove_all(di->path());
        }
      }
    }

    for (size_t i = 0; i < sentries.size(); i ++) {
      string of = sentries[i];

      push_path(src, of);
      struct stat st;
      string oname = src.path_cstr();
      if (!path_status(oname, &st)) {
        pop_path(src);
        continue;
      }

      push_path(dst, of);
      string nname = dst.path_cstr();

      if (path_is_directory(&st)) {
        b_fs::create_directory(nname);
        recursive_move_unionfs_dir(src, dst);
      } else if (path_is_regular(&st)) {
        b_fs::copy_file(oname, nname, b_fs::copy_option::overwrite_if_exists);
      }
      pop_path(src);
      pop_path(dst);
    }

    if (!ocomm.empty()) {
      b_fs::rename(ocomm, ncomm);
    }
  } catch (...) {
    // skip the rest
  }
}

void
UnionfsCstore::get_committed_marker(bool is_delete, string& marker)
{
  marker = (is_delete ? "-" : "");
  marker += mutable_cfg_path.path_cstr();
}

bool
UnionfsCstore::find_line_in_file(const FsPath& file, const string& line)
{
  bool ret = false;
  ifstream fin;
  try {
    fin.open(file.path_cstr());
    while (fin.good()) {
      string in;
      getline(fin, in);
      if (in == line) {
        ret = true;
        break;
      }
    }
  } catch (...) {
  }
  fin.close();
  return ret;
}

bool
UnionfsCstore::do_mount(const FsPath& rwdir, const FsPath& rdir,
                        const FsPath& mdir)
{
  string mopts = "dirs=";
  mopts += rwdir.path_cstr();
  mopts += "=rw:";
  mopts += rdir.path_cstr();
  mopts += "=ro";
  if (mount("unionfs", mdir.path_cstr(), "unionfs", 0, mopts.c_str()) != 0) {
    output_internal("union mount failed [%s][%s]\n",
                    strerror(errno), mdir.path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::do_umount(const FsPath& mdir)
{
  if (umount(mdir.path_cstr()) != 0) {
    output_internal("union umount failed [%s][%s]\n",
                    strerror(errno), mdir.path_cstr());
    return false;
  }
  return true;
}

bool
UnionfsCstore::path_status(const char *path, struct stat* st) const
{
  if (lstat(path, st) == -1) {
    return false;
  }
  return true;
}

bool
UnionfsCstore::path_exists(const char *path) const
{
  struct stat st;
  if (lstat(path, &st) == -1) {
    return false;
  }
  return true;
}

bool
UnionfsCstore::path_is_directory(const char *path) const
{
  struct stat st;
  if (lstat(path, &st) == -1) {
    return false;
  }
  return S_ISDIR(st.st_mode);
}

bool
UnionfsCstore::path_is_regular(const char *path) const
{
  struct stat st;
  if (lstat(path, &st) == -1) {
    return false;
  }
  return S_ISREG(st.st_mode);
}

bool
UnionfsCstore::file_size(const FsPath& path, size_t& size) const
{
  struct stat st;
  if (lstat(path.path_cstr(), &st) == -1) {
    return false;
  }
  size = st.st_size;
  return true;
}

bool
UnionfsCstore::remove_dir_content(const char *path)
{
  try {
    b_fs::directory_iterator di(path);
    for (; di != b_fs::directory_iterator(); ++di) {
      if (b_fs::remove_all(di->path()) < 1) {
        return false;
      }
    }
  } catch (...) {
    return false;
  }
  return true;
}

void
UnionfsCstore::move_dir_content(const FsPath& src, const FsPath& dst)
{
  string src_str = src.path_cstr();
  string dst_str = dst.path_cstr();

  b_fs::directory_iterator di(src_str);
  for (; di != b_fs::directory_iterator(); ++ di) {
    const char *oname = di->path().string().c_str();
    string nname = oname;
    nname.replace(0, src_str.length(), dst_str);
    b_fs::rename(di->path(), nname);
  }
}

bool
UnionfsCstore::compare_files(const FsPath& src, const FsPath& dst,
                             bool& different,
                             struct stat* src_st, struct stat* dst_st)
{
  string ds, dd;
  size_t src_size = 0, dst_size = 0;

  different = false;
  if (src_st) {
    src_size = file_size(src_st);
  } else {
    if (!file_size(src, src_size)) {
      return false;
    }
  }

  if (dst_st) {
    dst_size = file_size(dst_st);
  } else {
    if (!file_size(dst, dst_size)) {
      return false;
    }
  }

  if (src_size > C_UNIONFS_MAX_FILE_SIZE ||
      dst_size > C_UNIONFS_MAX_FILE_SIZE) {
    output_internal("compare_files too large [%s][%s]\n",
                    src.path_cstr(), dst.path_cstr());
    return false;
  }

  if (src_st->st_size != dst_st->st_size) {
    different = true;
    return true;
  }

  if (!read_whole_file(src, ds, src_size) ||
      !read_whole_file(dst, dd, dst_size)) {
    // error
    return false;
  }
  if (ds != dd) {
    different = true;
  }
  return true;
}

} // end namespace unionfs
} // end namespace cstore

