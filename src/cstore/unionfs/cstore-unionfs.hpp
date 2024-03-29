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

#ifndef _CSTORE_UNIONFS_H_
#define _CSTORE_UNIONFS_H_
#include <vector>
#include <string>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <boost/filesystem.hpp>

#include <cli_cstore.h>
#include <cstore/cstore.hpp>
#include <cstore/unionfs/fspath.hpp>

// forward decl
namespace commit {
class PrioNode;
}

namespace cstore { // begin namespace cstore
namespace unionfs { // begin namespace unionfs

namespace b_fs = boost::filesystem;
namespace b_s = boost::system;

typedef MapT<FsPath, mode_t, FsPathHash> PathPresentCacheT;

class UnionfsCstore : public Cstore {
public:
  UnionfsCstore(bool use_edit_level);
  UnionfsCstore(const string& session_id, string& env,
                bool use_edit_level = true);
  virtual ~UnionfsCstore();

  ////// public virtual functions declared in base class
  bool markSessionUnsaved();
  bool unmarkSessionUnsaved();
  bool sessionUnsaved();
  bool sessionChanged();
  bool setupSession();
  bool teardownSession();
  bool inSession();
  bool clearCommittedMarkers();
  bool commitConfig(commit::PrioNode& pnode);
  bool markCfgPathCommitted(const CstoreCPathListT& clist);
  void enableCacheMode();
  void disableCacheMode();
  bool isEmptyDir(const char *const dir);
  bool getNumberSession(int& sessions);

  class UnionfsCommitLock : public CommitLock {
  public:
    UnionfsCommitLock();
    ~UnionfsCommitLock();
    bool locked();

  private:
    bool _locked;
    int _lfd;
  };
  tr1::shared_ptr<CommitLock> getCommitLock();

private:
  // constants
  static const string C_ENV_TMPL_ROOT;
  static const string C_ENV_WORK_ROOT;
  static const string C_ENV_ACTIVE_ROOT;
  static const string C_ENV_CHANGE_ROOT;
  static const string C_ENV_TMP_ROOT;

  static const string C_DEF_TMPL_ROOT;
  static const string C_DEF_CFG_ROOT;
  static const string C_DEF_ACTIVE_ROOT;
  static const string C_DEF_CHANGE_PREFIX;
  static const string C_DEF_WORK_PREFIX;
  static const string C_DEF_TMP_PREFIX;

  static const string C_MARKER_DEF_VALUE;
  static const string C_MARKER_DEACTIVATE;
  static const string C_MARKER_CHANGED;
  static const string C_MARKER_UNSAVED;
  static const string C_COMMITTED_MARKER_FILE;
  static const string C_COMMENT_FILE;
  static const string C_TAG_NAME;
  static const string C_VAL_NAME;
  static const string C_DEF_NAME;
  static const string C_COMMIT_LOCK_FILE;
  static const string C_COMMIT_SID_FILE;
  static const string C_COMMIT_END_FILE;
  static const string C_WHITEOUT_PREFIX;
  static const string C_WHITEOUT_OPAQUE;

  /* max size for a file.
   * currently this includes value file and comment file.
   */
  static const size_t C_UNIONFS_MAX_FILE_SIZE = 262144;

  // root dirs (constant)
  FsPath work_root;   // working root (union)
  FsPath active_root; // active root (readonly part of union)
  FsPath change_root; // change root (r/w part of union)
  FsPath tmp_root;    // temp root
  FsPath tmpl_root;   // template root

  // path buffers
  FsPath mutable_cfg_path;  // mutable part of config path
  FsPath tmpl_path;         // whole template path
  FsPath orig_mutable_cfg_path;  // original mutable cfg path
  FsPath orig_tmpl_path;         // original template path

  // for commit processing
  FsPath tmp_active_root;
  FsPath tmp_work_root;
  FsPath commit_marker_file;
  void init_commit_data() {
    tmp_active_root = tmp_root;
    tmp_work_root = tmp_root;
    commit_marker_file = tmp_root;
    tmp_active_root.push("active");
    tmp_work_root.push("work");
    commit_marker_file.push(C_COMMITTED_MARKER_FILE);
  }
  bool construct_commit_active(commit::PrioNode& node);
  bool mark_dir_changed(const FsPath& d, const FsPath& root);
  bool sync_dir(const FsPath& src, const FsPath& dst, const FsPath& root);

  bool path_present_cache_enabled;
  PathPresentCacheT path_present_cache;

  ////// virtual functions defined in base class
  // begin path modifiers
  void push_tmpl_path(const char *new_comp) {
    push_path(tmpl_path, new_comp);
  };
  void push_tmpl_path_tag() {
    /* not using push_path => not "escaped".
     * NOTE: this is the only interface that can push tmpl_path "unescaped".
     *       this means the pop_tmpl_path() function potentially may return
     *       incorrect value if used in combination with this function.
     *       however, since current C_TAG_NAME doesn't contain any escape
     *       sequences, this cannot happen for now.
     */
    tmpl_path.push(C_TAG_NAME);
  };
  void pop_tmpl_path() {
    pop_path(tmpl_path);
  };
  void pop_tmpl_path(string& last) {
    pop_path(tmpl_path, last);
  };
  void push_cfg_path(const char *new_comp) {
    push_path(mutable_cfg_path, new_comp);
  };
  void pop_cfg_path() {
    pop_path(mutable_cfg_path);
  };
  void pop_cfg_path(string& last) {
    pop_path(mutable_cfg_path, last);
  };
  void append_cfg_path(const Cpath& path_comps) {
    for (size_t i = 0; i < path_comps.size(); i++) {
      push_cfg_path(path_comps[i]);
    }
  };
  void reset_paths(bool to_root=false) {
    if (to_root){
      char *val;
      if ((val = getenv(C_ENV_TMPL_ROOT.c_str()))) {
        tmpl_path = val; 
      } else {
        tmpl_path = C_DEF_TMPL_ROOT;
      }
      mutable_cfg_path = "/";
    } else {
      tmpl_path = orig_tmpl_path;
      mutable_cfg_path = orig_mutable_cfg_path;
    }
  };

  class UnionfsSavePaths : public SavePaths {
  public:
    UnionfsSavePaths(UnionfsCstore *cs)
      : cstore(cs), cpath(cs->mutable_cfg_path), tpath(cs->tmpl_path) {};

    ~UnionfsSavePaths() {
      cstore->mutable_cfg_path = cpath;
      cstore->tmpl_path = tpath;
    };

  private:
    UnionfsCstore *cstore;
    FsPath cpath;
    FsPath tpath;
  };
  auto_ptr<SavePaths> create_save_paths() {
    return auto_ptr<SavePaths>(new UnionfsSavePaths(this));
  };

  bool cfg_path_at_root() {
    return (!mutable_cfg_path.has_parent_path());
  };
  bool tmpl_path_at_root() {
    return (tmpl_path == tmpl_root);
  };
  // end path modifiers

  // these operate on current tmpl path
  bool tmpl_node_exists();
  Ctemplate *tmpl_parse();

  // these operate on current work path
  bool add_node();
  bool remove_node();
  void get_all_child_node_names_impl(vector<string>& cnodes, bool active_cfg);
  void get_all_child_item_names_impl(vector<string>& cnodes,
                                     vector<string>& cmarkers,
                                     const bool active_cfg);
  void get_changed_items(vector<string>& mnodes,
                         vector<string>& dnodes,
                         bool& content_changed,
                         bool& content_opaque);
  void get_all_tmpl_child_node_names(vector<string>& cnodes);
  bool write_value_vec(const vector<string>& vvec, bool active_cfg);
  bool update_value_vec();
  bool val_exists(const vector<string>& cmarkers);
  bool rename_child_node(const char *oname, const char *nname);
  bool copy_child_node(const char *oname, const char *nname);
  bool mark_display_default();
  bool unmark_display_default(bool& exists);
  bool mark_deactivated();
  bool unmark_deactivated();
  bool unmark_deactivated_descendants();
  bool mark_changed(const bool node_exists = false);
  bool mark_changed_with_ancestors(const bool node_exists = false);
  bool unmark_changed_with_descendants();
  bool remove_comment();
  bool set_comment(const string& comment);
  bool discard_changes(unsigned long long& num_removed);

  bool commit_node_config(commit::PrioNode& pnode);
  bool commit_full_config();

  // observers for work path
  bool cfg_node_changed();

  // observers for work path or active path
  bool cfg_node_exists(bool active_cfg);
  bool read_value_vec(vector<string>& vvec, bool active_cfg);
  bool marked_deactivated(bool active_cfg);
  bool marked_deactivated(const vector<string>& cmarkers);
  bool get_comment(string& comment, bool active_cfg);
  bool comment_exists(const vector<string>& cmarkers);
  bool marked_display_default(bool active_cfg);
  bool marked_display_default(const vector<string>& cmarkers);

  // observers for "edit/tmpl levels" (for "edit"-related operations).
  // note that these should be moved to base class in the future.
  string get_edit_level_path() {
    return cfg_path_to_str();
  };
  string get_tmpl_level_path() {
    return tmpl_path_to_str();
  };
  void get_edit_level(Cpath& path_comps);
  bool edit_level_at_root() {
    return cfg_path_at_root();
  };

  // functions for commit operation
  bool marked_committed(bool is_delete);
  bool mark_committed(bool is_delete);

  // for testing/debugging
  string cfg_path_to_str();
  string tmpl_path_to_str();

  ////// private functions
  FsPath get_work_path() { return (work_root / mutable_cfg_path); };
  FsPath get_active_path() { return (active_root / mutable_cfg_path); };
  FsPath get_change_path() { return (change_root / mutable_cfg_path); };
  void push_path(FsPath& old_path, const char *new_comp);
  void push_path(FsPath& old_path, const string& new_comp);
  void pop_path(FsPath& path);
  void pop_path(FsPath& path, string& last);
  bool check_dir_entries(const FsPath& root, vector<string>& cnodes,
                         bool filter_nodes = true);
  void get_all_child_dir_names(const FsPath& root, vector<string>& nodes) {
    check_dir_entries(root, nodes);
  }
  bool _write_file(const char *const file, const string& data,
                   const bool append);
  bool write_file(const FsPath& file, const string& data,
                  const bool append = false);
  bool _create_file(const char *const file);
  bool _create_excl_file(const FsPath& file);
  bool create_file(const FsPath& file);
  bool read_whole_file(const FsPath& file, string& data, size_t size = 0);
  void recursive_copy_dir(const FsPath& src, const FsPath& dst,
                          bool filter_dot_entries = false);
  void recursive_move_unionfs_dir(FsPath& src, FsPath& dst);

  void get_committed_marker(bool is_delete, string& marker);
  bool find_line_in_file(const FsPath& file, const string& line);
  bool do_mount(const FsPath& rwdir, const FsPath& rdir, const FsPath& mdir);
  bool do_umount(const FsPath& mdir);

  // file stat operations wrappers
  bool check_cached_path(const FsPath& path, mode_t& mode);
  bool path_status(const char *path, struct stat* st) const;
  bool path_status(const FsPath& path, struct stat* st) const {
    return path_status(path.path_cstr(), st);
  };
  bool path_status(const string& path, struct stat* st) const {
    return path_status(path.c_str(), st);
  };
  bool path_exists(const char *path) const;
  bool path_exists(const char *path, struct stat* st) const {
    return path_status(path, st);
  };
  bool path_exists(const FsPath& path) const {
    return path_exists(path.path_cstr());
  };
  bool path_exists(const FsPath& path, struct stat* st) const {
    return path_status(path.path_cstr(), st);
  };
  bool path_is_directory(const char *path) const;
  bool path_is_directory(const struct stat* st) const {
    return S_ISDIR(st->st_mode);
  }
  bool path_is_directory(const FsPath& path) const {
    return path_is_directory(path.path_cstr());
  };
  bool path_is_directory(const string& path) const {
    return path_is_directory(path.c_str());
  };
  bool path_is_regular(const char *path) const;
  bool path_is_regular(const struct stat* st) const {
    return S_ISREG(st->st_mode);
  }
  bool path_is_regular(const FsPath& path) const {
    return path_is_regular(path.path_cstr());
  };
  bool path_is_regular(const string& path) const {
    return path_is_regular(path.c_str());
  };
  bool file_size(const FsPath& path, size_t& size) const;
  size_t file_size(const struct stat* st) const {
    return st->st_size;
  }

  // boost operations wrappers
  bool remove_dir_content(const char *path);
  void move_dir_content(const FsPath& src, const FsPath& dst);
  bool compare_files(const FsPath& src, const FsPath& dst,
                     bool& different,
                     struct stat* src_st = NULL, struct stat* dst_st = NULL);

  mode_t _tmpl_path(const FsPath& path);
  bool _tmpl_file_exists(const FsPath& path);
  bool _tmpl_node_exists(const FsPath& path);
};

} // end namespace unionfs
} // end namespace cstore

#endif /* _CSTORE_UNIONFS_H_ */

