#include <stdio.h>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include "vyatta_config.hpp"

using namespace std;
using namespace cstore;

vyatta::Config::Config(const string& level) :
  _level(level)
{
  _init();
}

vyatta::Config::Config()
{
  _init();
}

void
vyatta::Config::_init()
{
  char *e = getenv("UBNT_CFGD_PROC_REQ_SID");
  if (e) {
    string dummy;
    _cstore.reset(Cstore::createCstore(e, dummy));
  } else {
    _cstore.reset(Cstore::createCstore(false));
  }
}

Cpath
vyatta::Config::get_path_comps(const string& path) const
{
  string tmp(_level);
  tmp += " " + path;
  boost::trim(tmp);

  Cpath path_comps;
  string s;
  stringstream pstr(tmp);
  while (getline(pstr, s, ' ')) {
    boost::trim(s);
    if (!s.empty()) {
      path_comps.push(s);
    }
  }
  return path_comps;
}

/**************************************************************************
 * low-level API functions that use the cstore library directly.
 * they are either new functions or old ones that have been
 * converted to use cstore.
 *************************************************************************/

/**************************************************************************
 * observers of current working config or active config during a commit.
 * * MOST users of this API should use these functions.
 * * these functions MUST NOT worry about the "deactivated" state, i.e.,
 *   deactivated nodes are equivalent to having been deleted for these
 *   functions. in other words, these functions are NOT "deactivate-aware".
 * * functions that can be used to observe "active config" can be used
 *   outside a commit as well (only when observing active config, of course).
 *
 * note: these functions accept a third argument "$include_deactivated", but
 *       it is for error checking purposes to ensure that all legacy
 *       invocations have been fixed. the functions MUST NOT be called
 *       with this argument. 
 *************************************************************************/
/*
 * Returns true if specified node exists in working config.
 */
bool
vyatta::Config::exists(const string& path)
{
  return _cstore->cfgPathExists(get_path_comps(path), false);
}

/*
 * Returns true if specified node exists in active config.
 */
bool
vyatta::Config::existsOrig(const string& path)
{
  return _cstore->cfgPathExists(get_path_comps(path), true);
}

/*
 * return array of all child nodes at "level" in working config.
 */
void
vyatta::Config::listNodes(const string& path, vector<string>& nodes,
                          const bool active)
{
  _cstore->cfgPathGetChildNodes(get_path_comps(path), nodes, active);
}

/*
 * return array of all child nodes at "level" in active config.
 */
void
vyatta::Config::listOrigNodes(const string& path, vector<string>& nodes)
{
  _cstore->cfgPathGetChildNodes(get_path_comps(path), nodes, true);
}

/*
 * return value of specified single-value node in working config.
 * return false if fail to get value (invalid node, node doesn't exist,
 * not a single-value node, etc.).
 */
bool
vyatta::Config::returnValue(const string& path, string& value)
{
  return _cstore->cfgPathGetValue(get_path_comps(path), value, false);
}

/*
 * return value of specified single-value node in active config.
 * return false if fail to get value (invalid node, node doesn't exist,
 * not a single-value node, etc.).
 */
bool
vyatta::Config::returnOrigValue(const string& path, string& value)
{
  return _cstore->cfgPathGetValue(get_path_comps(path), value, true);
}

/*
 * return array of values of specified multi-value node in working config.
 * return empty array if fail to get value (invalid node, node doesn't exist,
 * not a multi-value node, etc.).
 */
bool
vyatta::Config::returnValues(const string& path, vector<string>& values)
{
  return _cstore->cfgPathGetValues(get_path_comps(path), values, false);
}

/*
 * return array of values of specified multi-value node in active config.
 * return empty array if fail to get value (invalid node, node doesn't exist,
 * not a multi-value node, etc.).
 */
bool
vyatta::Config::returnOrigValues(const string& path, vector<string>& values)
{
  return _cstore->cfgPathGetValues(get_path_comps(path), values, true);
}

/**************************************************************************
 * observers of the "effective" config.
 * they can be used
 *   (1) outside a config session (e.g., op mode, daemons, callbacks, etc.).
 *   OR
 *   (2) during a config session
 *
 * HOWEVER, NOTE that the definition of "effective" is different under these
 * two scenarios.
 *   (1) when used outside a config session, "effective" == "active".
 *       in other words, in such cases the effective config is the same
 *       as the running config.
 *
 *   (2) when used during a config session, a config path (leading to either
 *       a "node" or a "value") is "effective" if it is "in effect" at the
 *       time when these observers are called. more detailed info can be
 *       found in the library code.
 *
 * originally, these functions are exclusively for use during config
 * sessions. however, for some usage scenarios, it is useful to have a set
 * of API functions that can be used both during and outside config
 * sessions. therefore, definition (1) is added above for convenience.
 *
 * for example, a developer can use these functions in a script that can
 * be used both during a commit action and outside config mode, as long as
 * the developer is clearly aware of the difference between the above two
 * definitions.
 *
 * note that when used outside a config session (i.e., definition (1)),
 * these functions are equivalent to the observers for the "active" config.
 *
 * to avoid any confusiton, when possible (e.g., in a script that is
 * exclusively used in op mode), developers should probably use those
 * "active" observers explicitly when outside a config session instead
 * of these "effective" observers.
 *
 * it is also important to note that when used outside a config session,
 * due to race conditions, it is possible that the "observed" active config
 * becomes out-of-sync with the config that is actually "in effect".
 * specifically, this happens when two things occur simultaneously:
 *   (a) an observer function is called from outside a config session.
 *   AND
 *   (b) someone invokes "commit" inside a config session (any session).
 *
 * this is because "commit" only updates the active config at the end after
 * all commit actions have been executed, so before the update happens,
 * some config nodes have already become "effective" but are not yet in the
 * "active config" and therefore are not observed by these functions.
 *
 * note that this is only a problem when the caller is outside config mode.
 * in such cases, the caller (which could be an op-mode command, a daemon,
 * a callback script, etc.) already must be able to handle config changes
 * that can happen at any time. if "what's configured" is more important,
 * using the "active config" should be fine as long as it is relatively
 * up-to-date. if the actual "system state" is more important, then the
 * caller should probably just check the system state in the first place
 * (instead of using these config observers).
 *************************************************************************/

/*
 * return "effective" value of specified "node" during current commit.
 */
bool
vyatta::Config::returnEffectiveValue(const string& path, string& value)
{
  return _cstore->cfgPathGetEffectiveValue(get_path_comps(path), value);
}

/*
 * return "effective" values of specified "node" during current commit.
 */
bool
vyatta::Config::returnEffectiveValues(const string& path,
                                      vector<string>& values)
{
  return _cstore->cfgPathGetEffectiveValues(get_path_comps(path), values);
}

/*
 * whether specified node has been deleted in working config
 */
bool
vyatta::Config::isDeleted(const string& path)
{
  return _cstore->cfgPathDeleted(get_path_comps(path));
}

/**************************************************************************
 * high-level API functions (not using the cstore library directly)
 *************************************************************************/
/*
 * set the current level of config hierarchy to specified level (if defined).
 * return the current level.
 */
const string&
vyatta::Config::setLevel(const string& level)
{
  if (!level.empty()) {
    _level = level;
  }
  return _level;
}
