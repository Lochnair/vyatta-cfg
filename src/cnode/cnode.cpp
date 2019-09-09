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
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>

#include <cli_cstore.h>
#include <cnode/cnode.hpp>

using namespace cnode;
using namespace cstore;


////// constructors/destructors
// for parser
CfgNode::CfgNode(Cpath& path_comps, char *name, char *val, char *comment,
                 int deact, Cstore *cstore, bool tag_if_invalid)
  : TreeNode<CfgNode>(),
    _is_tag(false), _is_leaf(false), _is_multi(false), _is_value(false),
    _is_default(false), _is_deactivated(false), _is_leaf_typeless(false),
    _is_invalid(false), _exists(true), _path_comps(path_comps)
{
  if (name && name[0]) {
    // name must be non-empty
    path_comps.push(name);
  }
  if (val) {
    // value could be empty
    path_comps.push(val);
  }

  while (1) {
    if (path_comps.size() == 0) {
      // nothing to do for root node
      break;
    }

    setTmpl(cstore->parseTmpl(path_comps, false));
    if (getTmpl().get()) {
      // got the def
      _is_tag = getTmpl()->isTag();
      _is_leaf = (!_is_tag && !getTmpl()->isTypeless());

      // match constructor from cstore (leaf node never _is_value)
      _is_value = (getTmpl()->isValue() && !_is_leaf);
      _is_multi = getTmpl()->isMulti();

      /* XXX given the current definition of "default" (i.e., the
       * "post-bug 1219" definition), the concept of "default" doesn't
       * really apply to config files. however, if in the future we
       * do go back to the original, simpler definition of "default"
       * (which IMO is the right thing to do), the "default handling"
       * here and elsewhere in the backend library will need to be
       * revamped.
       *
       * in fact, in that case pretty much the only place that need to
       * worry about "default" is in the "output" (i.e., "show")
       * processing, and even there the only thing that needs to be
       * done is to compare the current value with the "default value"
       * in the template.
       */
      _is_default = false;
      _is_deactivated = deact;

      vector<string> tcnodes;
      cstore->tmplGetChildNodes(path_comps, tcnodes);
      if (tcnodes.size() == 0) {
        // typeless leaf node
        _is_leaf_typeless = true;
      }

      if (comment) {
        _comment = comment;
      }
      // ignore return
    } else {
      // not a valid node
      _is_invalid = true;
      if (tag_if_invalid) {
        /* this is only used when the parser is creating a "tag node". force
         * the node to be tag since we don't have template for invalid node.
         */
        _is_tag = true;
      }
      if (val) {
        /* if parser got value for the invalid node, always treat it as
         * "tag value" for simplicity.
         */
        _is_tag = true;
        _is_value = true;
      }
      break;
    }

    break;
  }

  // restore path_comps. also set value/name for both valid and invalid nodes.
  if (val) {
    if (_is_multi) {
      _values.push_back(val);
    } else {
      _value = val;
    }
    path_comps.pop();
  }
  if (name && name[0]) {
    _name = name;
    path_comps.pop();
  }
}

// for active/working config
CfgNode::CfgNode(Cstore& cstore, Cpath& path_comps, bool active,
                 bool recursive)
  : TreeNode<CfgNode>(),
    _is_tag(false), _is_leaf(false), _is_multi(false), _is_value(false),
    _is_default(false), _is_deactivated(false), _is_leaf_typeless(false),
    _is_invalid(false), _exists(true), _path_comps(path_comps)
{
  _init(cstore, path_comps, active, recursive, NULL);
}

CfgNode::CfgNode(Cstore& cstore, Cpath& path_comps, const bool active,
                 const bool recursive, const CfgNode * const parent)
  : TreeNode<CfgNode>(),
    _is_tag(false), _is_leaf(false), _is_multi(false), _is_value(false),
    _is_default(false), _is_deactivated(false), _is_leaf_typeless(false),
    _is_invalid(false), _exists(true), _path_comps(path_comps)
{
  _init(cstore, path_comps, active, recursive, parent);
}

void
CfgNode::_init(Cstore& cstore, Cpath& path_comps, const bool active,
               const bool recursive, const CfgNode * const parent)
{
  vector<string> cnodes, cmarkers;
  /* first get the def (only if path is not empty). if path is empty, i.e.,
   * "root", treat it as an intermediate node.
   */
  if (path_comps.size() > 0) {
    setTmpl(cstore.parseTmpl(path_comps, false));
    if (getTmpl().get()) {
      // got the def
      // Node parents have already been checked if safe=true
      if (!parent && !cstore._cfgPathExists(path_comps, active)) {
        // path doesn't exist
        _exists = false;
        return;
      }

      _is_value = getTmpl()->isValue();
      _is_tag = getTmpl()->isTag();
      _is_leaf = (!_is_tag && !getTmpl()->isTypeless());
      _is_multi = getTmpl()->isMulti();

      cstore._cfgPathGetChildItems(path_comps, cnodes, cmarkers, active);
      _is_default = cstore._cfgPathDefault(cmarkers);
      if (!parent) {
        _is_deactivated = cstore._cfgPathDeactivated(path_comps, active);
      } else if (parent->isDeactivated()) {
        _is_deactivated = true;
      } else {
        _is_deactivated = cstore._cfgPathLeafDeactivated(cmarkers);
      }
      if (cstore._cfgPathCommentExists(cmarkers)) {
        cstore._cfgPathGetComment(path_comps, _comment, active);
      }
      // ignore return

      if (_is_leaf && _is_value) {
        /* "leaf value" so recursion should never reach here. if path is
         * specified by user, nothing further to do.
         */
        return;
      }
    } else {
      // not a valid node
      _is_invalid = true;
      return;
    }
  } else {
    cstore._cfgPathGetChildNodesDA(path_comps, cnodes, active, true);
  }

  // handle leaf node (note path_comps must be non-empty if this is leaf)
  if (_is_leaf) {
    _name = path_comps[path_comps.size() - 1];
    if (cstore._cfgPathValueExists(cmarkers)) {
      if (_is_multi) {
        // multi-value node
        _values.clear();
        cstore._cfgPathGetValuesDA(path_comps, _values, active, true, true);
        // ignore return value
      } else {
        // single-value node
        _value.clear();
        cstore._cfgPathGetValueDA(path_comps, _value, active, true, true);
        // ignore return value
      }
    }
    return;
  }

  // handle intermediate (typeless) or tag
  if (_is_value) {
    // tag value
    _name = path_comps[path_comps.size() - 2];
    _value = path_comps[path_comps.size() - 1];
  } else {
    // tag node or typeless node
    _name = (path_comps.size() > 0 ? path_comps[path_comps.size() - 1] : "");
  }

  // check child nodes
  if (cnodes.size() == 0) {
    // empty subtree. done.
    vector<string> tcnodes;
    cstore.tmplGetChildNodes(path_comps, tcnodes);
    if (tcnodes.size() == 0) {
      // typeless leaf node
      _is_leaf_typeless = true;
    }
    return;
  }

  if (!recursive) {
    // nothing further to do
    return;
  }

  // recurse
  for (size_t i = 0; i < cnodes.size(); i++) {
    path_comps.push(cnodes[i]);
    CfgNode *cn = new CfgNode(cstore, path_comps, active, recursive, this);
    addChildNode(cn);
    path_comps.pop();
  }
}

/* creates working configuration node from active if cstore particular
 * implementation has support for such operation
 * note: deactivate unaware
 */
CfgNode::CfgNode(cstore::Cstore& cstore, const CfgNode& aroot)
  : TreeNode<CfgNode>(),
  _is_tag(aroot._is_tag), _is_leaf(aroot._is_leaf), _is_multi(aroot._is_multi),
  _is_value(aroot._is_value), _is_default(aroot._is_default),
  _is_deactivated(aroot._is_deactivated),
  _is_leaf_typeless(aroot._is_leaf_typeless), _is_invalid(aroot._is_invalid),
  _exists(aroot._exists), _name(aroot._name), _value(aroot._value),
  _values(aroot._values), _comment(aroot._comment), _path_comps(aroot._path_comps)
{
  if (!aroot.getName().empty() || aroot.isInvalid() || !aroot.exists()) {
    return;
  }
  _copy_init(cstore, aroot, 0);
}

CfgNode::CfgNode(cstore::Cstore& cstore, const CfgNode& anode,
                 const CfgNode *const parent, const bool changed)
  : TreeNode<CfgNode>(),
  _is_tag(anode._is_tag), _is_leaf(anode._is_leaf), _is_multi(anode._is_multi),
  _is_value(anode._is_value), _is_default(anode._is_default),
  _is_deactivated(anode._is_deactivated),
  _is_leaf_typeless(anode._is_leaf_typeless), _is_invalid(anode._is_invalid),
  _exists(anode._exists), _name(anode._name), _value(anode._value),
  _values(anode._values), _comment(anode._comment), _path_comps(anode._path_comps)
{
  if (changed) {
    _copy_init(cstore, anode, parent);
  } else {
    const vector<CfgNode*>& acnodes = anode.getChildNodes();
    for (size_t i = 0; i < acnodes.size(); i ++) {
      // was not changed
      CfgNode *cn = new CfgNode(cstore, *acnodes[i], this, false);
      addChildNode(cn);
    }
  }
}

void
CfgNode::_copy_init(cstore::Cstore& cstore, const CfgNode& anode,
                    const CfgNode *const parent)
{
  vector<string> mnodes, dnodes;
  bool content_changed = false, content_opaque = false;

  cstore._cfgPathChangedItems(_path_comps, mnodes, dnodes,
                              content_changed, content_opaque);

  if (content_opaque) {
    /* directory is opaque:
     * ignore everything from active node
     * re-read content: default, value and etc.
     * add child nodes from working node only
     */
    _init(cstore, _path_comps, false, true, parent);
    return;
  }

  MapT<string, bool> mmap, dmap, amap;
  for (size_t i = 0; i < mnodes.size(); i++) {
    mmap[mnodes[i]] = true;
  }
  for (size_t i = 0; i < dnodes.size(); i++) {
    dmap[dnodes[i]] = true;
  }

  const vector<CfgNode*>& acnodes = anode.getChildNodes();
  if (mnodes.size()) {
    for (size_t i = 0; i < acnodes.size(); i ++) {
      size_t size = acnodes[i]->getPath().size();
      string name = acnodes[i]->getPath()[size - 1];
      amap[name] = true;
    }
  }

  if (content_changed) {
    /* content has been changed:
     * re-read content: default, value and etc.
     *
     * works in 2 cases:
     * 1. property has been changed, added, deleted
     * 2. a child node has been deleted
     */
    _init(cstore, _path_comps, false, false, parent);
  }

  /* modify changed childs
   * delete missing childs
   * copy untouched childs
   */
  if (!mnodes.size() && !dnodes.size()) {
    // was not changed
    for (size_t i = 0; i < acnodes.size(); i ++) {
      CfgNode *cn = new CfgNode(cstore, *acnodes[i], this, false);
      addChildNode(cn);
    }
  } else {
    for (size_t i = 0; i < acnodes.size(); i ++) {
      size_t size = acnodes[i]->getPath().size();
      string name = acnodes[i]->getPath()[size - 1];
      if (dmap.find(name) == dmap.end()) {
        // still present
        CfgNode *cn;
        if (mmap.find(name) != mmap.end()) {
          // a child node has been changed
          cn = new CfgNode(cstore, *acnodes[i], this, true);
        } else {
          // was not changed
          cn = new CfgNode(cstore, *acnodes[i], this, false);
        }
        addChildNode(cn);
      }
      // skip deleted
    }
  }

  // create added childs
  if (mnodes.size()) {
    Cpath path_comps(_path_comps);
    MapT<string, bool>::iterator it = mmap.begin();
    for (; it != mmap.end(); ++it) {
      if (amap.find((*it).first) == amap.end()) {
        path_comps.push((*it).first);
        CfgNode *cn = new CfgNode(cstore, path_comps, false, true, this);
        addChildNode(cn);
        path_comps.pop();
      }
    }
  }
}