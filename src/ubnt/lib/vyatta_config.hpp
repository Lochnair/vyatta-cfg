#ifndef _VYATTA_CONFIG_HPP_
#define _VYATTA_CONFIG_HPP_

#include <string>
#include <vector>

#include <cstore/cstore.hpp>

namespace vyatta { // begin namespace vyatta

using namespace std;

class Config 
{
public:
  Config(const string& level);
  Config();

  void listNodes(const string& path, vector<string>& nodes,
                 const bool active = false);
  void listNodes(vector<string>& nodes, const bool active = false) {
    listNodes(_dummy, nodes, active);
  }
  void listOrigNodes(const string& path, vector<string>& nodes);
  void listOrigNodes(vector<string>& nodes) {
    listOrigNodes(_dummy, nodes);
  }

  bool exists(const string& path);
  bool existsOrig(const string& path);

  bool returnValue(const string& path, string& value);
  bool returnValue(string& value) {
    return returnValue(_dummy, value);
  }
  bool returnOrigValue(const string& path, string& value);
  bool returnOrigValue(string& value) {
    return returnOrigValue(_dummy, value);
  }

  bool returnValues(const string& path, vector<string>& values);
  bool returnValues(vector<string>& values) {
    return returnValues(_dummy, values);
  }
  bool returnOrigValues(const string& path, vector<string>& values);
  bool returnOrigValues(vector<string>& values) {
    return returnOrigValues(_dummy, values);
  }

  bool isDeleted(const string& path);
  bool isDeleted() {
    return isDeleted(_dummy);
  }

  bool returnEffectiveValue(const string& path, string& value);
  bool returnEffectiveValue(string& value) {
    return returnEffectiveValue(_dummy, value);
  }
  bool returnEffectiveValues(const string& path, vector<string>& values);
  bool returnEffectiveValues(vector<string>& values) {
    return returnOrigValues(_dummy, values);
  }

  const string& setLevel(const string& level);

private:
  string _level, _dummy;
  tr1::shared_ptr<cstore::Cstore> _cstore;

  void _init();
  cstore::Cpath get_path_comps(const string& path) const;
  cstore::Cpath get_path_comps() const {
    string dummy;
    return get_path_comps(dummy);
  }
};

} // end namespace vyatta

#endif /* _VYATTA_CONFIG_HPP_ */
