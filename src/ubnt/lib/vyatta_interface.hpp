#ifndef _VYATTA_INTERFACE_HPP_
#define _VYATTA_INTERFACE_HPP_

#include <string>
#include <vector>

namespace vyatta { // begin namespace vyatta

using namespace std;
//using namespace cstore;

class Interface 
{
public:
  Interface(const string& name);

  string path() const;
  const string& name() const
  {
    return _name;
  }
  string dev() const
  {
    return _dev_type + _dev_id;
  }
  const string& vif() const
  {
    return _dev_vif;
  }
  const string& type() const
  {
    return _type;
  }
  bool get() const
  {
    return (!_name.empty());
  }

  string bridge_grp();
  string mtu();
  // device exists and is online
  bool up();

  static bool is_uniq_address(const string& ip);
  static bool is_uniq_address(const vector<string>& ips);

  static void listSystemInterfaces(vector<string>& intfs);

private:
  bool fill_interface(const string& dev, const string& dev_id,
                      const string& vif,
                      string& path, string& type) const;
  bool check_if_ppp(const string& dev, const string& dev_id) const;
  bool ppp_intf(const string& dev, string& intf) const;
  void parse_if_name(const string& name, string& dev, string& dev_type,
                                 string& dev_id, string& vif) const;
  string ppp_path() const;
  long flags();

  static string fill_path(const string& type, const string& name = _dummy,
                          const string& vifpath = _dummy,
                          const string& vif = _dummy);

  string  _type;
  string  _path;
  string  _name;
  string  _dev_type;
  string  _dev_id;
  string  _dev_vif;

  static const string _dummy;
};

} // end namespace vyatta

#endif /* _VYATTA_INTERFACE_HPP_ */
