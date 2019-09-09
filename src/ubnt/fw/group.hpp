#ifndef _FW_GROUP_HPP_
#define _FW_GROUP_HPP_

#include <string>
#include <vector>
#include <map>

#include <cstore/cstore.hpp>

class Group
{
public:
     enum FW_GROUP {
        ADDRESS = 0,
        NETWORK,
        PORT,
        IPV6_ADDRESS,
        IPV6_NETWORK,
        FW_GROUP_INVALID
    };
    Group(const std::string& name);
    Group(const std::string& name, const std::string& type,
          std::string family);
    ~Group();
    bool                 set_create(std::string& err);
    bool                 set_delete(std::string& err);
    bool                 set_exists() const;
    bool                 add_member(std::string member,
                                    const std::string& alias,
                                    std::string& err);
    bool                 delete_member(std::string member,
                                       std::string& err);
    void                 add_cmd(const std::string& cmd);
    bool                 commit(std::string& err);
    std::string          get_type_string() const;
    const std::string&   get_name() const;
    void                 debug(bool onoff);
    void                 print_cpath(const cstore::Cpath& cpath) const;
    const std::string&   get_family() const { return _family; };

private:
    Group();
    void                 Group_common(const std::string& name,
                                      enum Group::FW_GROUP type, 
                                      std::string& family);
    bool                 set_flush(std::string& err);
    void                 get_firewall_references(std::vector<std::string>& refs,
                                                 bool active) const;
    void                 get_nat_references(std::vector<std::string>& refs,
                                            bool active) const;
    int                  references() const;
    bool                 member_exists(const std::string& member) const;
    bool                 add_member_range(const std::string& start,
                                          const std::string& stop,
                                          const std::string& alias,
                                          std::string& err);
    bool                 delete_member_range(const std::string& start,
                                             const std::string& stop,
                                             std::string& err);

    std::string                   _name;
    enum FW_GROUP                 _type;
    std::string                   _family;
    bool                          _exists;
    bool                          _valid;
    int                           _refs;
    std::map<std::string, bool>   _members;
    bool                          _negate;
    bool                          _debug;
    std::vector<std::string>      _cmds;
};

#endif /* _FW_GROUP_HPP_ */
