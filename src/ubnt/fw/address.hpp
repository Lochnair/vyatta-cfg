#ifndef _FW_ADDRESS_HPP_
#define _FW_ADDRESS_HPP_

#include <string>

#include <cstore/cstore.hpp>

class Address
{
public:
    enum FW_GROUP {
        ADDRESS = 0,
        NETWORK,
        PORT,
        FW_GROUP_LAST
    };
    Address();
    void setup(cstore::Cpath& cpath, bool active);
    void set_ip_version(const std::string& ip_version);
    bool rule(std::string& rule_string, std::string& err) const;
    void print() const;

private:
    static bool validate_address(const std::string& version,
                                 const std::string& address);
    static bool validate_network(const std::string& version,
                                 const std::string& network);
    bool get_port_rule_string(bool can_use_port, std::string& port_rule,
                              std::string& err) const;

    std::string   _srcdst;
    std::string   _range_start;
    std::string   _range_stop;
    std::string   _network;
    std::string   _address;
    std::string   _port;
    std::string   _protocol;
    std::string   _src_mac;
    std::string   _address_group;
    std::string   _network_group;
    std::string   _port_group;

    std::string   _ip_version;
    bool          _setup;
};

#endif /* _FW_ADDRESS_HPP_ */
