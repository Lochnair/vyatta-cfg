#ifndef _FW_UTIL_HPP_
#define _FW_UTIL_HPP_

#include <regex.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <netdb.h>

extern bool debug_flag;

extern void log_msg(const char *format, ...);

extern void read_refcnt_file(const char *file_name,
                             std::vector<std::string>& v);
extern void write_refcnt_file(const char *file_name,
                              std::vector<std::string>& v);
extern void line_to_tokens(const std::string& line, std::vector<std::string>& v);
extern void tokens_to_line(const std::vector<std::string>& v,
                           std::string& line);
extern bool chain_exists(const std::string& ipt_cmd, const std::string& table,
                         const std::string& chain);
extern bool chain_referenced(const std::string& table,
                             const std::string& chain,
                             const std::string& ipt_cmd);
extern int fw_find_intf_rule(const std::string& ipt_cmd,
                             const std::string& ipt_table,
                             const std::string& dir, const std::string& intf);
extern std::string fw_get_hook(const std::string& dir);

extern bool validate_ipv4(const std::string& address);
extern bool is_valid_port_number(const std::string& number, std::string& err);
extern bool is_valid_port_name(const std::string& name, const char *proto,
                               std::string& err);
extern bool is_valid_port_range(const std::string& range_s,
                                const std::string& range_e,
                                std::string& err);
extern int my_atoi(const std::string& s);
extern std::string my_itoa(int i);
extern void split(const std::string& s, char c, std::vector<std::string>& v);
extern bool is_digit(const std::string& s);
extern bool is_port_range(const std::string& s, std::string& start,
                          std::string& stop);

#endif /* _FW_UTIL_HPP_ */