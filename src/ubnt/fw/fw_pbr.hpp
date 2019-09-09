#ifndef _FW_FW_PBR_HPP_
#define _FW_FW_PBR_HPP_

void add_route_table(const std::string& ip_version,
                     std::vector<std::string>& restore_vector,
                     const std::string& table, const std::string& rule);
void remove_route_table(const std::string& ip_version,
                        std::vector<std::string>& restore_vector,
                        const std::string& table, const std::string& rule);
void flush_route_table(const std::string& ip_version,
                       std::vector<std::string>& restore_vector,
                       const std::string& rule);
int run_ip_commands(void);

#endif /* _FW_FW_PBR_HPP_ */
