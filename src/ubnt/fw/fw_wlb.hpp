#ifndef _FW_FW_WLB_HPP_
#define _FW_FW_WLB_HPP_

void add_wlb_group(const std::string& ipt_cmd, 
                   std::vector<std::string>& restore_vector, 
                   const std::string& wlb, const std::string& rule);
void remove_wlb_group(const std::string& ipt_cmd,
                      std::vector<std::string>& restore_vector, 
                      const std::string& wlb, const std::string& rule);

#endif /* _FW_FW_WLB_HPP_ */
