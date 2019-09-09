#ifndef _FW_FW_DPI_HPP_
#define _FW_FW_DPI_HPP_

extern bool dpi_get_cat_mark(std::string& cat, const std::string& chain,
                             const std::string& rule, std::string& mark,
                             std::string& err);
extern bool dpi_set_cat_mark(std::string& cat, const std::string& chain,
                             const std::string& rule, std::string& err);
extern bool dpi_del_cat_mark(std::string& cat, const std::string& app,
                             const std::string& chain, const std::string& rule,
                             std::string& err);
extern bool dpi_flush_chain(const std::string& chain);

extern bool dpi_get_cust_cat_num(const std::string& cust_cat,
                                 std::string& cust_cat_num, std::string& err);
extern bool dpi_del_cust_cat_num(const std::string& cust_cat,
                                 std::string& cust_cat_num, std::string& err);
extern bool dpi_cust_cat_add_apps(const std::string& cust_cat_num,
                                  const std::vector<std::string>& apps);
extern bool dpi_get_cust_cat_mark(const std::string& cust_cat,
                                  const std::string& chain,
                                  const std::string& rule, std::string& mark,
                                  std::string& err);
extern void dpi_add_qos_cat(std::string& cat, const std::string& match_no);
extern void dpi_add_qos_cust_cat(const std::string& cat,
                                 const std::string& match_no);
extern void dpi_del_qos_cat(std::string& cat, const std::string& match_no);
extern void dpi_del_qos_cust_cat(const std::string& cat,
                                 const std::string& match_no);

#endif /* _FW_FW_DPI_HPP_ */
