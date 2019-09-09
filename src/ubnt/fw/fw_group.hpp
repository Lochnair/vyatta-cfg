#ifndef _FW_FW_GROUP_HPP_
#define _FW_FW_GROUP_HPP_

#include <regex.h>

#include <cstore/cstore.hpp>

extern cstore::Cstore *g_cstore;

extern std::string ipset;

extern regex_t type_regex;
extern regex_t refs_regex;
extern regex_t memb_regex;
extern regex_t rang_regex;
extern regex_t p_rang_regex;
extern regex_t loct_regex;
extern regex_t addm_regex;
extern regex_t p_name_regex;
extern regex_t family_regex;

#endif /* _FW_FW_GROUP_HPP_ */
