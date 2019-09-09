SUBDIRS = . perl_dmod

share_perl5dir = /opt/vyatta/share/perl5/Vyatta
completiondir	 = /etc/bash_completion.d
initddir	 = /etc/init.d
logrotatedir = /etc/logrotate.d
defaultdir = /etc/default
etc_shell_leveldir = $(sysconfdir)/shell/level
dhcphookdir = /etc/dhcp3/dhclient-exit-hooks.d
enumdir = $(datadir)/enumeration
rsbindir = /usr/sbin
preconfigdir = /etc/ubnt/pre-config.d

if CROSS_BUILD
usr_prefix_ = /usr/$(host_alias)
else
usr_prefix_ = /usr
endif

common_args = -Wall -Isrc -I$(usr_prefix_)/include
AM_CFLAGS = $(common_args) -D_FILE_OFFSET_BITS=64
AM_CXXFLAGS = -Werror $(common_args) -D_FILE_OFFSET_BITS=64
AM_YFLAGS = -d --name-prefix=yy_`basename $* .y`_
AM_LFLAGS = --prefix=yy_`basename $* .l`_ -olex.yy.c

completion_DATA = etc/bash_completion.d/vyatta-cfg
initd_SCRIPTS	= etc/init.d/vyatta-router
preconfig_SCRIPTS = etc/ubnt/pre-config.d/dhcp-options
dhcphook_SCRIPTS = scripts/vyatta-dhclient-hook
dhcphook_SCRIPTS += scripts/vyatta-dhclient-p2p
logrotate_DATA = etc/logrotate.d/vyatta-config-logs

src/cparse/cparse.cpp: src/cparse/cparse.ypp src/cparse/cparse_def.h
	bison -p cparse_ --defines=src/cparse/cparse.h -o $@ $<

src/cparse/cparse_lex.c: src/cparse/cparse_lex.l src/cparse/cparse.cpp
	flex -P cparse_ -o $@ $<

BUILT_SOURCES = src/cli_parse.h
lib_LTLIBRARIES = src/libvyatta-cfg.la
src_libvyatta_cfg_la_LIBADD = -lboost_system -lboost_filesystem
src_libvyatta_cfg_la_LIBADD += -lapt-pkg -lperl
src_libvyatta_cfg_la_LDFLAGS = -version-info 1:0:0
src_libvyatta_cfg_la_SOURCES = src/cli_parse.y src/cli_def.l src/cli_val.l
src_libvyatta_cfg_la_SOURCES += src/cli_new.c src/cli_path_utils.c
src_libvyatta_cfg_la_SOURCES += src/cli_val_engine.c src/cli_objects.c
src_libvyatta_cfg_la_SOURCES += src/cstore/cstore-c.cpp
src_libvyatta_cfg_la_SOURCES += src/cstore/cstore.cpp
src_libvyatta_cfg_la_SOURCES += src/cstore/cstore-varref.cpp
src_libvyatta_cfg_la_SOURCES += src/cstore/unionfs/cstore-unionfs.cpp
src_libvyatta_cfg_la_SOURCES += src/cnode/cnode.cpp
src_libvyatta_cfg_la_SOURCES += src/cnode/cnode-algorithm.cpp
src_libvyatta_cfg_la_SOURCES += src/cparse/cparse.cpp
src_libvyatta_cfg_la_SOURCES += src/cparse/cparse_lex.c
src_libvyatta_cfg_la_SOURCES += src/commit/commit-algorithm.cpp
CLEANFILES = src/cli_parse.c src/cli_parse.h src/cli_def.c src/cli_val.c
CLEANFILES += src/cparse/cparse.cpp src/cparse/cparse.h
CLEANFILES += src/cparse/cparse_lex.c
LDADD = src/libvyatta-cfg.la

vincludedir = $(includedir)/vyatta-cfg
vinclude_HEADERS = src/cli_cstore.h

vcincdir = $(vincludedir)/cstore
vcinc_HEADERS = src/cstore/cstore-c.h
vcinc_HEADERS += src/cstore/cstore.hpp
vcinc_HEADERS += src/cstore/cstore-varref.hpp
vcinc_HEADERS += src/cstore/ctemplate.hpp

vcuincdir = $(vcincdir)/unionfs
vcuinc_HEADERS = src/cstore/unionfs/cstore-unionfs.hpp

vnincdir = $(vincludedir)/cnode
vninc_HEADERS = src/cnode/cnode.hpp
vninc_HEADERS += src/cnode/cnode-algorithm.hpp

vpincdir = $(vincludedir)/cparse
vpinc_HEADERS = src/cparse/cparse.hpp

sbin_PROGRAMS = src/check_tmpl
sbin_PROGRAMS += src/my_cli_bin
sbin_PROGRAMS += src/my_cli_shell_api
sbin_PROGRAMS += src/ubnt/ubnt-cfgd
sbin_PROGRAMS += src/ubnt/ubnt-cfg-checks
sbin_PROGRAMS += src/ubnt/ubnt-dhclient-nodns

src_check_tmpl_SOURCES = src/check_tmpl.c
src_my_cli_bin_SOURCES = src/cli_bin.cpp
src_my_cli_bin_LDADD = src/libvyatta-cfg.la -lpthread

src_my_cli_shell_api_SOURCES = src/cli_shell_api.cpp

src_ubnt_ubnt_cfgd_SOURCES = src/ubnt/ubnt-cfgd.cpp
src_ubnt_ubnt_cfgd_LDADD = src/libvyatta-cfg.la
src_ubnt_ubnt_cfgd_LDADD += -lboost_system -lboost_thread
src_ubnt_ubnt_cfgd_LDADD += -lboost_serialization -lpthread

src_ubnt_ubnt_cfg_checks_SOURCES = src/ubnt/ubnt-cfg-checks.cpp
src_ubnt_ubnt_cfg_checks_LDADD = src/libvyatta-cfg.la

rsbin_PROGRAMS = src/ubnt/fw/ubnt-fw
rsbin_PROGRAMS += src/ubnt/fw/ubnt-fw-group
rsbin_PROGRAMS += src/ubnt/fw/ubnt-fw-syntax
rsbin_PROGRAMS += src/ubnt/ubnt-check-cfgfile
rsbin_PROGRAMS += src/ubnt/interface/ubnt-interface
rsbin_PROGRAMS += src/ubnt/tc/ubnt-tc
rsbin_PROGRAMS += src/ubnt/ubnt-gw-check
rsbin_PROGRAMS += src/ubnt/ubnt-bridge

src_ubnt_fw_ubnt_fw_SOURCES = src/ubnt/fw/fw.cpp src/ubnt/fw/fw.hpp
src_ubnt_fw_ubnt_fw_SOURCES += src/ubnt/fw/rule.cpp src/ubnt/fw/rule.hpp
src_ubnt_fw_ubnt_fw_SOURCES += src/ubnt/fw/address.cpp src/ubnt/fw/address.hpp
src_ubnt_fw_ubnt_fw_SOURCES += src/ubnt/fw/fw_pbr.cpp src/ubnt/fw/fw_pbr.hpp
src_ubnt_fw_ubnt_fw_SOURCES += src/ubnt/fw/fw_wlb.cpp src/ubnt/fw/fw_wlb.hpp
src_ubnt_fw_ubnt_fw_SOURCES += src/ubnt/fw/fw_dpi.cpp src/ubnt/fw/fw_dpi.hpp
src_ubnt_fw_ubnt_fw_SOURCES += src/ubnt/fw/util.cpp src/ubnt/fw/util.hpp
src_ubnt_fw_ubnt_fw_LDADD = src/libvyatta-cfg.la -lpcre

src_ubnt_fw_ubnt_fw_group_SOURCES = src/ubnt/fw/fw_group.cpp
src_ubnt_fw_ubnt_fw_group_SOURCES += src/ubnt/fw/fw_group.hpp
src_ubnt_fw_ubnt_fw_group_SOURCES += src/ubnt/fw/group.cpp
src_ubnt_fw_ubnt_fw_group_SOURCES += src/ubnt/fw/group.hpp
src_ubnt_fw_ubnt_fw_group_SOURCES += src/ubnt/fw/util.cpp src/ubnt/fw/util.hpp
src_ubnt_fw_ubnt_fw_group_LDADD = src/libvyatta-cfg.la

src_ubnt_fw_ubnt_fw_syntax_SOURCES = src/ubnt/fw/fw_syntax.cpp
src_ubnt_fw_ubnt_fw_syntax_SOURCES += src/ubnt/fw/util.cpp
src_ubnt_fw_ubnt_fw_syntax_SOURCES += src/ubnt/fw/util.hpp

src_ubnt_ubnt_check_cfgfile_SOURCES = src/ubnt/ubnt-check-cfgfile.cpp
src_ubnt_ubnt_check_cfgfile_LDADD = src/libvyatta-cfg.la

src_ubnt_ubnt_dhclient_nodns_SOURCES = src/ubnt/ubnt-dhclient-nodns.cpp
src_ubnt_ubnt_dhclient_nodns_LDADD = src/libvyatta-cfg.la -lstdc++

src_ubnt_interface_ubnt_interface_SOURCES = src/ubnt/interface/ubnt_interface.cpp
src_ubnt_interface_ubnt_interface_SOURCES += src/ubnt/interface/ubnt_interface.hpp
src_ubnt_interface_ubnt_interface_SOURCES += src/ubnt/lib/vyatta_interface.cpp
src_ubnt_interface_ubnt_interface_SOURCES += src/ubnt/lib/vyatta_interface.hpp
src_ubnt_interface_ubnt_interface_SOURCES += src/ubnt/lib/vyatta_config.cpp
src_ubnt_interface_ubnt_interface_SOURCES += src/ubnt/lib/vyatta_config.hpp
src_ubnt_interface_ubnt_interface_LDADD = src/libvyatta-cfg.la -lpcre
src_ubnt_interface_ubnt_interface_LDADD += -lboost_system -lboost_filesystem

src_ubnt_tc_ubnt_tc_SOURCES = src/ubnt/tc/ubnt-tc.cpp
src_ubnt_tc_ubnt_tc_SOURCES += src/ubnt/lib/vyatta_config.cpp
src_ubnt_tc_ubnt_tc_SOURCES += src/ubnt/lib/vyatta_config.hpp
src_ubnt_tc_ubnt_tc_LDADD = src/libvyatta-cfg.la -lpcre

src_ubnt_ubnt_gw_check_SOURCES = src/ubnt/ubnt-gw-check.cpp
src_ubnt_ubnt_gw_check_SOURCES += src/ubnt/lib/vyatta_config.cpp
src_ubnt_ubnt_gw_check_SOURCES += src/ubnt/lib/vyatta_config.hpp
src_ubnt_ubnt_gw_check_LDADD = src/libvyatta-cfg.la -lpcre

src_ubnt_ubnt_bridge_SOURCES = src/ubnt/ubnt-bridge.cpp
src_ubnt_ubnt_bridge_SOURCES += src/ubnt/lib/vyatta_interface.cpp
src_ubnt_ubnt_bridge_SOURCES += src/ubnt/lib/vyatta_interface.hpp
src_ubnt_ubnt_bridge_SOURCES += src/ubnt/lib/vyatta_config.cpp
src_ubnt_ubnt_bridge_SOURCES += src/ubnt/lib/vyatta_config.hpp
src_ubnt_ubnt_bridge_LDADD = src/libvyatta-cfg.la -lpcre
src_ubnt_ubnt_bridge_LDADD += -lboost_system -lboost_filesystem

sbin_SCRIPTS = scripts/vyatta-cfg-cmd-wrapper
sbin_SCRIPTS += scripts/vyatta-validate-type.pl
sbin_SCRIPTS += scripts/vyatta-find-type.pl
sbin_SCRIPTS += scripts/priority.pl
sbin_SCRIPTS += scripts/vyatta-boot-config-loader
sbin_SCRIPTS += scripts/vyatta-config-gen-sets.pl
sbin_SCRIPTS += scripts/vyatta-cli-expand-var.pl
sbin_SCRIPTS += scripts/vyatta-output-config.pl
sbin_SCRIPTS += scripts/vyatta-save-config.pl
sbin_SCRIPTS += scripts/vyatta-load-config.pl
sbin_SCRIPTS += scripts/vyatta-cfg-notify
sbin_SCRIPTS += scripts/vyatta-check-typeless-node.pl
sbin_SCRIPTS += scripts/ifname2path.pl

share_perl5_DATA = lib/Vyatta/Config.pm
share_perl5_DATA += lib/Vyatta/File.pm
share_perl5_DATA += lib/Vyatta/Misc.pm
share_perl5_DATA += lib/Vyatta/Interface.pm
share_perl5_DATA += lib/Vyatta/TypeChecker.pm
share_perl5_DATA += lib/Vyatta/ConfigOutput.pm
share_perl5_DATA += lib/Vyatta/ConfigLoad.pm
share_perl5_DATA += lib/Vyatta/Keepalived.pm

enum_SCRIPTS  = scripts/enumeration/existing-interfaces

default_DATA = etc/default/vyatta-cfg
default_DATA += etc/default/vyatta-load-boot

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(etc_shell_leveldir)
	cd etc/shell/level; $(cpiop) $(DESTDIR)$(etc_shell_leveldir)
	cd $(DESTDIR)$(sbindir); \
	  $(LN_S) my_cli_bin my_set; \
	  $(LN_S) my_cli_bin my_delete; \
	  $(LN_S) my_cli_bin my_rename; \
	  $(LN_S) my_cli_bin my_copy; \
	  $(LN_S) my_cli_bin my_comment; \
	  $(LN_S) my_cli_bin my_discard; \
	  $(LN_S) my_cli_bin my_move; \
	  $(LN_S) my_cli_bin my_commit
	mkdir -p $(DESTDIR)/bin
	cd $(DESTDIR)/bin ; \
	  $(LN_S) $(sbindir)/my_cli_shell_api cli-shell-api

