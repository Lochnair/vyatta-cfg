if CROSS_BUILD
usr_prefix_ = /usr/$(host_alias)
libc_prefix_ = $(usr_prefix_)/lib
else
usr_prefix_ = /usr
libc_prefix_ = /lib
endif
libc_file_ = $(word 1, $(wildcard $(libc_prefix_)/libc-*.so))

PERL_MODS = Cstore

# nop for all-local. make install will do a build anyway, so don't repeat
# the build here.
all-local: ;

XX_ENV = HOST_ALIAS=$(host_alias) BUILD_ALIAS=$(build_alias)
CLDIR = $(usr_prefix_)/lib
MM_ENV = AR=$(AR) CC=$(CXX) FULL_AR=$$(which $(AR)) LD=$(CXX)
MM_ENV += LDDLFLAGS='-shared -O2 -g -L$(CLDIR)'
MM_ENV += LDFLAGS='-L$(CLDIR)'
MM_ENV += LIBC=$(libc_file_)

install-exec-local:
	for pm in $(PERL_MODS); do \
		(cd $$pm; \
		 $(XX_ENV) perl Makefile.PL $(MM_ENV); \
		 $(MAKE) $(AM_MAKEFLAGS) install); \
	done

clean-local:
	for pm in $(PERL_MODS); do \
		(cd $$pm; \
		 $(XX_ENV) perl Makefile.PL $(MM_ENV); \
		 $(MAKE) $(AM_MAKEFLAGS) realclean); \
	done

# nops
check-local: ;
install-data-local: ;
uninstall-local: ;

