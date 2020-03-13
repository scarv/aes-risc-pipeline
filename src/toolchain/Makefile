# Copyright (C) 2018 SCARV project <info@scarv.org>
#
# Use of this source code is restricted per the MIT license, a copy of which 
# can be found at https://opensource.org/licenses/MIT (or should be included 
# as LICENSE.txt within the associated archive or repository).

ifndef REPO_HOME
  $(error "execute 'source ./bin/conf.sh' to configure environment")
endif

# =============================================================================

include $(REPO_HOME)/common.mk

clean       :
	rm -rf $(TC_BUILD)
	rm -rf $(TC_INSTALL)

configure   :
	mkdir -p $(TC_BUILD)
	cd $(TC_BUILD) && $(TC_SUBMODULE)/configure \
        --prefix $(TC_INSTALL) \
        --enable-multilib

build       :
	mkdir -p $(TC_INSTALL)
	cd $(TC_BUILD) && make -j 4
	
