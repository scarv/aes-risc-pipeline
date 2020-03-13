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

toolchain-% :
	$(MAKE) -C $(REPO_HOME)/src/toolchain ${*}
	
pk-configure    :
	mkdir -p $(PK_BUILD)
	export PATH=$(TC_INSTALL)/bin:$(PATH) && \
	cd $(PK_BUILD) && \
    $(PK_SUBMODULE)/configure \
        --prefix=$(TC_INSTALL) \
        --host=$(RISCV_HOST)

pk-build:    
	mkdir -p $(PK_INSTALL)
	export PATH=$(TC_INSTALL)/bin:$(PATH) && \
	cd $(PK_BUILD) && \
    make && make install

spike-configure    :
	mkdir -p $(SPIKE_BUILD)
	export PATH=$(TC_INSTALL)/bin:$(PATH) && \
	cd $(SPIKE_BUILD) && \
    $(SPIKE_SUBMODULE)/configure \
        --prefix=$(TC_INSTALL)

spike-build:    
	mkdir -p $(SPIKE_INSTALL)
	export PATH=$(TC_INSTALL)/bin:$(PATH) && \
	cd $(SPIKE_BUILD) && \
    make -j 4 && make install
