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

#
# Binutils
# ------------------------------------------------------------
	
binutils-update-patch:
	cd $(BINUTILS_SUBMODULE) && git diff --cached > $(BINUTILS_PATCH)

binutils-apply-patch:
	cd $(BINUTILS_SUBMODULE) && git apply $(BINUTILS_PATCH) && git add --all

binutils-revert-patch:
	cd $(BINUTILS_SUBMODULE) && \
    git reset HEAD && git checkout . &&  git clean -df

binutils-build:
	cd $(TC_BUILD)/build-binutils-newlib && make install

#
# Spike
# ------------------------------------------------------------

spike-configure    :
	mkdir -p $(SPIKE_BUILD)
	export PATH=$(TC_INSTALL)/bin:$(PATH) && \
	cd $(SPIKE_BUILD) && \
    $(SPIKE_SUBMODULE)/configure \
        --prefix=$(TC_INSTALL)

spike-update-patch:
	cd $(SPIKE_SUBMODULE) && git diff --cached > $(SPIKE_PATCH)

spike-apply-patch:
	cd $(SPIKE_SUBMODULE) && git apply $(SPIKE_PATCH) && git add --all

spike-revert-patch:
	cd $(SPIKE_SUBMODULE) && \
    git reset HEAD && git checkout . &&  git clean -df

spike-build:    
	mkdir -p $(SPIKE_INSTALL)
	export PATH=$(TC_INSTALL)/bin:$(PATH) && \
	cd $(SPIKE_BUILD) && \
    make -j 4 && make install

#
# Proxy Kernel
# ------------------------------------------------------------

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
