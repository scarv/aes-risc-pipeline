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
	
paper:
	$(MAKE) -C $(REPO_HOME)/doc all

opcodes:
	cat $(REPO_HOME)/src/toolchain/opcodes.txt \
    | python3 $(REPO_HOME)/bin/parse_opcodes.py -check
	cat $(REPO_HOME)/src/toolchain/opcodes.txt \
    | python3 $(REPO_HOME)/bin/parse_opcodes.py -c > build/opcodes-crypto.h

