# Copyright (C) 2018 SCARV project <info@scarv.org>
#
# Use of this source code is restricted per the MIT license, a copy of which 
# can be found at https://opensource.org/licenses/MIT (or should be included 
# as LICENSE.txt within the associated archive or repository).

ALL_TARGETS =
TEST_TARGETS=

include $(REPO_HOME)/src/common.mk

include $(REPO_HOME)/src/aes/bytewise/Makefile.in
include $(REPO_HOME)/src/aes/ttable/Makefile.in
include $(REPO_HOME)/src/aes/v1/Makefile.in
include $(REPO_HOME)/src/aes/v2/Makefile.in
include $(REPO_HOME)/src/aes/v3/Makefile.in
include $(REPO_HOME)/src/aes/tiled/Makefile.in
include $(REPO_HOME)/src/aes/rv64/Makefile.in
include $(REPO_HOME)/src/aes/ttable64/Makefile.in

all: $(ALL_TARGETS)

test: $(TEST_TARGETS)
