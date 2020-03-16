# Copyright (C) 2018 SCARV project <info@scarv.org>
#
# Use of this source code is restricted per the MIT license, a copy of which 
# can be found at https://opensource.org/licenses/MIT (or should be included 
# as LICENSE.txt within the associated archive or repository).


#
# Toolchain program paths
# ----------------------------------------------------------------------

include $(REPO_HOME)/common.mk

RISCV_PREFIX=riscv64-unknown-elf

CC      = $(TC_INSTALL)/bin/$(RISCV_PREFIX)-gcc
AS      = $(TC_INSTALL)/bin/$(RISCV_PREFIX)-as
AR      = $(TC_INSTALL)/bin/$(RISCV_PREFIX)-ar
OBJDUMP = $(TC_INSTALL)/bin/$(RISCV_PREFIX)-objdump
SPIKE   = $(TC_INSTALL)/bin/spike
PK32    = $(TC_INSTALL)/riscv32-unknown-elf/bin/pk
PK64    = $(TC_INSTALL)/riscv64-unknown-elf/bin/pk

REPO_SW_BUILD = $(REPO_BUILD)/src

TEST_SRC    = $(REPO_HOME)/src/test/test_aes.c \
              $(REPO_HOME)/src/test/test_util.c

CFLAGS     += -Wall -O2
CFLAGS     += -I$(REPO_HOME)/src/aes
CFLAGS     += -I$(REPO_HOME)/src/aes/share

#
# Build Macros
# ----------------------------------------------------------------------

# 1. Name of the AES variant
# 2. Object files to generate a path for
define map_object
$(patsubst $(REPO_HOME)/src/%,$(REPO_SW_BUILD)/obj/%,${2:%.c=%.o})
endef

# 1. Name of the AES variant
define map_lib
$(REPO_SW_BUILD)/lib/${1}.a
endef

# 1. Name of the AES variant
define map_aes_header
$(REPO_SW_BUILD)/include/aes.h
endef

# 1. Name of the AES variant
define map_test_program
$(REPO_SW_BUILD)/bin/test_${1}.elf
endef

# 1. Name of the AES variant
define map_test_output
$(REPO_SW_BUILD)/test/test_${1}.py
endef

# 1. Name of the AES variant
define map_test_result
$(REPO_SW_BUILD)/test/test_${1}.log
endef


# 1. AES variant name
# 2. source C file
# 3. Extra C flags
define add_obj_target

$(call map_object,${1},${2}) : ${2}
	@mkdir -p $(dir $(call map_object,${1},${2}))
	$(CC) $(CFLAGS) ${3} -c -o $${@} $${^}
	$(OBJDUMP) -D $${@} > $${@}.dis
endef

# 1. Name of the AES variant
# 2. The source files which make it up.
# 3. Extra Build flags
define add_aes_lib_target

$(foreach F,${2},$(call add_obj_target,${1},${F},${3}))

$(call map_lib,${1}) : $(call map_object,${1},${2})
	@mkdir -p $(dir $(call map_lib,${1}))
	$(AR) rcs $${@} $${^}

$(call map_aes_header,${1}) : $(REPO_HOME)/src/aes/aes.h
	@mkdir -p $(dir $(call map_aes_header,${1}))
	cp $${<} $${@}

aes-${1}: $(call map_lib,${1}) \
          $(call map_object,${1},${2}) \
          $(call map_aes_header,${1})

ALL_TARGETS += aes-${1}

endef


# 1. AES variant name to test
# 2. Compiler flags
# 3. Spike flags
# 4. Proxy Kernel Binary
define add_aes_test_target

$(call map_test_program,${1}) : $(TEST_SRC) $(call map_lib,${1})
	@mkdir -p $(dir $(call map_test_program,${1}))
	$(CC) $(CFLAGS) ${2} -DAES_VARIANT=${1} \
        -I $(REPO_HOME)/src/test \
        -o $${@} $${^}
	$(OBJDUMP) -D $${@} > $${@}.dis

ALL_TARGETS += $(call map_test_program,${1})

$(call map_test_output,${1}) : $(call map_test_program,${1})
	@mkdir -p $(dir $(call map_test_output,${1}))
	$(SPIKE) ${3} ${4} $${<} > $${@}
	sed -i "s/^bbl loader/#/" $${@}

$(call map_test_result,${1}) : $(call map_test_output,${1})
	@mkdir -p $(dir $(call map_test_result,${1}))
	python3 $${<} > $${@}

test-${1} : $(call map_test_program,${1}) \
            $(call map_test_output,${1}) \
            $(call map_test_result,${1})
endef

