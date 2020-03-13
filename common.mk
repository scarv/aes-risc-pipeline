# Copyright (C) 2018 SCARV project <info@scarv.org>
#
# Use of this source code is restricted per the MIT license, a copy of which 
# can be found at https://opensource.org/licenses/MIT (or should be included 
# as LICENSE.txt within the associated archive or repository).

#
# This makefile contains common parameters used across the repository
# ----------------------------------------------------------------------


#
# Toolchain paths
# ----------------------------------------------------------------------

TC_SUBMODULE    = $(REPO_HOME)/extern/riscv-gnu-toolchain
TC_BUILD        = $(REPO_BUILD)/toolchain/build
TC_INSTALL      = $(REPO_BUILD)/toolchain/install

PK_SUBMODULE    = $(REPO_HOME)/extern/riscv-pk
PK_BUILD        = $(REPO_BUILD)/pk
PK_INSTALL      = $(TC_INSTALL)

SPIKE_SUBMODULE = $(REPO_HOME)/extern/riscv-isa-sim
SPIKE_BUILD     = $(REPO_BUILD)/spike
SPIKE_INSTALL   = $(TC_INSTALL)
SPIKE_PATCH     = $(REPO_HOME)/src/toolchain/spike.patch

RISCV_HOST   = riscv64-unknown-elf

