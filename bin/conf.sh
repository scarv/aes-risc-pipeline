#!/bin/bash

# Copyright (C) 2019 SCARV project <info@scarv.org>
#
# Use of this source code is restricted per the MIT license, a copy of which
# can be found at https://opensource.org/licenses/MIT (or should be included
# as LICENSE.txt within the associated archive or repository).

echo "-------------------------[Setting Up Project]--------------------------"

export REPO_HOME="${PWD}"
export REPO_BUILD=$REPO_HOME/build

if [ -z $RISCV ] ; then
    export RISCV=$REPO_BUILD/toolchain/install
    echo "\$RISCV is empty. Setting to '$RISCV'"
else
    echo "\$RISCV is already set to '$RISCV'"
fi

export TEXMFLOCAL="${TEXMFLOCAL}:${REPO_HOME}/extern/texmf"

if [ -z $YOSYS_ROOT ] ; then
    # Export a dummy "Yosys Root" path environment variable.
    export YOSYS_ROOT=$REPO_HOME/build/yosys
    echo "\$YOSYS_ROOT is empty. Setting to '$YOSYS_ROOT'"
fi

if [[ -z "$VERILATOR_ROOT" ]]; then
    export VERILATOR_ROOT=$REPO_HOME/build/verilator
    echo "\$VERILATOR_ROOT is empty. Setting to '$VERILATOR_ROOT'"
fi

echo "----"
echo "REPO_HOME      = $REPO_HOME"
echo "REPO_BUILD     = $REPO_BUILD"
echo "YOSYS_ROOT     = $YOSYS_ROOT"
echo "VERILATOR_ROOT = $VERILATOR_ROOT"
echo "RISCV          = $RISCV"

echo "------------------------------[Finished]-------------------------------"

