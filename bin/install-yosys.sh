#!/bin/bash

echo "Installing yosys."

set -x

sudo apt-get install build-essential clang bison flex \
	libreadline-dev gawk tcl-dev libffi-dev git \
	graphviz xdot pkg-config python3 libboost-system-dev \
	libboost-python-dev libboost-filesystem-dev zlib1g-dev

cd $REPO_HOME/build
git clone https://github.com/cliffordwolf/yosys.git
cd yosys
git checkout 1dbc7017 # v0.9-1706
export YOSYS_ROOT=`pwd`
make config-gcc
make -j $(nproc)

echo "Installation complete"

cd $REPO_HOME

set +x

