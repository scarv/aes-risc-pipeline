#!/bin/bash

echo "Installing Verilator."

set -x

sudo apt-get install git make autoconf g++ flex bison
sudo apt-get install libfl2  # Ubuntu only (ignore if gives error)
sudo apt-get install libfl-dev  # Ubuntu only (ignore if gives error)

cd $REPO_HOME/build

git clone https://github.com/verilator/verilator
unset VERILATOR_ROOT  # For bash
cd verilator
export VERILATOR_ROOT=`pwd`
git pull        # Make sure git repository is up-to-date
git checkout stable      # Use most recent stable release
autoconf
./configure
make -j 4

echo "Installation complete"

cd $REPO_HOME

set +x

