#!/bin/sh

set -eu

./configure --disable-esdsa
make check

make distclean

./configure
make check
