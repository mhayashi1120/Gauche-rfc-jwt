#!/bin/sh

set -eu

./configure --disable-ecdsa
make check

make distclean

./configure
make check install validate
