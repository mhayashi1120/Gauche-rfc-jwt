#!/bin/sh

set -eu

./configure --disable-ecdsa --enable-werror
make check

make distclean

./configure --enable-werror
make check install validate
