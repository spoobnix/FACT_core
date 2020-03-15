#!/usr/bin/env sh
scons --enable-virtualenv -I./contrib/* \
	--install-sandbox=./_build --dir=./src/site_scons \
	--warn=future-depreciated --srcdir=./src

