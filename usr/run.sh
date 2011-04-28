#!/bin/sh

export FBCFG_PRELOAD_DIR=../src/

./fbcfg preload lana
./fbcfg preload sd_rr
./fbcfg preload sd_blackhole
./fbcfg preload fb_ethvlink
./fbcfg preload fb_dummy

./fbcfg add fb1 dummy
./fbcfg add fb2 dummy
./fbcfg add fb3 dummy

./fbcfg bind fb1 fb2
./fbcfg bind fb2 fb3

