#!/bin/sh

rmmod testskb

../usr/fbctl unbind fb2 fb3
../usr/fbctl unbind fb1 fb2
../usr/fbctl rm fb3
../usr/fbctl rm fb2
../usr/fbctl rm fb1

echo "-1" > /proc/net/lana/ppesched

sleep 1

rmmod fb_dummy
rmmod sd_blackhole
rmmod lana

