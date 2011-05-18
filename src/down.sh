#!/bin/sh

sleep 1

#rmmod testskb

../usr/fbctl unbind fb3 fb2
../usr/fbctl unbind fb2 fb1
../usr/fbctl rm fb3
../usr/fbctl rm fb2
../usr/fbctl rm fb1

echo "-1" > /proc/net/lana/ppesched

sleep 1

rmmod fb_dummy
rmmod fb_eth

sleep 1

rmmod sd_rand
rmmod lana

echo "down"

