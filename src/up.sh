#!/bin/sh

insmod lana.ko

sleep 5
echo "starting"

insmod sd_rr.ko
#echo "1" > /proc/net/lana/sched/sched_cpu
insmod fb_eth.ko
insmod fb_dummy.ko

../usr/fbctl add fb1 eth
#../usr/fbctl add fb1 dummy
../usr/fbctl add fb2 dummy
../usr/fbctl add fb3 dummy
../usr/fbctl bind fb3 fb2
../usr/fbctl bind fb2 fb1
#../usr/fbctl bind fb1 fb2
#../usr/fbctl bind fb2 fb3

#insmod testskb.ko

echo "up"
