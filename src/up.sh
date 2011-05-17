#!/bin/sh

insmod lana.ko
insmod sd_rr.ko
insmod fb_dummy.ko

#echo "1" > /proc/net/lana/sched/sched_cpu

../usr/fbctl add fb1 dummy
../usr/fbctl add fb2 dummy
../usr/fbctl add fb3 dummy
../usr/fbctl bind fb1 fb2
../usr/fbctl bind fb2 fb3

insmod testskb2.ko

echo "up"
