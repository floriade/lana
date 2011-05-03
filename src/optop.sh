#!/bin/sh

opcontrol --init
if [ $# -eq 0 ] ; then
        opcontrol --setup --vmlinux=../../linux-2.6/vmlinux
else
        opcontrol --setup --vmlinux=../../linux-2.6/vmlinux --event=$@
fi
opcontrol --status

opcontrol --start
while true; do
	sleep 1
	opcontrol --dump
	clear
	opreport -l -p ./ 2> /dev/zero | head -40
	opcontrol --reset
done

opcontrol --shutdown

