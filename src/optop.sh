#!/bin/sh

opcontrol --init
opcontrol --setup --vmlinux=../../linux-2.6/vmlinux
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

