/*
 * Lightweight Autonomic Network Architecture
 *
 * General purpose vlink layer userspace tool for binding low-level
 * transport layers to LANA, i.e. Ethernet, ATM, Bluetooth, Serial
 * Link, Inifiband and so on.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 *
 * Compile: gcc vlink.c -o vlink -O2 -I../src/
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/if.h>

#include "nl_vlink.h"

void main(int argc, char **argv)
{
	int sock;
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
	struct vlinknlmsg *vmsg;

	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_VLINK);

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pad = 0;
	src_addr.nl_pid = getpid();  /* self pid */
	src_addr.nl_groups = 0;

	bind(sock, (struct sockaddr *) &src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pad = 0;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0;

	nlh = malloc(NLMSG_SPACE(sizeof(*vmsg)));
	memset(nlh, 0, NLMSG_SPACE(sizeof(*vmsg)));

	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(*vmsg));
	nlh->nlmsg_pid = getpid();  /* self pid */
	nlh->nlmsg_type = VLINKNLGRP_BLUETOOTH;//VLINKNLGRP_ETHERNET;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	/* Fill in the netlink message payload */
	strcpy(NLMSG_DATA(nlh), "Hello you!");

	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(sock, &msg, 0);

	/* Read message from kernel */
//	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
//	recvmsg(sock, &msg, 0);
//	printf(" Received message payload: %s\n", (char *) NLMSG_DATA(nlh));

	close(sock);
}

