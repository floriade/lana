#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define AF_LANA		27

/* TODO: add support for SIOCGIFINDEX into AF_LANA */
static int device_ifindex(const char *ifname)
{
	int ret, sock, index;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return sock;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, strlen(ifname));

	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (!ret)
		index = ifr.ifr_ifindex;
	else
		index = -1;

	close(sock);
	return index;
}

int main(void)
{
	int sock, ret, idx;
	struct sockaddr sa;
	char buff[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0xac, 0xdc, 0xee, 0xee, 0xee, 0xee };

	sock = socket(AF_LANA, SOCK_RAW, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	idx = device_ifindex("eth10");
	if (idx < 0) {
		ret = idx;
		goto out;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_family = AF_LANA;
	sa.sa_data[0] = (uint8_t) idx;

	ret = bind(sock, &sa, sizeof(sa));
	if (ret < 0) {
		perror("bind");
		goto out;
	}

	ret = sendto(sock, buff, sizeof(buff), 0, &sa, sizeof(sa));
	if (ret < 0) {
		perror("sendmsg");
		goto out;
	}

	ret = 0;
out:
	close(sock);
	return ret;
}

