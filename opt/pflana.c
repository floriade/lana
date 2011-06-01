#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/socket.h>

#define AF_LANA		27

int main(void)
{
	int sock, i;
	char buff[1600];

	sock = socket(AF_LANA, SOCK_RAW, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	printf("Worked! Abort with ^C\n");
	while (1) {
		memset(buff, 0, sizeof(buff));
		int ret = recv(sock, buff, sizeof(buff), 0);
		if (ret < 0) {
			perror("recvmsg");
			continue;
		} else {
			assert(ret <= sizeof(buff));
			printf("RECEIVED ......\n");
			printf("hex:\n");
			for (i = 0; i < ret; i++)
				printf("0x%.2x ", (uint8_t) buff[i]);
			printf("ascii:\n");
			for (i = 0; i < ret; i++)
				printf("%c ", isprint(buff[i]) ? buff[i] : '.');
			printf("\n\n");
			fflush(stdout);
		}
	}

	close(sock);
	return 0;
}

