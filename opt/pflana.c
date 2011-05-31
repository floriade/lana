#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/socket.h>

#define AF_LANA		27

static sig_atomic_t sigint = 0;

static void intr(int sig)
{
	sigint = 1;
}

static inline void register_signal(int signal, void (*handler)(int))
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);
	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = SA_RESTART;

	sigaction(signal, &saction, NULL);
}

int main(void)
{
	int sock, i;
	char buff[256];

	register_signal(SIGINT, intr);
	sock = socket(AF_LANA, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

/*
	printf("Worked! Abort with ^C\n");
	while (!sigint) {
		memset(buff, 0, sizeof(buff));
		int ret = recv(sock, buff, sizeof(buff), 0);
		if (ret < 0) {
			perror("recvmsg");
			sleep(1);
			continue;
		} else {
			assert(ret <= sizeof(buff));
			for (i = 0; i < ret; i++)
				printf("0x%x ", buff[i]);
			printf("\n\n");
		}
	}
*/

	close(sock);
	return 0;
}

