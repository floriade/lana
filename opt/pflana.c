#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
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
	int sock;
	char buff[256];
	struct iovec iov[1];
	struct msghdr msg;

	register_signal(SIGINT, intr);
	sock = socket(AF_LANA, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	memset(&msg, 0, sizeof(msg));
	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = buff;
	iov[0].iov_len = sizeof(buff);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	printf("Worked! Abort with ^C\n");
	while (!sigint) {
		int ret = recvmsg(sock, &msg, 0);
		if (ret < 0) {
			perror("recvmsg");
			sleep(1);
			continue;
		} else {
			printf("msg received: %s!\n", (char *) iov[0].iov_base);
			break;
		}
	}

	close(sock);
	return 0;
}

