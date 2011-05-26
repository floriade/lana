#include <stdio.h>
#include <unistd.h>
#include <signal.h>
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
	register_signal(SIGINT, intr);
	sock = socket(AF_LANA, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	printf("Worked! Abort with ^C\n");
	while (!sigint);

	close(sock);
	return 0;
}

