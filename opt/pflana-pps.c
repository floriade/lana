/* Compile with -lrt */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#define AF_LANA		27

static sig_atomic_t sigint = 0;

static inline double timespec_to_double(const struct timespec *time)
{
	return time->tv_nsec * 1E-9 + (double) time->tv_sec;
}

static void sig_handler(int sig)
{
	if (sig == SIGINT)
		sigint = 1;
}

int main(int argc, char **argv)
{
	int sock, ret;
	char buff[1600];
        struct timespec before, after;
	unsigned long long pkts = 0, byte = 0, max;
	double x1, x2, elapsed;

	if (geteuid() != 0) {
		fprintf(stderr, "Not root?!\n");
		exit(EXIT_FAILURE);
	}
//	if (argc != 2) {
//		fprintf(stderr, "No pkt number given!\n");
//		exit(EXIT_FAILURE);
//	}
//	max = (unsigned long long) atol(argv[argc - 1]);
//
	signal(SIGINT, sig_handler);

	sock = socket(AF_LANA, SOCK_RAW, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	printf("Hit key to start!\n");
	getchar();
	printf("Abort with ^C\n");

	memset(&before, 0, sizeof(before));
	memset(&after, 0, sizeof(after));

        clock_gettime(CLOCK_REALTIME, &before);
	while (!sigint/* || pkts > max*/) {
		ret = recv(sock, buff, sizeof(buff), 0);
		if (ret < 0) {
			perror("recvmsg");
			continue;
		} else {
			pkts++;
			byte += ret;
//			printf("got\n");
		}
	}
        clock_gettime(CLOCK_REALTIME, &after);

	x1 = timespec_to_double(&after);
	x2 = timespec_to_double(&before);
	elapsed = x1 - x2;

	printf("\n\n");
	fflush(stdout);
	printf("time: %lf, pkts/s: %.2lf, bytes/s: %.2lf\n",
	       elapsed, 1.0 * pkts / elapsed, 1.0 * byte / elapsed);

	close(sock);
	return 0;
}

