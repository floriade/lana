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
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

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

int main(void)
{
	int sock, ret;
	char buff[1600];
        struct timespec before, after;
	unsigned long long pkts = 0, byte = 0;
	double x1, x2, elapsed;

	if (geteuid() != 0) {
		fprintf(stderr, "Not root?!\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, sig_handler);

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
	while (!sigint) {
		ret = recv(sock, buff, sizeof(buff), 0);
		if (ret < 0) {
			perror("recvmsg");
			continue;
		} else {
			pkts++;
			byte += ret;
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

