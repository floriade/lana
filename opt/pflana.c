#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

#define AF_LANA		27

int main(void)
{
	int sock;
	sock = socket(AF_LANA, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	printf("Worked!\n");

	close(sock);
	return 0;
}

