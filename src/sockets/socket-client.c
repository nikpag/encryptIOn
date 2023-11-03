/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Nikos Pagonas <nikospagonas00@gmail.com>
 * Nikitas Tsinnas <nikitsin2000@gmail.com>
 */

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;

	while (cnt > 0) {
		ret = write(fd, buf, cnt);
		if (ret < 0)
			return ret;
		buf += ret;
		cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char **argv)
{
	int sd, port;
	ssize_t n;
	char buf[100];
	char *hostname;
	struct pollfd fds[N_FDS];
	struct hostent *hp;
	struct sockaddr_in sa;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]);

	/* Create TCP/IP socket, used as main chat channel */

	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Look up remote hostname on DNS */
	if (!(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr_list[0], sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... ");
	fflush(stderr);
	if (connect(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	fds[0].fd = 0;		/* 0 for stdin */
	fds[0].events = POLLIN; /* There is data to read */

	fds[1].fd = sd; /* socket descriptor */
	fds[1].events = POLLIN;

	for (;;) {
		poll(fds, N_FDS, -1);
		/* if there is actually data to read from stdin */
		if (fds[0].revents & POLLIN) {
			n = read(STDIN, buf, sizeof(buf));
			if (n < 0) {
				perror("client --> read from stdin:");
				exit(1);
			}
			if (n == 0) {
				break;
			}
			if (insist_write(sd, buf, n) != n) {
				perror("client --> write to server");
				exit(1);
			}
		}
		/* if there is actually data to read from socket */
		else if (fds[1].revents & POLLIN) {
			n = read(sd, buf, sizeof(buf));
			if (n < 0) {
				perror("client --> read from server:");
				// break;
				exit(1);
			}
			if (n == 0) {
				fprintf(stderr, "client --> server went away\n");
				break;
			}
			if (insist_write(STDOUT, buf, n) != n) {
				perror("client --> write to stdout");
				exit(1);
			}
		}
	}

	/* should we close socket here ?? */
	if (close(sd) < 0) {
		perror("close(sd)");
		exit(1);
	};

	return 0;
}
