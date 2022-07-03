/*
 * crypto-server.c
 * Simple TCP/IP communication using sockets (with encryption)
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Nikos Pagonas <nikospagonas00@gmail.com>
 * Nikitas Tsinnas <nikitsin2000@gmail.com>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <crypto/cryptodev.h>

#include "virtio-common.h"

/* those global declarations could be common somehow */
unsigned char buf[DATA_SIZE];

struct session_op sess;

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

int encrypt(int cfd)
{
	struct crypt_op cryp;
	struct {
		unsigned char encrypted[DATA_SIZE], iv[BLOCK_SIZE];
	} data;

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = buf;
	cryp.dst = data.encrypted;
	cryp.iv = iv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}

	memcpy(buf, data.encrypted, sizeof(buf));

	return 0;
}

int decrypt(int cfd)
{
	struct crypt_op cryp;
	struct {
		unsigned char decrypted[DATA_SIZE], iv[BLOCK_SIZE];
	} data;

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = buf;
	cryp.dst = data.decrypted;
	cryp.iv = iv;
	cryp.op = COP_DECRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}

	memcpy(buf, data.decrypted, sizeof(buf));

	return 0;
}

int main(int argc, char **argv)
{
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd, cfd;
	ssize_t n;
	socklen_t len;
	struct pollfd fds[N_FDS];
	struct sockaddr_in sa;
	char *filename = argc == 1 ? "/dev/cryptodev0" : argv[1];

	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));

	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY); /* maybe this should be changed ?? */

	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accepting connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}

		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		cfd = open(filename, O_RDWR);
		if (cfd < 0) {
			perror("open(/dev/crypto)");
			return 1;
		}

		memset(&sess, 0, sizeof(sess));

		sess.cipher = CRYPTO_AES_CBC;
		sess.keylen = KEY_SIZE;
		sess.key = key;

		if (ioctl(cfd, CIOCGSESSION, &sess)) {
			perror("ioctl(CIOCGSESSION)");
			return 1;
		}

		fds[0].fd = STDIN;
		fds[0].events = POLLIN;

		fds[1].fd = newsd;
		fds[1].events = POLLIN;

		for (;;) {
			poll(fds, N_FDS, -1);
			if (fds[0].revents & POLLIN) {
				memset(buf, '\0', sizeof(buf));
				n = read(STDIN, buf, sizeof(buf));
				if (n < 0) {
					perror("server --> read from stdin");
					exit(1);
				}

				if (n == 0) {
					break;
				}

				if (encrypt(cfd)) {
					perror("encrypt");
					exit(1);
				}

				if (insist_write(newsd, buf, sizeof(buf)) != sizeof(buf)) {
					perror("server --> write to client");
					exit(1);
				}
			}
			else if (fds[1].revents & POLLIN) {
				n = read(newsd, buf, sizeof(buf));
				if (n < 0) {
					perror("server --> read from client");
					exit(1);
				}

				if (n == 0) {
					fprintf(stderr, "server --> client went away\n");
					break;
				}

				if (decrypt(cfd)) {
					perror("decrypt");
					exit(1);
				}

				if (insist_write(STDOUT, buf, n) != n) {
					perror("server --> write to stdout");
					exit(1);
				}
			}
		}

		if (close(newsd) < 0) {
			perror("close");
		}

		if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
			perror("ioctl(CIOCFSESSION)");
			return 1;
		}

		if (close(cfd) < 0) {
			perror("close(cfd)");
			return 1;
		}
	}

	/* This will never happen */
	return 1;
}
