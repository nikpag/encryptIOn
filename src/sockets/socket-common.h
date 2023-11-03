/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Nikos Pagonas <nikospagonas00@gmail.com>
 * Nikitas Tsinnas <nikitsin2000@gmail.com>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT 35001
#define TCP_BACKLOG 5

#define N_FDS 2
#define STDIN 0
#define STDOUT 1
#define STDERR 2

#endif /* _SOCKET_COMMON_H */
