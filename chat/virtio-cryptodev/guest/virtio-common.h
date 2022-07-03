/*
 * crypto-common.h
 *
 * Simple TCP/IP communication using sockets (with encryption)
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

#define HELLO_THERE "Hello there!"

#define N_FDS 2
#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define DATA_SIZE 128
#define BLOCK_SIZE 16
#define KEY_SIZE 16 /* AES 128 */

unsigned char key[16] = "1234567890123456";
unsigned char iv[16] = "1234567890123456";

#endif /* _SOCKET_COMMON_H */
