/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _IPC_H
#define _IPC_H

/* ssize_t */
#include <sys/types.h>

#define BUFSIZE 1024
#define MAX_CLIENTS 1024
#define SOCKET_NAME "/tmp/sohack.socket"

enum socket_type_t { UNIX, INET };

struct settings_t {
	int max_connections;
	enum socket_type_t socket_type;
	char *hostname;
	int port;
};

struct settings_t settings = {.max_connections = 5,
							  .socket_type = UNIX,
							  .hostname = "127.0.0.1",
							  .port = 5432};

int create_socket(void);
int connect_socket(int fd);
ssize_t send_socket(int fd, const char *buf, size_t len);
ssize_t recv_socket(int fd, char *buf, size_t len);
void close_socket(int fd);

#endif /* _IPC_H */
