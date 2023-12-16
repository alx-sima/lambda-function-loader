// SPDX-License-Identifier: BSD-3-Clause

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

#define PORT 5432

int create_socket(void)
{
	int ret = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret == -1) {
		perror("socket");
		exit(-1);
	}

	return ret;
}

int connect_socket(int fd)
{
	struct sockaddr_un sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sun_family = AF_UNIX;
	strncpy(sockaddr.sun_path, SOCKET_NAME, sizeof(sockaddr.sun_path) - 1);

	int ret = connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	return ret;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		int ret = send(fd, buf + sent, len - sent, 0);

		if (ret == -1) {
			perror("send");
			exit(-1);
		}

		sent += ret;
	}
	printf("Sent: %s\n", buf);
	return sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	size_t received = 0;

	int ret = read(fd, buf, len);

	if (ret < 0) {
		perror("recv");
		exit(-1);
	}

	received += ret;

	printf("Received: %s\n", buf);
	return received;
}

void close_socket(int fd)
{
	int ret = close(fd);
	if (ret == -1) {
		perror("close");
		exit(-1);
	}
}
