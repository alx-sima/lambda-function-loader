// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	/* Create outputfile name. */
	lib->outputfile = malloc(sizeof(OUTPUT_TEMPLATE));
	if (!lib->outputfile) {
		perror("malloc");
		return -1;
	}
	strncpy(lib->outputfile, OUTPUT_TEMPLATE, sizeof(OUTPUT_TEMPLATE));

	/* Create outputfile. */
	int fd = mkstemp(lib->outputfile);
	if (fd == -1) {
		perror("mkstemp");
		return -1;
	}

	printf("outputfile: %s\n", lib->outputfile);
	return 0;
}

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (!lib->handle) {
		perror("dlopen");
		return -1;
	}

	printf("libname: %s\n", lib->libname);

	void *addr = dlsym(lib->handle, lib->funcname);
	if (!addr) {
		fprintf(stderr, "%s\n", dlerror());
		return -1;
	}

	if (lib->filename) {
		lib->p_run = addr;
	} else {
		lib->run = addr;
	}
	return 0;
}

static int lib_execute(struct lib *lib)
{
	if (lib->filename) {
		lib->p_run(lib->filename);
	} else {
		lib->run();
	}

	return 0;
}

static int lib_close(struct lib *lib)
{
	dlclose(lib->handle);
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	int opt = 1;
	int fd = create_socket();

	/* Initialize socket address. */
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);

	// if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
	// 	perror("setsockopt");
	// 	exit(EXIT_FAILURE);
	// }

	int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		perror("bind");
		exit(-1);
	}

	if (listen(fd, MAX_CLIENTS) < 0) {
		perror("listen");
		exit(-1);
	}

	int sockfd = accept(fd, (struct sockaddr *)&addr, &addrlen);
	if (sockfd == -1) {
		perror("accept");
		exit(-1);
	}

	printf("accepted\n");

	char buf[BUFSIZE] = {0};
	struct lib lib;

	while (1) {
		if (recv_socket(sockfd, buf, BUFSIZE) < 0) {
			perror("recv err");
			exit(-1);
		}

		char name[BUFSIZ] = {0};
		char func[BUFSIZ] = {0};
		char params[BUFSIZ] = {0};

		parse_command(buf, name, func, params);
		printf("buf: %s\n", buf);
		printf("func: %p\n", func);
		printf("name: %s\n", name);

		if (strlen(func) == 0) {
			strcpy(func, "run");
		}

		struct lib lib = {
			.libname = name, .funcname = func, .filename = params};

		/* TODO - get message from client */
		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		if (lib_run(&lib) < 0) {
			perror("run err");
			exit(-1);
		}

		printf("outputfile: %s\n", lib.outputfile);
		if (send_socket(sockfd, lib.outputfile, strlen(lib.outputfile)) < 0) {
			perror("send err");
			exit(-1);
		}
	}

	close_socket(sockfd);
	close_socket(fd);

	return 0;
}
